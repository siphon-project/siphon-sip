//! `SiphonServer` — public builder API for embedding siphon as a library.
//!
//! Consumers create their own `main()`, optionally embed a Python script
//! with `include_str!()`, and call `SiphonServer::builder().run()`.

mod bootstrap;
mod event_clock;
mod sbi_callbacks;

#[cfg(test)]
mod event_clock_tests;
#[cfg(test)]
mod sbi_callbacks_tests;
#[cfg(test)]
mod tests;

// `li_manager` is reached as `crate::server::li_manager` by the dispatcher, so
// its path has to survive the move out of this file.
pub use bootstrap::li_manager;

use bootstrap::*;

use std::sync::Arc;

use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use crate::config::{self, Config};
use crate::gateway::DispatcherManager;
use crate::hep::HepSender;
use crate::script::engine::{spawn_file_watcher, ScriptEngine};
use crate::script::ScriptHandle;
use crate::transport;
use crate::uac::UacSender;
use crate::{dispatcher, shutdown};

/// Deferred constructor for a host-provided Python namespace.
///
/// Boxed because the inner closure is generic over the user's `#[pyclass]`
/// type and we need to type-erase it for storage on the builder.
type UserNamespaceFactory = Box<dyn FnOnce(Python<'_>) -> PyResult<Py<PyAny>> + Send>;

/// Deferred hook that mounts an extension's contents onto the `siphon` package
/// module itself, rather than into a single named attribute.
type ModuleExtension = crate::script::api::ModuleExtension;

/// Deferred extension task — invoked after the script engine has been
/// initialised, with a [`ScriptHandle`] cloned for the task's exclusive
/// use. The closure typically calls `tokio_handle().spawn(...)` to
/// install long-running background work.
type ExtensionTask = Box<dyn FnOnce(ScriptHandle) + Send>;

/// A per-protocol control adapter registered by a host binary (the built-in SIP
/// adapter is always registered; extensions add their own — e.g. SMPP).
type ControlAdapterHandle = Arc<dyn crate::control::ControlAdapter>;

/// Builder for running a siphon server instance.
///
/// # Examples
///
/// ```rust,no_run
/// use siphon::SiphonServer;
///
/// SiphonServer::builder()
///     .config_path("siphon.yaml")
///     .embedded_script(include_str!("../../scripts/proxy_default.py"))
///     .run();
/// ```
pub struct SiphonServer {
    config_path: Option<String>,
    config_string: Option<String>,
    embedded_script: Option<&'static str>,
    embedded_bytecode: Option<&'static [u8]>,
    skip_logging_init: bool,
    product_name: Option<&'static str>,
    product_version: Option<&'static str>,
    user_namespaces: Vec<(String, UserNamespaceFactory)>,
    module_extensions: Vec<(String, ModuleExtension)>,
    extension_tasks: Vec<ExtensionTask>,
    control_adapters: Vec<ControlAdapterHandle>,
}

impl SiphonServer {
    /// Create a new builder with no configuration set.
    pub fn builder() -> Self {
        Self {
            config_path: None,
            config_string: None,
            embedded_script: None,
            embedded_bytecode: None,
            skip_logging_init: false,
            product_name: None,
            product_version: None,
            user_namespaces: Vec::new(),
            module_extensions: Vec::new(),
            extension_tasks: Vec::new(),
            control_adapters: Vec::new(),
        }
    }

    /// Override the product name and version used in startup logs and the
    /// default `User-Agent` / `Server` header values for outbound requests.
    ///
    /// Defaults to `"SIPhon"` and `env!("CARGO_PKG_VERSION")` when unset.
    /// Host applications that embed siphon as a library typically set this
    /// to their own product identity.
    pub fn product(mut self, name: &'static str, version: &'static str) -> Self {
        self.product_name = Some(name);
        self.product_version = Some(version);
        self
    }

    /// Set the path to the YAML configuration file.
    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_owned());
        self
    }

    /// Provide the YAML configuration as an in-memory string.
    /// This takes priority over `config_path`.
    pub fn config_string(mut self, yaml: &str) -> Self {
        self.config_string = Some(yaml.to_owned());
        self
    }

    /// Embed a Python script source into the binary.
    /// When set, the script is loaded from this string instead of from disk.
    /// Hot-reload is automatically disabled for embedded scripts.
    pub fn embedded_script(mut self, source: &'static str) -> Self {
        self.embedded_script = Some(source);
        self
    }

    /// Embed pre-compiled Python bytecode into the binary.
    /// Expects a `.pyc` file (16-byte header + marshalled code object).
    /// Hot-reload is automatically disabled.
    pub fn embedded_bytecode(mut self, pyc: &'static [u8]) -> Self {
        self.embedded_bytecode = Some(pyc);
        self
    }

    /// Skip siphon's built-in tracing subscriber initialization.
    ///
    /// The embedder is responsible for installing a global subscriber before
    /// calling `run()`. The values in the `log:` section of the config (level,
    /// format, file) are ignored when this is set.
    ///
    /// Use this when the host application already configures `tracing` (e.g.
    /// to rewrite log targets, add custom layers, or ship logs to a different
    /// sink) — siphon's `.init()` would otherwise panic on a second global
    /// default.
    pub fn skip_logging_init(mut self) -> Self {
        self.skip_logging_init = true;
        self
    }

    /// Register a host-provided Python namespace.
    ///
    /// `value` must be a `#[pyclass]` instance — host applications use this
    /// to expose their own Rust state to siphon scripts. The namespace is
    /// injected alongside the built-ins, so user scripts can write
    /// `from siphon import <name>`.
    ///
    /// Naming a host namespace after a built-in (e.g. `registrar`, `auth`,
    /// `cache`) is rejected at startup with a fatal error — collisions are
    /// never silently shadowed. Duplicate registrations of the same name
    /// are also rejected.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use pyo3::prelude::*;
    /// use siphon::SiphonServer;
    ///
    /// #[pyclass]
    /// struct MyNamespace { /* … */ }
    ///
    /// SiphonServer::builder()
    ///     .config_path("siphon.yaml")
    ///     .register_namespace("my_app", MyNamespace { /* … */ })
    ///     .run();
    /// ```
    pub fn register_namespace<T>(mut self, name: &str, value: T) -> Self
    where
        T: pyo3::PyClass + Send + 'static,
        pyo3::PyClassInitializer<T>: From<T>,
    {
        let factory: UserNamespaceFactory =
            Box::new(move |python| Py::new(python, value).map(|py_cell| py_cell.into_any()));
        self.user_namespaces.push((name.to_owned(), factory));
        self
    }

    /// Register a host-provided Python namespace with a deferred constructor.
    ///
    /// Use this form when the namespace's construction needs the `Python`
    /// token — for example, to embed `Py<PyAny>` references or to import
    /// other Python modules during init. For the common case of
    /// "instantiate this `#[pyclass]`", prefer `register_namespace()`.
    ///
    /// The same collision rules as `register_namespace()` apply: the name
    /// must not collide with a built-in or a previously-registered host
    /// namespace.
    pub fn register_namespace_with<F>(mut self, name: &str, factory: F) -> Self
    where
        F: FnOnce(Python<'_>) -> PyResult<Py<PyAny>> + Send + 'static,
    {
        self.user_namespaces
            .push((name.to_owned(), Box::new(factory)));
        self
    }

    /// Register a host-provided hook that mounts its contents onto the `siphon`
    /// package module itself.
    ///
    /// Use this when an extension's surface is more than one attribute — several
    /// namespaces, plus shared `#[pyclass]` types, an exception type, or
    /// module-level functions — so that `from siphon import a, b, SomeError`
    /// all resolve. For the common "expose one namespace object" case, prefer
    /// [`register_namespace`](Self::register_namespace) /
    /// [`register_namespace_with`](Self::register_namespace_with), which get
    /// collision-checked against the built-in namespace names.
    ///
    /// `name` identifies the extension for diagnostics and duplicate rejection;
    /// it is not itself turned into an attribute. The hook chooses its own
    /// attribute names, so it is *not* protected from shadowing a built-in
    /// namespace — that responsibility sits with the extension.
    ///
    /// The hook runs after every other namespace and singleton has been
    /// installed, and re-runs on each script load and reload (hence `Fn`, not
    /// `FnOnce`).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use siphon::SiphonServer;
    ///
    /// SiphonServer::builder()
    ///     .config_path("siphon.yaml")
    ///     // mounts `ss7` / `gsm_map` / `gsm_cap` / `inap` + shared types
    ///     .register_module_extension("sigtran", siphon_sigtran::python::register)
    ///     .run();
    /// ```
    pub fn register_module_extension<F>(mut self, name: &str, hook: F) -> Self
    where
        F: Fn(Python<'_>, &Bound<'_, PyModule>) -> PyResult<()> + Send + Sync + 'static,
    {
        self.module_extensions
            .push((name.to_owned(), Box::new(hook)));
        self
    }

    /// Register a host-provided task that runs after the script engine is
    /// initialised.
    ///
    /// The closure receives a [`ScriptHandle`] from which it can spawn
    /// long-running background work on siphon's tokio runtime
    /// ([`ScriptHandle::tokio_handle`]) and dispatch into custom-kind
    /// handlers the script registered ([`ScriptHandle::handlers_for`] +
    /// [`ScriptHandle::call_handler`]).
    ///
    /// Tasks are invoked sequentially in registration order, after script
    /// loading and before transport listeners come up. Each task gets
    /// its own `ScriptHandle` clone — no sharing required.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use siphon::SiphonServer;
    ///
    /// SiphonServer::builder()
    ///     .config_path("siphon.yaml")
    ///     .register_task(|script| {
    ///         script.tokio_handle().spawn(async move {
    ///             // long-running extension work — read handlers via
    ///             // script.handlers_for("my.kind"), dispatch with
    ///             // script.call_handler(&h, args).await.
    ///         });
    ///     })
    ///     .run();
    /// ```
    pub fn register_task<F>(mut self, task: F) -> Self
    where
        F: FnOnce(ScriptHandle) + Send + 'static,
    {
        self.extension_tasks.push(Box::new(task));
        self
    }

    /// Number of extension tasks currently registered on the builder.
    /// Exposed primarily for tests and host applications that want to
    /// log how many tasks they've wired up before `.run()`.
    pub fn extension_task_count(&self) -> usize {
        self.extension_tasks.len()
    }

    /// Register a per-protocol control adapter for the external remote-control
    /// plane (sibling of [`register_namespace`](Self::register_namespace) /
    /// [`register_task`](Self::register_task)).
    ///
    /// The built-in SIP adapter is always registered. A protocol extension
    /// (e.g. `siphon-smpp`) registers its own adapter here so its resource model
    /// and verbs are reachable over the same control WebSocket. Command routing
    /// is by `module()`; the substrate never parses the adapter's args/payload.
    ///
    /// No-op unless a `control:` block is configured.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use siphon::SiphonServer;
    ///
    /// SiphonServer::builder()
    ///     .config_path("siphon.yaml")
    ///     .register_control_adapter(Arc::new(MySmppAdapter::new()))
    ///     .run();
    /// ```
    pub fn register_control_adapter(mut self, adapter: ControlAdapterHandle) -> Self {
        self.control_adapters.push(adapter);
        self
    }

    /// Number of host-registered control adapters (excludes the always-on SIP
    /// adapter). Exposed for tests + host logging.
    pub fn control_adapter_count(&self) -> usize {
        self.control_adapters.len()
    }

    /// Run the siphon server. This blocks until shutdown (SIGINT/SIGTERM).
    ///
    /// Creates its own tokio runtime, so callers do not need `#[tokio::main]`.
    pub fn run(self) {
        // Install rustls crypto provider before any TLS operations
        if tokio_rustls::rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            eprintln!("Failed to install rustls CryptoProvider");
            std::process::exit(1);
        }

        // Initialize Python interpreter on the main thread first — this also
        // marks the main thread as "the python initial thread" so subsequent
        // PyGILState_Ensure calls from workers create proper per-thread state.
        pyo3::Python::initialize();

        // Build the Tokio runtime with hooks that pin each runtime thread
        // (async worker + blocking) to the Python interpreter for the thread's
        // lifetime, and unpin it when the thread is torn down. See
        // `pin_python_thread_state` for why both halves matter.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .on_thread_start(pin_python_thread_state)
            .on_thread_stop(unpin_python_thread_state)
            .build()
            .unwrap_or_else(|error| {
                eprintln!("Failed to create tokio runtime: {error}");
                std::process::exit(1);
            });

        runtime.block_on(self.run_async());
    }

    /// Async entry point — all the real work happens here.
    #[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. run_async: 60 bootstrap sections; becomes src/server/{logging,components,...}
    async fn run_async(mut self) {
        let product_name = self.product_name.unwrap_or("SIPhon");
        let product_version = self.product_version.unwrap_or(env!("CARGO_PKG_VERSION"));

        // --- Load configuration ---
        let config = if let Some(ref yaml) = self.config_string {
            Arc::new(Config::from_str(yaml).unwrap_or_else(|error| {
                eprintln!("Failed to parse config: {error}");
                std::process::exit(1);
            }))
        } else {
            let path = self.config_path.as_deref().unwrap_or("siphon.yaml");
            Arc::new(Config::from_file(path).unwrap_or_else(|error| {
                eprintln!("Failed to load {path}: {error}");
                std::process::exit(1);
            }))
        };

        // --- Initialise structured logging ---
        let _log_guard = if self.skip_logging_init {
            None
        } else {
            init_logging(&config.log)
        };

        // --- Verify jemalloc is actually the global allocator ---
        // A binary that forgot `siphon::install_allocator!()` runs siphon's Rust
        // working set on the system allocator (RSS bloat + meaningless
        // siphon_memory_* gauges). Catch it in the boot log, not a post-mortem.
        // Read-only probe — never changes allocator config.
        crate::metrics::verify_global_allocator();

        // --- Allocator tuning (glibc arena cap + periodic trim) ---
        // Applied as early as possible so the arena cap takes effect before the
        // Python/script workload starts creating glibc arenas. The
        // `siphon_glibc_*` gauges are always on regardless; this only bounds the
        // pool. No-op off glibc.
        if let Some(memory) = config.memory.as_ref() {
            if let Some(arena_max) = memory.glibc.arena_max {
                if crate::metrics::glibc::set_arena_max(arena_max) {
                    tracing::info!(arena_max, "glibc M_ARENA_MAX cap applied");
                } else {
                    tracing::warn!(
                        arena_max,
                        "glibc M_ARENA_MAX cap not applied (non-glibc target or mallopt rejected it)"
                    );
                }
            }
            let trim_interval = memory.glibc.trim_interval_secs;
            if trim_interval > 0 {
                tokio::spawn(async move {
                    let mut ticker =
                        tokio::time::interval(std::time::Duration::from_secs(trim_interval));
                    ticker.tick().await; // consume the immediate first tick
                    loop {
                        ticker.tick().await;
                        let released = crate::metrics::glibc::trim();
                        tracing::debug!(released, "periodic glibc malloc_trim(0)");
                    }
                });
            }
        }

        // SIGUSR2 → dump the full glibc `malloc_info` XML to the log for
        // call-site attribution (which arena, how fragmented). A passive
        // diagnostic, always installed on Unix; pair with heaptrack
        // (`PYTHONMALLOC=malloc`) under load to name a true raw-domain leak.
        #[cfg(unix)]
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut stream = match signal(SignalKind::user_defined2()) {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::warn!(%error, "could not install SIGUSR2 glibc malloc_info handler");
                    return;
                }
            };
            while stream.recv().await.is_some() {
                match crate::metrics::glibc::malloc_info_xml() {
                    Some(xml) => tracing::info!("glibc malloc_info dump (SIGUSR2):\n{xml}"),
                    None => tracing::info!("glibc malloc_info unavailable (non-glibc target)"),
                }
            }
        });

        let script_desc = if self.embedded_script.is_some() || self.embedded_bytecode.is_some() {
            "<embedded>".to_owned()
        } else {
            config.script.path.clone()
        };

        info!(
            "{product_name} v{product_version} starting — script: {}, domain: {:?}",
            script_desc, config.domain.local
        );

        // --- Inject Rust singletons before script loads ---
        pyo3::Python::initialize();

        // Spin up the async script-handler driver pool before any script is
        // loaded so the very first handler invocation routes through it.
        // Sized from `script.async_pool_size` (default = num CPUs); each
        // driver is a dedicated OS thread running a Python event loop
        // forever, which is what gives `asyncio.create_task(...)` from
        // inside a handler real fire-and-forget semantics (see
        // `script::async_pool` for the full story).
        let async_pool_size = config
            .script
            .async_pool_size
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
        crate::script::async_pool::AsyncPool::install(
            async_pool_size,
            tokio::runtime::Handle::current(),
        );

        // Spin up the synchronous Python executor pool — a fixed set of
        // never-reaped OS threads that all `Python::attach` handler
        // invocations route through instead of tokio's elastic
        // `spawn_blocking` pool.  Without this, reaped blocking threads orphan
        // their pinned free-threaded-CPython mimalloc heap (~2 MB each) — the
        // anonymous-heap leak under steady SIP signalling.  See
        // `script::py_executor` for the full story.
        //
        // The pool is ELASTIC: `core_threads` always-on workers, growing on
        // demand to `max_threads` when every worker is busy, then never
        // shrinking. This is the proper fix for the regression where moving
        // inbound dispatch off tokio's elastic `spawn_blocking` pool onto a
        // FIXED pool removed the burst valve — a blocking-I/O handler (HTTP /
        // Diameter digest auth, an `on_change` notify) pins a worker for the
        // whole call, so on a small box a couple of concurrent blocking
        // REGISTERs exhausted the fixed pool and wedged the engine. Growth-on-
        // demand restores the headroom; never-reaping keeps the persistent
        // free-threaded-CPython attach from leaking (the reason the pool stopped
        // using `spawn_blocking`).
        //
        // The default ceiling is MEMORY-AWARE, not just CPU-derived. Each grown
        // worker carries its own persistent free-threaded-CPython mimalloc heap
        // measured at ~8 MB (not the ~2 MB the original estimate assumed), and a
        // purely CPU-derived ceiling (`max(32, 4×core)`) scaled the pool's memory
        // ceiling with the *host* core count — unrelated to the NF's memory
        // budget — so an un-cpu-limited NF on a 16-core box defaulted to
        // core=32/max=128 ≈ 1 GB of pool heap. `resolve_sizing` instead takes the
        // MINIMUM of that CPU cap and a memory budget (~30 % of the container's
        // cgroup limit ÷ per-worker heap), and caps `core` the same way so the
        // pool also doesn't *start* at 32 workers on a big box. On a 512 MB NF the
        // ceiling resolves to ~15 (was 32/128); the `script.sync_pool_size` /
        // `script.sync_pool_max` overrides still win. `auth.http.cache_ttl_secs`
        // remains the right lever to keep an auth storm from ever needing to grow.
        let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
        let mem_limit = crate::script::py_executor::read_memory_limit_bytes();
        let sizing = crate::script::py_executor::resolve_sizing(
            cpus,
            mem_limit,
            config.script.sync_pool_size,
            config.script.sync_pool_max,
        );
        info!(
            cpus,
            mem_limit_mb = mem_limit.map(|bytes| bytes / 1024 / 1024),
            core_threads = sizing.core_threads,
            max_threads = sizing.max_threads,
            bound = sizing.bound.as_str(),
            "resolved synchronous Python executor pool sizing"
        );
        let core_threads = sizing.core_threads;
        let max_threads = sizing.max_threads;
        // Bound the queue (load-shed under overload instead of unbounded growth)
        // and arm the liveness watchdog (abort + supervisor-restart only if the
        // pool reaches the cap and still wedges). `handler_stall_abort_secs == 0`
        // disables the watchdog.
        let executor_config = crate::script::py_executor::ExecutorConfig {
            core_threads,
            max_threads,
            queue_capacity: config.script.executor_queue_capacity,
            stall_abort: match config.script.handler_stall_abort_secs {
                0 => None,
                secs => Some(std::time::Duration::from_secs(secs)),
            },
        };
        crate::script::py_executor::PyExecutor::install(
            tokio::runtime::Handle::current(),
            executor_config,
        );

        dispatcher::inject_python_singletons(&config);
        // Media-engine async event channel (DTMF, media-timeout). Created before
        // init_rtpengine so the native siphon-rtp backend can forward events from
        // its control connection over the same channel the rtpengine NG event
        // listener feeds; the dispatcher consumes from `rtpengine_events_rx`.
        let (rtpengine_events_tx, rtpengine_events_rx) =
            tokio::sync::mpsc::channel::<crate::rtpengine::events::RtpEngineEvent>(256);
        let pre_rtpengine = dispatcher::init_rtpengine(&config, rtpengine_events_tx.clone());

        // --- Gateway dispatcher ---
        let gateway_manager = init_gateway(&config);

        // --- CDR singleton ---
        if config.cdr.is_some() {
            pyo3::Python::attach(|python| {
                let py_cdr = crate::script::api::cdr::PyCdrNamespace::new();
                if let Err(error) = crate::script::api::set_cdr_singleton(python, py_cdr) {
                    error!("failed to store CDR singleton: {error}");
                } else {
                    info!("CDR namespace registered for injection");
                }
            });
        }

        // --- Presence singleton ---
        let presence_store = Arc::new(crate::presence::PresenceStore::new());
        // Install the global handle so the dispatcher's cleanup tick can expire
        // stale presence documents/subscriptions (L1 has no TTL reaper of its own).
        crate::presence::set_global_store(Arc::clone(&presence_store));
        pyo3::Python::attach(|python| {
            let py_presence =
                crate::script::api::presence::PyPresence::new(Arc::clone(&presence_store));
            if let Err(error) = crate::script::api::set_presence_singleton(python, py_presence) {
                error!("failed to store presence singleton: {error}");
            } else {
                info!("presence namespace registered for injection");
            }
        });

        // --- LI singleton ---
        let li_state = init_li(&config);

        // --- Diameter singleton ---
        let diameter_manager = init_diameter(&config);

        // Wire Diameter manager into PyAuth for IMS digest
        if let Some(ref manager) = diameter_manager {
            pyo3::Python::attach(|python| {
                crate::script::api::wire_auth_diameter_manager(python, Arc::clone(manager));
                info!("Diameter manager wired into auth namespace for IMS digest");
            });
        }

        // --- Rf offline charging service (TS 32.299) ---
        let rf_charger = init_rf_charging(&config, diameter_manager.as_ref());
        let ro_charger = init_ro_charging(&config, diameter_manager.as_ref());

        // --- Initialize metrics ---
        if let Err(error) = crate::metrics::init() {
            error!("Failed to initialize metrics: {error}");
        }

        // --- Spawn RTPEngine health-check task ---
        // Must run after metrics::init so the gauges exist when the task
        // publishes its first probe result.
        if let Some(rtpengine_set) = pre_rtpengine.0.as_ref() {
            let interval_secs = config
                .media
                .as_ref()
                .map(|m| m.health_check_interval_secs)
                .unwrap_or(0);
            dispatcher::spawn_rtpengine_health_check(Arc::clone(rtpengine_set), interval_secs);
        }

        // --- Initialize custom metrics namespace for Python scripts ---
        // Must happen before script engine so `from siphon import metrics` works.
        if let Some(custom) = crate::metrics::custom_metrics() {
            pyo3::Python::attach(|python| {
                let py_metrics = crate::script::api::metrics::PyMetricsNamespace::new(
                    std::sync::Arc::clone(custom),
                );
                if let Err(error) = crate::script::api::set_metrics_singleton(python, py_metrics) {
                    error!("failed to store metrics singleton: {error}");
                } else {
                    info!("metrics namespace registered for Python scripts");
                }
            });
        }

        // --- Initialize SDP namespace for Python scripts ---
        // Stateless parser — always available, no config needed.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_sdp_singleton(python) {
                error!("failed to store sdp singleton: {error}");
            }
        });

        // --- Initialize QoS namespace for Python scripts ---
        // Stateless SDP→IPFilterRule helper — always available, no config needed.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_qos_singleton(python) {
                error!("failed to store qos singleton: {error}");
            }
        });

        // --- Initialize numbers namespace + number-policy runtime ---
        // E.164 identity normalization. The parser namespace is always
        // available; the home locale and named policies come from the config.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_numbers_singleton(python) {
                error!("failed to store numbers singleton: {error}");
            }
        });
        {
            let (registry, warnings) = crate::numbers::policy::NumberRegistry::build(
                &config.numbering,
                &config.number_policies,
            );
            for warning in &warnings {
                warn!("number policy: {warning}");
            }
            let default_b2bua_policy = match &config.b2bua.default_number_policy {
                Some(name) => match registry.get(name) {
                    Some(policy) => Some(policy),
                    None => {
                        warn!(
                            "b2bua.default_number_policy {name:?} not found in number_policies; \
                             no default number normalization will be applied"
                        );
                        None
                    }
                },
                None => None,
            };
            crate::script::api::numbers::set_number_runtime(std::sync::Arc::new(
                crate::script::api::numbers::NumberRuntime {
                    registry,
                    default_b2bua_policy,
                },
            ));
        }

        // --- Initialize timer namespace for Python scripts ---
        // Runtime scheduler for timer.set / timer.cancel — always available.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_timer_singleton(python) {
                error!("failed to store timer singleton: {error}");
            }
        });

        // --- Initialize imperative B2BUA control for Python scripts ---
        // Backs b2bua.terminate() — always available, reaches the dispatcher via
        // a global handle set once run() starts.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_b2bua_control_singleton(python) {
                error!("failed to store b2bua control singleton: {error}");
            }
        });

        // --- Initialize ISC namespace before script load ---
        // Must be registered before ScriptEngine::new() so that
        // install_siphon_module() can inject the Rust-backed isc instance
        // instead of leaving the Python stub.
        {
            let global_ifcs = if let Some(ref isc_config) = config.isc {
                let xml = if let Some(ref path) = isc_config.ifc_xml_path {
                    match std::fs::read_to_string(path) {
                        Ok(contents) => Some(contents),
                        Err(error) => {
                            error!("failed to read iFC XML from {path}: {error}");
                            None
                        }
                    }
                } else {
                    isc_config.ifc_xml.clone()
                };

                if let Some(xml) = xml {
                    match crate::ifc::parse_service_profile(&xml) {
                        Ok(ifcs) => {
                            info!(count = ifcs.len(), "iFC rules loaded from config");
                            ifcs
                        }
                        Err(error) => {
                            error!("failed to parse iFC XML: {error}");
                            vec![]
                        }
                    }
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

            let ifc_store = Arc::new(crate::ifc::IfcStore::new(global_ifcs));
            pyo3::Python::attach(|python| {
                let py_isc = crate::script::api::isc::PyIsc::new(Arc::clone(&ifc_store));
                if let Err(error) =
                    crate::script::api::set_isc_singleton(python, py_isc, Arc::clone(&ifc_store))
                {
                    error!("failed to store ISC singleton: {error}");
                } else {
                    info!("ISC namespace registered for injection");
                }
            });
        }

        // --- Stamp the per-process identity onto the registrar BEFORE the
        // backend restore.  Bindings accepted from now on will carry
        // (instance_id, instance_epoch); restored bindings keep whatever
        // identity their original writer stamped on them.
        init_registrar_identity(&config);

        // --- Restore registrar contacts + iFC profiles from backend ---
        // Must run after ISC singleton init so ifc_store_arc() is available
        // for the iFC Redis restore in init_ifc_redis_backend().
        init_registrar_backend(&config).await;

        // --- Host-registered user namespaces ---
        // Run each factory under Python::attach, then store the resulting
        // Py<PyAny> on the global registry so install_siphon_module() picks
        // it up. Collisions with built-in namespaces are fatal.
        let user_namespaces = std::mem::take(&mut self.user_namespaces);
        if !user_namespaces.is_empty() {
            pyo3::Python::attach(|python| {
                for (name, factory) in user_namespaces {
                    let py_obj = match factory(python) {
                        Ok(obj) => obj,
                        Err(error) => {
                            eprintln!("Failed to construct user namespace '{name}': {error}");
                            std::process::exit(1);
                        }
                    };
                    if let Err(error) = crate::script::api::set_user_namespace(&name, py_obj) {
                        eprintln!("Failed to register user namespace '{name}': {error}");
                        std::process::exit(1);
                    }
                    info!(name = %name, "user namespace registered for injection");
                }
            });
        }

        // --- Host-registered module extensions ---
        // Stored on the global registry the same way; install_siphon_module()
        // replays them against the `siphon` module on every script load.
        let module_extensions = std::mem::take(&mut self.module_extensions);
        for (name, hook) in module_extensions {
            if let Err(error) = crate::script::api::set_module_extension(&name, hook) {
                eprintln!("Failed to register module extension '{name}': {error}");
                std::process::exit(1);
            }
            info!(name = %name, "module extension registered for injection");
        }

        // --- IPsec SA manager + singleton ---
        //
        // Must be wired BEFORE `ScriptEngine::new()` so the script's
        // top-level `from siphon import ipsec` resolves.  The manager
        // Arc is also passed to the dispatcher much later in this fn.
        //
        // pcscf_addr is derived from the first UDP listen entry in
        // config (no actual binding has happened yet).  Falls back to
        // 0.0.0.0 if no UDP listener is configured — XFRM will not
        // match traffic against the wildcard, but the singleton is
        // still wired so the script can import it.
        let ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>> =
            if let Some(ref ipsec_config) = config.ipsec {
                let backend = match ipsec_config.backend {
                    crate::config::IpsecBackend::Netlink => crate::ipsec::XfrmBackend::Netlink,
                    crate::config::IpsecBackend::Ip => crate::ipsec::XfrmBackend::IpCommand,
                };
                let spi_start = ipsec_config.spi_range_start.unwrap_or(10000);
                let spi_count = ipsec_config.spi_range_count;
                let manager = Arc::new(crate::ipsec::IpsecManager::with_partition(
                    backend, spi_start, spi_count,
                ));
                // Register the process-wide handle so the dispatcher's 30 s
                // cleanup tick can sweep abandoned SA pairs (states + policies +
                // map entry) once they pass their own hard-lifetime + grace.
                crate::ipsec::set_global_manager(Arc::clone(&manager));
                info!(
                    backend = ?backend,
                    spi_start,
                    spi_count,
                    active = manager.active_count(),
                    "IPsec SA manager initialized (script-driven via siphon.ipsec)"
                );

                // Derive the P-CSCF local address per family from the first UDP
                // listen entry of each family, without binding the listener.  Used
                // at SA creation time as the P-CSCF side of the kernel's xfrm
                // selectors — which must match the UE's family (3GPP TS 33.203
                // §7.2), so a dual-stack P-CSCF needs both.
                let mut pcscf_addr_v4: Option<std::net::IpAddr> = None;
                let mut pcscf_addr_v6: Option<std::net::IpAddr> = None;
                // Prefer a concrete bind address over a wildcard (0.0.0.0 / [::]):
                // an unspecified address yields a dead XFRM selector, so take the
                // first concrete listener of each family when one exists, only
                // falling back to a wildcard entry if that's all that's configured
                // (preserves the historical single-wildcard-listener behaviour).
                for entry in &config.listen.udp {
                    if let Ok(addr) = entry.address().parse::<std::net::SocketAddr>() {
                        let ip = addr.ip();
                        let slot = if ip.is_ipv6() {
                            &mut pcscf_addr_v6
                        } else {
                            &mut pcscf_addr_v4
                        };
                        match slot {
                            None => *slot = Some(ip),
                            Some(existing) if existing.is_unspecified() && !ip.is_unspecified() => {
                                *slot = Some(ip);
                            }
                            _ => {}
                        }
                    }
                }

                let ipsec_manager_for_singleton = Arc::clone(&manager);
                let ipsec_config_arc = Arc::new(ipsec_config.clone());
                pyo3::Python::attach(|python| {
                    let py_ipsec = crate::script::api::ipsec::PyIpsec::new(
                        ipsec_manager_for_singleton,
                        ipsec_config_arc,
                        pcscf_addr_v4,
                        pcscf_addr_v6,
                    );
                    if let Err(error) = crate::script::api::set_ipsec_singleton(python, py_ipsec) {
                        error!("failed to store IPsec singleton: {error}");
                    } else {
                        info!(
                            pcscf_addr_v4 = ?pcscf_addr_v4,
                            pcscf_addr_v6 = ?pcscf_addr_v6,
                            "ipsec namespace registered for injection"
                        );
                    }
                });

                Some(manager)
            } else {
                None
            };

        // --- STIR/SHAKEN namespace (siphon.stir) ---
        //
        // Must be wired BEFORE `ScriptEngine::new()` so the script's top-level
        // `from siphon import stir` resolves.  Loads the signing key + STI-CA
        // trust anchors from disk and builds the x5u HTTP client; a bad path /
        // unparseable key fails startup loudly rather than at first call.
        if let Some(ref stir_config) = config.stir {
            if stir_config.enabled
                && (stir_config.signing.is_some() || stir_config.verification.is_some())
            {
                match crate::stir::StirService::from_config(stir_config) {
                    Ok(service) => {
                        let signing = service.signing_enabled();
                        let verification = service.verification_enabled();
                        pyo3::Python::attach(|python| {
                            let py_stir = crate::script::api::stir::PyStir::new(service);
                            if let Err(error) =
                                crate::script::api::set_stir_singleton(python, py_stir)
                            {
                                error!("failed to store STIR singleton: {error}");
                            } else {
                                info!(
                                    signing,
                                    verification,
                                    "stir namespace registered for injection (STIR/SHAKEN)"
                                );
                            }
                        });
                    }
                    Err(error) => {
                        error!("failed to initialize STIR/SHAKEN service: {error}");
                        eprintln!("STIR/SHAKEN configuration error: {error}");
                        std::process::exit(1);
                    }
                }
            } else {
                info!("stir block present but disabled or empty — STIR/SHAKEN not wired");
            }
        }

        // --- Subscribe-state namespace (proxy.subscribe_state) ---
        //
        // Must run BEFORE `ScriptEngine::new()` so that
        // `install_siphon_module()` can replace the Python `_SubscribeStateStub`
        // with the Rust-backed namespace on the very first script load.
        // Embedded-bytecode apps load the script exactly once, so a
        // post-engine setup leaves the stub bound forever and any
        // `await proxy.subscribe_state.send(...)` raises AttributeError.
        // Source-script apps masked the bug because file-watcher reloads
        // re-run install_siphon_module after the singleton is set.
        {
            let cache_manager = std::sync::Arc::new(crate::cache::CacheManager::new(
                config.cache.as_deref().unwrap_or(&[]),
            ));
            let mut store = crate::subscribe_state::SubscribeStore::new();
            if let Some(ref cfg) = config.subscribe_state {
                if let Some(ref cache_name) = cfg.cache {
                    if cache_manager.has_cache(cache_name) {
                        store = store.with_cache(Arc::clone(&cache_manager), cache_name.clone());
                        info!(cache = %cache_name, "subscribe_state: L2 persistence enabled");
                    } else {
                        error!(
                            cache = %cache_name,
                            "subscribe_state: configured cache not found in cache: list"
                        );
                    }
                }
            }
            let store_arc = Arc::new(store);
            // Install the global handle so the dispatcher's cleanup tick can
            // sweep expired/abandoned subscribe dialogs out of L1 (which, unlike
            // L2, has no TTL reaper of its own).
            crate::subscribe_state::set_global_store(Arc::clone(&store_arc));
            pyo3::Python::attach(|python| {
                let namespace = crate::script::api::subscribe_state::PySubscribeState::new(
                    Arc::clone(&store_arc),
                );
                if let Err(error) =
                    crate::script::api::set_subscribe_state_singleton(python, namespace)
                {
                    error!("failed to store subscribe_state singleton: {error}");
                }
            });
        }

        // --- Registrant manager + registration namespace ---
        //
        // Create the manager and install the `registration` Python namespace
        // BEFORE `ScriptEngine::new()` — same reason as subscribe_state above.
        // A script's `from siphon import registration` binds whatever
        // `siphon.registration` is at import time; if the Rust namespace is
        // installed later (when the background loop is wired, which needs
        // `outbound_senders`), the script keeps the no-op `_RegistrationNamespace`
        // stub and `registration.flow()` / `service_route()` raise
        // NotImplementedError at call time. The config entries + refresh loop
        // are wired later in `init_registrant` using this same manager.
        let registrant_manager: Option<Arc<crate::registrant::RegistrantManager>> =
            config.registrant.as_ref().map(|registrant_config| {
                let registrant_user_agent = config
                    .server
                    .as_ref()
                    .and_then(|server| server.user_agent_header.clone())
                    .or_else(|| Some(format!("{product_name}/{product_version}")));
                let manager = Arc::new(crate::registrant::RegistrantManager::new(
                    registrant_config.default_interval,
                    std::time::Duration::from_secs(registrant_config.retry_interval),
                    std::time::Duration::from_secs(registrant_config.max_retry_interval),
                    registrant_user_agent,
                ));
                pyo3::Python::attach(|python| {
                    // PyRegistration ignores local_addr (flow() takes ue_ip
                    // explicitly); pass a placeholder.
                    let py_registration = crate::script::api::registrant::PyRegistration::new(
                        Arc::clone(&manager),
                        std::net::SocketAddr::from(([0u8, 0, 0, 0], 0)),
                    );
                    if let Err(error) =
                        crate::script::api::set_registration_singleton(python, py_registration)
                    {
                        error!("failed to store registration singleton: {error}");
                    } else {
                        info!("registration namespace registered for injection");
                    }
                });
                manager
            });

        // Least-Cost Routing (LCR) HTTP client — backs the B2BUA-only
        // `lcr.route(...)` namespace. Registered BEFORE the script engine so a
        // script's top-level `from siphon import lcr` resolves to the real
        // namespace (not the import stub). The API owns the cost decision;
        // siphon caches it and executes the ordered route set against the
        // gateway health/failover machinery.
        if let Some(ref lcr_config) = config.lcr {
            // The LCR client keeps its own CacheManager over the same `cache:`
            // config. Its L2 (Redis) is shared by key with every replica, so a
            // decision cached on one node is reused fleet-wide; only the L1 LRU
            // is process-local (fine — the `lcr` cache isn't touched via the
            // `cache` namespace).
            let (cache_handle, cache_name) = match lcr_config.cache.as_ref() {
                Some(name) => {
                    let manager = Arc::new(crate::cache::CacheManager::new(
                        config.cache.as_deref().unwrap_or(&[]),
                    ));
                    if manager.has_cache(name) {
                        (Some(manager), Some(name.clone()))
                    } else {
                        tracing::warn!(
                            cache = %name,
                            "lcr.cache names an unconfigured cache — LCR decisions won't be cached",
                        );
                        (None, None)
                    }
                }
                None => (None, None),
            };
            let lcr_client = Arc::new(crate::lcr::LcrClient::new(
                lcr_config.api_url.clone(),
                lcr_config.timeout_ms,
                lcr_config.auth_header.clone(),
                cache_handle,
                cache_name,
                lcr_config.cache_ttl_secs,
                lcr_config.fallback_gateway_group.clone(),
            ));
            // Install the process-wide reroute-cause set (the generic level).
            let reroute_causes = lcr_config
                .reroute_causes
                .clone()
                .map(|codes| codes.into_iter().collect())
                .unwrap_or_else(crate::lcr::default_reroute_causes);
            crate::lcr::set_global_reroute_causes(reroute_causes);
            pyo3::Python::attach(|python| {
                let py_lcr = crate::script::api::lcr::PyLcr::new(lcr_client);
                if let Err(error) = crate::script::api::set_lcr_singleton(python, py_lcr) {
                    error!("failed to store LCR singleton: {error}");
                }
            });
            info!(
                api_url = %lcr_config.api_url,
                "LCR client initialized and exposed to Python (B2BUA-only)",
            );
        }

        // --- Script engine ---
        let engine = if let Some(bytecode) = self.embedded_bytecode {
            Arc::new(
                ScriptEngine::new_from_bytecode(bytecode).unwrap_or_else(|error| {
                    eprintln!("Failed to load embedded bytecode: {error}");
                    std::process::exit(1);
                }),
            )
        } else if let Some(source) = self.embedded_script {
            Arc::new(ScriptEngine::new_embedded(source).unwrap_or_else(|error| {
                eprintln!("Failed to load embedded script: {error}");
                std::process::exit(1);
            }))
        } else {
            Arc::new(ScriptEngine::new(&config.script).unwrap_or_else(|error| {
                eprintln!("Failed to load script: {error}");
                std::process::exit(1);
            }))
        };

        // Start file watcher for hot-reload (no-op for embedded scripts)
        spawn_file_watcher(Arc::clone(&engine));

        // Start any @timer.every() handlers registered in the script.
        engine.restart_timers();

        // --- Host-registered extension tasks ---
        // Run each registered extension task with its own ScriptHandle.
        // These typically spawn long-running background work (HTTP
        // listeners, side-channel clients, periodic sweeps) on siphon's
        // tokio runtime. Sequential invocation in registration order;
        // panics in a task closure abort the server.
        let extension_tasks = std::mem::take(&mut self.extension_tasks);
        if !extension_tasks.is_empty() {
            let runtime_handle = tokio::runtime::Handle::current();
            for task in extension_tasks {
                let script_handle = ScriptHandle::new(engine.state_arc(), runtime_handle.clone());
                task(script_handle);
            }
            info!("extension tasks started");
        }

        // --- Kernel firewall (nf_tables) — opt-in, needs CAP_NET_ADMIN ---
        // Programs banned sources into a kernel set so abusive traffic is
        // dropped before it reaches siphon's socket. On failure (missing
        // capability, non-Linux) we warn and fall back to the userspace ACL —
        // never fatal.
        let kernel_firewall = match config
            .security
            .as_ref()
            .and_then(|sec| sec.firewall.as_ref())
        {
            Some(firewall_config) => match crate::firewall::start(firewall_config).await {
                Ok(handle) => Some(handle),
                Err(error) => {
                    warn!(%error, "kernel firewall (nf_tables) unavailable — falling back to the userspace ACL (missing CAP_NET_ADMIN?)");
                    None
                }
            },
            None => None,
        };

        // --- Build transport ACL ---
        let transport_acl = build_transport_acl(&config, kernel_firewall.clone());

        // --- Stream message-size ceiling ---
        // Always installed (unlike the opt-in guards below): a stream reader
        // that trusts a peer's declared Content-Length has no upper bound on
        // what one connection can make it buffer, so the ceiling has to hold
        // even when no `security:` block is configured at all.
        let max_message_bytes = config
            .security
            .as_ref()
            .and_then(|sec| sec.max_message_bytes)
            .unwrap_or(crate::security::DEFAULT_MAX_MESSAGE_BYTES);
        crate::security::set_max_message_bytes(max_message_bytes);
        debug!(max_message_bytes, "stream message-size ceiling installed");

        // --- Inbound connection ceilings ---
        // Also always installed, and for the same reason: nothing else bounds
        // how many connections or concurrent handshakes one source can make
        // siphon carry, and a TLS handshake is real CPU held for the whole
        // handshake timeout. `trusted_cidrs` are exempt so a trunk or a
        // monitoring probe is never refused.
        let connection_limits_config = config
            .security
            .as_ref()
            .map(|sec| sec.connection_limits.clone())
            .unwrap_or_default();
        let trusted_cidrs = config
            .security
            .as_ref()
            .map(|sec| sec.trusted_cidrs.clone())
            .unwrap_or_default();
        let connection_limits = crate::security::ConnectionLimits::from(&connection_limits_config);
        crate::security::set_connection_limiter(Arc::new(crate::security::ConnectionLimiter::new(
            connection_limits,
            &trusted_cidrs,
        )));
        info!(
            max_handshakes_per_source = connection_limits.max_handshakes_per_source,
            max_handshakes = connection_limits.max_handshakes,
            max_connections_per_source = connection_limits.max_connections_per_source,
            max_connections = connection_limits.max_connections,
            trusted_cidrs = trusted_cidrs.len(),
            "inbound connection ceilings installed (0 = unlimited)"
        );

        // --- Auto-ban (failed_auth_ban scanner protection) ---
        // Opt-in: only installed when configured. Once installed, the auth path
        // (challenge/success), the dispatcher (non-ACK INVITE Timer H), and the
        // transport ACL (is_allowed) all reach it via crate::security::auto_ban().
        if let Some(ref sec) = config.security {
            if let Some(ref fab) = sec.failed_auth_ban {
                // Default the sliding-expiry cap to a day's worth of bans at the
                // configured duration. Long enough that a scanner leaning on the
                // box stays pinned across a working day, short enough that a
                // wrong verdict on a CGNAT address ages out on its own.
                let max_ban_duration_secs = fab
                    .max_ban_duration_secs
                    .unwrap_or_else(|| fab.ban_duration_secs.saturating_mul(24));
                let store = Arc::new(crate::security::AutoBanStore::new(
                    fab.threshold,
                    fab.window_secs,
                    fab.ban_duration_secs,
                    &sec.trusted_cidrs,
                    fab.strong_signal_weight,
                    fab.missing_credentials_weight,
                    max_ban_duration_secs,
                ));
                crate::security::set_auto_ban(Arc::clone(&store));
                if let Some(ref firewall) = kernel_firewall {
                    store.set_firewall(firewall.clone());
                }
                info!(
                    threshold = fab.threshold,
                    window_secs = fab.window_secs,
                    ban_duration_secs = fab.ban_duration_secs,
                    max_ban_duration_secs,
                    strong_signal_weight = fab.strong_signal_weight,
                    missing_credentials_weight = fab.missing_credentials_weight,
                    trusted_cidrs = sec.trusted_cidrs.len(),
                    "failed_auth_ban scanner protection enabled"
                );
                // Periodic prune (bounds memory under scanner churn) + publish the
                // banned_ips gauge authoritatively each tick.
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                    loop {
                        ticker.tick().await;
                        store.prune();
                        if let Some(metrics) = crate::metrics::try_metrics() {
                            metrics.banned_ips.set(store.active_bans() as i64);
                        }
                    }
                });
            }

            // --- Request security filter (rate_limit + scanner_block) ---
            // Opt-in: only installed when `security.rate_limit` and/or
            // `security.scanner_block` is set. Once installed, the dispatcher
            // consults it on every inbound request (before transaction/dialog
            // processing) via crate::security::security_filter(). trusted_cidrs
            // are exempt from both checks.
            if let Some(filter) = crate::security::SecurityFilter::from_config(sec) {
                crate::security::set_security_filter(Arc::clone(&filter));
                info!(
                    rate_limit = sec.rate_limit.is_some(),
                    scanner_user_agents = sec
                        .scanner_block
                        .as_ref()
                        .map(|block| block.user_agents.len())
                        .unwrap_or(0),
                    trusted_cidrs = sec.trusted_cidrs.len(),
                    "request security filter enabled (rate_limit / scanner_block)"
                );
                // Periodic prune to bound the rate-limiter maps under scanner churn.
                tokio::spawn(async move {
                    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
                    loop {
                        ticker.tick().await;
                        filter.prune();
                    }
                });
            }
        }

        // --- Transport channels ---
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (tcp_outbound_tx, tcp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (tls_outbound_tx, tls_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (wss_outbound_tx, wss_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        // The `sctp` sender always exists on the OutboundRouter so the
        // `Transport::Sctp` routing arm stays infallible; the receiver is only
        // consumed by the SCTP listener loop, which is compiled in under the
        // `sctp` feature. Without it the receiver is intentionally unused.
        #[cfg(feature = "sctp")]
        let (sctp_outbound_tx, sctp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        #[cfg(not(feature = "sctp"))]
        let (sctp_outbound_tx, _sctp_outbound_rx) =
            flume::unbounded::<transport::OutboundMessage>();

        // UDP listeners get a dedicated outbound channel each — required
        // for IPsec sec-agree on the P-CSCF role (3GPP TS 33.203 §7.4)
        // where a reply must egress on the same local socket the request
        // arrived on.  The first *configured* listener's channel doubles as
        // the default fallback for messages without a `source_local_addr`
        // (see `default_udp_egress_addr`).
        let mut udp_listener_channels: std::collections::HashMap<
            std::net::SocketAddr,
            (
                flume::Sender<transport::OutboundMessage>,
                flume::Receiver<transport::OutboundMessage>,
            ),
        > = std::collections::HashMap::new();
        for entry in &config.listen.udp {
            let addr: std::net::SocketAddr = match entry.address().parse() {
                Ok(addr) => addr,
                Err(_) => continue, // re-validated by the listener loop below
            };
            udp_listener_channels
                .entry(addr)
                .or_insert_with(flume::unbounded);
        }
        // Per-listener routing is only needed for the IPsec sec-agree
        // path (TS 33.203 §7.4 — replies must egress on the same SA's
        // local socket).  For non-P-CSCF deployments the per-listener
        // map adds a HashMap lookup to every UDP response (~15-20 % CPU
        // bump at 10 kcps in the README scale baseline), so leave it
        // empty unless `ipsec` is configured.  All listeners then share
        // the `udp_default` sender — the legacy shared-receiver
        // behaviour of the original design, which the no-ipsec scale
        // baseline was tuned against.
        let mut udp_by_local: std::collections::HashMap<
            std::net::SocketAddr,
            flume::Sender<transport::OutboundMessage>,
        > = std::collections::HashMap::new();
        let ipsec_enabled = config.ipsec.is_some();
        // Populate the per-listener UDP channel map when IPsec is enabled OR the
        // host is multi-homed (more than one UDP listener).  A single-listener
        // deployment — the README perf baseline — keeps `udp_by_local` empty so
        // `OutboundRouter::send` stays on the branch-predicted fast path (no
        // per-message HashMap lookup).  Multi-homing is what makes a script
        // `send_socket=` egress pin meaningful, and it also covers
        // IPsec-protected replies (TS 33.203 §7.4).
        let per_listener_udp = ipsec_enabled || udp_listener_channels.len() > 1;
        if per_listener_udp {
            for (addr, (tx, _)) in udp_listener_channels.iter() {
                udp_by_local.insert(*addr, tx.clone());
            }
        }
        // Default egress socket for UDP sends without a `source_local_addr` pin
        // (relays, forks, UAC-originated).  Deterministically the FIRST
        // configured `listen.udp` listener — the same one advertised as
        // `listen_addrs[Udp]` / the outgoing Via sent-by — NOT an arbitrary
        // `udp_listener_channels` HashMap-iteration pick (per-process randomized
        // seed).  Without this a multi-homed UDP host could egress from a
        // different socket than its Via advertised and flip between restarts.
        let udp_default = default_udp_egress_addr(&config.listen.udp)
            .and_then(|addr| udp_listener_channels.get(&addr).map(|(tx, _)| tx.clone()))
            .unwrap_or_else(|| flume::unbounded().0);

        let outbound_senders = Arc::new(transport::OutboundRouter {
            udp: udp_default,
            udp_by_local,
            tcp: tcp_outbound_tx,
            tls: tls_outbound_tx,
            ws: ws_outbound_tx,
            wss: wss_outbound_tx,
            sctp: sctp_outbound_tx,
        });

        // --- Start transport listeners ---
        let mut first_listen_addr: Option<std::net::SocketAddr> = None;
        let mut listen_addrs = std::collections::HashMap::new();
        let mut advertised_addrs: std::collections::HashMap<transport::Transport, String> =
            std::collections::HashMap::new();
        // Every configured listener (transport + bound addr + advertised host),
        // for `send_socket=` egress resolution.  Unlike `listen_addrs` (first
        // per transport), this keeps the FULL multi-homed set across transports.
        let mut listener_registry_entries: Vec<(
            transport::Transport,
            std::net::SocketAddr,
            Option<String>,
        )> = Vec::new();

        // DSCP → TOS byte resolution helper.
        // Per-entry overrides the global listen.dscp (default CS3 = 24 → TOS 96).
        let global_dscp = config.listen.dscp;
        let udp_recv_buffer_bytes = config.listen.udp_recv_buffer_bytes;
        let resolve_tos = |entry: &config::ListenEntry| -> Option<u32> {
            let dscp = entry.dscp().or(global_dscp)?;
            if dscp == 0 {
                None
            } else {
                Some(config::dscp_to_tos(dscp))
            }
        };

        // Reject listen addresses that cannot share one socket, and work out
        // which ones are shared legitimately, before any listener is bound.
        let (tcp_ws_mux, tls_wss_mux) =
            resolve_mux_addresses(&config.listen).unwrap_or_else(|error| {
                eprintln!("{error}");
                std::process::exit(1);
            });

        // UDP
        for entry in &config.listen.udp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid UDP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs
                .entry(transport::Transport::Udp)
                .or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs
                    .entry(transport::Transport::Udp)
                    .or_insert_with(|| adv.to_string());
            }
            listener_registry_entries.push((
                transport::Transport::Udp,
                addr,
                entry.advertise().map(str::to_string),
            ));
            let tos = resolve_tos(entry);
            info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting UDP transport");
            // Use this listener's dedicated outbound channel (TS 33.203
            // §7.4 — replies to IPsec-protected requests must egress on
            // the same socket they arrived on; sharing one channel makes
            // that impossible because any listener can pick up any send).
            let listener_rx = udp_listener_channels
                .get(&addr)
                .map(|(_, rx)| rx.clone())
                .unwrap_or_else(|| flume::unbounded().1);
            transport::udp::listen(
                addr,
                inbound_tx.clone(),
                listener_rx,
                Arc::clone(&transport_acl),
                tos,
                udp_recv_buffer_bytes,
            )
            .await;
        }

        // RFC 5626 §4.4.1 pong tracker — created up front so it can be
        // wired into TCP/TLS listeners and the outbound pool.  The
        // keepalive prober is spawned later, once both connection maps
        // exist; the tracker is shared between the prober and the
        // per-connection read tasks that record peer pongs.  Always
        // create the tracker when the config opts in; transport read
        // tasks answer peer pings unconditionally either way.
        let crlf_pong_tracker = config
            .nat
            .as_ref()
            .and_then(|nat_config| nat_config.crlf_keepalive.as_ref())
            .map(|_| Arc::new(transport::crlf_keepalive::CrlfPongTracker::new()));

        // RFC 5626 §4.2.2 flow-failure deregistration.  When registration
        // liveness is enabled, a closed stream connection (peer FIN/RST, read
        // error, idle timeout, or CRLF-keepalive failure) deregisters the
        // bindings that arrived on it.  Each stream listener (TCP/TLS/WS/WSS)
        // is handed `close_tx` and enqueues the dead `ConnectionId.0`; this
        // task drains the channel and calls `Registrar::unregister_flow`.
        // Left `None` when liveness is disabled so transports never enqueue
        // (an unbounded channel with no receiver would otherwise grow).
        let connection_close_tx: Option<flume::Sender<u64>> = if config.registrar.liveness.enabled {
            let liveness = &config.registrar.liveness;
            tracing::info!(
                keepalive_interval_secs = liveness.keepalive_interval_secs,
                idle_multiplier = liveness.idle_multiplier,
                probe_timeout_ms = liveness.probe_timeout_ms,
                dereg_mode = ?liveness.dereg_mode,
                "registrar liveness ENABLED — flow-failure dereg (non-IPsec stream) + IPsec SA-idle sweep active"
            );
            let dereg_mode = liveness.dereg_mode;
            let (close_tx, close_rx) = flume::unbounded::<u64>();
            tokio::spawn(async move {
                // A closed stream flow defers to the SA-idle sweep for IPsec
                // bindings (RFC 5626 §4.2.2 flow recovery) and only
                // deregisters non-IPsec bindings immediately — see
                // `dispatcher::liveness_on_flow_close`.
                while let Ok(connection_id) = close_rx.recv_async().await {
                    crate::dispatcher::liveness_on_flow_close(connection_id, dereg_mode).await;
                }
            });
            Some(close_tx)
        } else {
            tracing::debug!("registrar liveness disabled — Expires-only deregistration");
            None
        };

        // --- Protocol mux (raw SIP + SIP-over-WebSocket on one socket) ---
        // An address that appears under both `listen.tcp` and `listen.ws` (or
        // both `listen.tls` and `listen.wss`) is served by a single muxed
        // listener that classifies each connection from its first line
        // (RFC 3261 §7.1 start-line vs RFC 6455 §4.1 request line), instead of
        // two listeners which — both binding with SO_REUSEPORT — would have the
        // kernel split arriving connections between them arbitrarily.
        let tcp_listen = listen_addr_map(&config.listen.tcp, "TCP");
        let tls_listen = listen_addr_map(&config.listen.tls, "TLS");
        let ws_listen = listen_addr_map(&config.listen.ws, "WS");
        let wss_listen = listen_addr_map(&config.listen.wss, "WSS");
        // Declared here (rather than beside their listeners) because a muxed
        // listener registers into the same per-transport map as the dedicated
        // one, so a WS connection is reachable identically either way.
        let ws_connection_map: Arc<
            dashmap::DashMap<transport::ConnectionId, tokio::sync::mpsc::Sender<bytes::Bytes>>,
        > = Arc::new(dashmap::DashMap::new());
        let wss_connection_map: Arc<
            dashmap::DashMap<transport::ConnectionId, tokio::sync::mpsc::Sender<bytes::Bytes>>,
        > = Arc::new(dashmap::DashMap::new());

        // TCP
        let tcp_connection_map = Arc::new(dashmap::DashMap::new());
        // Resolve TCP listen addresses up-front so we know the
        // `pool_local_addr` (first listen address) before constructing the
        // ConnectionPool — the pool must exist before `tcp::listen` is
        // spawned, since the TCP outbound distributor needs the pool to
        // fall back on for fire-and-forget sends that arrive with
        // `ConnectionId::default()` (e.g. in-dialog NOTIFY from the
        // subscribe_state module).
        let mut tcp_entries: Vec<(std::net::SocketAddr, Option<u32>, Option<u8>)> = Vec::new();
        for entry in &config.listen.tcp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid TCP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs
                .entry(transport::Transport::Tcp)
                .or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs
                    .entry(transport::Transport::Tcp)
                    .or_insert_with(|| adv.to_string());
            }
            listener_registry_entries.push((
                transport::Transport::Tcp,
                addr,
                entry.advertise().map(str::to_string),
            ));
            let tos = resolve_tos(entry);
            tcp_entries.push((addr, tos, entry.dscp().or(global_dscp)));
        }

        // Stream-connection registry — created before the pool/listeners so all
        // stream transports (TLS, WS, WSS) and the pool register here, and the
        // dispatcher can reuse an inbound connection for MT routing (the only
        // way to reach a WebSocket UE; RFC 7118 §5 / RFC 5626 §5.3).  Supersedes
        // the former TLS-only `tls_addr_map`.
        let stream_connections = transport::StreamConnections::new();
        // Publish it process-globally so the Python `Flow.is_alive` getter can
        // do a real liveness lookup against the live connection set.
        crate::script::api::set_stream_connections(stream_connections.clone());
        let tls_connection_map: Arc<
            dashmap::DashMap<transport::ConnectionId, tokio::sync::mpsc::Sender<bytes::Bytes>>,
        > = Arc::new(dashmap::DashMap::new());

        // --- Connection pool ---
        // Created before TCP/TLS listeners so outbound messages on those
        // transports can fall back to the pool when no inbound connection
        // matches the requested `ConnectionId`.
        let pool_tos = global_dscp.filter(|&d| d > 0).map(config::dscp_to_tos);
        let pool_local_addr = first_listen_addr.unwrap_or_else(|| "0.0.0.0:5060".parse().unwrap());
        // Outbound client-certificate (mutual TLS): when `tls.client_certificate`
        // + `tls.client_private_key` are configured, siphon presents that client
        // identity on outbound TLS connections whose peer requests one (upstream
        // SIP trunks requiring client-certificate auth). Both must be set, or
        // neither; a one-sided setting or an unreadable/unparseable file is a
        // hard startup error (fail closed) — mirrors `verify_client` without
        // `client_ca` in the TLS acceptor.
        let outbound_client_identity = match config
            .tls
            .as_ref()
            .map(|t| (&t.client_certificate, &t.client_private_key))
        {
            Some((Some(certificate_path), Some(private_key_path))) => {
                match transport::pool::load_outbound_client_identity(
                    certificate_path,
                    private_key_path,
                ) {
                    Ok(identity) => {
                        info!(
                            certificate = %certificate_path,
                            "outbound mutual TLS enabled — presenting client certificate on outbound TLS"
                        );
                        Some(identity)
                    }
                    Err(error) => {
                        eprintln!("Failed to load outbound TLS client certificate/key: {error}");
                        std::process::exit(1);
                    }
                }
            }
            Some((Some(_), None)) | Some((None, Some(_))) => {
                eprintln!(
                    "tls.client_certificate and tls.client_private_key must both be set \
                         (outbound mutual TLS) — one was provided without the other"
                );
                std::process::exit(1);
            }
            _ => None,
        };
        // One floor for both directions: `tls.method` governs the versions siphon
        // accepts on its listeners and the versions it offers when it dials out.
        // No `tls:` block at all means the default floor (TLS 1.2), i.e. exactly
        // what outbound TLS negotiated before the setting was honored.
        let outbound_tls_method = config.tls.as_ref().map(|t| t.method).unwrap_or_default();
        let tls_client_config = match transport::pool::build_outbound_tls_config(
            outbound_client_identity,
            outbound_tls_method,
        ) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("Failed to build outbound TLS client config: {error}");
                std::process::exit(1);
            }
        };
        let connection_pool = Arc::new(transport::pool::ConnectionPool::new(
            Arc::clone(&tcp_connection_map),
            inbound_tx.clone(),
            pool_local_addr,
            pool_tos,
            Some(stream_connections.clone()),
            crlf_pong_tracker.clone(),
            tls_client_config,
        ));

        // Hot-reload the outbound client certificate alongside the inbound
        // acceptor: when `tls.client_certificate` + `tls.client_private_key` are
        // configured (outbound mutual TLS — Teams Direct Routing, carrier
        // interconnects), watch them on disk and swap the renewed identity into
        // the pool so outbound handshakes present the new cert without a restart.
        if let Some((Some(certificate_path), Some(private_key_path))) = config
            .tls
            .as_ref()
            .map(|t| (&t.client_certificate, &t.client_private_key))
        {
            transport::pool::ConnectionPool::spawn_client_cert_hot_reload(
                &connection_pool,
                certificate_path,
                private_key_path,
                outbound_tls_method,
            );
        }

        // Spawn TCP listeners now that the pool exists.
        for (addr, tos, dscp) in tcp_entries {
            if tcp_ws_mux.contains(&addr) {
                continue; // served by the TCP+WS mux listener below
            }
            info!(addr = %addr, dscp = ?dscp, "starting TCP transport");
            // A configured listener that cannot bind is fatal. Coming up
            // "healthy" while silently missing a transport is how an operator
            // learns of it from a customer instead of from us.
            if let Err(error) = transport::tcp::listen(
                addr,
                inbound_tx.clone(),
                tcp_outbound_rx.clone(),
                Arc::clone(&tcp_connection_map),
                Arc::clone(&transport_acl),
                tos,
                Some(Arc::clone(&connection_pool)),
                crlf_pong_tracker.clone(),
                connection_close_tx.clone(),
            )
            .await
            {
                error!(%addr, "failed to bind TCP listener: {error}");
                std::process::exit(1);
            }
        }

        if let Some(ref tls_config) = config.tls {
            for entry in &config.listen.tls {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid TLS listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs
                    .entry(transport::Transport::Tls)
                    .or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs
                        .entry(transport::Transport::Tls)
                        .or_insert_with(|| adv.to_string());
                }
                listener_registry_entries.push((
                    transport::Transport::Tls,
                    addr,
                    entry.advertise().map(str::to_string),
                ));
                if tls_wss_mux.contains(&addr) {
                    continue; // served by the TLS+WSS mux listener below
                }
                let tos = resolve_tos(entry);
                info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting TLS transport");
                // A configured listener that cannot bind is fatal. Coming up
                // "healthy" while silently missing a transport is how an operator
                // learns of it from a customer instead of from us.
                if let Err(error) = transport::tls::listen(
                    addr,
                    tls_config,
                    inbound_tx.clone(),
                    tls_outbound_rx.clone(),
                    Arc::clone(&tls_connection_map),
                    Arc::clone(&transport_acl),
                    stream_connections.clone(),
                    tos,
                    Some(Arc::clone(&connection_pool)),
                    crlf_pong_tracker.clone(),
                    connection_close_tx.clone(),
                )
                .await
                {
                    error!(%addr, "failed to bind TLS listener: {error}");
                    std::process::exit(1);
                }
            }
        }

        // WebSocket
        for entry in &config.listen.ws {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid WS listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs
                .entry(transport::Transport::WebSocket)
                .or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs
                    .entry(transport::Transport::WebSocket)
                    .or_insert_with(|| adv.to_string());
            }
            listener_registry_entries.push((
                transport::Transport::WebSocket,
                addr,
                entry.advertise().map(str::to_string),
            ));
            if tcp_ws_mux.contains(&addr) {
                continue; // served by the TCP+WS mux listener below
            }
            let tos = resolve_tos(entry);
            info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting WS transport");
            // A configured listener that cannot bind is fatal. Coming up
            // "healthy" while silently missing a transport is how an operator
            // learns of it from a customer instead of from us.
            if let Err(error) = transport::ws::listen(
                addr,
                inbound_tx.clone(),
                ws_outbound_rx.clone(),
                Arc::clone(&ws_connection_map),
                Arc::clone(&transport_acl),
                stream_connections.clone(),
                tos,
                connection_close_tx.clone(),
            )
            .await
            {
                error!(%addr, "failed to bind WS listener: {error}");
                std::process::exit(1);
            }
        }

        // WSS
        if let Some(ref tls_config) = config.tls {
            for entry in &config.listen.wss {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid WSS listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs
                    .entry(transport::Transport::WebSocketSecure)
                    .or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs
                        .entry(transport::Transport::WebSocketSecure)
                        .or_insert_with(|| adv.to_string());
                }
                listener_registry_entries.push((
                    transport::Transport::WebSocketSecure,
                    addr,
                    entry.advertise().map(str::to_string),
                ));
                if tls_wss_mux.contains(&addr) {
                    continue; // served by the TLS+WSS mux listener below
                }
                let tos = resolve_tos(entry);
                info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting WSS transport");
                // A configured listener that cannot bind is fatal. Coming up
                // "healthy" while silently missing a transport is how an operator
                // learns of it from a customer instead of from us.
                if let Err(error) = transport::ws::listen_secure(
                    addr,
                    tls_config,
                    inbound_tx.clone(),
                    wss_outbound_rx.clone(),
                    Arc::clone(&wss_connection_map),
                    Arc::clone(&transport_acl),
                    stream_connections.clone(),
                    tos,
                    connection_close_tx.clone(),
                )
                .await
                {
                    error!(%addr, "failed to bind WSS listener: {error}");
                    std::process::exit(1);
                }
            }
        }

        // --- Protocol-multiplexed listeners (raw SIP + WebSocket, one socket) ---
        // Both halves already registered in `listen_addrs` / `advertised_addrs`
        // / the listener registry in the per-transport loops above, so Via and
        // Contact generation, flow capture and MT routing see a normal listener
        // on each transport — only the socket is shared.
        for addr in tcp_ws_mux {
            let tos = resolve_tos(tcp_listen[&addr]);
            if resolve_tos(ws_listen[&addr]) != tos {
                warn!(addr = %addr,
                    "listen.tcp and listen.ws set different dscp on the shared address; \
                     using the listen.tcp value for the muxed socket");
            }
            info!(addr = %addr, dscp = ?tcp_listen[&addr].dscp().or(global_dscp),
                "starting TCP+WS mux transport");
            // A configured listener that cannot bind is fatal. Coming up
            // "healthy" while silently missing a transport is how an operator
            // learns of it from a customer instead of from us.
            if let Err(error) = transport::mux::listen(
                addr,
                None,
                transport::mux::MuxChannels {
                    sip_outbound_rx: tcp_outbound_rx.clone(),
                    sip_connection_map: Arc::clone(&tcp_connection_map),
                    websocket_outbound_rx: ws_outbound_rx.clone(),
                    websocket_connection_map: Arc::clone(&ws_connection_map),
                },
                inbound_tx.clone(),
                Arc::clone(&transport_acl),
                stream_connections.clone(),
                tos,
                Some(Arc::clone(&connection_pool)),
                crlf_pong_tracker.clone(),
                connection_close_tx.clone(),
            )
            .await
            {
                error!(%addr, "failed to bind mux listener: {error}");
                std::process::exit(1);
            }
        }
        if let Some(ref tls_config) = config.tls {
            for addr in tls_wss_mux {
                let tos = resolve_tos(tls_listen[&addr]);
                if resolve_tos(wss_listen[&addr]) != tos {
                    warn!(addr = %addr,
                        "listen.tls and listen.wss set different dscp on the shared address; \
                         using the listen.tls value for the muxed socket");
                }
                info!(addr = %addr, dscp = ?tls_listen[&addr].dscp().or(global_dscp),
                    "starting TLS+WSS mux transport");
                // A configured listener that cannot bind is fatal. Coming up
                // "healthy" while silently missing a transport is how an operator
                // learns of it from a customer instead of from us.
                if let Err(error) = transport::mux::listen(
                    addr,
                    Some(tls_config),
                    transport::mux::MuxChannels {
                        sip_outbound_rx: tls_outbound_rx.clone(),
                        sip_connection_map: Arc::clone(&tls_connection_map),
                        websocket_outbound_rx: wss_outbound_rx.clone(),
                        websocket_connection_map: Arc::clone(&wss_connection_map),
                    },
                    inbound_tx.clone(),
                    Arc::clone(&transport_acl),
                    stream_connections.clone(),
                    tos,
                    Some(Arc::clone(&connection_pool)),
                    crlf_pong_tracker.clone(),
                    connection_close_tx.clone(),
                )
                .await
                {
                    error!(%addr, "failed to bind mux listener: {error}");
                    std::process::exit(1);
                }
            }
        }

        // SCTP — compiled in only under the `sctp` feature (links libsctp).
        #[cfg(feature = "sctp")]
        {
            let sctp_connection_map = Arc::new(dashmap::DashMap::new());
            for entry in &config.listen.sctp {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid SCTP listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs
                    .entry(transport::Transport::Sctp)
                    .or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs
                        .entry(transport::Transport::Sctp)
                        .or_insert_with(|| adv.to_string());
                }
                listener_registry_entries.push((
                    transport::Transport::Sctp,
                    addr,
                    entry.advertise().map(str::to_string),
                ));
                let tos = resolve_tos(entry);
                info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting SCTP transport");
                transport::sctp::listen(
                    addr,
                    inbound_tx.clone(),
                    sctp_outbound_rx.clone(),
                    Arc::clone(&sctp_connection_map),
                    Arc::clone(&transport_acl),
                    tos,
                )
                .await;
            }
        }
        // Built without the `sctp` feature: any configured SCTP listener cannot
        // be honoured. Warn loudly rather than silently dropping it so the
        // misconfiguration is visible (rebuild with `--features sctp`).
        #[cfg(not(feature = "sctp"))]
        if !config.listen.sctp.is_empty() {
            tracing::warn!(
                count = config.listen.sctp.len(),
                "listen.sctp configured but this binary was built without the `sctp` feature; \
                 SCTP listeners are ignored. Rebuild with `--features sctp` to enable SIP-over-SCTP."
            );
        }

        let local_addr = first_listen_addr.unwrap_or_else(|| {
            eprintln!("No listen addresses configured");
            std::process::exit(1);
        });

        drop(inbound_tx);

        // --- HEP capture ---
        let hep_sender = if let Some(ref tracing_config) = config.tracing {
            if let Some(ref hep_config) = tracing_config.hep {
                match HepSender::new(hep_config).await {
                    Ok(sender) => Some(Arc::new(sender)),
                    Err(error) => {
                        warn!("HEP capture disabled: {error}");
                        None
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        // --- Prometheus metrics endpoint ---
        if let Some(ref metrics_config) = config.metrics {
            if let Some(ref prom_config) = metrics_config.prometheus {
                let listen_addr: std::net::SocketAddr =
                    prom_config.listen.parse().unwrap_or_else(|error| {
                        eprintln!(
                            "Invalid metrics listen address '{}': {error}",
                            prom_config.listen
                        );
                        std::process::exit(1);
                    });
                let path = prom_config.path.clone();
                let cors = prom_config.cors.clone();
                tokio::spawn(async move {
                    use axum::{routing::get, Router};
                    let mut app = Router::new()
                        .route(&path, get(|| async { crate::metrics::encode_metrics() }));
                    if let Some(layer) = cors.as_ref().and_then(crate::cors::build_cors_layer) {
                        app = app.layer(layer);
                    }
                    info!(addr = %listen_addr, path = %path, "Prometheus metrics endpoint started");
                    match tokio::net::TcpListener::bind(listen_addr).await {
                        Ok(listener) => {
                            if let Err(error) = axum::serve(listener, app).await {
                                error!("metrics HTTP server failed: {error}");
                            }
                        }
                        Err(error) => {
                            error!(addr = %listen_addr, "failed to bind metrics listener: {error}");
                        }
                    }
                });
            }
        }

        // --- UAC sender ---
        let uac_user_agent = config
            .server
            .as_ref()
            .and_then(|server| server.user_agent_header.clone())
            .or_else(|| Some(format!("{product_name}/{product_version}")));
        let uac_sender = Arc::new(UacSender::new(
            Arc::clone(&outbound_senders),
            local_addr,
            listen_addrs.clone(),
            advertised_addrs.clone(),
            config.advertised_address.clone(),
            hep_sender.clone(),
            uac_user_agent,
        ));

        // Wire UAC sender into proxy.send_request() Python API
        {
            let dns_resolver = Arc::new(match crate::dns::SipResolver::from_system() {
                Ok(resolver) => resolver,
                Err(error) => {
                    error!("failed to initialize DNS resolver for proxy.send_request(): {error}");
                    std::process::exit(1);
                }
            });
            crate::script::api::proxy_utils::set_uac_sender(
                Arc::clone(&uac_sender),
                Arc::clone(&dns_resolver),
            );
            crate::script::api::subscribe_state::set_uac_sender(Arc::clone(&uac_sender));
            crate::script::api::subscribe_state::set_resolver(Arc::clone(&dns_resolver));
        }

        // --- Gateway health probers ---
        if let Some(ref manager) = gateway_manager {
            crate::gateway::spawn_health_probers(Arc::clone(manager), Arc::clone(&uac_sender));
        }

        // --- CDR writer ---
        if let Some(ref cdr_yaml) = config.cdr {
            // `init` starts one writer task per configured sink; the sinks
            // are named in its own log line.
            let cdr_config = cdr_yaml.to_cdr_config();
            crate::cdr::init(&cdr_config);
        }

        // --- RTPEngine event listener (DTMF, etc.) ---
        // The event channel was created earlier (before init_rtpengine). This
        // standalone TCP listener serves the rtpengine NG backend, which delivers
        // events over a separate connection; the native siphon-rtp backend feeds
        // the same channel directly from its control connection, so it does not
        // need this listener (and `media.events` is typically unset there).
        if let Some(ref media_config) = config.media {
            if let Some(ref events_config) = media_config.events {
                match events_config.listen_addr.parse() {
                    Ok(addr) => {
                        if let Err(error) = crate::rtpengine::events::spawn_event_listener(
                            addr,
                            rtpengine_events_tx.clone(),
                        )
                        .await
                        {
                            error!(%error, "rtpengine event listener failed to start");
                        }
                    }
                    Err(error) => {
                        error!(
                            listen_addr = %events_config.listen_addr,
                            %error,
                            "rtpengine events: invalid listen_addr"
                        );
                    }
                }
            }
        }

        // --- Diameter peers ---
        // Shared channel for incoming Diameter requests from all peers (RTR, etc.).
        let (diameter_incoming_tx, diameter_incoming_rx) = tokio::sync::mpsc::channel::<(
            crate::diameter::peer::IncomingRequest,
            std::sync::Arc<crate::diameter::peer::DiameterPeer>,
        )>(256);
        if let Some(ref diameter_config) = config.diameter {
            if let Some(ref manager) = diameter_manager {
                for peer_entry in &diameter_config.peers {
                    let peer_config =
                        diameter_config.to_peer_config(peer_entry, product_name, product_version);
                    let peer_name = peer_entry.name.clone();
                    let manager_for_task = Arc::clone(manager);
                    let tx = diameter_incoming_tx.clone();
                    let reconnect_delay = peer_config.reconnect_delay;

                    // Publish the peer as down before the first connect attempt.
                    // The reconnect task below only registers a client *after* a
                    // successful connect, so without this a peer that has never
                    // come up would be absent from the gauge rather than
                    // reported down — the failure most worth seeing.
                    crate::metrics::set_diameter_peer_up(&peer_name, false);

                    // Spawn a persistent reconnect task per peer — reconnects
                    // when the connection drops (watchdog failure, TCP reset, etc.)
                    // and re-registers the client in the DiameterManager.
                    tokio::spawn(async move {
                        loop {
                            match crate::diameter::peer::connect(peer_config.clone()).await {
                                Ok((peer, mut incoming_rx)) => {
                                    let client = Arc::new(crate::diameter::DiameterClient::new(
                                        Arc::clone(&peer),
                                    ));
                                    manager_for_task.register(peer_name.clone(), client);
                                    crate::metrics::set_diameter_peer_up(&peer_name, true);
                                    info!(peer = %peer_name, "Diameter peer connected");

                                    // Forward incoming requests until the peer disconnects.
                                    //
                                    // The awaiting send is deliberate, and is the one
                                    // shape of it that is correct: this task does nothing
                                    // else, holds no lock, no handler thread and no read
                                    // loop, so parking it on a full dispatch queue is
                                    // backpressure rather than a stall. It resumes in
                                    // order when capacity frees, losing nothing.
                                    //
                                    // What must not happen is that backpressure reaching
                                    // the peer's *reader* task, which is also what
                                    // correlates answers — that would fail every
                                    // in-flight request on the peer at once. It cannot:
                                    // the reader sheds into `incoming_rx` rather than
                                    // awaiting it, so a wedged dispatcher degrades to
                                    // dropped inbound requests (the peer retries) and
                                    // never to a stalled connection.
                                    let tx_inner = tx.clone();
                                    let peer_for_forward = Arc::clone(&peer);
                                    while let Some(request) = incoming_rx.recv().await {
                                        if tx_inner
                                            .send((request, Arc::clone(&peer_for_forward)))
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                    }

                                    // incoming_rx closed — peer disconnected
                                    crate::metrics::set_diameter_peer_up(&peer_name, false);
                                    warn!(peer = %peer_name, "Diameter peer disconnected, reconnecting");
                                }
                                Err(error) => {
                                    crate::metrics::set_diameter_peer_up(&peer_name, false);
                                    warn!(
                                        peer = %peer_name, %error,
                                        "Diameter connection failed, retrying in {reconnect_delay}s",
                                    );
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(reconnect_delay))
                                .await;
                        }
                    });
                }
            }
        }
        // Do NOT drop diameter_incoming_tx here — the reconnect tasks hold clones
        // and the channel must stay open for the lifetime of the process.

        // --- Diameter server (server mode) ---
        // Opt-in via `diameter.listen`: connects tenant backends, binds the
        // inbound listeners, and dispatches inbound requests to
        // `@diameter.on_request`.
        if let Some(ref diameter_config) = config.diameter {
            if let Some(ref manager) = diameter_manager {
                crate::script::diameter_dispatch::spawn(
                    diameter_config,
                    Arc::clone(manager),
                    Arc::clone(&engine),
                    product_name,
                    product_version,
                );
            }
        }

        // --- Outbound registration ---
        // `registrant_manager` was created (and its Python namespace installed)
        // before ScriptEngine::new; here we wire its config entries + loop.
        if let Some(ref manager) = registrant_manager {
            init_registrant(
                manager,
                &config,
                &outbound_senders,
                local_addr,
                &listen_addrs,
                &advertised_addrs,
                &hep_sender,
                stream_connections.clone(),
            );
        }

        // --- LI tasks ---
        spawn_li_tasks(li_state, &config).await;

        // The IPsec SA manager + singleton are wired earlier (before
        // `ScriptEngine::new`) so user scripts can `from siphon import
        // ipsec` at top level.  We just thread the already-built Arc
        // into the dispatcher below.

        // --- SBI client ---
        if let Some(ref sbi_config) = config.sbi {
            let sbi_internal_config = sbi_config.to_sbi_config();
            let _sbi_manager = crate::sbi::SbiManager::new(sbi_internal_config);
            info!("SBI client initialized");
            if let Some(ref nrf_url) = sbi_config.nrf_url {
                info!(nrf_url = %nrf_url, "NRF discovery endpoint configured");
            }

            // Create NpcfClient and inject as Python singleton
            if let Some(ref npcf_url) = sbi_config.npcf_url {
                // SBI communication model (TS 29.500 §6.10): direct to the NF
                // (default) or indirect via the SCP with 3gpp-Sbi-* headers.
                let communication = crate::sbi::Communication::from_config_str(
                    sbi_config.communication.as_deref().unwrap_or("direct"),
                );
                let requester_nf_type = sbi_config.requester_nf_type.as_deref().unwrap_or("AF");

                let http_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(sbi_config.timeout_secs))
                    .build()
                    .unwrap_or_default();
                let npcf_client = std::sync::Arc::new(
                    crate::sbi::npcf::NpcfClient::new(npcf_url, http_client)
                        .with_communication(communication),
                );

                // Optional Nbsf_Management (BSF) discovery client. Its own
                // reqwest client carries the BSF-specific timeout
                // (bsf_timeout_ms, falling back to timeout_secs).
                let bsf_client = sbi_config.bsf_url.as_ref().map(|bsf_url| {
                    let bsf_timeout = std::time::Duration::from_millis(
                        sbi_config
                            .bsf_timeout_ms
                            .unwrap_or(sbi_config.timeout_secs.saturating_mul(1000)),
                    );
                    let bsf_http = reqwest::Client::builder()
                        .timeout(bsf_timeout)
                        .build()
                        .unwrap_or_default();
                    std::sync::Arc::new(
                        crate::sbi::nbsf::BsfClient::new(bsf_url, bsf_http)
                            .with_communication(communication)
                            .with_requester_nf_type(requester_nf_type),
                    )
                });
                let pcf_scheme = crate::sbi::nbsf::Scheme::from_config_str(
                    sbi_config.pcf_scheme.as_deref().unwrap_or("http"),
                );

                pyo3::Python::attach(|python| {
                    let py_sbi =
                        crate::script::api::sbi::PySbi::new(npcf_client, bsf_client, pcf_scheme);
                    if let Err(error) = crate::script::api::set_sbi_singleton(python, py_sbi) {
                        error!("failed to store SBI singleton: {error}");
                    }
                });
                info!(npcf_url = %npcf_url, "Npcf client initialized and exposed to Python");
                if let Some(ref bsf_url) = sbi_config.bsf_url {
                    info!(bsf_url = %bsf_url, "BSF (Nbsf_Management) discovery client initialized");
                }
            } else if sbi_config.bsf_url.is_some() {
                tracing::warn!(
                    "sbi.bsf_url is set but sbi.npcf_url is not — the sbi namespace \
                     (and discover_pcf_binding) is only exposed when npcf_url is configured"
                );
            }

            // N5 callback listener: TS 29.514 eventNotification and
            // terminationRequest (see server::sbi_callbacks).
            if let Some(ref notif_listen) = sbi_config.notif_listen {
                let notif_addr: std::net::SocketAddr =
                    notif_listen.parse().unwrap_or_else(|error| {
                        eprintln!(
                            "Invalid sbi.notif_listen address '{}': {error}",
                            notif_listen
                        );
                        std::process::exit(1);
                    });
                sbi_callbacks::spawn_listener(notif_addr, engine.state_arc());
            }
        }

        // --- NAT keepalive ---
        if let Some(ref nat_config) = config.nat {
            if let Some(ref keepalive_config) = nat_config.keepalive {
                if let Some(registrar) = crate::script::api::registrar_arc() {
                    crate::nat::spawn_keepalive(
                        keepalive_config.clone(),
                        Arc::clone(registrar),
                        Arc::clone(&uac_sender),
                        stream_connections.clone(),
                    );
                }
            }
        }

        // --- CRLF keepalive prober ---
        // Tracker was created up front (above) so the listeners and pool
        // could record peer pongs.  Spawn the periodic ping task here
        // now that both connection maps are populated.
        if let (Some(tracker), Some(crlf_config)) = (
            crlf_pong_tracker.as_ref(),
            config
                .nat
                .as_ref()
                .and_then(|nat_config| nat_config.crlf_keepalive.as_ref()),
        ) {
            transport::crlf_keepalive::spawn(
                crlf_config.clone(),
                vec![
                    Arc::clone(&tcp_connection_map),
                    Arc::clone(&tls_connection_map),
                ],
                Arc::clone(tracker),
            );
        }

        // Subscribe to registrar events
        let registrar_event_rx = crate::script::api::registrar_arc().map(|r| r.subscribe_events());

        // --- Rf ACR-EVENT auto-emit on registration changes ---
        if let (Some(rf_service), Some(registrar)) =
            (rf_charger.as_ref(), crate::script::api::registrar_arc())
        {
            if rf_service.auto_emit_register() {
                spawn_rf_register_emitter(Arc::clone(rf_service), registrar.subscribe_events());
            }
        }

        // --- Start dispatcher ---
        let drain = Arc::new(dispatcher::DrainState::new());

        // --- HTTP admin API (health/readiness probes + registration inspection) ---
        // Spawned here so it can share the drain signal: /admin/ready reports 503
        // while draining. Independent of the Prometheus `metrics` listener above
        // (the admin router also serves /metrics for convenience).
        if let Some(ref admin_config) = config.admin {
            match admin_config.listen.parse::<std::net::SocketAddr>() {
                Ok(listen_addr) => {
                    if let Some(registrar) = crate::script::api::registrar_arc() {
                        let auth = admin_config.auth.clone().unwrap_or_default();
                        let ui_enabled = admin_config
                            .ui
                            .as_ref()
                            .map(|ui| ui.enabled)
                            .unwrap_or(false);
                        let instance_id = config
                            .server
                            .as_ref()
                            .and_then(|server| server.instance_id.clone())
                            .or_else(|| std::env::var("HOSTNAME").ok());

                        // The log tail publishes signalling-adjacent content
                        // (call-ids, numbers, peer addresses), so it is gated on
                        // the bearer token regardless of `protect_reads`. With
                        // no token there is nothing to gate it with, and
                        // enabling it anyway would publish the node's log stream
                        // to anyone who can reach the port — so refuse, loudly,
                        // rather than silently serving it or silently ignoring
                        // the setting.
                        let has_token = auth.token.as_ref().is_some_and(|token| !token.is_empty());
                        if let Some(ref log_tail) = admin_config.log_tail {
                            if log_tail.enabled && has_token {
                                crate::log_tail::enable(log_tail.max_streams);
                                info!(max_streams = log_tail.max_streams, "admin log tail enabled");
                            } else if log_tail.enabled {
                                error!(
                                    "admin.log_tail.enabled is set but admin.auth.token is not; \
                                     refusing to expose the log stream unauthenticated"
                                );
                            }
                        }

                        if let Some(ref capture) = admin_config.capture {
                            if capture.enabled && has_token {
                                crate::capture::enable(crate::capture::CaptureLimits {
                                    max_bytes: capture.max_bytes,
                                    max_calls: capture.max_calls,
                                    max_messages_per_call: capture.max_messages_per_call,
                                    redact_bodies: capture.redact_bodies,
                                });
                                warn!(
                                    max_bytes = capture.max_bytes,
                                    max_calls = capture.max_calls,
                                    redact_bodies = capture.redact_bodies,
                                    "SIP message capture enabled — signalling is retained in \
                                     memory and readable over the admin API; this is a debugging \
                                     facility, not lawful intercept"
                                );
                            } else if capture.enabled {
                                error!(
                                    "admin.capture.enabled is set but admin.auth.token is not; \
                                     refusing to expose captured signalling unauthenticated"
                                );
                            }
                        }

                        let admin_state = crate::admin::AdminState {
                            registrar: Arc::clone(registrar),
                            start_time: std::time::Instant::now(),
                            draining: Some(Arc::clone(&drain)),
                            auth_token: auth
                                .token
                                .filter(|token| !token.is_empty())
                                .map(|token| std::sync::Arc::from(token.as_str())),
                            protect_reads: auth.protect_reads,
                            instance_id,
                            features: crate::admin::AdminFeatures::from_config(&config),
                            script_engine: Some(Arc::clone(&engine)),
                        };
                        tokio::spawn(crate::admin::serve(
                            listen_addr,
                            admin_state,
                            admin_config.cors.clone(),
                            ui_enabled,
                        ));
                    } else {
                        error!("admin API enabled but registrar is not initialized; not starting");
                    }
                }
                Err(error) => {
                    error!(listen = %admin_config.listen, "invalid admin.listen address: {error}");
                }
            }
        }

        // --- External remote-control plane (ARI/ESL-class) ---
        // Installs the ControlBus, spawns the command consumer + inbound WS
        // listener, and registers the built-in SIP adapter plus any host adapters
        // (e.g. SMPP). Per-call-connect apps are dialed lazily at handover.
        if let Some(ref control_config) = config.control {
            let control_adapters = std::mem::take(&mut self.control_adapters);
            crate::control::spawn_control_plane(control_config, control_adapters);
        } else if !self.control_adapters.is_empty() {
            warn!(
                adapters = self.control_adapters.len(),
                "control adapters registered but no `control:` config block — control plane not started"
            );
        }

        let dispatcher_handle = tokio::spawn(dispatcher::run(
            inbound_rx,
            outbound_senders,
            Arc::clone(&engine),
            Arc::clone(&config),
            local_addr,
            listen_addrs,
            advertised_addrs,
            transport::ListenerRegistry::from_entries(listener_registry_entries),
            hep_sender,
            uac_sender,
            connection_pool,
            pre_rtpengine,
            registrant_manager,
            ipsec_manager,
            config.ipsec.clone(),
            stream_connections,
            registrar_event_rx,
            diameter_incoming_rx,
            rtpengine_events_rx,
            rf_charger.clone(),
            ro_charger.clone(),
            Arc::clone(&drain),
            product_name,
            product_version,
        ));

        // Keep the sender alive for the lifetime of the server so the listener
        // task never sees a "channel closed" error when no DTMF activity happens.
        let _rtpengine_events_keepalive = rtpengine_events_tx;

        // Evict connection-oriented contacts restored from the backend
        if let Some(registrar) = crate::script::api::registrar_arc() {
            let evicted = registrar.evict_connection_oriented();
            if evicted > 0 {
                info!(
                    evicted,
                    "evicted connection-oriented contacts after restart"
                );
            }
        }

        info!("{product_name} ready — press Ctrl+C to stop");

        // Wait for shutdown signal (SIGINT or SIGTERM)
        shutdown::wait_for_signal().await;

        let drain_secs = config.server.as_ref().map(|s| s.drain_secs).unwrap_or(30);

        if drain_secs > 0 {
            // Stop accepting new INVITEs; let in-flight transactions and B2BUA
            // calls finish for up to drain_secs.
            drain
                .is_draining
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let (initial_tx, initial_calls) = drain.active_counts();
            info!(
                drain_secs,
                active_transactions = initial_tx,
                active_calls = initial_calls,
                "draining — refusing new INVITEs while in-flight work completes"
            );
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            tick.tick().await; // burn the immediate first tick
            loop {
                let (txs, calls) = drain.active_counts();
                if txs == 0 && calls == 0 {
                    info!("drain complete — all in-flight work finished");
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    warn!(
                        active_transactions = txs,
                        active_calls = calls,
                        "drain timeout — exiting with in-flight work still active"
                    );
                    break;
                }
                tick.tick().await;
            }
        } else {
            info!("shutting down (drain disabled)");
        }

        dispatcher_handle.abort();
        let _ = dispatcher_handle.await;

        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------
// Helper functions extracted from main.rs
// ---------------------------------------------------------------------------

type LiState = (
    crate::li::LiManager,
    tokio::sync::mpsc::Receiver<crate::li::IriEvent>,
    tokio::sync::mpsc::Receiver<crate::li::AuditEntry>,
);
