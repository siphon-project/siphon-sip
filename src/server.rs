//! `SiphonServer` — public builder API for embedding siphon as a library.
//!
//! Consumers create their own `main()`, optionally embed a Python script
//! with `include_str!()`, and call `SiphonServer::builder().run()`.

use std::sync::Arc;

use pyo3::prelude::*;
use tracing::{error, info, warn};

use crate::config::{self, Config};
use crate::hep::HepSender;
use crate::gateway::DispatcherManager;
use crate::script::engine::{ScriptEngine, spawn_file_watcher};
use crate::script::ScriptHandle;
use crate::transport;
use crate::uac::UacSender;
use crate::{dispatcher, shutdown};

/// Deferred constructor for a host-provided Python namespace.
///
/// Boxed because the inner closure is generic over the user's `#[pyclass]`
/// type and we need to type-erase it for storage on the builder.
type UserNamespaceFactory = Box<dyn FnOnce(Python<'_>) -> PyResult<Py<PyAny>> + Send>;

/// Deferred extension task — invoked after the script engine has been
/// initialised, with a [`ScriptHandle`] cloned for the task's exclusive
/// use. The closure typically calls `tokio_handle().spawn(...)` to
/// install long-running background work.
type ExtensionTask = Box<dyn FnOnce(ScriptHandle) + Send>;

/// Builder for running a siphon server instance.
///
/// # Examples
///
/// ```rust,no_run
/// use siphon::SiphonServer;
///
/// SiphonServer::builder()
///     .config_path("siphon.yaml")
///     .embedded_script(include_str!("../scripts/proxy_default.py"))
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
    extension_tasks: Vec<ExtensionTask>,
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
            extension_tasks: Vec::new(),
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

        // Build the Tokio runtime with custom on_thread_start hooks that
        // permanently attach each worker (async + blocking) to the Python
        // interpreter. Free-threaded Python (3.14t) tears down a thread's
        // mimalloc heap on every PyGILState_Release when the attach count
        // returns to 0 — calling munmap and serializing all 24 worker
        // threads on the process-wide mm_struct rwsem (clearly visible in
        // perf flame graphs as `_PyThreadState_ClearMimallocHeaps →
        // rwsem_down_write_slowpath`). By doing one un-paired
        // `PyGILState_Ensure` at thread start we keep the count > 0 for
        // the lifetime of the worker thread, turning every per-request
        // pyo3 attach into a cheap nested no-op.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .on_thread_start(|| {
                // SAFETY: the gstate is intentionally leaked — we want the
                // thread state to outlive every pyo3 attach/release cycle.
                // It will be cleaned up when the worker thread itself
                // terminates (i.e. process shutdown).
                unsafe {
                    let _gstate = pyo3::ffi::PyGILState_Ensure();
                    // Re-detach so other threads (and pyo3 attaches on this
                    // thread) can take the per-thread state without conflict
                    // — but the underlying PyThreadState remains cached, so
                    // mimalloc heap teardown is avoided.
                    let tstate = pyo3::ffi::PyEval_SaveThread();
                    std::mem::forget(tstate);
                    // Don't call PyGILState_Release: we want the gstate
                    // lifetime to match the OS thread.
                    std::mem::forget(_gstate);
                }
            })
            .build()
            .unwrap_or_else(|error| {
                eprintln!("Failed to create tokio runtime: {error}");
                std::process::exit(1);
            });

        runtime.block_on(self.run_async());
    }

    /// Async entry point — all the real work happens here.
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

        let script_desc = if self.embedded_script.is_some() || self.embedded_bytecode.is_some() {
            "<embedded>".to_owned()
        } else {
            config.script.path.clone()
        };

        info!(
            "{product_name} v{product_version} starting — script: {}, domain: {:?}",
            script_desc,
            config.domain.local
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
        // Default to 2× CPUs: the hot inbound path runs here, and the elastic
        // `spawn_blocking` pool this replaces absorbed bursts by spawning extra
        // threads.  A fixed pool sized to just `num_cpus` adds queue latency at
        // the throughput ceiling (≈28k cps → sipp retransmits), so 2× restores
        // that burst headroom.  Idle workers are cheap (a per-thread Python heap
        // only materialises under load); memory-constrained low-traffic NFs can
        // lower `script.sync_pool_size`.
        let sync_pool_size = config
            .script
            .sync_pool_size
            .unwrap_or_else(|| std::thread::available_parallelism().map_or(2, |n| n.get() * 2));
        crate::script::py_executor::PyExecutor::install(
            sync_pool_size,
            tokio::runtime::Handle::current(),
        );

        dispatcher::inject_python_singletons(&config);
        let pre_rtpengine = dispatcher::init_rtpengine(&config);

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
            let py_presence = crate::script::api::presence::PyPresence::new(Arc::clone(&presence_store));
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
            dispatcher::spawn_rtpengine_health_check(
                Arc::clone(rtpengine_set),
                interval_secs,
            );
        }

        // --- Initialize custom metrics namespace for Python scripts ---
        // Must happen before script engine so `from siphon import metrics` works.
        if let Some(custom) = crate::metrics::custom_metrics() {
            pyo3::Python::attach(|python| {
                let py_metrics =
                    crate::script::api::metrics::PyMetricsNamespace::new(
                        std::sync::Arc::clone(custom),
                    );
                if let Err(error) =
                    crate::script::api::set_metrics_singleton(python, py_metrics)
                {
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

        // --- Initialize timer namespace for Python scripts ---
        // Runtime scheduler for timer.set / timer.cancel — always available.
        pyo3::Python::attach(|python| {
            if let Err(error) = crate::script::api::set_timer_singleton(python) {
                error!("failed to store timer singleton: {error}");
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
                if let Err(error) = crate::script::api::set_isc_singleton(python, py_isc, Arc::clone(&ifc_store)) {
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
                            eprintln!(
                                "Failed to construct user namespace '{name}': {error}"
                            );
                            std::process::exit(1);
                        }
                    };
                    if let Err(error) =
                        crate::script::api::set_user_namespace(&name, py_obj)
                    {
                        eprintln!("Failed to register user namespace '{name}': {error}");
                        std::process::exit(1);
                    }
                    info!(name = %name, "user namespace registered for injection");
                }
            });
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
        let ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>> = if let Some(ref ipsec_config) = config.ipsec {
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

            // Derive pcscf_addr from the first UDP listen entry without
            // binding the listener.  Used at SA creation time as the
            // P-CSCF side of the kernel's xfrm selectors.
            let pcscf_addr = config
                .listen
                .udp
                .first()
                .and_then(|entry| entry.address().parse::<std::net::SocketAddr>().ok())
                .map(|addr| addr.ip())
                .unwrap_or_else(|| std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

            let ipsec_manager_for_singleton = Arc::clone(&manager);
            let ipsec_config_arc = Arc::new(ipsec_config.clone());
            pyo3::Python::attach(|python| {
                let py_ipsec = crate::script::api::ipsec::PyIpsec::new(
                    ipsec_manager_for_singleton,
                    ipsec_config_arc,
                    pcscf_addr,
                );
                if let Err(error) =
                    crate::script::api::set_ipsec_singleton(python, py_ipsec)
                {
                    error!("failed to store IPsec singleton: {error}");
                } else {
                    info!(pcscf_addr = %pcscf_addr, "ipsec namespace registered for injection");
                }
            });

            Some(manager)
        } else {
            None
        };

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
            let cache_manager = std::sync::Arc::new(
                crate::cache::CacheManager::new(config.cache.as_deref().unwrap_or(&[])),
            );
            let mut store = crate::subscribe_state::SubscribeStore::new();
            if let Some(ref cfg) = config.subscribe_state {
                if let Some(ref cache_name) = cfg.cache {
                    if cache_manager.has_cache(cache_name) {
                        store = store.with_cache(
                            Arc::clone(&cache_manager),
                            cache_name.clone(),
                        );
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
                let namespace =
                    crate::script::api::subscribe_state::PySubscribeState::new(
                        Arc::clone(&store_arc),
                    );
                if let Err(error) =
                    crate::script::api::set_subscribe_state_singleton(python, namespace)
                {
                    error!("failed to store subscribe_state singleton: {error}");
                }
            });
        }

        // --- Script engine ---
        let engine = if let Some(bytecode) = self.embedded_bytecode {
            Arc::new(ScriptEngine::new_from_bytecode(bytecode).unwrap_or_else(|error| {
                eprintln!("Failed to load embedded bytecode: {error}");
                std::process::exit(1);
            }))
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
            info!(
                "extension tasks started"
            );
        }

        // --- Build transport ACL ---
        let transport_acl = build_transport_acl(&config);

        // --- Transport channels ---
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (tcp_outbound_tx, tcp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (tls_outbound_tx, tls_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (wss_outbound_tx, wss_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();
        let (sctp_outbound_tx, sctp_outbound_rx) = flume::unbounded::<transport::OutboundMessage>();

        // UDP listeners get a dedicated outbound channel each — required
        // for IPsec sec-agree on the P-CSCF role (3GPP TS 33.203 §7.4)
        // where a reply must egress on the same local socket the request
        // arrived on.  The first listener's channel doubles as the
        // default fallback for messages without a `source_local_addr`.
        let mut udp_listener_channels: std::collections::HashMap<
            std::net::SocketAddr,
            (flume::Sender<transport::OutboundMessage>, flume::Receiver<transport::OutboundMessage>),
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
        let mut udp_default: Option<flume::Sender<transport::OutboundMessage>> = None;
        let ipsec_enabled = config.ipsec.is_some();
        for (addr, (tx, _)) in udp_listener_channels.iter() {
            if ipsec_enabled {
                udp_by_local.insert(*addr, tx.clone());
            }
            if udp_default.is_none() {
                udp_default = Some(tx.clone());
            }
        }
        let udp_default = udp_default.unwrap_or_else(|| flume::unbounded().0);

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
        let mut advertised_addrs: std::collections::HashMap<transport::Transport, String> = std::collections::HashMap::new();

        // DSCP → TOS byte resolution helper.
        // Per-entry overrides the global listen.dscp (default CS3 = 24 → TOS 96).
        let global_dscp = config.listen.dscp;
        let resolve_tos = |entry: &config::ListenEntry| -> Option<u32> {
            let dscp = entry.dscp().or(global_dscp)?;
            if dscp == 0 { None } else { Some(config::dscp_to_tos(dscp)) }
        };

        // UDP
        for entry in &config.listen.udp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid UDP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Udp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Udp).or_insert_with(|| adv.to_string());
            }
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
            transport::udp::listen(addr, inbound_tx.clone(), listener_rx, Arc::clone(&transport_acl), tos).await;
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
            listen_addrs.entry(transport::Transport::Tcp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Tcp).or_insert_with(|| adv.to_string());
            }
            let tos = resolve_tos(entry);
            tcp_entries.push((addr, tos, entry.dscp().or(global_dscp)));
        }

        // TLS maps — created before pool so pool can register connections for reuse.
        let tls_addr_map: Arc<dashmap::DashMap<std::net::SocketAddr, transport::ConnectionId>> =
            Arc::new(dashmap::DashMap::new());
        let tls_connection_map: Arc<dashmap::DashMap<transport::ConnectionId, tokio::sync::mpsc::Sender<bytes::Bytes>>> =
            Arc::new(dashmap::DashMap::new());

        // --- Connection pool ---
        // Created before TCP/TLS listeners so outbound messages on those
        // transports can fall back to the pool when no inbound connection
        // matches the requested `ConnectionId`.
        let pool_tos = global_dscp
            .filter(|&d| d > 0)
            .map(config::dscp_to_tos);
        let pool_local_addr = first_listen_addr.unwrap_or_else(||
            "0.0.0.0:5060".parse().unwrap()
        );
        let connection_pool = Arc::new(transport::pool::ConnectionPool::new(
            Arc::clone(&tcp_connection_map),
            inbound_tx.clone(),
            pool_local_addr,
            pool_tos,
            Some(Arc::clone(&tls_addr_map)),
            crlf_pong_tracker.clone(),
        ));

        // Spawn TCP listeners now that the pool exists.
        for (addr, tos, dscp) in tcp_entries {
            info!(addr = %addr, dscp = ?dscp, "starting TCP transport");
            transport::tcp::listen(addr, inbound_tx.clone(), tcp_outbound_rx.clone(), Arc::clone(&tcp_connection_map), Arc::clone(&transport_acl), tos, Some(Arc::clone(&connection_pool)), crlf_pong_tracker.clone()).await;
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
                listen_addrs.entry(transport::Transport::Tls).or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs.entry(transport::Transport::Tls).or_insert_with(|| adv.to_string());
                }
                let tos = resolve_tos(entry);
                info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting TLS transport");
                transport::tls::listen(addr, tls_config, inbound_tx.clone(), tls_outbound_rx.clone(), Arc::clone(&tls_connection_map), Arc::clone(&transport_acl), Arc::clone(&tls_addr_map), tos, Some(Arc::clone(&connection_pool)), crlf_pong_tracker.clone()).await;
            }
        }

        // WebSocket
        let ws_connection_map = Arc::new(dashmap::DashMap::new());
        for entry in &config.listen.ws {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid WS listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::WebSocket).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::WebSocket).or_insert_with(|| adv.to_string());
            }
            let tos = resolve_tos(entry);
            info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting WS transport");
            transport::ws::listen(addr, inbound_tx.clone(), ws_outbound_rx.clone(), Arc::clone(&ws_connection_map), Arc::clone(&transport_acl), tos).await;
        }

        // WSS
        if let Some(ref tls_config) = config.tls {
            let wss_connection_map = Arc::new(dashmap::DashMap::new());
            for entry in &config.listen.wss {
                let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                    eprintln!("Invalid WSS listen address '{}': {error}", entry.address());
                    std::process::exit(1);
                });
                if first_listen_addr.is_none() {
                    first_listen_addr = Some(addr);
                }
                listen_addrs.entry(transport::Transport::WebSocketSecure).or_insert(addr);
                if let Some(adv) = entry.advertise() {
                    advertised_addrs.entry(transport::Transport::WebSocketSecure).or_insert_with(|| adv.to_string());
                }
                let tos = resolve_tos(entry);
                info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting WSS transport");
                transport::ws::listen_secure(addr, tls_config, inbound_tx.clone(), wss_outbound_rx.clone(), Arc::clone(&wss_connection_map), Arc::clone(&transport_acl), tos).await;
            }
        }

        // SCTP
        let sctp_connection_map = Arc::new(dashmap::DashMap::new());
        for entry in &config.listen.sctp {
            let addr: std::net::SocketAddr = entry.address().parse().unwrap_or_else(|error| {
                eprintln!("Invalid SCTP listen address '{}': {error}", entry.address());
                std::process::exit(1);
            });
            if first_listen_addr.is_none() {
                first_listen_addr = Some(addr);
            }
            listen_addrs.entry(transport::Transport::Sctp).or_insert(addr);
            if let Some(adv) = entry.advertise() {
                advertised_addrs.entry(transport::Transport::Sctp).or_insert_with(|| adv.to_string());
            }
            let tos = resolve_tos(entry);
            info!(addr = %addr, dscp = ?entry.dscp().or(global_dscp), "starting SCTP transport");
            transport::sctp::listen(addr, inbound_tx.clone(), sctp_outbound_rx.clone(), Arc::clone(&sctp_connection_map), Arc::clone(&transport_acl), tos).await;
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
                let listen_addr: std::net::SocketAddr = prom_config.listen.parse().unwrap_or_else(|error| {
                    eprintln!("Invalid metrics listen address '{}': {error}", prom_config.listen);
                    std::process::exit(1);
                });
                let path = prom_config.path.clone();
                tokio::spawn(async move {
                    use axum::{routing::get, Router};
                    let app = Router::new().route(&path, get(|| async {
                        crate::metrics::encode_metrics()
                    }));
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
        let uac_user_agent = config.server.as_ref()
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
            crate::gateway::spawn_health_probers(
                Arc::clone(manager),
                Arc::clone(&uac_sender),
            );
        }

        // --- CDR writer ---
        if let Some(ref cdr_yaml) = config.cdr {
            let cdr_config = cdr_yaml.to_cdr_config();
            if let Some(receiver) = crate::cdr::init(&cdr_config) {
                let writer_config = cdr_config.clone();
                tokio::spawn(crate::cdr::writer_task(receiver, writer_config));
                info!("CDR writer started (backend: {})", cdr_yaml.backend);
            }
        }

        // --- RTPEngine event listener (DTMF, etc.) ---
        let (rtpengine_events_tx, rtpengine_events_rx) =
            tokio::sync::mpsc::channel::<crate::rtpengine::events::RtpEngineEvent>(256);
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
        let (diameter_incoming_tx, diameter_incoming_rx) =
            tokio::sync::mpsc::channel::<(
                crate::diameter::peer::IncomingRequest,
                std::sync::Arc<crate::diameter::peer::DiameterPeer>,
            )>(256);
        if let Some(ref diameter_config) = config.diameter {
            if let Some(ref manager) = diameter_manager {
                for peer_entry in &diameter_config.peers {
                    let peer_config = diameter_config.to_peer_config(peer_entry, product_name, product_version);
                    let peer_name = peer_entry.name.clone();
                    let manager_for_task = Arc::clone(manager);
                    let tx = diameter_incoming_tx.clone();
                    let reconnect_delay = peer_config.reconnect_delay;

                    // Spawn a persistent reconnect task per peer — reconnects
                    // when the connection drops (watchdog failure, TCP reset, etc.)
                    // and re-registers the client in the DiameterManager.
                    tokio::spawn(async move {
                        loop {
                            match crate::diameter::peer::connect(peer_config.clone()).await {
                                Ok((peer, mut incoming_rx)) => {
                                    let client = Arc::new(
                                        crate::diameter::DiameterClient::new(Arc::clone(&peer)),
                                    );
                                    manager_for_task.register(peer_name.clone(), client);
                                    info!(peer = %peer_name, "Diameter peer connected");

                                    // Forward incoming requests until the peer disconnects
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
                                    warn!(peer = %peer_name, "Diameter peer disconnected, reconnecting");
                                }
                                Err(error) => {
                                    warn!(
                                        peer = %peer_name, %error,
                                        "Diameter connection failed, retrying in {reconnect_delay}s",
                                    );
                                }
                            }
                            tokio::time::sleep(std::time::Duration::from_secs(reconnect_delay)).await;
                        }
                    });
                }
            }
        }
        // Do NOT drop diameter_incoming_tx here — the reconnect tasks hold clones
        // and the channel must stay open for the lifetime of the process.

        // --- Outbound registration ---
        let registrant_manager = init_registrant(&config, &outbound_senders, local_addr, &listen_addrs, &advertised_addrs, &hep_sender, Arc::clone(&tls_addr_map), product_name, product_version);

        // --- LI tasks ---
        spawn_li_tasks(li_state, &config);

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
                let http_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(sbi_config.timeout_secs))
                    .build()
                    .unwrap_or_default();
                let npcf_client = std::sync::Arc::new(
                    crate::sbi::npcf::NpcfClient::new(npcf_url, http_client)
                );
                pyo3::Python::attach(|python| {
                    let py_sbi = crate::script::api::sbi::PySbi::new(npcf_client);
                    if let Err(error) = crate::script::api::set_sbi_singleton(python, py_sbi) {
                        error!("failed to store SBI singleton: {error}");
                    }
                });
                info!(npcf_url = %npcf_url, "Npcf client initialized and exposed to Python");
            }

            // Start SBI notification listener for PCF events (N5 callback)
            if let Some(ref notif_listen) = sbi_config.notif_listen {
                let notif_addr: std::net::SocketAddr = notif_listen.parse().unwrap_or_else(|error| {
                    eprintln!("Invalid sbi.notif_listen address '{}': {error}", notif_listen);
                    std::process::exit(1);
                });
                let engine_for_sbi = Arc::clone(&engine);
                tokio::spawn(async move {
                    use axum::{routing::post, extract::State, Json, Router};

                    #[derive(Clone)]
                    struct SbiNotifState {
                        engine: Arc<crate::script::engine::ScriptEngine>,
                    }

                    async fn handle_pcf_notification(
                        State(state): State<SbiNotifState>,
                        Json(body): Json<crate::sbi::npcf::PcfEventNotification>,
                    ) -> axum::http::StatusCode {
                        let _ = crate::script::py_executor::run(move || {
                            pyo3::Python::attach(|python| {
                                use pyo3::types::PyAnyMethods;
                                let engine_state = state.engine.state();
                                let handlers = engine_state.handlers_for(
                                    &crate::script::engine::HandlerKind::SbiOnEvent
                                );
                                if handlers.is_empty() {
                                    return;
                                }

                                // Convert PcfEventNotification to a Python dict via json.loads
                                let json_str = match serde_json::to_string(&body) {
                                    Ok(s) => s,
                                    Err(error) => {
                                        tracing::error!(%error, "failed to serialize PCF event");
                                        return;
                                    }
                                };
                                let py_dict: pyo3::Py<pyo3::PyAny> = {
                                    use pyo3::types::PyAnyMethods;
                                    match python.import("json")
                                        .and_then(|m| m.call_method1("loads", (&json_str,)))
                                    {
                                        Ok(d) => d.unbind(),
                                        Err(error) => {
                                            tracing::error!(%error, "failed to parse PCF event as Python dict");
                                            return;
                                        }
                                    }
                                };

                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((py_dict.bind(python),));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = crate::script::engine::run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async sbi.on_event handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "sbi.on_event handler failed"
                                            );
                                        }
                                    }
                                }
                            });
                        }).await;
                        axum::http::StatusCode::NO_CONTENT
                    }

                    let app = Router::new()
                        .route("/sbi/events", post(handle_pcf_notification))
                        .with_state(SbiNotifState { engine: engine_for_sbi });

                    info!(addr = %notif_addr, "SBI notification listener started on /sbi/events");
                    match tokio::net::TcpListener::bind(notif_addr).await {
                        Ok(listener) => {
                            if let Err(error) = axum::serve(listener, app).await {
                                error!("SBI notification server failed: {error}");
                            }
                        }
                        Err(error) => {
                            error!(addr = %notif_addr, "failed to bind SBI notification listener: {error}");
                        }
                    }
                });
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
                        Arc::clone(&tls_addr_map),
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
        let registrar_event_rx = crate::script::api::registrar_arc()
            .map(|r| r.subscribe_events());

        // --- Rf ACR-EVENT auto-emit on registration changes ---
        if let (Some(rf_service), Some(registrar)) = (
            rf_charger.as_ref(),
            crate::script::api::registrar_arc(),
        ) {
            if rf_service.auto_emit_register() {
                spawn_rf_register_emitter(Arc::clone(rf_service), registrar.subscribe_events());
            }
        }

        // --- Start dispatcher ---
        let drain = Arc::new(dispatcher::DrainState::new());
        let dispatcher_handle = tokio::spawn(dispatcher::run(
            inbound_rx,
            outbound_senders,
            Arc::clone(&engine),
            Arc::clone(&config),
            local_addr,
            listen_addrs,
            advertised_addrs,
            hep_sender,
            uac_sender,
            connection_pool,
            pre_rtpengine,
            registrant_manager,
            ipsec_manager,
            config.ipsec.clone(),
            tls_addr_map,
            registrar_event_rx,
            diameter_incoming_rx,
            rtpengine_events_rx,
            rf_charger.clone(),
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
                info!(evicted, "evicted connection-oriented contacts after restart");
            }
        }

        info!("{product_name} ready — press Ctrl+C to stop");

        // Wait for shutdown signal (SIGINT or SIGTERM)
        shutdown::wait_for_signal().await;

        let drain_secs = config.server.as_ref()
            .map(|s| s.drain_secs)
            .unwrap_or(30);

        if drain_secs > 0 {
            // Stop accepting new INVITEs; let in-flight transactions and B2BUA
            // calls finish for up to drain_secs.
            drain.is_draining.store(true, std::sync::atomic::Ordering::SeqCst);
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

fn init_logging(
    log_config: &crate::config::LogConfig,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    use crate::config::{LogFormat, LogLevel};
    use tracing_subscriber::prelude::*;

    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            let level = match log_config.level {
                LogLevel::Debug => "debug",
                LogLevel::Info => "info",
                LogLevel::Warn => "warn",
                LogLevel::Error => "error",
            };
            tracing_subscriber::EnvFilter::new(level)
        });

    let is_json = log_config.format == LogFormat::Json;

    let console_layer = if is_json {
        tracing_subscriber::fmt::layer()
            .json()
            .boxed()
    } else {
        tracing_subscriber::fmt::layer()
            .boxed()
    };

    let (file_layer, guard) = if let Some(ref path) = log_config.file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap_or_else(|error| {
                eprintln!("Failed to open log file {path}: {error}");
                std::process::exit(1);
            });
        let (non_blocking, guard) = tracing_appender::non_blocking(file);

        let layer = if is_json {
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        } else {
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .boxed()
        };

        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    guard
}

/// Compute the per-process identity tag from config + environment, then
/// stamp it onto the registrar so subsequent `save()`s carry it.
///
/// Resolution order for `instance_id`:
///   1. ``server.instance_id`` from siphon.yaml (env-expanded by serde_yml).
///   2. The ``HOSTNAME`` environment variable (Linux default).
///   3. Literal ``"siphon"`` as a last-resort fallback.
///
/// `instance_epoch` is always a fresh UUID v4 generated at startup so two
/// runs of the same logical replica are distinguishable.
fn init_registrar_identity(config: &Config) {
    use crate::registrar::InstanceIdentity;
    use crate::script::api::registrar_arc;

    let registrar = match registrar_arc() {
        Some(r) => r,
        None => return,
    };

    let id = config
        .server
        .as_ref()
        .and_then(|server| server.instance_id.clone())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "siphon".to_string());

    let epoch = uuid::Uuid::new_v4().to_string();

    info!(instance_id = %id, instance_epoch = %epoch, "registrar instance identity");
    registrar.set_instance_identity(InstanceIdentity { id, epoch });
}

async fn init_registrar_backend(config: &Config) {
    use crate::config::RegistrarBackendType;
    use crate::registrar::backend;
    use crate::script::api::registrar_arc;

    let registrar = match registrar_arc() {
        Some(r) => r,
        None => return,
    };

    match config.registrar.backend {
        RegistrarBackendType::Redis => {
            let redis_cfg = match &config.registrar.redis {
                Some(redis_cfg) => redis_cfg,
                None => {
                    error!("registrar backend is redis but no redis config provided");
                    return;
                }
            };
            let redis_config = backend::RedisBackendConfig {
                url: redis_cfg.url.clone(),
                urls: Vec::new(),
                key_prefix: redis_cfg.key_prefix.clone(),
                shard_count: 0,
                ttl_slack_secs: redis_cfg.ttl_slack_secs as u64,
            };
            match backend::RedisBackend::connect(redis_config).await {
                Ok(redis_backend) => {
                    match backend::restore_from_backend(&redis_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.registrations_active.set(aors as i64);
                            }
                            info!(aors, contacts, "restored contacts from Redis backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Redis backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(redis_backend));

                    // --- iFC profile persistence (shares the same Redis instance) ---
                    init_ifc_redis_backend(&redis_cfg.url, config).await;
                }
                Err(err) => {
                    error!(%err, "failed to connect to Redis registrar backend");
                }
            }
        }
        RegistrarBackendType::Postgres => {
            let pg_config = match &config.registrar.postgres {
                Some(cfg) => backend::PostgresBackendConfig {
                    url: cfg.url.clone(),
                    urls: Vec::new(),
                    table: cfg.table.clone(),
                    shard_count: 0,
                },
                None => {
                    error!("registrar backend is postgres but no postgres config provided");
                    return;
                }
            };
            match backend::PostgresBackend::connect(pg_config).await {
                Ok(pg_backend) => {
                    match backend::restore_from_backend(&pg_backend, registrar).await {
                        Ok((aors, contacts)) => {
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.registrations_active.set(aors as i64);
                            }
                            info!(aors, contacts, "restored contacts from Postgres backend");
                        }
                        Err(err) => {
                            error!(%err, "failed to restore contacts from Postgres backend");
                        }
                    }
                    registrar.set_backend_writer(backend::spawn_backend_writer(pg_backend));
                }
                Err(err) => {
                    error!(%err, "failed to connect to Postgres registrar backend");
                }
            }
        }
        RegistrarBackendType::Memory | RegistrarBackendType::Python => {}
    }
}

/// Initialize iFC Redis persistence — restore profiles and wire the backend writer.
///
/// Called from `init_registrar_backend` when the registrar uses a Redis backend,
/// reusing the same Redis instance for iFC profile storage.
#[cfg(feature = "redis-backend")]
async fn init_ifc_redis_backend(redis_url: &str, config: &Config) {
    use crate::script::api::ifc_store_arc;

    let ifc_store = match ifc_store_arc() {
        Some(store) => store,
        None => return,
    };

    let ifc_key_prefix = config
        .isc
        .as_ref()
        .map(|isc| isc.ifc_key_prefix.clone())
        .unwrap_or_else(|| "siphon:ifc:".to_owned());

    let client = match redis::Client::open(redis_url) {
        Ok(client) => client,
        Err(error) => {
            error!(%error, "failed to open Redis client for iFC backend");
            return;
        }
    };

    let mut connection = match client.get_multiplexed_async_connection().await {
        Ok(connection) => connection,
        Err(error) => {
            error!(%error, "failed to connect to Redis for iFC backend");
            return;
        }
    };

    // Restore iFC profiles from Redis.
    match crate::ifc::restore_ifc_profiles(&mut connection, &ifc_key_prefix, ifc_store).await {
        Ok((profiles, ifcs)) => {
            if profiles > 0 {
                info!(profiles, ifcs, "restored iFC profiles from Redis");
            }
        }
        Err(error) => {
            error!(error, "failed to restore iFC profiles from Redis");
        }
    }

    // Wire the backend writer for ongoing persistence.
    let writer = crate::ifc::spawn_ifc_backend_writer(connection, ifc_key_prefix);
    ifc_store.set_backend_writer(writer);
    info!("iFC Redis backend writer initialized");
}

fn init_gateway(config: &Config) -> Option<Arc<DispatcherManager>> {
    use crate::gateway::{
        extract_address_from_uri, resolve_address, Algorithm, Destination, DispatcherGroup,
        ProbeConfig,
    };

    let gateway_config = config.gateway.as_ref()?;

    let manager = Arc::new(DispatcherManager::new());

    for group_config in &gateway_config.groups {
        let algorithm = Algorithm::from_str(&group_config.algorithm)
            .unwrap_or_else(|| {
                warn!(
                    algorithm = %group_config.algorithm,
                    group = %group_config.name,
                    "unknown algorithm, defaulting to weighted"
                );
                Algorithm::Weighted
            });

        let mut destinations = Vec::new();
        for dest_config in &group_config.destinations {
            let address_str = dest_config
                .address
                .clone()
                .unwrap_or_else(|| extract_address_from_uri(&dest_config.uri));

            let address = match resolve_address(&address_str) {
                Ok(addr) => addr,
                Err(error) => {
                    error!(
                        address = %address_str,
                        uri = %dest_config.uri,
                        error = %error,
                        "cannot resolve gateway destination address, skipping"
                    );
                    continue;
                }
            };
            // Derive transport from config field, or from URI ;transport= param
            let transport_type = match dest_config.effective_transport().as_str() {
                "tcp" => transport::Transport::Tcp,
                "tls" => transport::Transport::Tls,
                _ => transport::Transport::Udp,
            };
            // Store original hostname string for DNS re-resolution on failure
            let is_hostname = address_str.parse::<std::net::SocketAddr>().is_err();
            let mut dest = Destination::new(
                dest_config.uri.clone(),
                address,
                transport_type,
                dest_config.weight,
                dest_config.priority,
            )
            .with_attrs(dest_config.attrs.clone());
            if is_hostname {
                dest = dest.with_address_str(address_str.clone());
            }
            destinations.push(dest);
        }

        let probe = ProbeConfig {
            enabled: group_config.probe.enabled,
            interval: std::time::Duration::from_secs(group_config.probe.interval_secs as u64),
            failure_threshold: group_config.probe.failure_threshold,
            from_user: group_config.probe.from_user.clone(),
            from_domain: group_config.probe.from_domain.clone(),
        };

        manager.add_group(
            DispatcherGroup::new(group_config.name.clone(), algorithm, destinations)
                .with_probe_config(probe),
        );
    }

    // Inject gateway Python API before script loads
    pyo3::Python::attach(|python| {
        let py_gateway = crate::script::api::gateway::PyGateway::new(Arc::clone(&manager));
        if let Err(error) = crate::script::api::set_gateway_singleton(python, py_gateway) {
            error!("failed to store gateway singleton: {error}");
        } else {
            info!("gateway registered for injection");
        }
    });

    Some(manager)
}

type LiState = (
    crate::li::LiManager,
    tokio::sync::mpsc::Receiver<crate::li::IriEvent>,
    tokio::sync::mpsc::Receiver<crate::li::AuditEntry>,
);

/// Cloned LiManager handle that survives `init_li` so `spawn_li_tasks` can
/// hand the X3 manager into it once X3 has been constructed.
static LI_MANAGER: std::sync::OnceLock<crate::li::LiManager> = std::sync::OnceLock::new();

fn init_li(config: &Config) -> Option<LiState> {
    let li_config = config.lawful_intercept.as_ref()?;
    if !li_config.enabled {
        return None;
    }

    let channel_size = li_config.x2.as_ref()
        .map(|x2| x2.channel_size)
        .unwrap_or(10_000);
    let (li_manager, iri_rx, audit_rx) =
        crate::li::LiManager::new(li_config.clone(), channel_size);

    let py_li_manager = li_manager.clone();
    pyo3::Python::attach(|python| {
        let py_li = crate::script::api::li::PyLiNamespace::new(py_li_manager);
        if let Err(error) = crate::script::api::set_li_singleton(python, py_li) {
            error!("failed to store LI singleton: {error}");
        } else {
            info!("lawful intercept namespace registered for injection");
        }
    });

    // Stash a clone for spawn_li_tasks to wire up X3 once it's built. All
    // LiManager clones share the same `Arc<OnceLock<X3Manager>>`, so setting
    // X3 on this clone makes it visible to the Python singleton too.
    let _ = LI_MANAGER.set(li_manager.clone());

    Some((li_manager, iri_rx, audit_rx))
}

fn init_diameter(config: &Config) -> Option<Arc<crate::diameter::DiameterManager>> {
    config.diameter.as_ref()?;

    let manager = Arc::new(crate::diameter::DiameterManager::new());

    pyo3::Python::attach(|python| {
        let py_diameter = crate::script::api::diameter::PyDiameter::new(Arc::clone(&manager));
        if let Err(error) = crate::script::api::set_diameter_singleton(python, py_diameter) {
            warn!("failed to set Diameter Python singleton: {error}");
        } else {
            info!("Diameter namespace registered for injection");
        }
    });

    Some(manager)
}

/// Background task that consumes the registrar's broadcast channel and
/// emits an Rf ACR-EVENT for every registration state change.  Each
/// event is a one-shot accounting record — no session state is held.
///
/// `cause_code` per RFC 3326 / TS 32.299 §5.2.5:
/// - `Registered` / `Refreshed` → 0 (success)
/// - `Deregistered` → -200 (clean unbind, mapped from successful 200 OK)
/// - `Expired` → -487 (Request Terminated semantically — the binding
///   was torn down because no refresh arrived)
fn spawn_rf_register_emitter(
    service: Arc<crate::diameter::rf_service::RfChargingService>,
    mut events: tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>,
) {
    use crate::diameter::ro::{ImsChargingData, NodeRole};
    use crate::registrar::RegistrationEvent;

    tokio::spawn(async move {
        info!("rf: registrar ACR-EVENT emitter started");
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!(skipped, "rf: registrar event emitter lagged");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            let (aor, cause_code) = match &event {
                RegistrationEvent::Registered { aor }
                | RegistrationEvent::Refreshed { aor } => (aor.clone(), 0i32),
                RegistrationEvent::Deregistered { aor } => (aor.clone(), -200),
                RegistrationEvent::Expired { aor } => (aor.clone(), -487),
            };
            let mut ims_data = ImsChargingData::default();
            ims_data.calling_party = Some(aor.clone());
            ims_data.sip_method = Some("REGISTER".to_string());
            ims_data.role_of_node = Some(NodeRole::OriginatingRole);
            ims_data.node_functionality = service.node_functionality();
            ims_data.cause_code = Some(cause_code);
            let _ = service.acr_event(ims_data, Some(aor)).await;
        }
        info!("rf: registrar ACR-EVENT emitter stopped");
    });
}

/// Build the Rf offline-charging service from the `rf:` config block.
///
/// Returns `None` (charging fully disabled) when:
/// - the `rf:` section is missing,
/// - `rf.enabled = false`, or
/// - no Diameter manager is available (no `diameter:` peers configured).
fn init_rf_charging(
    config: &Config,
    diameter_manager: Option<&Arc<crate::diameter::DiameterManager>>,
) -> Option<Arc<crate::diameter::rf_service::RfChargingService>> {
    let rf_config = config.rf.as_ref()?;
    if !rf_config.enabled {
        return None;
    }
    let manager = match diameter_manager {
        Some(m) => Arc::clone(m),
        None => {
            warn!("rf.enabled = true but no diameter: peers configured — disabling Rf");
            return None;
        }
    };
    let service = crate::diameter::rf_service::RfChargingService::new(manager, rf_config.clone());
    info!(
        node_functionality = %rf_config.node_functionality,
        service_context_id = %rf_config.service_context_id,
        auto_emit_proxy = rf_config.auto_emit_proxy,
        auto_emit_b2bua = rf_config.auto_emit_b2bua,
        auto_emit_register = rf_config.auto_emit_register,
        interim_secs = rf_config.interim_interval_secs,
        "Rf offline charging enabled"
    );
    Some(service)
}

fn init_registrant(
    config: &Config,
    outbound_senders: &Arc<transport::OutboundRouter>,
    local_addr: std::net::SocketAddr,
    listen_addrs: &std::collections::HashMap<transport::Transport, std::net::SocketAddr>,
    advertised_addrs: &std::collections::HashMap<transport::Transport, String>,
    hep_sender: &Option<Arc<HepSender>>,
    tls_addr_map: Arc<dashmap::DashMap<std::net::SocketAddr, transport::ConnectionId>>,
    product_name: &str,
    product_version: &str,
) -> Option<Arc<crate::registrant::RegistrantManager>> {
    use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager};

    let registrant_config = config.registrant.as_ref()?;

    let registrant_user_agent = config.server.as_ref()
        .and_then(|server| server.user_agent_header.clone())
        .or_else(|| Some(format!("{product_name}/{product_version}")));

    let manager = Arc::new(RegistrantManager::new(
        registrant_config.default_interval,
        std::time::Duration::from_secs(registrant_config.retry_interval),
        std::time::Duration::from_secs(registrant_config.max_retry_interval),
        registrant_user_agent,
    ));

    for entry_config in &registrant_config.entries {
        let registrar_host = entry_config.registrar
            .strip_prefix("sip:")
            .or_else(|| entry_config.registrar.strip_prefix("sips:"))
            .unwrap_or(&entry_config.registrar);

        let transport_type = match entry_config.transport.as_str() {
            "tcp" => transport::Transport::Tcp,
            "tls" => transport::Transport::Tls,
            _ => transport::Transport::Udp,
        };

        let default_port: u16 = if transport_type == transport::Transport::Tls { 5061 } else { 5060 };
        let address_str = if registrar_host.contains(':') {
            registrar_host.to_string()
        } else {
            format!("{registrar_host}:{default_port}")
        };
        let destination = match crate::gateway::resolve_address(&address_str) {
            Ok(addr) => addr,
            Err(error) => {
                error!(
                    host = %registrar_host,
                    error = %error,
                    "cannot resolve registrant host, skipping entry"
                );
                continue;
            }
        };

        let is_hostname = address_str.parse::<std::net::SocketAddr>().is_err();
        let mut entry = RegistrantEntry::new(
            entry_config.aor.clone(),
            entry_config.registrar.clone(),
            destination,
            transport_type,
            RegistrantCredentials {
                username: entry_config.user.clone(),
                password: entry_config.password.clone(),
                realm: entry_config.realm.clone(),
            },
            entry_config.interval.unwrap_or(registrant_config.default_interval),
            entry_config.contact.clone(),
        );
        if is_hostname {
            entry.address_str = Some(address_str.clone());
        }
        manager.add(entry);
    }

    info!(
        count = registrant_config.entries.len(),
        "outbound registrations configured"
    );

    // Spawn background registration loop
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let loop_manager = Arc::clone(&manager);
    let loop_outbound = Arc::clone(outbound_senders);
    let loop_listen_addrs = listen_addrs.clone();
    let loop_advertised_addrs = advertised_addrs.clone();
    let loop_advertised_address = config.advertised_address.clone();
    let loop_hep_sender = hep_sender.clone();
    let loop_tls_addr_map = Some(tls_addr_map);
    tokio::spawn(async move {
        crate::registrant::registration_loop(
            loop_manager,
            loop_outbound,
            local_addr,
            loop_listen_addrs,
            loop_advertised_addrs,
            loop_advertised_address,
            loop_hep_sender,
            loop_tls_addr_map,
            shutdown_rx,
        ).await;
    });

    // Keep shutdown_tx alive — dropping it would cause the registration
    // loop's shutdown.changed() to resolve immediately on every select tick,
    // starving the sleep branch and preventing REGISTERs from being sent.
    std::mem::forget(shutdown_tx);

    // Inject registration Python API
    let py_manager = Arc::clone(&manager);
    pyo3::Python::attach(|python| {
        let py_registration = crate::script::api::registrant::PyRegistration::new(
            py_manager,
            local_addr,
        );
        if let Err(error) = crate::script::api::set_registration_singleton(python, py_registration) {
            error!("failed to store registration singleton: {error}");
        } else {
            info!("registration namespace registered for injection");
        }
    });

    Some(manager)
}

fn spawn_li_tasks(
    li_state: Option<LiState>,
    config: &Config,
) {
    let (_, iri_rx, audit_rx) = match li_state {
        Some(state) => state,
        None => return,
    };

    let li_config = match config.lawful_intercept.as_ref() {
        Some(cfg) => cfg,
        None => {
            error!("lawful_intercept config missing despite LI state being initialized");
            return;
        }
    };

    // Spawn X2 IRI delivery task
    if let Some(ref x2_config) = li_config.x2 {
        let x2_arc = Arc::new(x2_config.clone());
        tokio::spawn(crate::li::x2::delivery_task(iri_rx, x2_arc));
        info!("X2 IRI delivery task started");
    } else {
        tokio::spawn(async move {
            let mut receiver = iri_rx;
            while receiver.recv().await.is_some() {}
        });
    }

    // Spawn X3 media capture task
    if let Some(ref x3_config) = li_config.x3 {
        match crate::li::x3::X3Manager::new(x3_config) {
            Ok(x3_manager) => {
                // Hand a clone to LiManager so intercept() can register and
                // stop_intercept() can deregister capture sessions.
                if let Some(li) = LI_MANAGER.get() {
                    li.set_x3_manager(x3_manager.clone());
                }
                let listen_address = x3_config.listen_udp.clone();
                tokio::spawn(async move {
                    if let Err(error) = crate::li::x3::receive_and_forward_task(
                        &listen_address, x3_manager,
                    ).await {
                        error!("X3 receive task failed: {error}");
                    }
                });
                info!("X3 media capture task started");
            }
            Err(error) => {
                error!("failed to create X3 manager: {error}");
            }
        }
    }

    // Spawn audit log writer
    let audit_log_path = li_config.audit_log.clone();
    tokio::spawn(async move {
        let mut receiver = audit_rx;
        let mut file = if let Some(ref path) = audit_log_path {
            match tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
            {
                Ok(file) => Some(file),
                Err(error) => {
                    error!("failed to open LI audit log {path}: {error}");
                    None
                }
            }
        } else {
            None
        };

        use tokio::io::AsyncWriteExt;
        while let Some(entry) = receiver.recv().await {
            if let Some(ref mut file) = file {
                let line = format!(
                    "{:?} {:?} liid={} {}\n",
                    entry.timestamp,
                    entry.operation,
                    entry.liid.as_deref().unwrap_or("-"),
                    entry.detail,
                );
                let _ = file.write_all(line.as_bytes()).await;
            }
        }
    });
}

fn build_transport_acl(config: &Config) -> Arc<transport::acl::TransportAcl> {
    use transport::acl::TransportAcl;

    if let Some(ref sec) = config.security {
        let apiban_set = if let Some(ref apiban_config) = sec.apiban {
            match crate::apiban::ApiBanClient::new(apiban_config) {
                Ok(client) => {
                    let banned = client.banned();
                    client.start();
                    info!("APIBAN blocklist poller started");
                    Some(banned)
                }
                Err(error) => {
                    error!("Failed to create APIBAN client: {error}");
                    None
                }
            }
        } else {
            None
        };

        let acl = if let Some(banned) = apiban_set {
            TransportAcl::with_apiban(vec![], vec![], banned)
        } else {
            TransportAcl::new(vec![], vec![])
        };
        Arc::new(acl)
    } else {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn register_task_records_in_order() {
        let server = SiphonServer::builder()
            .register_task(|_| {})
            .register_task(|_| {})
            .register_task(|_| {});
        assert_eq!(server.extension_task_count(), 3);
    }

    #[test]
    fn register_task_empty_by_default() {
        let server = SiphonServer::builder();
        assert_eq!(server.extension_task_count(), 0);
    }

    #[test]
    fn register_task_accepts_move_closures_carrying_state() {
        // Verify the closure signature is `FnOnce` so callers can move
        // state in (e.g. an Arc holding extension config). Compile-only
        // contract test — the closure body is not executed here.
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let owned: Vec<&'static str> = vec!["a", "b", "c"];
        let server = SiphonServer::builder().register_task(move |_| {
            // owned is moved in.
            COUNTER.fetch_add(owned.len(), Ordering::Relaxed);
        });
        assert_eq!(server.extension_task_count(), 1);
    }
}
