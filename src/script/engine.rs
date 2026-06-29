//! Script engine — compiles Python scripts once at startup, caches callable
//! references, and hot-reloads on file change via inotify.
//!
//! # Design
//!
//! The engine holds a `ScriptState` behind an `ArcSwap` so readers (the SIP
//! hot path) never block while a reload is in progress. On file change:
//!   1. Read the new source from disk
//!   2. Compile + execute in a fresh Python module (populates decorator registry)
//!   3. Atomically swap the `ScriptState` pointer
//!
//! Python is initialised once via `Python::initialize()`.
//! With free-threaded Python 3.14t there is no GIL — multiple Rust worker
//! threads can call into Python concurrently.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use tracing::{debug, error, info, warn};

use crate::config::{ReloadMode, ScriptConfig};
use crate::error::{Result, SiphonError};

/// Serializes the `clear → exec → extract` sequence against the global
/// `_siphon_registry` Python module. Free-threaded Python 3.14t no longer
/// serializes via the GIL, so concurrent compilers would otherwise see each
/// other's handler registrations leak through the shared registry list.
/// Compilation only happens at startup and on hot-reload, so a single mutex
/// is fine — the request hot path never touches it.
static REGISTRY_COMPILE_LOCK: Mutex<()> = Mutex::new(());

// ---------------------------------------------------------------------------
// Handler kind — each decorator type maps to one variant
// ---------------------------------------------------------------------------

/// Identifies which SIP event a registered Python handler listens for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HandlerKind {
    /// `@proxy.on_request` — optional method filter (None = all methods).
    ProxyRequest(Option<String>),
    /// `@proxy.on_reply` — intercept responses.
    ProxyReply,
    /// `@proxy.on_failure` — all branches failed.
    ProxyFailure,
    /// `@proxy.on_cancel` — relayed INVITE was CANCELled before a final
    /// response (RFC 3261 §9). Fires once per cancelled call with the
    /// original INVITE so a script can release per-call resources
    /// (Diameter Rx/N5 QoS, rtpengine media) that no BYE will ever clear.
    ProxyCancel,
    /// `@proxy.on_register_reply` — REGISTER-specific reply handler.
    ProxyRegisterReply,
    /// `@b2bua.on_invite`
    B2buaInvite,
    /// `@b2bua.on_early_media` — provisional response with SDP (183/180).
    B2buaEarlyMedia,
    /// `@b2bua.on_answer`
    B2buaAnswer,
    /// `@b2bua.on_failure`
    B2buaFailure,
    /// `@b2bua.on_bye`
    B2buaBye,
    /// `@b2bua.on_refer` — call transfer (RFC 3515).
    B2buaRefer,
    /// `@b2bua.on_cancel` — an unanswered call (Calling/Ringing) was
    /// CANCELled. Fires once per call with the Call object so a B2BUA
    /// script can release per-call resources (rtpengine media, QoS) that
    /// no BYE will ever clear.
    B2buaCancel,
    /// `@registrar.on_change` — registration state change callback.
    RegistrarOnChange,
    /// `@registration.on_change` — outbound registration state change callback.
    RegistrantOnChange,
    /// `@srs.on_invite` — inbound SIPREC INVITE to SRS.
    SrsOnInvite,
    /// `@srs.on_session_end` — recording session completed.
    SrsOnSessionEnd,
    /// `@timer.every(seconds=N)` — periodic timer callback.
    TimerEvery {
        interval_secs: u64,
        name: String,
        jitter_secs: u64,
    },
    /// `@diameter.on_inbound_cer` — server mode CER identity decision.
    DiameterOnInboundCer,
    /// `@diameter.on_request` — server mode inbound request dispatch.
    /// Optional filter: `None` = every command; `"ULR"` / `"ULR|AIR"` = those
    /// commands (any application); `"S6a:ULR"` = app-qualified. Matched by
    /// command **code** in `script::diameter_dispatch`, not by this string.
    DiameterOnRequest(Option<String>),
    /// `@diameter.on_reply` — server mode answer-rewrite hook. Fires on the
    /// answer an `on_request` handler produced (relayed via `forward_to` or
    /// built by `answer`/`reject`) just before it goes back upstream, so a
    /// script can rewrite AVPs centrally (topology hiding, Origin/Result-Code
    /// mapping). The handler mutates the answer in place; its return is ignored.
    DiameterOnReply,
    /// `@diameter.on_request_completed` — server mode post-answer hook.
    DiameterOnRequestCompleted,
    /// `@sbi.on_event` — incoming PCF event notification (N5).
    SbiOnEvent,
    /// `@rtpengine.on_dtmf` — inbound DTMF event from rtpengine.
    ///
    /// ``call_id`` and ``from_tag`` are optional filters: when set, only
    /// matching DTMF events invoke the handler.
    RtpEngineOnDtmf {
        call_id: Option<String>,
        from_tag: Option<String>,
    },
    /// Open extension point for handler kinds owned by host extensions.
    /// The string is the registry key the extension wrote (e.g.
    /// `"audit.sink"`); siphon-core does not interpret it. Per-handler
    /// metadata travels alongside on [`HandlerEntry::options`].
    Custom { kind: String },
}

// ---------------------------------------------------------------------------
// Handler entry
// ---------------------------------------------------------------------------

/// A single registered Python callback.
#[derive(Debug, Clone)]
pub struct HandlerEntry {
    pub kind: HandlerKind,
    /// The Python callable (function / coroutine function).
    pub callable: Py<PyAny>,
    /// `true` when `asyncio.iscoroutinefunction(callable)` returned `True`.
    pub is_async: bool,
    /// Optional per-handler metadata dict carried through from the
    /// Python registry. Populated for [`HandlerKind::Custom`] handlers
    /// so extensions can ship arbitrary options alongside the kind name
    /// (e.g. HTTP route methods, audit-sink filters). Built-in kinds
    /// that carry their own typed fields inside the variant leave this
    /// `None`.
    pub options: Option<Py<PyDict>>,
}

// ---------------------------------------------------------------------------
// Script state — the atomically-swapped payload
// ---------------------------------------------------------------------------

/// Immutable snapshot of a compiled script's handler registrations.
/// Replaced atomically on hot-reload.
#[derive(Debug)]
pub struct ScriptState {
    /// Path the script was loaded from.
    pub source_path: PathBuf,
    /// All registered handlers, keyed by kind.
    pub handlers: Vec<HandlerEntry>,
}

impl ScriptState {
    /// Return all handlers that match the given kind.
    pub fn handlers_for(&self, kind: &HandlerKind) -> Vec<&HandlerEntry> {
        self.handlers.iter().filter(|h| &h.kind == kind).collect()
    }

    /// Return all `ProxyRequest` handlers whose method filter matches `method`.
    /// A handler with `None` filter matches everything.
    pub fn proxy_request_handlers(&self, method: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::ProxyRequest(None) => true,
                HandlerKind::ProxyRequest(Some(filter)) => {
                    filter.split('|').any(|m| m == method)
                }
                _ => false,
            })
            .collect()
    }

    /// All `@diameter.on_request` handlers with their (already-validated)
    /// filter strings, in registration order. The diameter dispatch layer
    /// (`script::diameter_dispatch`) scores these against the inbound request by command
    /// **code** — not name — so the matching vocabulary stays consistent with
    /// decoration-time validation, and the generic engine stays free of any
    /// Diameter-dictionary coupling.
    pub fn diameter_request_handlers(&self) -> impl Iterator<Item = (Option<&str>, &HandlerEntry)> {
        self.handlers.iter().filter_map(|handler| match &handler.kind {
            HandlerKind::DiameterOnRequest(filter) => Some((filter.as_deref(), handler)),
            _ => None,
        })
    }

    /// Return all `RtpEngineOnDtmf` handlers whose optional call-id/from-tag
    /// filters match the event.  `None` filters match everything.
    pub fn dtmf_handlers(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| match &h.kind {
                HandlerKind::RtpEngineOnDtmf { call_id: filter_cid, from_tag: filter_ftag } => {
                    filter_cid.as_deref().map_or(true, |v| v == call_id)
                        && filter_ftag.as_deref().map_or(true, |v| v == from_tag)
                }
                _ => false,
            })
            .collect()
    }

    /// Return all [`HandlerKind::Custom`] handlers whose registry key
    /// equals `kind`. The lookup is exact — no globbing or prefix match.
    pub fn handlers_for_custom(&self, kind: &str) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| matches!(&h.kind, HandlerKind::Custom { kind: k } if k == kind))
            .collect()
    }

    /// Whether the script registered any B2BUA handlers.
    pub fn has_b2bua_handlers(&self) -> bool {
        self.handlers.iter().any(|h| matches!(
            h.kind,
            HandlerKind::B2buaInvite
                | HandlerKind::B2buaAnswer
                | HandlerKind::B2buaFailure
                | HandlerKind::B2buaBye
                | HandlerKind::B2buaRefer
        ))
    }

    /// Return all timer handlers.
    pub fn timer_handlers(&self) -> Vec<&HandlerEntry> {
        self.handlers
            .iter()
            .filter(|h| matches!(h.kind, HandlerKind::TimerEvery { .. }))
            .collect()
    }

    /// Whether the script registered any timer handlers.
    pub fn has_timer_handlers(&self) -> bool {
        self.handlers
            .iter()
            .any(|h| matches!(h.kind, HandlerKind::TimerEvery { .. }))
    }
}

// ---------------------------------------------------------------------------
// Script engine
// ---------------------------------------------------------------------------

/// The script engine manages Python initialisation, script compilation,
/// hot-reload watching, and the handler registry.
pub struct ScriptEngine {
    /// Atomically-swappable current script state.
    state: Arc<ArcSwap<ScriptState>>,
    /// Script file path (from config).
    script_path: PathBuf,
    /// Reload mode (auto = inotify, sighup = manual).
    reload_mode: ReloadMode,
    /// Active timer task handles — aborted and re-spawned on reload.
    timer_handles: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl ScriptEngine {
    /// Create and initialise the engine.
    ///
    /// 1. Initialise the Python interpreter (idempotent).
    /// 2. Register the `siphon` built-in module so scripts can `from siphon import ...`.
    /// 3. Compile and execute the configured script.
    /// 4. Extract registered handlers from the decorator registry.
    pub fn new(config: &ScriptConfig) -> Result<Self> {
        let script_path = PathBuf::from(&config.path);

        // Ensure the script file exists before we initialise Python.
        if !script_path.exists() {
            return Err(SiphonError::Script(format!(
                "script not found: {}",
                script_path.display()
            )));
        }

        // Initialise the free-threaded Python interpreter (no-op if already done).
        Python::initialize();

        let state = Self::compile_script(&script_path)?;

        info!(
            path = %script_path.display(),
            handlers = state.handlers.len(),
            "script loaded"
        );

        let state = Arc::new(ArcSwap::from_pointee(state));

        Ok(Self {
            state,
            script_path,
            reload_mode: config.reload.clone(),
            timer_handles: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Create the engine from an embedded script source string.
    ///
    /// The script is compiled directly from the provided source — no file is
    /// read from disk and hot-reload is disabled (reload mode forced to Sighup).
    pub fn new_embedded(source: &str) -> Result<Self> {
        let script_path = PathBuf::from("<embedded>");

        // Initialise the free-threaded Python interpreter (no-op if already done).
        Python::initialize();

        let state = Self::compile_source_standalone(&script_path, source)?;

        info!(
            handlers = state.handlers.len(),
            "embedded script loaded"
        );

        let state = Arc::new(ArcSwap::from_pointee(state));

        Ok(Self {
            state,
            script_path,
            reload_mode: ReloadMode::Sighup,
            timer_handles: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Create the engine from pre-compiled Python bytecode (`.pyc` format).
    ///
    /// The bytecode is loaded via `marshal.loads()` and executed directly,
    /// skipping the compilation step. Hot-reload is disabled.
    pub fn new_from_bytecode(pyc: &[u8]) -> Result<Self> {
        let script_path = PathBuf::from("<embedded>");

        Python::initialize();

        let state = Self::load_bytecode(&script_path, pyc)?;

        info!(
            handlers = state.handlers.len(),
            "bytecode script loaded"
        );

        let state = Arc::new(ArcSwap::from_pointee(state));

        Ok(Self {
            state,
            script_path,
            reload_mode: ReloadMode::Sighup,
            timer_handles: std::sync::Mutex::new(Vec::new()),
        })
    }

    /// Get a snapshot of the current script state.
    /// This is cheap — just an `Arc` clone.
    pub fn state(&self) -> arc_swap::Guard<Arc<ScriptState>> {
        self.state.load()
    }

    /// Clone of the atomically-swappable state pointer. Used by host
    /// extensions (via [`crate::script::ScriptHandle`]) to read the live
    /// handler set without taking a guard borrow.
    pub fn state_arc(&self) -> Arc<ArcSwap<ScriptState>> {
        Arc::clone(&self.state)
    }

    /// Reload the script from disk and atomically swap the state.
    /// Called by the file watcher or on SIGHUP.
    pub fn reload(&self) -> Result<()> {
        info!(path = %self.script_path.display(), "reloading script");

        match Self::compile_script(&self.script_path) {
            Ok(new_state) => {
                info!(
                    handlers = new_state.handlers.len(),
                    "script reloaded successfully"
                );
                self.state.store(Arc::new(new_state));
                self.restart_timers();
                Ok(())
            }
            Err(error) => {
                // Keep the old state on failure — never leave the engine without handlers.
                error!(%error, "script reload failed, keeping previous version");
                Err(error)
            }
        }
    }

    /// Whether auto-reload (inotify) is configured.
    pub fn auto_reload(&self) -> bool {
        self.reload_mode == ReloadMode::Auto
    }

    /// The path being watched.
    pub fn script_path(&self) -> &Path {
        &self.script_path
    }

    /// Cancel all running timer tasks and spawn new ones from the current state.
    ///
    /// Called after every script load/reload and once at server startup.
    pub fn restart_timers(&self) {
        let mut handles = self.timer_handles.lock().unwrap_or_else(|e| e.into_inner());

        // Abort all existing timer tasks.
        for handle in handles.drain(..) {
            handle.abort();
        }

        let state = self.state.load();
        for handler in state.timer_handlers() {
            if let HandlerKind::TimerEvery {
                interval_secs,
                ref name,
                jitter_secs,
            } = handler.kind
            {
                // Attach before cloning the Py callback — `restart_timers`
                // runs outside any attach scope (server startup / hot reload),
                // and on free-threaded Python cloning a `Py<>` while detached
                // panics ("Cannot clone pointer into Python heap without the
                // thread being attached"), crashing any `@timer.every` script.
                let callable = Python::attach(|python| handler.callable.clone_ref(python));
                let is_async = handler.is_async;
                let timer_name = name.clone();
                let interval = interval_secs;
                let jitter = jitter_secs;

                info!(
                    name = %timer_name,
                    interval_secs = interval,
                    jitter_secs = jitter,
                    "starting timer"
                );

                let handle = tokio::spawn(async move {
                    timer_loop(callable, is_async, interval, jitter, timer_name).await;
                });
                handles.push(handle);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal: compile + extract handlers
    // -----------------------------------------------------------------------

    /// Read, compile, and execute a Python script file. Returns the extracted
    /// handler registrations.
    fn compile_script(path: &Path) -> Result<ScriptState> {
        let source = std::fs::read_to_string(path).map_err(|error| {
            SiphonError::Script(format!("cannot read {}: {error}", path.display()))
        })?;

        let _registry_guard = REGISTRY_COMPILE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Python::attach(|python| {
            Self::compile_source(python, path, &source)
        })
    }

    /// Load pre-compiled bytecode (.pyc) and execute it. Used for embedded bytecode.
    fn load_bytecode(path: &Path, pyc: &[u8]) -> Result<ScriptState> {
        // .pyc files have a 16-byte header: 4-byte magic, 4-byte flags,
        // 4-byte timestamp, 4-byte source size. The rest is marshalled code.
        if pyc.len() < 16 {
            return Err(SiphonError::Script(
                "bytecode too short (missing .pyc header)".into(),
            ));
        }

        let bytecode_payload = &pyc[16..];

        let _registry_guard = REGISTRY_COMPILE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        Python::attach(|python| {
            let registry_module = get_or_create_registry(python)?;
            super::api::install_siphon_module(python)?;

            // Clear the handler registry.
            registry_module
                .getattr("clear")
                .map_err(|error| SiphonError::Script(format!("registry.clear: {error}")))?
                .call0()
                .map_err(|error| SiphonError::Script(format!("registry.clear(): {error}")))?;

            // Unmarshal the code object from the bytecode payload.
            let marshal = python
                .import("marshal")
                .map_err(|error| SiphonError::Script(format!("import marshal: {error}")))?;
            let code_object = marshal
                .call_method1("loads", (bytecode_payload,))
                .map_err(|error| SiphonError::Script(format!("marshal.loads: {error}")))?;

            // Execute the code object in a proper module namespace so imports work.
            let globals = PyDict::new(python);
            let builtins = python
                .import("builtins")
                .map_err(|error| SiphonError::Script(format!("import builtins: {error}")))?;
            globals
                .set_item("__builtins__", &*builtins)
                .map_err(|error| SiphonError::Script(format!("set __builtins__: {error}")))?;
            globals
                .set_item("__name__", "siphon_user_script")
                .map_err(|error| SiphonError::Script(format!("set __name__: {error}")))?;
            builtins
                .getattr("exec")
                .map_err(|error| SiphonError::Script(format!("builtins.exec: {error}")))?
                .call1((code_object, &*globals))
                .map_err(|error| {
                    SiphonError::Script(format!(
                        "bytecode execution failed for {}: {error}",
                        path.display()
                    ))
                })?;

            let handlers = extract_handlers(python, &registry_module)?;

            debug!(
                path = %path.display(),
                handler_count = handlers.len(),
                "bytecode loaded and handlers extracted"
            );

            Ok(ScriptState {
                source_path: path.to_owned(),
                handlers,
            })
        })
    }

    /// Compile an already-loaded source string. Used for embedded scripts.
    fn compile_source_standalone(path: &Path, source: &str) -> Result<ScriptState> {
        let _registry_guard = REGISTRY_COMPILE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Python::attach(|python| {
            Self::compile_source(python, path, source)
        })
    }

    /// Compile source code and extract handlers. Runs inside `Python::attach`.
    fn compile_source(
        python: Python<'_>,
        path: &Path,
        source: &str,
    ) -> Result<ScriptState> {
        // Create (or get) the registry module first — siphon_package.py imports it.
        let registry_module = get_or_create_registry(python)?;

        // Ensure the siphon package is installed in sys.modules.
        super::api::install_siphon_module(python)?;

        // Clear the handler registry before executing the script.
        let clear_fn = registry_module
            .getattr("clear")
            .map_err(|error| SiphonError::Script(format!("registry.clear: {error}")))?;
        clear_fn
            .call0()
            .map_err(|error| SiphonError::Script(format!("registry.clear(): {error}")))?;

        // Compile and execute the script in a fresh globals dict.
        //
        // We intentionally avoid `PyModule::from_code` here because it
        // delegates to `PyImport_ExecCodeModuleEx`, which inserts the
        // module into `sys.modules`.  On subsequent loads (hot-reload),
        // that API *reuses* the existing module dict instead of creating
        // a fresh one, which on free-threaded Python 3.14t can leave
        // stale descriptor state that causes property getters on
        // `#[pyclass]` objects (e.g. `request.method`) to silently
        // return incorrect values on the first load.
        //
        // Using `compile()` + `exec()` with an isolated dict — the same
        // approach `load_bytecode` already uses — eliminates the
        // interaction with `sys.modules` for user scripts entirely.
        let builtins = python
            .import("builtins")
            .map_err(|error| SiphonError::Script(format!("import builtins: {error}")))?;
        let file_name_str = path.to_str().unwrap_or("<script>");
        let code_object = builtins
            .getattr("compile")
            .map_err(|error| SiphonError::Script(format!("builtins.compile: {error}")))?
            .call1((source, file_name_str, "exec"))
            .map_err(|error| {
                SiphonError::Script(format!(
                    "compilation failed for {}: {error}",
                    path.display()
                ))
            })?;
        let globals = PyDict::new(python);
        globals
            .set_item("__builtins__", &*builtins)
            .map_err(|error| SiphonError::Script(format!("set __builtins__: {error}")))?;
        globals
            .set_item("__name__", "siphon_user_script")
            .map_err(|error| SiphonError::Script(format!("set __name__: {error}")))?;
        globals
            .set_item("__file__", file_name_str)
            .map_err(|error| SiphonError::Script(format!("set __file__: {error}")))?;
        builtins
            .getattr("exec")
            .map_err(|error| SiphonError::Script(format!("builtins.exec: {error}")))?
            .call1((&code_object, &globals))
            .map_err(|error| {
                SiphonError::Script(format!(
                    "script execution failed for {}: {error}",
                    path.display()
                ))
            })?;

        // The script has now executed — decorators have registered themselves
        // into the registry module.
        let handlers = extract_handlers(python, &registry_module)?;

        debug!(
            path = %path.display(),
            handler_count = handlers.len(),
            "script compiled and handlers extracted"
        );

        Ok(ScriptState {
            source_path: path.to_owned(),
            handlers,
        })
    }
}

// ---------------------------------------------------------------------------
// File watcher task
// ---------------------------------------------------------------------------

/// Spawn a background tokio task that watches the script file for changes
/// and triggers hot-reload. Returns immediately.
pub fn spawn_file_watcher(engine: Arc<ScriptEngine>) {
    use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    if !engine.auto_reload() {
        info!("script auto-reload disabled (mode: sighup)");
        return;
    }

    let path = engine.script_path().to_owned();

    // `notify` v8 uses std channels for sync, we bridge to tokio via spawn_blocking.
    tokio::task::spawn_blocking(move || {
        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "failed to create file watcher");
                return;
            }
        };

        // Watch the parent directory so we catch renames/recreates
        // (editors like vim write to a temp file then rename).
        let watch_dir = path.parent().unwrap_or(Path::new("."));
        if let Err(error) = watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
            error!(%error, path = %watch_dir.display(), "failed to watch directory");
            return;
        }

        info!(path = %path.display(), "file watcher started");

        let file_name = path.file_name();

        for event in receiver {
            match event {
                Ok(Event {
                    kind: EventKind::Modify(_) | EventKind::Create(_),
                    paths,
                    ..
                }) => {
                    // Only reload if the event is about our specific file.
                    let is_our_file = paths.iter().any(|p| p.file_name() == file_name);
                    if !is_our_file {
                        continue;
                    }

                    // Small debounce — editors sometimes generate multiple events.
                    std::thread::sleep(std::time::Duration::from_millis(50));

                    if let Err(error) = engine.reload() {
                        warn!(%error, "hot-reload failed");
                    }
                }
                Ok(_) => {} // Ignore other event kinds
                Err(error) => {
                    warn!(%error, "file watcher error");
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Registry — Python-side handler storage
// ---------------------------------------------------------------------------

/// The registry is a small Python module (`_siphon_registry`) that decorators
/// write into. After script execution we read it from Rust.
///
/// This approach decouples the decorator implementation (pure Python, lives in
/// `src/script/api/`) from the extraction (Rust, here).
fn get_or_create_registry(python: Python<'_>) -> Result<Bound<'_, PyAny>> {
    // Ensure the registry module exists (idempotent).
    super::api::ensure_registry(python)?;

    // Return it from sys.modules.
    let registry = python
        .import("_siphon_registry")
        .map_err(|error| SiphonError::Script(format!("import _siphon_registry: {error}")))?;

    Ok(registry.into_any())
}

/// Read the handlers list from the Python registry and convert to Rust types.
fn extract_handlers(
    _python: Python<'_>,
    registry: &Bound<'_, PyAny>,
) -> Result<Vec<HandlerEntry>> {
    let entries = registry
        .getattr("entries")
        .map_err(|error| SiphonError::Script(format!("registry.entries: {error}")))?
        .call0()
        .map_err(|error| SiphonError::Script(format!("registry.entries(): {error}")))?;

    let mut handlers = Vec::new();

    for item in entries
        .try_iter()
        .map_err(|error| SiphonError::Script(format!("iterate entries: {error}")))?
    {
        let item: Bound<'_, PyAny> =
            item.map_err(|error| SiphonError::Script(format!("entry item: {error}")))?;

        let kind_str: String = item
            .get_item(0)
            .map_err(|error| SiphonError::Script(format!("entry[0]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[0] str: {error}")))?;

        let filter: Option<String> = item
            .get_item(1)
            .ok()
            .and_then(|v: Bound<'_, PyAny>| {
                if v.is_none() { None } else { v.extract().ok() }
            });

        let callable: Py<PyAny> = item
            .get_item(2)
            .map_err(|error| SiphonError::Script(format!("entry[2]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[2] callable: {error}")))?;

        let is_async: bool = item
            .get_item(3)
            .map_err(|error| SiphonError::Script(format!("entry[3]: {error}")))?
            .extract()
            .map_err(|error| SiphonError::Script(format!("entry[3] bool: {error}")))?;

        // Optional 5th element: metadata dict (used by timer.every, etc.).
        let metadata: Option<Bound<'_, PyAny>> = item
            .get_item(4)
            .ok()
            .and_then(|v: Bound<'_, PyAny>| if v.is_none() { None } else { Some(v) });

        let kind = match kind_str.as_str() {
            "proxy.on_request" => HandlerKind::ProxyRequest(filter),
            "proxy.on_reply" => HandlerKind::ProxyReply,
            "proxy.on_failure" => HandlerKind::ProxyFailure,
            "proxy.on_cancel" => HandlerKind::ProxyCancel,
            "proxy.on_register_reply" => HandlerKind::ProxyRegisterReply,
            "b2bua.on_invite" => HandlerKind::B2buaInvite,
            "b2bua.on_early_media" => HandlerKind::B2buaEarlyMedia,
            "b2bua.on_answer" => HandlerKind::B2buaAnswer,
            "b2bua.on_failure" => HandlerKind::B2buaFailure,
            "b2bua.on_bye" => HandlerKind::B2buaBye,
            "b2bua.on_refer" => HandlerKind::B2buaRefer,
            "b2bua.on_cancel" => HandlerKind::B2buaCancel,
            "registrar.on_change" => HandlerKind::RegistrarOnChange,
            "registration.on_change" => HandlerKind::RegistrantOnChange,
            "srs.on_invite" => HandlerKind::SrsOnInvite,
            "srs.on_session_end" => HandlerKind::SrsOnSessionEnd,
            "diameter.on_inbound_cer" => HandlerKind::DiameterOnInboundCer,
            "diameter.on_request" => HandlerKind::DiameterOnRequest(filter),
            "diameter.on_reply" => HandlerKind::DiameterOnReply,
            "diameter.on_request_completed" => HandlerKind::DiameterOnRequestCompleted,
            "sbi.on_event" => HandlerKind::SbiOnEvent,
            "timer.every" => {
                let meta = metadata.as_ref().ok_or_else(|| {
                    SiphonError::Script("timer.every handler missing metadata".into())
                })?;
                let interval_secs: u64 = meta
                    .get_item("seconds")
                    .map_err(|error| SiphonError::Script(format!("timer metadata 'seconds': {error}")))?
                    .extract()
                    .map_err(|error| SiphonError::Script(format!("timer 'seconds' u64: {error}")))?;
                let name: String = meta
                    .get_item("name")
                    .map_err(|error| SiphonError::Script(format!("timer metadata 'name': {error}")))?
                    .extract()
                    .map_err(|error| SiphonError::Script(format!("timer 'name' str: {error}")))?;
                let jitter_secs: u64 = meta
                    .get_item("jitter")
                    .and_then(|v| v.extract())
                    .unwrap_or(0);
                HandlerKind::TimerEvery { interval_secs, name, jitter_secs }
            }
            "rtpengine.on_dtmf" => {
                let call_id: Option<String> = metadata
                    .as_ref()
                    .and_then(|meta| meta.get_item("call_id").ok())
                    .and_then(|v| v.extract().ok());
                let from_tag: Option<String> = metadata
                    .as_ref()
                    .and_then(|meta| meta.get_item("from_tag").ok())
                    .and_then(|v| v.extract().ok());
                HandlerKind::RtpEngineOnDtmf { call_id, from_tag }
            }
            other => HandlerKind::Custom { kind: other.to_owned() },
        };

        // Custom handlers carry their metadata dict through verbatim so
        // extensions can read whatever options the script registered.
        // Built-in kinds embed their typed fields inside the variant and
        // don't need the dict copied out.
        let options = match &kind {
            HandlerKind::Custom { .. } => metadata
                .as_ref()
                .and_then(|m| m.cast::<PyDict>().ok())
                .map(|d| d.clone().unbind()),
            _ => None,
        };

        handlers.push(HandlerEntry {
            kind,
            callable,
            is_async,
            options,
        });
    }

    Ok(handlers)
}

// ---------------------------------------------------------------------------
// Timer loop — runs as a spawned Tokio task
// ---------------------------------------------------------------------------

/// Periodic loop for a single timer handler.
///
/// Sleeps for `interval_secs` (plus optional random jitter), then calls the
/// Python callback.  Errors are logged and do not stop the loop.
async fn timer_loop(
    callable: Py<PyAny>,
    is_async: bool,
    interval_secs: u64,
    jitter_secs: u64,
    name: String,
) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    loop {
        let mut wait = Duration::from_secs(interval_secs);
        if jitter_secs > 0 {
            // Lightweight pseudo-random jitter without adding the `rand` crate.
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .subsec_nanos() as u64;
            let jitter = nanos % (jitter_secs + 1);
            wait += Duration::from_secs(jitter);
        }
        tokio::time::sleep(wait).await;

        let timer_name = name.clone();
        // Attach before cloning the Py callback — `timer_loop` runs as a
        // spawned Tokio task whose worker is detached from the interpreter
        // (pyo3 `ATTACH_COUNT == 0`), and on free-threaded Python cloning a
        // `Py<>` while detached panics ("Cannot clone pointer into Python heap
        // without the thread being attached"). Mirrors the clone at the timer
        // registration site (`restart_timers`).
        let callback = Python::attach(|python| callable.clone_ref(python));
        let result = crate::script::py_executor::try_run(move || {
            Python::attach(|python| {
                let bound = callback.bind(python);
                match bound.call0() {
                    Ok(ret) => {
                        if is_async {
                            if let Err(error) = run_coroutine(python, &ret) {
                                warn!(
                                    timer = %timer_name,
                                    %error,
                                    "async timer callback error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        warn!(timer = %timer_name, %error, "timer callback error");
                    }
                }
            });
        })
        .await;

        if result.is_err() {
            warn!(name = %name, "timer callback panicked");
        }
    }
}

// ---------------------------------------------------------------------------
// Async Python coroutine runner (shared by dispatcher and timer scheduler)
// ---------------------------------------------------------------------------

thread_local! {
    /// Per-thread asyncio event loop reused across `run_coroutine` calls.
    ///
    /// `pyo3_async_runtimes::tokio::future_into_py(...)` captures the asyncio
    /// loop that is running at the moment a script `await`s the bridged
    /// awaitable, then later wakes the awaiter from a Tokio worker via
    /// `loop.call_soon_threadsafe(...)`.  Driving each handler with a fresh
    /// `asyncio.run(coro)` would close that loop between handler invocations,
    /// racing the Tokio side and surfacing as `RuntimeError: Event loop is
    /// closed` (with the chained `TypeError` because the awaiter's result is
    /// never delivered).  Reusing one long-lived loop per worker thread keeps
    /// `call_soon_threadsafe` targets valid for the lifetime of the thread.
    static PYTHON_LOOP: RefCell<Option<Py<PyAny>>> = const { RefCell::new(None) };
}

/// Acquire — creating it on first use — this thread's persistent fallback
/// asyncio loop (the legacy path used when no global async pool is installed).
/// Reused across calls so `call_soon_threadsafe` targets stay valid for the
/// lifetime of the thread (see [`PYTHON_LOOP`]).
///
/// Pulled out as a named helper so the per-thread caching can be unit-tested
/// directly: the public [`run_coroutine`] entry point short-circuits to the
/// global async pool when one is installed (a process-wide `OnceLock`), which
/// would otherwise route around — and thus never populate — this fallback loop
/// whenever a sibling test installs the pool.
fn fallback_thread_loop(python: Python<'_>) -> PyResult<Py<PyAny>> {
    PYTHON_LOOP.with(|cell| {
        let mut slot = cell.borrow_mut();
        match slot.as_ref() {
            Some(handle) => Ok(handle.clone_ref(python)),
            None => {
                let asyncio = python.import("asyncio")?;
                let new_loop = asyncio.call_method0("new_event_loop")?;
                // Bind this loop to the thread for any code path that still
                // calls the (deprecated) `asyncio.get_event_loop()`.  The
                // running-loop lookup used by `pyo3_async_runtimes` is set
                // automatically by `run_until_complete`.
                asyncio.call_method1("set_event_loop", (&new_loop,))?;
                let unbound = new_loop.unbind();
                let handle = unbound.clone_ref(python);
                *slot = Some(unbound);
                Ok(handle)
            }
        }
    })
}

/// Run a Python coroutine to completion on this thread's persistent asyncio
/// event loop.
///
/// `block_in_place` lets the multi-threaded Tokio runtime steal this worker
/// for the duration of the synchronous `loop.run_until_complete(...)` call so
/// other Tokio tasks (transport I/O, timers, RTPEngine UDP, etc.) keep
/// progressing on other workers.
pub(crate) fn run_coroutine(
    python: Python<'_>,
    coroutine: &Bound<'_, pyo3::PyAny>,
) -> PyResult<()> {
    run_coroutine_value(python, coroutine).map(|_| ())
}

/// Run a Python coroutine to completion on this thread's persistent asyncio
/// event loop and return its resolved value.
///
/// Same scheduling semantics as [`run_coroutine`] — exposed separately so
/// callers that need the coroutine's return value (e.g. host extensions
/// dispatching to script handlers) don't have to re-drive the loop.
///
/// When the global async pool is installed (the production path,
/// initialised from `SiphonServer` bootstrap), the coroutine is dispatched
/// onto one of the pool's long-running asyncio loops via
/// `asyncio.run_coroutine_threadsafe`.  That path keeps the loop running
/// across handler invocations so `asyncio.create_task(...)` actually runs
/// to completion (see `script::async_pool` for details).  When no pool is
/// installed (e.g. in lightweight tests that don't need fire-and-forget
/// task semantics), we fall back to the legacy per-thread
/// `loop.run_until_complete(coro)` path below.
pub(crate) fn run_coroutine_value(
    python: Python<'_>,
    coroutine: &Bound<'_, pyo3::PyAny>,
) -> PyResult<Py<PyAny>> {
    if let Some(value) =
        crate::script::async_pool::run_coroutine_via_pool(python, coroutine)?
    {
        return Ok(value);
    }
    let loop_handle = fallback_thread_loop(python)?;

    let bound_loop = loop_handle.bind(python);
    let result = tokio::task::block_in_place(|| {
        bound_loop.call_method1("run_until_complete", (coroutine,))
    })?;
    Ok(result.unbind())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Helper: write Python source to a temp file and compile it.
    fn compile_temp_script(source: &str) -> Result<ScriptState> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(source.as_bytes()).unwrap();
        file.flush().unwrap();

        Python::initialize();
        ScriptEngine::compile_script(file.path())
    }

    #[test]
    fn empty_script_yields_no_handlers() {
        let state = compile_temp_script("# empty script\npass\n").unwrap();
        assert!(state.handlers.is_empty());
    }

    /// Regression: `timer_loop` re-clones the timer's Python callable on every
    /// fire to hand it to the executor. It runs as a spawned Tokio task whose
    /// worker is detached from the interpreter (pyo3 `ATTACH_COUNT == 0`), so a
    /// bare `Py::clone` there panics ("Cannot clone pointer into Python heap
    /// without the thread being attached") on free-threaded CPython — the same
    /// family of bug as the dispatcher relay callbacks. The clone must go
    /// through `Python::attach` / `clone_ref` (mirrors `restart_timers`).
    #[test]
    fn timer_loop_fires_without_detached_clone_panic() {
        Python::initialize();

        // The periodic timer loop calls the handler with no arguments.
        let callable: Py<PyAny> = Python::attach(|python| {
            python
                .eval(c"lambda: None", None, None)
                .expect("compile timer lambda")
                .unbind()
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        // interval = 1s, so exactly one fire lands inside the 1200ms window.
        // With a bare clone the worker panics at the first fire (~1s) and the
        // panic unwinds `block_on`, failing the test. With the fix the loop
        // keeps running and the timeout elapses.
        let outcome = runtime.block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(1200),
                timer_loop(callable, false, 1, 0, "regression-timer".to_string()),
            )
            .await
        });

        assert!(
            outcome.is_err(),
            "timer_loop returned early — it should loop forever after firing"
        );
    }

    #[test]
    fn proxy_on_request_decorator_registers_handler() {
        let source = r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyRequest(None));
        assert!(!state.handlers[0].is_async);
    }

    #[test]
    fn proxy_on_request_with_method_filter() {
        let source = r#"
from siphon import proxy

@proxy.on_request("REGISTER")
def handle_register(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(
            state.handlers[0].kind,
            HandlerKind::ProxyRequest(Some("REGISTER".to_owned()))
        );
    }

    #[test]
    fn proxy_on_request_pipe_separated_filter() {
        let source = r#"
from siphon import proxy

@proxy.on_request("INVITE|SUBSCRIBE")
def handle_invite_subscribe(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        let handlers = state.proxy_request_handlers("INVITE");
        assert_eq!(handlers.len(), 1);
        let handlers = state.proxy_request_handlers("SUBSCRIBE");
        assert_eq!(handlers.len(), 1);
        let handlers = state.proxy_request_handlers("REGISTER");
        assert!(handlers.is_empty());
    }

    #[test]
    fn b2bua_decorators_register_correctly() {
        let source = r#"
from siphon import b2bua

@b2bua.on_invite
def new_call(call):
    pass

@b2bua.on_answer
def answered(call):
    pass

@b2bua.on_bye
def ended(call, initiator):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 3);
        assert!(state.handlers_for(&HandlerKind::B2buaInvite).len() == 1);
        assert!(state.handlers_for(&HandlerKind::B2buaAnswer).len() == 1);
        assert!(state.handlers_for(&HandlerKind::B2buaBye).len() == 1);
    }

    #[test]
    fn proxy_on_cancel_decorator_registers_handler() {
        let source = r#"
from siphon import proxy

@proxy.on_cancel
async def on_cancel(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyCancel);
        assert!(state.handlers[0].is_async);
        assert_eq!(state.handlers_for(&HandlerKind::ProxyCancel).len(), 1);
    }

    #[test]
    fn b2bua_on_cancel_decorator_registers_handler() {
        let source = r#"
from siphon import b2bua

@b2bua.on_cancel
def on_cancel(call):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::B2buaCancel);
        assert!(!state.handlers[0].is_async);
        assert_eq!(state.handlers_for(&HandlerKind::B2buaCancel).len(), 1);
    }

    #[test]
    fn registrar_on_change_decorator_registers_handler() {
        let source = r#"
from siphon import registrar

@registrar.on_change
def on_reg_change(aor, event_type, contacts):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers_for(&HandlerKind::RegistrarOnChange).len() == 1);
    }

    #[test]
    fn registration_on_change_decorator_registers_handler() {
        let source = r#"
from siphon import registration

@registration.on_change
def on_trunk_change(aor, event_type, state):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers_for(&HandlerKind::RegistrantOnChange).len() == 1);
    }

    #[test]
    fn async_handler_detected() {
        let source = r#"
from siphon import proxy

@proxy.on_request
async def route(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers[0].is_async);
    }

    #[test]
    fn syntax_error_returns_script_error() {
        let result = compile_temp_script("def broken(\n");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(matches!(error, SiphonError::Script(_)));
    }

    #[test]
    fn missing_file_returns_error() {
        let config = ScriptConfig {
            path: "/nonexistent/script.py".to_owned(),
            reload: ReloadMode::Auto,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            executor_queue_capacity: 1024,
        };
        let result = ScriptEngine::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn reload_swaps_state_atomically() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#
        )
        .unwrap();
        file.flush().unwrap();

        let config = ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: ReloadMode::Auto,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            executor_queue_capacity: 1024,
        };
        let engine = ScriptEngine::new(&config).unwrap();
        assert_eq!(engine.state().handlers.len(), 1);

        // Overwrite with a script that has 2 handlers
        let mut file_handle = std::fs::File::create(file.path()).unwrap();
        write!(
            file_handle,
            r#"
from siphon import proxy

@proxy.on_request("REGISTER")
def handle_register(request):
    pass

@proxy.on_request("INVITE")
def handle_invite(request):
    pass
"#
        )
        .unwrap();
        file_handle.flush().unwrap();

        engine.reload().unwrap();
        assert_eq!(engine.state().handlers.len(), 2);
    }

    #[test]
    fn failed_reload_keeps_previous_state() {
        let mut file = NamedTempFile::new().unwrap();
        write!(
            file,
            r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#
        )
        .unwrap();
        file.flush().unwrap();

        let config = ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: ReloadMode::Auto,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            executor_queue_capacity: 1024,
        };
        let engine = ScriptEngine::new(&config).unwrap();
        assert_eq!(engine.state().handlers.len(), 1);

        // Overwrite with broken syntax
        std::fs::write(file.path(), "def broken(\n").unwrap();

        let result = engine.reload();
        assert!(result.is_err());
        // Old state is preserved
        assert_eq!(engine.state().handlers.len(), 1);
    }

    #[test]
    fn proxy_on_reply_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_reply
def handle_reply(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyReply);
    }

    #[test]
    fn proxy_on_failure_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_failure
def failure_route(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyFailure);
    }

    #[test]
    fn proxy_on_register_reply_registers() {
        let source = r#"
from siphon import proxy

@proxy.on_register_reply
async def handle_register_reply(request, reply):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyRegisterReply);
        assert!(state.handlers[0].is_async);
    }

    #[test]
    fn b2bua_session_timer_python_api() {
        use crate::script::api::call::PyCall;
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::uri::SipUri;
        use std::sync::{Arc, Mutex};

        // Compile a script that sets a per-call session timer override
        let source = r#"
from siphon import b2bua, log

@b2bua.on_invite
def new_call(call):
    log.info(f"Setting session timer for call {call.id}")
    call.session_timer(expires=3600, min_se=120, refresher="uas")
    call.dial("sip:bob@10.0.0.2:5060")
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::B2buaInvite);

        // Build a real SIP INVITE
        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-py".to_string())
            .from("<sip:alice@atlanta.com>;tag=py-test".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("session-timer-py@test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let message_arc = Arc::new(Mutex::new(invite));
        let py_call = PyCall::new(
            "st-test-001".to_string(),
            Arc::clone(&message_arc),
            "10.0.0.1".to_string(),
        );

        // Invoke the handler and verify the override was set
        Python::attach(|python| {
            let call_obj = Py::new(python, py_call).expect("failed to create PyCall");
            let callable = state.handlers[0].callable.bind(python);
            callable.call1((call_obj.bind(python),)).expect("handler invocation failed");

            // Check that session_timer() set the override
            let borrowed = call_obj.borrow(python);
            let override_config = borrowed.session_timer_override()
                .expect("session_timer_override should be set after handler runs");
            assert_eq!(override_config.session_expires, 3600);
            assert_eq!(override_config.min_se, 120);
            assert_eq!(override_config.refresher, "uas");

            // Also check that dial() set the action
            let action = borrowed.action();
            assert_eq!(
                action,
                &crate::script::api::call::CallAction::Dial {
                    target: "sip:bob@10.0.0.2:5060".to_string(),
                    next_hop: None,
                    flow: None,
                    route: vec![],
                    timeout: 30,
                }
            );
        });
    }

    #[test]
    fn b2bua_dial_next_hop_decouples_ruri_from_routing() {
        // IMS BGCF use case: stamp the canonical home-domain IMPU on the
        // R-URI of the B-leg INVITE (so the receiving S-CSCF's alias-chain
        // lookup hits), but route the message to a fixed I-CSCF next-hop.
        // Pre-fix: the wire destination was always derived from `target`,
        // so scripts had to put the I-CSCF host in the R-URI and lose the
        // IMPU shape — registrar.lookup() then missed.
        use crate::script::api::call::{CallAction, PyCall};
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::parser::parse_uri_standalone;
        use crate::sip::uri::SipUri;
        use std::sync::{Arc, Mutex};

        let source = r#"
from siphon import b2bua

@b2bua.on_invite
def new_call(call):
    call.dial(
        "sip:5112@ims.mnc088.mcc204.3gppnetwork.org",
        next_hop="sip:172.16.0.111:4060",
    )
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);

        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("ims.mnc088.mcc204.3gppnetwork.org".to_string())
                    .with_user("5112".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bgcf-test".to_string())
            .from("<sip:caller@pstn.example>;tag=bgcf-test".to_string())
            .to("<sip:5112@ims.mnc088.mcc204.3gppnetwork.org>".to_string())
            .call_id("bgcf-next-hop@test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let py_call = PyCall::new(
            "bgcf-test-001".to_string(),
            Arc::new(Mutex::new(invite)),
            "10.0.0.1".to_string(),
        );

        Python::attach(|python| {
            let call_obj = Py::new(python, py_call).expect("failed to create PyCall");
            let callable = state.handlers[0].callable.bind(python);
            callable.call1((call_obj.bind(python),)).expect("handler invocation failed");

            let borrowed = call_obj.borrow(python);
            let action = borrowed.action();
            let CallAction::Dial { target, next_hop, .. } = action else {
                panic!("expected Dial action, got {action:?}");
            };

            // Contract 1: target drives the B-leg R-URI host (preserves IMPU shape).
            let target_parsed = parse_uri_standalone(target)
                .expect("target_uri must parse");
            assert_eq!(target_parsed.host, "ims.mnc088.mcc204.3gppnetwork.org");
            assert_eq!(target_parsed.user.as_deref(), Some("5112"));

            // Contract 2: next_hop is what the dispatcher resolves for the wire
            // destination — host = 172.16.0.111, port = 4060.
            let next_hop_str = next_hop.as_deref()
                .expect("next_hop must be set");
            let next_hop_parsed = parse_uri_standalone(next_hop_str)
                .expect("next_hop_uri must parse");
            assert_eq!(next_hop_parsed.host, "172.16.0.111");
            assert_eq!(next_hop_parsed.port, Some(4060));
            assert!(next_hop_parsed.user.is_none(),
                "next_hop is a routing destination, not a called party");
        });
    }

    #[test]
    fn b2bua_session_timer_default_values() {
        use crate::script::api::call::PyCall;
        use crate::sip::builder::SipMessageBuilder;
        use crate::sip::message::Method;
        use crate::sip::uri::SipUri;
        use std::sync::{Arc, Mutex};

        // Script calls session_timer() with no arguments — should get defaults
        let source = r#"
from siphon import b2bua

@b2bua.on_invite
def new_call(call):
    call.session_timer()
    call.dial("sip:bob@10.0.0.2:5060")
"#;
        let state = compile_temp_script(source).unwrap();

        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("example.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-st-def".to_string())
            .from("<sip:alice@atlanta.com>;tag=def-test".to_string())
            .to("<sip:bob@example.com>".to_string())
            .call_id("session-timer-defaults@test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let message_arc = Arc::new(Mutex::new(invite));
        let py_call = PyCall::new(
            "st-test-002".to_string(),
            message_arc,
            "10.0.0.1".to_string(),
        );

        Python::attach(|python| {
            let call_obj = Py::new(python, py_call).expect("failed to create PyCall");
            let callable = state.handlers[0].callable.bind(python);
            callable.call1((call_obj.bind(python),)).expect("handler invocation failed");

            let borrowed = call_obj.borrow(python);
            let override_config = borrowed.session_timer_override()
                .expect("session_timer_override should be set");
            // Defaults from #[pyo3(signature = (expires=1800, min_se=90, refresher="b2bua"))]
            assert_eq!(override_config.session_expires, 1800);
            assert_eq!(override_config.min_se, 90);
            assert_eq!(override_config.refresher, "b2bua");
        });
    }

    #[test]
    fn multiple_handler_types_in_one_script() {
        let source = r#"
from siphon import proxy, b2bua

@proxy.on_request
def route(request):
    pass

@proxy.on_reply
def reply_route(request, reply):
    pass

@proxy.on_failure
def failure_route(request, reply):
    pass

@proxy.on_register_reply
def register_reply_route(request, reply):
    pass

@b2bua.on_invite
def new_call(call):
    pass

@b2bua.on_failure
def failed(call, code, reason):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 6);
    }

    #[test]
    fn timer_every_decorator_registers_handler() {
        let source = r#"
from siphon import timer

@timer.every(seconds=30)
def health_check():
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(
            state.handlers[0].kind,
            HandlerKind::TimerEvery {
                interval_secs: 30,
                name: "health_check".to_owned(),
                jitter_secs: 0,
            }
        );
        assert!(!state.handlers[0].is_async);
    }

    #[test]
    fn timer_every_with_custom_name_and_jitter() {
        let source = r#"
from siphon import timer

@timer.every(seconds=300, name="stats_push", jitter=10)
def push_stats():
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(
            state.handlers[0].kind,
            HandlerKind::TimerEvery {
                interval_secs: 300,
                name: "stats_push".to_owned(),
                jitter_secs: 10,
            }
        );
    }

    #[test]
    fn timer_every_async_handler_detected() {
        let source = r#"
from siphon import timer

@timer.every(seconds=60)
async def check_gateways():
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers[0].is_async);
        assert!(matches!(
            state.handlers[0].kind,
            HandlerKind::TimerEvery { interval_secs: 60, .. }
        ));
    }

    #[test]
    fn multiple_timers_coexist_with_other_handlers() {
        let source = r#"
from siphon import proxy, timer

@proxy.on_request
def route(request):
    pass

@timer.every(seconds=10)
def fast_check():
    pass

@timer.every(seconds=600, name="slow_task")
async def slow_task():
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 3);
        assert_eq!(state.timer_handlers().len(), 2);
        assert!(state.has_timer_handlers());
        assert_eq!(state.proxy_request_handlers("INVITE").len(), 1);
    }

    #[test]
    fn timer_handlers_empty_without_timers() {
        let source = r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#;
        let state = compile_temp_script(source).unwrap();
        assert!(state.timer_handlers().is_empty());
        assert!(!state.has_timer_handlers());
    }

    // -----------------------------------------------------------------
    // Custom (extension) handler kind
    // -----------------------------------------------------------------

    #[test]
    fn custom_kind_is_captured_with_options() {
        let source = r#"
import _siphon_registry as _r

def my_handler(event):
    pass

_r.register("audit.sink", None, my_handler, False, {"path": "/var/log/audit", "level": "info"})
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(matches!(
            state.handlers[0].kind,
            HandlerKind::Custom { ref kind } if kind == "audit.sink"
        ));
        assert!(!state.handlers[0].is_async);

        let options = state.handlers[0]
            .options
            .as_ref()
            .expect("custom handler should carry its metadata dict");
        Python::attach(|python| {
            let bound = options.bind(python);
            let path: String = bound
                .get_item("path")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(path, "/var/log/audit");
            let level: String = bound
                .get_item("level")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(level, "info");
        });
    }

    #[test]
    fn custom_kind_async_handler_detected() {
        let source = r#"
import _siphon_registry as _r

async def handle(event):
    pass

_r.register("custom.thing", None, handle, True, None)
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert!(state.handlers[0].is_async);
        assert!(matches!(
            state.handlers[0].kind,
            HandlerKind::Custom { ref kind } if kind == "custom.thing"
        ));
        // No metadata dict registered → options is None.
        assert!(state.handlers[0].options.is_none());
    }

    #[test]
    fn custom_kind_filter_by_name() {
        let source = r#"
import _siphon_registry as _r

def a(_): pass
def b(_): pass
def c(_): pass

_r.register("alpha.kind", None, a, False, None)
_r.register("beta.kind",  None, b, False, None)
_r.register("alpha.kind", None, c, False, None)
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 3);
        assert_eq!(state.handlers_for_custom("alpha.kind").len(), 2);
        assert_eq!(state.handlers_for_custom("beta.kind").len(), 1);
        assert_eq!(state.handlers_for_custom("missing").len(), 0);
    }

    #[test]
    fn custom_kind_does_not_collide_with_builtin_kinds() {
        // A script using both built-ins and a custom kind: built-ins must
        // still parse to their typed variants, and the custom entry must
        // remain separate.
        let source = r#"
from siphon import proxy
import _siphon_registry as _r

@proxy.on_request
def route(request):
    pass

def custom_fn(event):
    pass

_r.register("ext.thing", None, custom_fn, False, {"k": "v"})
"#;
        let state = compile_temp_script(source).unwrap();
        assert_eq!(state.handlers.len(), 2);
        assert_eq!(state.proxy_request_handlers("INVITE").len(), 1);
        assert_eq!(state.handlers_for_custom("ext.thing").len(), 1);
        // The built-in proxy.on_request handler did not pick up an options dict.
        let proxy_handler = state
            .proxy_request_handlers("INVITE")
            .into_iter()
            .next()
            .unwrap();
        assert!(proxy_handler.options.is_none());
    }

    /// Helper: compile Python source to .pyc bytes using py_compile + marshal.
    fn source_to_pyc(source: &str) -> Vec<u8> {
        Python::initialize();
        Python::attach(|python| {
            let mut file = NamedTempFile::with_suffix(".py").unwrap();
            file.write_all(source.as_bytes()).unwrap();
            file.flush().unwrap();

            let pyc_path = file.path().with_extension("pyc");
            let py_compile = python.import("py_compile").unwrap();
            py_compile
                .call_method1(
                    "compile",
                    (file.path().to_str().unwrap(), pyc_path.to_str().unwrap()),
                )
                .unwrap();

            std::fs::read(&pyc_path).unwrap()
        })
    }

    #[test]
    fn bytecode_loads_proxy_handler() {
        let source = r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#;
        let pyc = source_to_pyc(source);
        let state =
            ScriptEngine::load_bytecode(Path::new("<test>"), &pyc).unwrap();
        assert_eq!(state.handlers.len(), 1);
        assert_eq!(state.handlers[0].kind, HandlerKind::ProxyRequest(None));
    }

    #[test]
    fn bytecode_loads_multiple_handlers() {
        let source = r#"
from siphon import proxy, b2bua

@proxy.on_request("REGISTER")
def handle_register(request):
    pass

@b2bua.on_invite
async def new_call(call):
    pass
"#;
        let pyc = source_to_pyc(source);
        let state =
            ScriptEngine::load_bytecode(Path::new("<test>"), &pyc).unwrap();
        assert_eq!(state.handlers.len(), 2);
        assert_eq!(
            state.handlers[0].kind,
            HandlerKind::ProxyRequest(Some("REGISTER".to_owned()))
        );
        assert_eq!(state.handlers[1].kind, HandlerKind::B2buaInvite);
        assert!(state.handlers[1].is_async);
    }

    #[test]
    fn bytecode_too_short_returns_error() {
        let result = ScriptEngine::load_bytecode(Path::new("<test>"), &[0u8; 8]);
        assert!(result.is_err());
        let error = format!("{}", result.unwrap_err());
        assert!(error.contains("too short"));
    }

    #[test]
    fn bytecode_corrupt_payload_returns_error() {
        // Valid-length header but garbage payload
        let mut bad_pyc = vec![0u8; 16];
        bad_pyc.extend_from_slice(b"\xff\xff\xff\xff");
        let result = ScriptEngine::load_bytecode(Path::new("<test>"), &bad_pyc);
        assert!(result.is_err());
    }

    #[test]
    fn new_from_bytecode_creates_engine() {
        let source = r#"
from siphon import proxy

@proxy.on_request
def route(request):
    pass
"#;
        let pyc = source_to_pyc(source);
        let engine = ScriptEngine::new_from_bytecode(&pyc).unwrap();
        assert_eq!(engine.state().handlers.len(), 1);
        assert!(!engine.auto_reload());
    }

    // -----------------------------------------------------------------
    // Host-registered user namespaces
    // -----------------------------------------------------------------

    

    #[pyclass]
    struct UserNamespaceProbe {
        value: i64,
    }

    #[pymethods]
    impl UserNamespaceProbe {
        fn answer(&self) -> i64 {
            self.value
        }
    }

    /// Serializes the user-namespace tests against each other. Each test
    /// mutates the global USER_NAMESPACES registry; running them in
    /// parallel would cause spurious collisions on shared names.
    static USER_NS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn user_namespace_visible_to_script() {
        let _guard = USER_NS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Python::initialize();
        crate::script::api::clear_user_namespaces();

        Python::attach(|python| {
            let probe = Py::new(python, UserNamespaceProbe { value: 42 })
                .unwrap()
                .into_any();
            crate::script::api::set_user_namespace("probe_ns", probe).unwrap();
        });

        let source = r#"
from siphon import probe_ns

assert probe_ns.answer() == 42
"#;
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(source.as_bytes()).unwrap();
        file.flush().unwrap();

        ScriptEngine::compile_script(file.path()).unwrap();

        crate::script::api::clear_user_namespaces();
    }

    #[test]
    fn user_namespace_collision_with_builtin_errors() {
        let _guard = USER_NS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Python::initialize();
        crate::script::api::clear_user_namespaces();

        Python::attach(|python| {
            let probe = Py::new(python, UserNamespaceProbe { value: 1 })
                .unwrap()
                .into_any();
            let result = crate::script::api::set_user_namespace("registrar", probe);
            assert!(result.is_err());
            let error = format!("{}", result.unwrap_err());
            assert!(
                error.contains("collides") && error.contains("built-in"),
                "unexpected error: {error}"
            );
        });
    }

    #[test]
    fn user_namespace_duplicate_name_errors() {
        let _guard = USER_NS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Python::initialize();
        crate::script::api::clear_user_namespaces();

        Python::attach(|python| {
            let probe1 = Py::new(python, UserNamespaceProbe { value: 1 })
                .unwrap()
                .into_any();
            let probe2 = Py::new(python, UserNamespaceProbe { value: 2 })
                .unwrap()
                .into_any();
            crate::script::api::set_user_namespace("dup_probe", probe1).unwrap();
            let result = crate::script::api::set_user_namespace("dup_probe", probe2);
            assert!(result.is_err());
            let error = format!("{}", result.unwrap_err());
            assert!(
                error.contains("already registered"),
                "unexpected error: {error}"
            );
        });

        crate::script::api::clear_user_namespaces();
    }
}

// ---------------------------------------------------------------------------
// Async runner regression tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod async_runner_tests {
    use super::*;
    use std::ffi::CString;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    
    use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyModule, PyModuleMethods};

    /// Tokio-backed coroutine bridged to Python via
    /// `pyo3_async_runtimes::tokio::future_into_py` — the same mechanism used
    /// by `cache.fetch`, `registrar.aor_count`, etc.  When the runner created
    /// a fresh asyncio loop per handler invocation, the Tokio worker that
    /// resolves this future raced with `asyncio.run()`'s loop teardown and
    /// hit `RuntimeError: Event loop is closed`.
    #[pyfunction]
    fn _ra_async_op(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            Ok(42i64)
        })
    }

    /// Install the test module exposing `_ra_async_op` into `sys.modules` so
    /// scripts can `import _siphon_run_coroutine_test`.
    fn install_test_module(python: Python<'_>) {
        let module = PyModule::new(python, "_siphon_run_coroutine_test").unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(_ra_async_op, &module).unwrap())
            .unwrap();
        let sys = python.import("sys").unwrap();
        sys.getattr("modules")
            .unwrap()
            .set_item("_siphon_run_coroutine_test", &module)
            .unwrap();
    }

    /// Build a coroutine factory that, when called, returns a fresh coroutine
    /// awaiting the bridged Tokio future.
    fn build_factory(python: Python<'_>) -> Py<PyAny> {
        let code = CString::new(
            "import _siphon_run_coroutine_test\n\
             async def factory():\n\
             \x20\x20\x20\x20return await _siphon_run_coroutine_test._ra_async_op()\n",
        )
        .unwrap();
        let globals = PyDict::new(python);
        python.run(code.as_c_str(), Some(&globals), None).unwrap();
        globals.get_item("factory").unwrap().unwrap().unbind()
    }

    /// Drive many `run_coroutine` invocations in parallel across multiple
    /// Tokio worker threads, each awaiting a `future_into_py`-backed call.
    /// With per-call `asyncio.run(coro)` this surfaces `RuntimeError: Event
    /// loop is closed` because the wake-up `call_soon_threadsafe` from the
    /// Tokio side races the loop teardown.  With a per-thread persistent
    /// loop the wake target is always alive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_coroutine_drives_future_into_py_across_threads() {
        Python::initialize();
        Python::attach(install_test_module);
        let factory: Arc<Py<PyAny>> = Arc::new(Python::attach(build_factory));

        let total: usize = 60;
        let success = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..total {
            let factory = Arc::clone(&factory);
            let success = Arc::clone(&success);
            handles.push(tokio::spawn(async move {
                tokio::task::spawn_blocking(move || {
                    Python::attach(|python| {
                        let coro = factory.bind(python).call0().unwrap();
                        run_coroutine(python, &coro)
                            .expect("coroutine must complete without closed-loop error");
                    });
                    success.fetch_add(1, Ordering::Relaxed);
                })
                .await
                .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert_eq!(success.load(Ordering::Relaxed), total);
    }

    /// The fallback (no-pool) path must reuse the same per-thread asyncio
    /// loop across calls; tearing the loop down between calls is exactly what
    /// creates the closed-loop race.
    ///
    /// Exercises `fallback_thread_loop` directly rather than going through
    /// `run_coroutine`: the public entry point short-circuits to the global
    /// async pool when a sibling test has installed it (a process-wide
    /// `OnceLock`), which would route around — and thus never populate — the
    /// per-thread fallback loop this test verifies.  Both calls run on the
    /// same thread inside one `Python::attach`, so they share the thread-local.
    #[test]
    fn fallback_loop_is_reused_across_calls() {
        Python::initialize();
        Python::attach(|python| {
            let first = fallback_thread_loop(python).expect("first fallback loop");
            let second = fallback_thread_loop(python).expect("second fallback loop");
            assert_eq!(
                first.bind(python).as_ptr() as usize,
                second.bind(python).as_ptr() as usize,
                "the same per-thread fallback asyncio loop must be reused across calls"
            );
        });
    }
}
