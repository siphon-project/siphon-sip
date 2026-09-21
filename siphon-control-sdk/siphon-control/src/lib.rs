//! Python bindings (PyO3) for the SIPhon external control plane.
//!
//! Wraps [`siphon_control_client`]. Async methods return Python awaitables via
//! `pyo3-async-runtimes`, so a control app reads like idiomatic asyncio.
//!
//! # Two connection modes (both exposed here)
//!
//! - **Inbound-persistent** — [`ControlClient`]. The app dials siphon's
//!   `/control/ws` and keeps one long-lived socket (does the `hello`
//!   handshake). Simplest to reason about; ideal for development and
//!   single-process controllers.
//!
//!   ```python
//!   from siphon_control import ControlClient
//!
//!   client = ControlClient(app="ivr-app", token="s3cr3t",
//!                          url="ws://siphon:9090/control/ws")
//!
//!   @client.on_call
//!   async def handle(call):
//!       await call.answer()
//!       await call.transfer("sip:agent@pbx")   # raises ControlError on a typed error
//!
//!   async with client:          # closes on the way out — see Shutdown below
//!       await client.run()
//!   ```
//!
//! - **Per-call-connect** — [`ControlServer`]. *siphon dials the app* at
//!   handover, so the app is a WebSocket server; each accepted connection owns
//!   exactly one call and the first frame is a pushed `StasisStart` (no `hello`
//!   from the app side). This is the documented production default for
//!   multi-pod controllers — "the audio lands on the wrong pod" is structurally
//!   impossible when the accepting socket *is* the call.
//!
//!   ```python
//!   from siphon_control import ControlServer
//!
//!   server = ControlServer(app="ivr-app", token="s3cr3t", bind="0.0.0.0:8790")
//!
//!   @server.on_call
//!   async def handle(call):
//!       await call.answer()
//!       await call.transfer("sip:agent@pbx")
//!
//!   async with server:
//!       await server.serve()
//!   ```
//!
//! Both modes reuse the SAME `@on_call` decorator and the SAME [`Call`] handle;
//! only the transport differs (dial-out vs. be-dialed). The layering mirrors the
//! Rust crate: `ControlClient.command(...)` is the generic `{module, verb,
//! target, args}` primitive for any adapter, and the `on_call` decorator +
//! `Call` verbs are the SIP facade on top.
//!
//! # Shutdown
//!
//! Both classes are async context managers, and `async with` is the recommended
//! shape (`close()` is the same thing explicitly). `run()` / `serve()` are
//! driven by a background tokio task, and each handed-over call is dispatched
//! from another one; nothing joins them and the runtime outlives the
//! interpreter, so an app that finishes without closing leaves them delivering
//! results into an asyncio loop — and then a Python — that is no longer there.
//!
//! Not closing is handled rather than fatal: [`attach_if_running`] declines a
//! re-entry into a departed interpreter instead of panicking, a handover onto a
//! closed loop is dropped rather than dispatched, and a handler cancelled during
//! teardown is not reported as a failure. That is damage control; closing is the
//! fix.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3_async_runtimes::TaskLocals;

use siphon_control_client::proto::ControlErrorCode;
use siphon_control_client::sip::{Call as RustCall, OriginateOptions, SipClient, SipServer};
use siphon_control_client::{ClientConfig, ControlError as ClientError, ServerConfig};

mod args;
mod call;

use args::{
    extract_headers, extract_privacy, extract_session_timer, extract_string_pairs, originate_media,
};
use call::Call;

// ---------------------------------------------------------------------------
// Interpreter lifecycle
// ---------------------------------------------------------------------------

/// Set once Python has begun shutting down, from the `atexit` hook registered
/// at module import. See [`attach_if_running`].
static INTERPRETER_GOING_AWAY: AtomicBool = AtomicBool::new(false);

/// Run `body` attached to the interpreter, or return `None` if the interpreter
/// is no longer there to attach to.
///
/// Every `Python::attach` in this file is reachable from a **detached** tokio
/// task: the client's read loop hands a handover to `SipFacade::dispatch`,
/// which `tokio::spawn`s the handler bridge, and `future_into_py` drives each
/// awaitable on the same runtime. Nothing joins or aborts those tasks, and the
/// runtime outlives the interpreter — so a task that wakes after Python has
/// gone reaches `Python::attach`, which is not fallible: pyo3's
/// `AttachGuard::attach` sees `Py_IsInitialized() == 0`, falls into
/// `ensure_initialized()`, and asserts. That surfaces as a `tokio-rt-worker`
/// panic advising the reader to call `Python::initialize()` — advice aimed at
/// an embedder and meaningless to someone whose app just exited, printed
/// *after* the app's own clean finish and easily mistaken for the cause of it.
///
/// Two checks, because they close different windows:
///
/// * `INTERPRETER_GOING_AWAY` is the one that does the work. `atexit` runs
///   while Python is still fully alive, well before `Py_FinalizeEx` starts
///   tearing anything down, so every late callback is already declining by the
///   time finalization could race it.
/// * `Py_IsInitialized` is the backstop for a teardown that never ran `atexit`
///   at all — `os._exit`, an embedder finalizing directly.
///
/// A dropped callback is the correct outcome here, not a lossy one: the
/// process is on its way out, and the work would have had nowhere to report to
/// anyway. The same shutdown also closes the asyncio loop the handler bridge
/// resolves its awaitables on, which is the milder form of this defect — a
/// flood of `RuntimeError: Event loop is closed` from tasks still driving a
/// loop the app has finished with.
pub(crate) fn attach_if_running<R>(body: impl FnOnce(Python<'_>) -> R) -> Option<R> {
    if INTERPRETER_GOING_AWAY.load(Ordering::Acquire) {
        return None;
    }
    // SAFETY: `Py_IsInitialized` reads a process-global flag. It is callable
    // from any thread, attached or not, and touches no Python object — it is
    // the one lifecycle call that is safe to make when we do not yet know
    // whether there is an interpreter to talk to.
    if unsafe { pyo3::ffi::Py_IsInitialized() } == 0 {
        return None;
    }
    Some(Python::attach(body))
}

/// `atexit` hook: stop re-entering Python from tokio tasks. Registered at
/// module import, so it fires before the interpreter tears anything down.
#[pyfunction]
fn _mark_interpreter_going_away() {
    INTERPRETER_GOING_AWAY.store(true, Ordering::Release);
}

/// What an in-flight command resolves to when the interpreter went away under
/// it. Nothing observes this — delivering *any* result needs Python — but it
/// keeps the value in `PyResult` shape without re-entering an interpreter that
/// is gone. `ControlError::new_err` builds the exception lazily, so
/// constructing it does not itself touch Python.
pub(crate) fn interpreter_gone() -> PyErr {
    ControlError::new_err("the Python interpreter shut down while this command was in flight")
}

pyo3::create_exception!(
    siphon_control,
    ControlError,
    PyException,
    "Raised when a control command is rejected (carrying a stable `.code`) or the connection fails."
);

// ---------------------------------------------------------------------------
// JSON <-> Python conversion (via the stdlib `json` module — robust + dep-free)
// ---------------------------------------------------------------------------

pub(crate) fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let text =
        serde_json::to_string(value).map_err(|error| PyValueError::new_err(error.to_string()))?;
    let json = py.import("json")?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

fn py_to_json(object: &Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if object.is_none() {
        return Ok(serde_json::Value::Null);
    }
    let json = object.py().import("json")?;
    let text: String = json.call_method1("dumps", (object,))?.extract()?;
    serde_json::from_str(&text).map_err(|error| PyValueError::new_err(error.to_string()))
}

pub(crate) fn optional_json(object: Option<Bound<'_, PyAny>>) -> PyResult<serde_json::Value> {
    match object {
        Some(object) => py_to_json(&object),
        None => Ok(serde_json::Value::Null),
    }
}

fn code_to_str(code: ControlErrorCode) -> Option<String> {
    serde_json::to_value(code)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
}

/// Map a client error to the Python `ControlError` exception, attaching `.code`.
///
/// Called from inside `future_into_py` futures, i.e. on the tokio runtime, so
/// it can run after the interpreter has gone — attaching to set `.code` has to
/// go through the lifecycle guard. Without the interpreter the exception keeps
/// its message and simply carries no `.code`; `ControlError::new_err` builds
/// lazily, so returning it re-enters nothing.
pub(crate) fn to_pyerr(error: ClientError) -> PyErr {
    let code = error.code().and_then(code_to_str);
    let message = error.to_string();
    let err = ControlError::new_err(message);
    attach_if_running(|py| {
        let _ = err.value(py).setattr("code", code);
    });
    err
}

// ---------------------------------------------------------------------------
// ControlClient pyclass
// ---------------------------------------------------------------------------

struct ClientInner {
    config: ClientConfig,
    client: tokio::sync::Mutex<Option<Arc<SipClient>>>,
    handler: Mutex<Option<Py<PyAny>>>,
}

/// The control client. Construct it, register a handler with `@client.on_call`,
/// then `await client.run()`.
#[pyclass(module = "siphon_control", name = "ControlClient")]
struct ControlClient {
    inner: Arc<ClientInner>,
}

#[pymethods]
impl ControlClient {
    #[new]
    #[pyo3(signature = (app, token, url=None, protocol=1, reply_timeout_ms=10_000, reconnect_backoff_ms=1_000))]
    fn new(
        app: String,
        token: String,
        url: Option<String>,
        protocol: u32,
        reply_timeout_ms: u64,
        reconnect_backoff_ms: u64,
    ) -> Self {
        let url = url.unwrap_or_else(|| "ws://127.0.0.1:9090/control/ws".to_string());
        let mut config = ClientConfig::new(url, app, token);
        config.protocol = protocol;
        config.reply_timeout = Duration::from_millis(reply_timeout_ms);
        config.reconnect_backoff = Duration::from_millis(reconnect_backoff_ms);
        Self {
            inner: Arc::new(ClientInner {
                config,
                client: tokio::sync::Mutex::new(None),
                handler: Mutex::new(None),
            }),
        }
    }

    /// Register the per-call handler. Usable as a decorator: `@client.on_call`.
    fn on_call(&self, py: Python<'_>, handler: Py<PyAny>) -> Py<PyAny> {
        *lock(&self.inner.handler) = Some(handler.clone_ref(py));
        handler
    }

    /// Connect + `hello` (idempotent). Returns an awaitable resolving to `None`.
    fn connect<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            ensure_client(&inner).await?;
            Ok(())
        })
    }

    /// Fetch the registered adapters' schema (`describe`).
    fn describe<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = ensure_client(&inner).await?;
            let value = client.describe().await.map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Send a raw command on any module — the generic `{module, verb, target,
    /// args}` primitive. Returns the reply `result` object.
    #[pyo3(signature = (verb, module=None, target=None, args=None))]
    fn command<'py>(
        &self,
        py: Python<'py>,
        verb: String,
        module: Option<String>,
        target: Option<Bound<'py, PyAny>>,
        args: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        let target = optional_json(target)?;
        let args = optional_json(args)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = ensure_client(&inner).await?;
            let value = client
                .command(module.as_deref(), &verb, target, args)
                .await
                .map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Place an outbound call under a caller-supplied channel id.
    ///
    /// The one verb that creates a channel rather than addressing one. It
    /// resolves as soon as the INVITE is on the wire, to `{"channel", "call_id",
    /// "sip_call_id"}`: the call is `calling`, and the answer, a failure or the
    /// ring timeout arrive later as events on the channel.
    ///
    /// Exactly one media plan: `media=True` (siphon anchors the leg, shaped by
    /// `profile` / `ws_uri`), `sdp=` (your own offer) or `body=` with its
    /// `content_type`. `from_uri`, `from_display`, `to_display`, `next_hop`,
    /// `p_asserted_identity`, `privacy` (`"allowed"` / `"restricted"`), `headers`,
    /// `timeout`, `on_lost` and `vars` shape the call as on the server.
    /// `session_timer={"expires": 1800, "min_se": 90, "refresher": "b2bua"}` runs an
    /// RFC 4028 session timer on it, each key left out taking the server's
    /// default; left out entirely, the configured timer runs.
    ///
    /// Raises `ValueError` before anything is sent for what the server would
    /// refuse (no media plan or two, an unknown privacy, a session timer siphon
    /// cannot run), and `ControlError` for the server's own refusals (`conflict`
    /// for a channel id in use, `not_found` for no route, ...).
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        channel,
        to,
        *,
        media=false,
        profile=None,
        ws_uri=None,
        sdp=None,
        body=None,
        content_type=None,
        from_uri=None,
        from_display=None,
        to_display=None,
        next_hop=None,
        p_asserted_identity=None,
        privacy=None,
        headers=None,
        timeout=None,
        on_lost=None,
        vars=None,
        session_timer=None,
    ))]
    fn originate<'py>(
        &self,
        py: Python<'py>,
        channel: String,
        to: String,
        media: bool,
        profile: Option<String>,
        ws_uri: Option<String>,
        sdp: Option<String>,
        body: Option<String>,
        content_type: Option<String>,
        from_uri: Option<String>,
        from_display: Option<String>,
        to_display: Option<String>,
        next_hop: Option<String>,
        p_asserted_identity: Option<String>,
        privacy: Option<String>,
        headers: Option<Bound<'py, PyAny>>,
        timeout: Option<u64>,
        on_lost: Option<String>,
        vars: Option<Bound<'py, PyAny>>,
        session_timer: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let plan = originate_media(media, profile, ws_uri, sdp, body, content_type)?;
        let privacy = extract_privacy("originate", privacy)?;
        let options = OriginateOptions {
            from: from_uri,
            from_display,
            to_display,
            next_hop,
            p_asserted_identity,
            privacy,
            headers: headers
                .map(|headers| extract_headers(&headers))
                .transpose()?
                .unwrap_or_default(),
            timeout,
            on_lost,
            vars: vars
                .map(|vars| extract_string_pairs(&vars, "vars"))
                .transpose()?
                .unwrap_or_default(),
            session_timer: session_timer
                .map(|timer| extract_session_timer(&timer))
                .transpose()?,
        };
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = ensure_client(&inner).await?;
            let placed = client
                .originate(&channel, &to, plan, options)
                .await
                .map_err(to_pyerr)?;
            let value = serde_json::json!({
                "channel": placed.channel,
                "call_id": placed.call_id,
                "sip_call_id": placed.sip_call_id,
            });
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Connect (if needed), register the handler bridge, then drive the
    /// supervised connection loop (reconnect + resync) to completion.
    fn run<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        // Capture the running loop's task locals *now* (on the Python thread) so
        // the handler bridge can drive Python coroutines from Rust.
        let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
        let handler = lock(&self.inner.handler).as_ref().map(|h| h.clone_ref(py));
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let client = ensure_client(&inner).await?;
            if let Some(handler) = handler {
                install_handler_bridge(&client, handler, locals);
            }
            client.run().await.map_err(to_pyerr)?;
            Ok(())
        })
    }

    /// Stop the client and unblock `run`.
    fn shutdown(&self) {
        if let Ok(guard) = self.inner.client.try_lock() {
            if let Some(client) = guard.as_ref() {
                client.shutdown();
            }
        }
    }

    /// Stop the client and drop the registered handler, so nothing else is
    /// dispatched into Python on this client.
    ///
    /// Prefer this — or the `async with` form below — over letting the process
    /// exit with `run()` still in flight. `run()` is backed by a tokio task
    /// that nothing joins, and both it and any handler still dispatching
    /// re-enter Python to deliver their results; if the interpreter goes away
    /// first, that lands on a dead interpreter. This crate declines those
    /// re-entries rather than crashing (see `attach_if_running`), but declining
    /// them is damage control — closing first means there is nothing in flight
    /// to decline.
    fn close(&self) {
        self.shutdown();
        // Drop the handler reference as well: a call handed over between the
        // shutdown and the socket actually closing would otherwise still be
        // dispatched into an app that has said it is done.
        *lock(&self.inner.handler) = None;
    }

    /// `async with ControlClient(...) as client:` — closes on the way out,
    /// including on an exception or a cancellation.
    fn __aenter__<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let slf = slf.unbind();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (*_args))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _args: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.close();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(false) })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Connect the underlying [`SipClient`] once, caching it.
async fn ensure_client(inner: &Arc<ClientInner>) -> PyResult<Arc<SipClient>> {
    let mut guard = inner.client.lock().await;
    if let Some(client) = guard.as_ref() {
        return Ok(Arc::clone(client));
    }
    let client = Arc::new(
        SipClient::connect(inner.config.clone())
            .await
            .map_err(to_pyerr)?,
    );
    *guard = Some(Arc::clone(&client));
    Ok(client)
}

/// Bridge the Rust call handler to the stored Python coroutine function: for each
/// handed-over call, build a `Call` pyobject, invoke the handler, and drive the
/// returned coroutine on the asyncio loop captured in `locals`.
fn install_handler_bridge(client: &SipClient, handler: Py<PyAny>, locals: TaskLocals) {
    client.set_call_handler(move |call: RustCall| {
        // Runs on a detached `tokio::spawn` from `SipFacade::dispatch`, so it
        // can wake after the interpreter has gone — clone the handler through
        // the lifecycle guard rather than `Python::attach` directly.
        let handler = attach_if_running(|py| handler.clone_ref(py));
        let locals = locals.clone();
        async move {
            // `None` = Python is on its way out. Drop the call: there is nobody
            // left to hand it to and the process is not going to place it
            // either. Dropped without a word on purpose — the point of this
            // path is that a finished app exits quietly, and this crate has no
            // logger of its own to say it through.
            if let Some(handler) = handler {
                dispatch_to_python(handler, locals, call).await;
            }
            Ok(())
        }
    });
}

async fn dispatch_to_python(handler: Py<PyAny>, locals: TaskLocals, call: RustCall) {
    // The asyncio loop captured when `run()` was called can be closed while the
    // client is still live — an app that finished without closing, which is the
    // shape that produced this bug report. Dispatching onto a closed loop does
    // not fail quietly: `pyo3-async-runtimes` resolves every awaitable through
    // `loop.call_soon_threadsafe`, which raises `RuntimeError: Event loop is
    // closed` and gets dumped as a traceback from inside the dependency, once
    // per handed-over call. Nothing here can catch that after the fact, so
    // check before handing the call over at all. One `is_closed()` per
    // handover, against building a `Call` and driving a coroutine.
    let loop_usable = attach_if_running(|py| {
        locals
            .event_loop(py)
            .call_method0("is_closed")
            .and_then(|closed| closed.extract::<bool>())
            .map(|closed| !closed)
            // An event loop that cannot answer `is_closed()` is not one to
            // dispatch onto either.
            .unwrap_or(false)
    });
    if loop_usable != Some(true) {
        return;
    }

    let scoped = pyo3_async_runtimes::tokio::scope(locals, async move {
        let awaitable = attach_if_running(|py| -> PyResult<Option<_>> {
            let py_call = Bound::new(py, Call { inner: call })?;
            let result = handler.bind(py).call1((py_call,))?;
            if result.hasattr("__await__")? {
                Ok(Some(pyo3_async_runtimes::tokio::into_future(result)?))
            } else {
                Ok(None)
            }
        })?;
        Some(match awaitable {
            Ok(Some(future)) => future.await.map(|_| ()),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        })
    })
    .await;
    // Printing a traceback is itself a Python call, and this one runs after the
    // handler has already awaited — the widest window for shutdown to have
    // started underneath it. If the interpreter is gone the traceback goes
    // nowhere, which is correct: there is no stderr contract left to honour
    // once the app has finished, and the alternative was the panic this guard
    // exists to remove. `None` from the scope means the handler was never
    // entered at all, for the same reason.
    if let Some(Err(error)) = scoped {
        attach_if_running(|py| {
            // A handler cancelled as the loop shuts down is teardown, not a
            // failure. asyncio does not print a traceback for a cancelled task
            // and neither should this: with calls in flight it turns every
            // clean exit into a wall of CancelledError, one per call, which is
            // the same "the exit reason is buried under noise the app did not
            // cause" problem as the panic above.
            if !error.is_instance_of::<pyo3::exceptions::asyncio::CancelledError>(py) {
                error.print(py);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// ControlServer pyclass (per-call-connect mode — siphon dials the app)
// ---------------------------------------------------------------------------

struct ServerInner {
    config: ServerConfig,
    server: tokio::sync::Mutex<Option<Arc<SipServer>>>,
    handler: Mutex<Option<Py<PyAny>>>,
    local_addr: Mutex<Option<String>>,
}

/// The per-call-connect control server: **siphon dials the app**, so this is a
/// WebSocket server. Construct it, register a handler with `@server.on_call`,
/// then `await server.serve()`. Each accepted connection owns exactly one call;
/// the first frame is a pushed `StasisStart` (no `hello`).
#[pyclass(module = "siphon_control", name = "ControlServer")]
struct ControlServer {
    inner: Arc<ServerInner>,
}

#[pymethods]
impl ControlServer {
    #[new]
    #[pyo3(signature = (app, token, bind=None, reply_timeout_ms=10_000))]
    fn new(
        app: String,
        token: String,
        bind: Option<String>,
        reply_timeout_ms: u64,
    ) -> PyResult<Self> {
        let bind = bind.unwrap_or_else(|| "0.0.0.0:8790".to_string());
        let listen: SocketAddr = bind.parse().map_err(|error| {
            PyValueError::new_err(format!("invalid bind address {bind:?}: {error}"))
        })?;
        let mut config = ServerConfig::new(listen, app, token);
        config.reply_timeout = Duration::from_millis(reply_timeout_ms);
        Ok(Self {
            inner: Arc::new(ServerInner {
                config,
                server: tokio::sync::Mutex::new(None),
                handler: Mutex::new(None),
                local_addr: Mutex::new(None),
            }),
        })
    }

    /// Register the per-call handler. Usable as a decorator: `@server.on_call`.
    /// Reuses the SAME `Call` handle + dispatch as `ControlClient.on_call`.
    fn on_call(&self, py: Python<'_>, handler: Py<PyAny>) -> Py<PyAny> {
        *lock(&self.inner.handler) = Some(handler.clone_ref(py));
        handler
    }

    /// Bind the listener (idempotent). Returns an awaitable resolving to the
    /// bound address string, e.g. `"127.0.0.1:54321"` — useful when binding to
    /// port `0` to learn the ephemeral port before siphon dials in.
    fn bind<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            ensure_server(&inner).await?;
            Ok(lock(&inner.local_addr).clone())
        })
    }

    /// The bound address once [`ControlServer::bind`] (or `serve`) has run, else
    /// `None`. When constructed with a port-`0` bind, this is where siphon dials.
    #[getter]
    fn local_addr(&self) -> Option<String> {
        lock(&self.inner.local_addr).clone()
    }

    /// Bind (if needed), register the handler bridge, then run the accept loop
    /// forever — accepting each per-call dial siphon makes. Runs until the
    /// awaitable is cancelled or the listener fails.
    fn serve<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.serve_impl(py)
    }

    /// Alias for [`ControlServer::serve`].
    fn run<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.serve_impl(py)
    }

    /// Drop the registered handler, so no further accepted call is dispatched
    /// into Python. Same reasoning as [`ControlClient::close`]: close before
    /// the interpreter goes away rather than leaving dispatches in flight for
    /// the lifecycle guard to decline.
    fn close(&self) {
        *lock(&self.inner.handler) = None;
    }

    /// `async with ControlServer(...) as server:` — closes on the way out,
    /// including on an exception or a cancellation.
    fn __aenter__<'py>(slf: Bound<'py, Self>, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let slf = slf.unbind();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(slf) })
    }

    #[pyo3(signature = (*_args))]
    fn __aexit__<'py>(
        &self,
        py: Python<'py>,
        _args: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.close();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(false) })
    }
}

impl ControlServer {
    fn serve_impl<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = Arc::clone(&self.inner);
        // Capture the running loop's task locals *now* (on the Python thread) so
        // the handler bridge can drive Python coroutines from Rust.
        let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
        let handler = lock(&self.inner.handler).as_ref().map(|h| h.clone_ref(py));
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let server = ensure_server(&inner).await?;
            if let Some(handler) = handler {
                install_server_handler_bridge(&server, handler, locals);
            }
            server.run().await.map_err(to_pyerr)?;
            Ok(())
        })
    }
}

/// Bind the underlying [`SipServer`] once, caching it + its bound address.
async fn ensure_server(inner: &Arc<ServerInner>) -> PyResult<Arc<SipServer>> {
    let mut guard = inner.server.lock().await;
    if let Some(server) = guard.as_ref() {
        return Ok(Arc::clone(server));
    }
    let server = Arc::new(
        SipServer::bind(inner.config.clone())
            .await
            .map_err(to_pyerr)?,
    );
    let bound = server.local_addr().map_err(to_pyerr)?;
    *lock(&inner.local_addr) = Some(bound.to_string());
    *guard = Some(Arc::clone(&server));
    Ok(server)
}

/// Bridge the stored Python handler to the SIP server, reusing the same
/// per-call dispatch as the inbound client (identical `Call` + coroutine drive).
fn install_server_handler_bridge(server: &SipServer, handler: Py<PyAny>, locals: TaskLocals) {
    server.set_call_handler(move |call: RustCall| {
        // Same detached-task lifetime as the client bridge above — guard the
        // attach for the same reason.
        let handler = attach_if_running(|py| handler.clone_ref(py));
        let locals = locals.clone();
        async move {
            if let Some(handler) = handler {
                dispatch_to_python(handler, locals, call).await;
            }
            Ok(())
        }
    });
}

// ---------------------------------------------------------------------------
// Transfer-outcome helpers
// ---------------------------------------------------------------------------
//
// `next_event()` hands back a plain ``{"kind": ..., "payload": ...}`` dict, so
// unlike the Rust client there is no `CallEvent` to hang methods off. These are
// the module-level twins of `CallEvent::is_transfer_final` /
// `CallEvent::transfer_outcome` and of TypeScript's `isTransferFinal`, and they
// exist so an application does not have to hardcode the wire strings — which is
// exactly the thing that rots in silence when the event set grows.

/// Whether an event kind ends a transfer this app asked for.
///
/// Exactly one such event arrives per ``refer()`` / ``transfer()``, so this is
/// the signal to stop waiting. The verb's own reply says only that the REFER
/// went on the wire: RFC 3515 §2.4.4 delivers the outcome afterwards, on the
/// implicit subscription, as zero or more ``TransferProgress`` and then one
/// ``TransferCompleted`` / ``TransferFailed``.
///
/// ```python
/// await call.transfer("sip:agent@example.test")
/// async for event in call.events():
///     if siphon_control.is_transfer_final(event["kind"]):
///         outcome = siphon_control.transfer_outcome(event)
///         break
/// ```
#[pyfunction]
fn is_transfer_final(kind: &str) -> bool {
    matches!(kind, "TransferCompleted" | "TransferFailed")
}

/// The transfer verdict carried by an event, or ``None`` if it is not one.
///
/// Accepts an event dict as ``next_event()`` returns it and yields its
/// ``payload`` for ``TransferProgress`` / ``TransferCompleted`` /
/// ``TransferFailed`` — ``stage``, ``refer_to``, ``status``, ``reason``,
/// ``attempt``. Anything else, including a `TransferRequested` (an *inbound*
/// REFER somebody else asked for, not a verdict on one of ours), gives ``None``.
#[pyfunction]
fn transfer_outcome(py: Python<'_>, event: &Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
    let kind: Option<String> = event
        .get_item("kind")
        .ok()
        .and_then(|value| value.extract().ok());
    let is_outcome = matches!(
        kind.as_deref(),
        Some("TransferProgress" | "TransferCompleted" | "TransferFailed")
    );
    if !is_outcome {
        return Ok(py.None());
    }
    match event.get_item("payload") {
        Ok(payload) => Ok(payload.unbind()),
        Err(_) => Ok(py.None()),
    }
}

// ---------------------------------------------------------------------------
// Module init
// ---------------------------------------------------------------------------

#[pymodule]
#[pyo3(name = "siphon_control")]
fn siphon_control(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<ControlClient>()?;
    module.add_class::<ControlServer>()?;
    module.add_class::<Call>()?;
    module.add("ControlError", module.py().get_type::<ControlError>())?;
    module.add_function(wrap_pyfunction!(is_transfer_final, module)?)?;
    module.add_function(wrap_pyfunction!(transfer_outcome, module)?)?;

    // Stop driving Python from the tokio runtime once shutdown begins. The
    // runtime outlives the interpreter and nothing joins its tasks, so without
    // this a callback landing during teardown reaches `Python::attach` on a
    // dead interpreter and panics — see `attach_if_running`. `atexit` is the
    // right hook because it runs while Python is still fully alive, ahead of
    // finalization rather than racing it.
    let mark = wrap_pyfunction!(_mark_interpreter_going_away, module)?;
    module
        .py()
        .import("atexit")?
        .call_method1("register", (&mark,))?;
    module.add("_mark_interpreter_going_away", mark)?;
    module.add(
        "__all__",
        PyList::new(
            module.py(),
            [
                "ControlClient",
                "ControlServer",
                "Call",
                "ControlError",
                "is_transfer_final",
                "transfer_outcome",
            ],
        )?,
    )?;
    Ok(())
}
