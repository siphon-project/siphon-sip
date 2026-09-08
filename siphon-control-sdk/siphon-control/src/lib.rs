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

use siphon_control_client::proto::sip::PeerHangupPolicy;
use siphon_control_client::proto::ControlErrorCode;
use siphon_control_client::sip::{
    Call as RustCall, DtmfOptions, PlayOptions, PlaySource, RouteTarget, SipClient, SipServer,
};
use siphon_control_client::{ClientConfig, ControlError as ClientError, ServerConfig};

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
fn attach_if_running<R>(body: impl FnOnce(Python<'_>) -> R) -> Option<R> {
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
fn interpreter_gone() -> PyErr {
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

fn json_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
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

fn optional_json(object: Option<Bound<'_, PyAny>>) -> PyResult<serde_json::Value> {
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
fn to_pyerr(error: ClientError) -> PyErr {
    let code = error.code().and_then(code_to_str);
    let message = error.to_string();
    let err = ControlError::new_err(message);
    attach_if_running(|py| {
        let _ = err.value(py).setattr("code", code);
    });
    err
}

/// Extract one `route` target: a bare URI `str`, or a dict
/// `{uri, next_hop?, headers?, timeout?}`.
fn extract_route_target(item: &Bound<'_, PyAny>) -> PyResult<RouteTarget> {
    if let Ok(uri) = item.extract::<String>() {
        return Ok(RouteTarget::uri(uri));
    }
    let dict = item.cast::<pyo3::types::PyDict>().map_err(|_| {
        PyValueError::new_err(
            "each route target must be a URI str or a dict {uri, next_hop, headers, timeout}",
        )
    })?;
    let uri: String = match dict.get_item("uri")? {
        Some(value) => value.extract()?,
        None => {
            return Err(PyValueError::new_err(
                "route target dict requires a string 'uri'",
            ))
        }
    };
    let next_hop = match dict.get_item("next_hop")? {
        Some(value) if !value.is_none() => Some(value.extract::<String>()?),
        _ => None,
    };
    let headers = match dict.get_item("headers")? {
        Some(value) if !value.is_none() => extract_headers(&value)?,
        _ => Vec::new(),
    };
    let timeout_secs = match dict.get_item("timeout")? {
        Some(value) if !value.is_none() => Some(value.extract::<u32>()?),
        _ => None,
    };
    Ok(RouteTarget {
        uri,
        next_hop,
        headers,
        timeout_secs,
    })
}

/// Build a [`PlaySource`] from the mutually-exclusive `file` / `db_id` / `blob`
/// kwargs (exactly one must be set — mirrors the in-process `play_media`).
fn build_play_source(
    file: Option<String>,
    db_id: Option<u64>,
    blob: Option<Vec<u8>>,
) -> PyResult<PlaySource> {
    match (file, db_id, blob) {
        (Some(file), None, None) => Ok(PlaySource::file(file)),
        (None, Some(db_id), None) => Ok(PlaySource::db_id(db_id)),
        (None, None, Some(blob)) => Ok(PlaySource::blob(blob)),
        _ => Err(PyValueError::new_err(
            "play requires exactly one of file (str), db_id (int), or blob (bytes)",
        )),
    }
}

/// Parse the `on_peer_hangup` argument of `bridge`. Refused here rather than at
/// the server, so a typo raises before anything touches the two live calls.
fn parse_peer_hangup(policy: Option<String>) -> PyResult<Option<PeerHangupPolicy>> {
    match policy {
        None => Ok(None),
        Some(token) => PeerHangupPolicy::parse(&token).map(Some).ok_or_else(|| {
            PyValueError::new_err(format!(
                "on_peer_hangup must be \"hangup\" or \"hold\", got {token:?}"
            ))
        }),
    }
}

/// Extract a `{name: value}` header dict into ordered string pairs.
fn extract_headers(object: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    let dict = object
        .cast::<pyo3::types::PyDict>()
        .map_err(|_| PyValueError::new_err("headers must be a dict of str -> str"))?;
    let mut pairs = Vec::with_capacity(dict.len());
    for (key, value) in dict.iter() {
        pairs.push((key.extract::<String>()?, value.extract::<String>()?));
    }
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// Call pyclass
// ---------------------------------------------------------------------------

/// A handed-over SIP call. Async methods return awaitables.
#[pyclass(module = "siphon_control", name = "Call")]
struct Call {
    inner: RustCall,
}

#[pymethods]
impl Call {
    #[getter]
    fn channel_id(&self) -> String {
        self.inner.channel_id().to_string()
    }

    #[getter]
    fn call_id(&self) -> Option<String> {
        self.inner.call_id().map(str::to_string)
    }

    #[getter]
    fn sip_call_id(&self) -> Option<String> {
        self.inner.sip_call_id().map(str::to_string)
    }

    #[getter]
    fn app(&self) -> Option<String> {
        self.inner.app().map(str::to_string)
    }

    #[getter]
    fn is_reattached(&self) -> bool {
        self.inner.is_reattached()
    }

    #[getter]
    fn payload(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_to_py(py, self.inner.payload())
    }

    fn answer<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.answer().await.map_err(to_pyerr)
        })
    }

    #[pyo3(signature = (code, reason=None, body=None, content_type=None))]
    fn answer_with<'py>(
        &self,
        py: Python<'py>,
        code: u16,
        reason: Option<String>,
        body: Option<String>,
        content_type: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.answer_with(
                code,
                reason.as_deref(),
                body.as_deref(),
                content_type.as_deref(),
            )
            .await
            .map_err(to_pyerr)
        })
    }

    /// Answer the parked A-leg **and** anchor its media to the media engine in
    /// one act — the verb form of the routing script's
    /// ``call.handover(answer=True, profile=..., ws_uri=...)``.
    ///
    /// This is how an application that accepted an **un-answered** handover
    /// connects the call. It can already hold the call open for as long as its
    /// own policy says with ``ring()``; what it could not do is connect the
    /// caller to anything, because a plain ``answer()`` sends a 2xx and anchors
    /// nothing. Answering first and attaching a stream afterwards is not the
    /// same thing: ``received_from``, echo cancellation and the VAD engine are
    /// properties of the answer, not of a bridge attached after it.
    ///
    /// ``profile`` names a media profile (default ``voice_ai``) and ``ws_uri``
    /// overrides that profile's WebSocket bridge URI for this call, with
    /// ``{call_id}`` / ``{from_tag}`` / ``{from_user}`` / ``{to_user}``
    /// templating.
    ///
    /// Synthesizing the RFC 3264 answer against the media engine is a
    /// siphon-rtp capability, so on rtpengine / rtpproxy this raises with
    /// ``code == "unavailable"`` rather than sending a 200 with nothing behind
    /// it. On any media failure the 2xx is never sent and the call stays parked
    /// — retry with another profile, or reject it.
    ///
    /// ```python
    /// @client.on_call
    /// async def handle(call):
    ///     await call.ring()
    ///     agent = await pick_an_agent(call)      # only the app knows when
    ///     await call.answer_anchored(profile="voice_ai")
    /// ```
    #[pyo3(signature = (profile=None, ws_uri=None))]
    fn answer_anchored<'py>(
        &self,
        py: Python<'py>,
        profile: Option<String>,
        ws_uri: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.answer_anchored(profile.as_deref(), ws_uri.as_deref())
                .await
                .map_err(to_pyerr)
        })
    }

    /// Send ``180 Ringing``: alerting only, no early media.
    ///
    /// RFC 3261 §13.2.1 makes the 180 the "callee is being alerted" signal, and
    /// RFC 3960 §3.1 puts early media on a response that carries SDP — two
    /// different acts, so two verbs. Ring for as long as your own policy says,
    /// then ``answer()``; open an early-media path with ``progress_with()``.
    #[pyo3(signature = (reason=None))]
    fn ring<'py>(&self, py: Python<'py>, reason: Option<String>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match reason {
                Some(reason) => call.ring_with_reason(&reason).await,
                None => call.ring().await,
            }
            .map_err(to_pyerr)
        })
    }

    fn progress<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.progress().await.map_err(to_pyerr)
        })
    }

    #[pyo3(signature = (code, reason=None))]
    fn reject<'py>(
        &self,
        py: Python<'py>,
        code: u16,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.reject(code, reason.as_deref()).await.map_err(to_pyerr)
        })
    }

    #[pyo3(signature = (reason=None))]
    fn hangup<'py>(&self, py: Python<'py>, reason: Option<String>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match reason {
                Some(reason) => call.hangup_with_reason(&reason).await,
                None => call.hangup().await,
            }
            .map_err(to_pyerr)
        })
    }

    fn refer<'py>(&self, py: Python<'py>, to: String) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.refer(&to).await.map_err(to_pyerr)
        })
    }

    /// Blind-transfer alias for `refer`.
    fn transfer<'py>(&self, py: Python<'py>, to: String) -> PyResult<Bound<'py, PyAny>> {
        self.refer(py, to)
    }

    /// Accept a pending inbound REFER (surfaced as a `TransferRequested` event)
    /// and run the transfer. `target` overrides the Refer-To URI, `next_hop`
    /// steers egress, and `mode` is `"terminate"` / `"transparent"`. No pending
    /// REFER raises `ControlError` with `code == "not_found"`.
    ///
    /// `profile` names the media profile for the pairing the transfer creates,
    /// and is **required when the call is anchored with a direction-bound
    /// profile** (`srtp_to_rtp` and every other SRTP edge): its answer half was
    /// written for the party being transferred away, so inheriting it re-offers
    /// that party's transport to whoever remains and the survivor answers
    /// `m=audio 0` — a connected call with no audio either way. Pass the profile
    /// for the pair that remains, commonly `"rtp_passthrough"`.
    #[pyo3(signature = (target=None, next_hop=None, mode=None, profile=None))]
    fn accept_refer<'py>(
        &self,
        py: Python<'py>,
        target: Option<String>,
        next_hop: Option<String>,
        mode: Option<String>,
        profile: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.accept_refer(
                target.as_deref(),
                next_hop.as_deref(),
                mode.as_deref(),
                profile.as_deref(),
            )
            .await
            .map_err(to_pyerr)
        })
    }

    /// Reject a pending inbound REFER with a final non-2xx (default
    /// `603 Decline`). No pending REFER raises `code == "not_found"`.
    #[pyo3(signature = (code, reason=None))]
    fn reject_refer<'py>(
        &self,
        py: Python<'py>,
        code: u16,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.reject_refer(code, reason.as_deref())
                .await
                .map_err(to_pyerr)
        })
    }

    /// Join this call to another leg the app owns, so the two parties hear each
    /// other.
    ///
    /// **This call is the anchor.** It keeps its media session — its ports and
    /// everything attached to them; the `with_channel` leg's own media session
    /// is deleted and it becomes the second party on this one's. So bridge
    /// *into* the leg whose media you want to keep (the one being recorded,
    /// teed, or carrying the prompt). The argument is named `with_channel`
    /// because `with` is a Python keyword; on the wire it is `with`.
    ///
    /// Both legs must already be answered. `on_peer_hangup` is `"hangup"` (the
    /// default) to tear the survivor down when its partner leaves, or `"hold"`
    /// to keep it up, held and still owned so it can be bridged to somebody
    /// else; anything else raises `ValueError`.
    ///
    /// Returns as soon as the media has been re-pointed and the first re-INVITE
    /// is on the wire — that is *offered*, not *bridged*. A bridge is two
    /// RFC 3261 §14 re-INVITEs across two dialogs, so the outcome arrives on the
    /// event stream instead: exactly one `ChannelBridged` / `BridgeFailed`, on
    /// **both** channels.
    ///
    /// The return value is the reply `result` (`{"channel", "with", "call_id",
    /// "peer_call_id", "anchored", "on_peer_hangup", "state": "bridging"}`).
    /// Raises `ControlError` with a `code` a caller can act on: `"not_found"`
    /// (no such leg), `"invalid_state"` (a leg has not answered, is already
    /// bridged, has a re-INVITE outstanding, or carries no media description),
    /// `"bad_request"` (the same leg named twice), `"forbidden"` (the other
    /// channel belongs to another app), `"unsupported_verb"` (the media backend
    /// cannot express it).
    #[pyo3(signature = (with_channel, on_peer_hangup=None))]
    fn bridge<'py>(
        &self,
        py: Python<'py>,
        with_channel: String,
        on_peer_hangup: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let policy = parse_peer_hangup(on_peer_hangup)?;
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = call.bridge(&with_channel, policy).await.map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Break this call's bridge.
    ///
    /// Both legs stay answered, owned and held — re-offered `a=sendonly`
    /// (RFC 3264 §8.4, which RFC 6337 §3.1 prefers to `c=0.0.0.0`). Neither is
    /// hung up: that would be indistinguishable from two hangups and would take
    /// away the calls the app still owns. A later `bridge` re-offers `sendrecv`.
    ///
    /// `reason` is free text carried on the `ChannelUnbridged` event both
    /// channels receive (default `"unbridged"`). Returns the reply `result`
    /// (`{"channel", "with", "reason", "state": "unbridged"}`), where `"with"`
    /// is the channel id of the leg that was on the other side. A call that is
    /// not bridged raises `ControlError` with `code == "invalid_state"`.
    #[pyo3(signature = (reason=None))]
    fn unbridge<'py>(
        &self,
        py: Python<'py>,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = call.unbridge(reason.as_deref()).await.map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Replace one leg of this answered call with a freshly dialed target,
    /// with no REFER involved.
    ///
    /// The transfer siphon already runs for a REFER it terminates, reachable
    /// because *this app* decided: an IVR that has worked out where the caller
    /// should go, a controller handing a call from an AI to a human, a
    /// supervisor take-over. siphon dials `target` as a new leg on the same
    /// call, re-anchors the surviving party's media onto it, and once the
    /// target answers promotes it into the surviving pair and BYEs the leg it
    /// replaced.
    ///
    /// The replaced leg **stays up while the target rings**, so the surviving
    /// party hears ringback rather than silence, and a target that refuses or
    /// never answers leaves the call exactly as it was.
    ///
    /// `replace_a_leg` picks the direction: `False` (default) replaces the
    /// callee and keeps the caller, `True` does the reverse. `profile` names the
    /// media profile for the pair this creates — required when the call is
    /// anchored with a direction-bound one, whose answer half describes the
    /// party that is leaving. `timeout` bounds the ring in seconds (`0` = no
    /// ring policy, only siphon's guard against a target that answers nothing).
    ///
    /// Returns as soon as the INVITE is on the wire
    /// (`{"channel", "replacement": "dialing", "target"}`) and says nothing
    /// about the target. Wait for the `PeerReplaced` / `ReplaceFailed` event
    /// for the outcome — acting on the reply alone would tear down a call whose
    /// replacement is still ringing.
    ///
    /// Raises `ControlError` with `code == "not_found"` (no such call),
    /// `"invalid_state"` (not answered, no peer leg, or a replacement already
    /// in flight — all worth retrying later), or `"bad_request"` (the target
    /// will not parse or route).
    #[pyo3(signature = (target, next_hop=None, replace_a_leg=None, profile=None, timeout=None))]
    fn replace_peer<'py>(
        &self,
        py: Python<'py>,
        target: String,
        next_hop: Option<String>,
        replace_a_leg: Option<bool>,
        profile: Option<String>,
        timeout: Option<u32>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = call
                .replace_peer(
                    &target,
                    next_hop.as_deref(),
                    replace_a_leg,
                    profile.as_deref(),
                    timeout,
                )
                .await
                .map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Un-park this controlled call and dial the B-leg via siphon's LCR
    /// sequential-failover engine, returning control to siphon.
    ///
    /// `targets` is a non-empty list of carriers tried cheapest-first: each entry
    /// is a bare URI `str` or a dict `{"uri", "next_hop"?, "headers"?, "timeout"?}`.
    /// `strategy` defaults to `"sequential"` (v1 supports only sequential/single —
    /// anything else raises `ControlError` with `code == "unsupported_verb"`).
    /// `headers` is an optional dict applied to every attempt's B-leg INVITE.
    ///
    /// Returns the reply `result` (`{"channel", "state": "routing", "targets": N}`).
    /// An empty / invalid `targets` list raises `ControlError` (`code ==
    /// "bad_request"`); a call that is already gone raises `code == "not_found"`.
    #[pyo3(signature = (targets, strategy="sequential".to_string(), headers=None))]
    fn route<'py>(
        &self,
        py: Python<'py>,
        targets: Vec<Bound<'py, PyAny>>,
        strategy: String,
        headers: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut route_targets = Vec::with_capacity(targets.len());
        for item in targets {
            route_targets.push(extract_route_target(&item)?);
        }
        let extra_headers = match headers {
            Some(headers) => extract_headers(&headers)?,
            None => Vec::new(),
        };
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = call
                .route(route_targets, Some(strategy.as_str()), extra_headers)
                .await
                .map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    fn set_header<'py>(
        &self,
        py: Python<'py>,
        name: String,
        value: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.set_header(&name, &value).await.map_err(to_pyerr)
        })
    }

    fn get_header<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.get_header(&name).await.map_err(to_pyerr)
        })
    }

    /// Remove a header from the stored A-leg INVITE.
    fn remove_header<'py>(&self, py: Python<'py>, name: String) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.remove_header(&name).await.map_err(to_pyerr)
        })
    }

    fn set_var<'py>(
        &self,
        py: Python<'py>,
        key: String,
        value: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.set_var(&key, &value).await.map_err(to_pyerr)
        })
    }

    fn get_var<'py>(&self, py: Python<'py>, key: String) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.get_var(&key).await.map_err(to_pyerr)
        })
    }

    /// Play an announcement on the A-leg media (fire-and-forget). Pass exactly one
    /// of `file` (str), `db_id` (int), or `blob` (bytes, base64-encoded on the
    /// wire); the rest shape playback. A call with no anchored media session
    /// raises `ControlError` with `code == "not_found"`.
    #[pyo3(signature = (file=None, db_id=None, blob=None, repeat=None, start_ms=None, duration_ms=None, to_tag=None))]
    #[allow(clippy::too_many_arguments)]
    fn play<'py>(
        &self,
        py: Python<'py>,
        file: Option<String>,
        db_id: Option<u64>,
        blob: Option<Vec<u8>>,
        repeat: Option<u64>,
        start_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = build_play_source(file, db_id, blob)?;
        let options = PlayOptions {
            repeat,
            start_ms,
            duration_ms,
            to_tag,
        };
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.play(source, options).await.map_err(to_pyerr)
        })
    }

    /// Convenience for `play(file=...)` with default options.
    fn play_file<'py>(&self, py: Python<'py>, file: String) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.play_file(&file).await.map_err(to_pyerr)
        })
    }

    /// Stop the announcement currently playing on the A-leg media.
    fn stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.stop().await.map_err(to_pyerr)
        })
    }

    /// Inject DTMF digits toward the A-leg (fire-and-forget). The optional
    /// `duration_ms` / `volume_dbm0` / `pause_ms` / `to_tag` shape the tones.
    #[pyo3(signature = (digits, duration_ms=None, volume_dbm0=None, pause_ms=None, to_tag=None))]
    fn dtmf<'py>(
        &self,
        py: Python<'py>,
        digits: String,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = DtmfOptions {
            duration_ms,
            volume_dbm0,
            pause_ms,
            to_tag,
        };
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.dtmf(&digits, options).await.map_err(to_pyerr)
        })
    }

    /// Hold the A-leg media via silence.
    fn hold<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.hold().await.map_err(to_pyerr)
        })
    }

    /// Resume the A-leg media after a `hold`.
    fn unhold<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.unhold().await.map_err(to_pyerr)
        })
    }

    /// Attach a WebSocket audio tee streaming a copy of the call's audio to
    /// `ws_uri`. `direction` is `"both"` (default) / `"caller"` / `"callee"`;
    /// `channels` is `1` (mono) or `2` (stereo). siphon-rtp backend only:
    /// rtpengine / rtpproxy raise `ControlError` (`code == "unsupported_verb"`).
    #[pyo3(signature = (ws_uri, direction=None, channels=None))]
    fn stream_start<'py>(
        &self,
        py: Python<'py>,
        ws_uri: String,
        direction: Option<String>,
        channels: Option<u8>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.stream_start(&ws_uri, direction.as_deref(), channels)
                .await
                .map_err(to_pyerr)
        })
    }

    /// Detach the WebSocket audio tee (idempotent on siphon-rtp).
    fn stream_stop<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.stream_stop().await.map_err(to_pyerr)
        })
    }

    /// Send an arbitrary SIP verb + args, returning the reply `result` object.
    #[pyo3(signature = (verb, args=None))]
    fn command<'py>(
        &self,
        py: Python<'py>,
        verb: String,
        args: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        let args = optional_json(args)?;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let value = call.command(&verb, args).await.map_err(to_pyerr)?;
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Await the next event for this call — a dict `{kind, payload}` or `None`.
    fn next_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match call.next_event().await {
                Some(event) => attach_if_running(|py| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("kind", event.kind.as_str())?;
                    dict.set_item("payload", json_to_py(py, &event.payload)?)?;
                    Ok(dict.into_any().unbind())
                })
                .unwrap_or_else(|| Err(interpreter_gone())),
                None => attach_if_running(|py| py.None()).ok_or_else(interpreter_gone),
            }
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "Call(channel_id={:?}, sip_call_id={:?}, reattached={})",
            self.inner.channel_id(),
            self.inner.sip_call_id(),
            self.inner.is_reattached()
        )
    }
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
