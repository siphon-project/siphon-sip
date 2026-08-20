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
//!   await client.run()
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
//!   await server.serve()
//!   ```
//!
//! Both modes reuse the SAME `@on_call` decorator and the SAME [`Call`] handle;
//! only the transport differs (dial-out vs. be-dialed). The layering mirrors the
//! Rust crate: `ControlClient.command(...)` is the generic `{module, verb,
//! target, args}` primitive for any adapter, and the `on_call` decorator +
//! `Call` verbs are the SIP facade on top.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3_async_runtimes::TaskLocals;

use siphon_control_client::proto::ControlErrorCode;
use siphon_control_client::sip::{
    Call as RustCall, DtmfOptions, PlayOptions, PlaySource, RouteTarget, SipClient, SipServer,
};
use siphon_control_client::{ClientConfig, ControlError as ClientError, ServerConfig};

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
fn to_pyerr(error: ClientError) -> PyErr {
    let code = error.code().and_then(code_to_str);
    let message = error.to_string();
    Python::attach(|py| {
        let err = ControlError::new_err(message);
        let _ = err.value(py).setattr("code", code);
        err
    })
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
        None => return Err(PyValueError::new_err("route target dict requires a string 'uri'")),
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
            call.answer_with(code, reason.as_deref(), body.as_deref(), content_type.as_deref())
                .await
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
    #[pyo3(signature = (target=None, next_hop=None, mode=None))]
    fn accept_refer<'py>(
        &self,
        py: Python<'py>,
        target: Option<String>,
        next_hop: Option<String>,
        mode: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.accept_refer(target.as_deref(), next_hop.as_deref(), mode.as_deref())
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
            call.reject_refer(code, reason.as_deref()).await.map_err(to_pyerr)
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
            Python::attach(|py| json_to_py(py, &value))
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
            Python::attach(|py| json_to_py(py, &value))
        })
    }

    /// Await the next event for this call — a dict `{kind, payload}` or `None`.
    fn next_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            match call.next_event().await {
                Some(event) => Python::attach(|py| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("kind", event.kind.as_str())?;
                    dict.set_item("payload", json_to_py(py, &event.payload)?)?;
                    Ok(dict.into_any().unbind())
                }),
                None => Ok(Python::attach(|py| py.None())),
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
            Python::attach(|py| json_to_py(py, &value))
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
            Python::attach(|py| json_to_py(py, &value))
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
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Connect the underlying [`SipClient`] once, caching it.
async fn ensure_client(inner: &Arc<ClientInner>) -> PyResult<Arc<SipClient>> {
    let mut guard = inner.client.lock().await;
    if let Some(client) = guard.as_ref() {
        return Ok(Arc::clone(client));
    }
    let client = Arc::new(SipClient::connect(inner.config.clone()).await.map_err(to_pyerr)?);
    *guard = Some(Arc::clone(&client));
    Ok(client)
}

/// Bridge the Rust call handler to the stored Python coroutine function: for each
/// handed-over call, build a `Call` pyobject, invoke the handler, and drive the
/// returned coroutine on the asyncio loop captured in `locals`.
fn install_handler_bridge(client: &SipClient, handler: Py<PyAny>, locals: TaskLocals) {
    client.set_call_handler(move |call: RustCall| {
        let handler = Python::attach(|py| handler.clone_ref(py));
        let locals = locals.clone();
        async move {
            dispatch_to_python(handler, locals, call).await;
            Ok(())
        }
    });
}

async fn dispatch_to_python(handler: Py<PyAny>, locals: TaskLocals, call: RustCall) {
    let outcome = pyo3_async_runtimes::tokio::scope(locals, async move {
        let awaitable = Python::attach(|py| -> PyResult<Option<_>> {
            let py_call = Bound::new(py, Call { inner: call })?;
            let result = handler.bind(py).call1((py_call,))?;
            if result.hasattr("__await__")? {
                Ok(Some(pyo3_async_runtimes::tokio::into_future(result)?))
            } else {
                Ok(None)
            }
        });
        match awaitable {
            Ok(Some(future)) => future.await.map(|_| ()),
            Ok(None) => Ok(()),
            Err(error) => Err(error),
        }
    })
    .await;
    if let Err(error) = outcome {
        Python::attach(|py| error.print(py));
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
    fn new(app: String, token: String, bind: Option<String>, reply_timeout_ms: u64) -> PyResult<Self> {
        let bind = bind.unwrap_or_else(|| "0.0.0.0:8790".to_string());
        let listen: SocketAddr = bind
            .parse()
            .map_err(|error| PyValueError::new_err(format!("invalid bind address {bind:?}: {error}")))?;
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
    let server = Arc::new(SipServer::bind(inner.config.clone()).await.map_err(to_pyerr)?);
    let bound = server.local_addr().map_err(to_pyerr)?;
    *lock(&inner.local_addr) = Some(bound.to_string());
    *guard = Some(Arc::clone(&server));
    Ok(server)
}

/// Bridge the stored Python handler to the SIP server, reusing the same
/// per-call dispatch as the inbound client (identical `Call` + coroutine drive).
fn install_server_handler_bridge(server: &SipServer, handler: Py<PyAny>, locals: TaskLocals) {
    server.set_call_handler(move |call: RustCall| {
        let handler = Python::attach(|py| handler.clone_ref(py));
        let locals = locals.clone();
        async move {
            dispatch_to_python(handler, locals, call).await;
            Ok(())
        }
    });
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
    module.add(
        "__all__",
        PyList::new(
            module.py(),
            ["ControlClient", "ControlServer", "Call", "ControlError"],
        )?,
    )?;
    Ok(())
}
