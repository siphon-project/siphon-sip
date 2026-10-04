//! The `Call` pyclass — the per-call verb surface, shared by both connection
//! modes (`ControlClient` and `ControlServer` hand out the same handle).
//!
//! Split from [`lib`](crate) because pyo3 accepts a single `#[pymethods]` block
//! per class without the `multiple-pymethods` feature, so this surface grows in
//! one place, and that place had reached the repository's per-file budget.

use pyo3::prelude::*;

use siphon_control_client::sip::{
    Call as RustCall, DialOptions, Dialing, DtmfOptions, PlayOptions, RecordOptions, Ringback,
    StreamOptions,
};

use crate::args::{
    build_play_source, extract_dial_on_answer, extract_dial_strategy, extract_dial_targets,
    extract_headers, extract_play_repeat, extract_privacy, extract_record_channels,
    extract_record_direction, extract_route_target, extract_stream_channels,
    extract_stream_direction, extract_stream_mode, parse_peer_hangup,
};
use crate::{attach_if_running, interpreter_gone, json_to_py, optional_json, to_pyerr};

/// The dict `dial` resolves to. The bridge fields are added only for a bridge
/// dial, so a connecting dial's dict keeps the four keys it always had.
fn dialing_to_json(dialing: &Dialing) -> serde_json::Value {
    let mut value = serde_json::json!({
        "channel": dialing.channel,
        "targets": dialing.targets,
        "strategy": dialing.strategy,
        "timeout": dialing.timeout_secs,
    });
    if let (Some(on_answer), Some(fields)) = (&dialing.on_answer, value.as_object_mut()) {
        fields.insert("on_answer".into(), serde_json::json!(on_answer));
        fields.insert("group_id".into(), serde_json::json!(dialing.group_id));
        fields.insert(
            "total_timeout".into(),
            serde_json::json!(dialing.total_timeout_secs),
        );
        let ringback = match &dialing.ringback {
            Some(Ringback::Default) => serde_json::json!(true),
            Some(Ringback::Silent) => serde_json::json!(false),
            Some(Ringback::Tone(tone)) => serde_json::json!(tone),
            None => serde_json::Value::Null,
        };
        fields.insert("ringback".into(), ringback);
        fields.insert("branches".into(), serde_json::json!(dialing.branches));
    }
    value
}

/// A handed-over SIP call. Async methods return awaitables.
#[pyclass(module = "siphon_control", name = "Call")]
pub(crate) struct Call {
    pub(crate) inner: RustCall,
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
    /// templating. ``{call_id}`` is the call's SIP Call-ID (``sip_call_id``),
    /// not the control-plane ``call_id``.
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

    /// Abandon this **un-answered** call with nothing on the wire — no final
    /// response, no CANCEL — and release it.
    ///
    /// The third way out of a parked call, and the only silent one. `reject` and
    /// an un-answered `hangup` both answer, and on a SIP port reachable from the
    /// internet that answer is the prize: a `404` to an INVITE for a number
    /// nobody claims confirms the number to an enumeration sweep, where silence
    /// leaves it unable to tell a missing extension from a filtered one.
    ///
    /// Not a way to hang up: an answered dialog is owed a BYE (RFC 3261 §15), so
    /// an answered call raises `ControlError` with `code == "invalid_state"` —
    /// use `hangup` there. A call that has already ended is `"not_found"`.
    ///
    /// `reason` is for the record, not the wire: it reaches siphon's log and the
    /// CDR (`sip_reason`, beside `disconnect_initiator: "control"` and no
    /// response code).
    ///
    /// ``ban=True`` also scores the caller's source address toward an auto-ban
    /// in siphon's ``security.failed_auth_ban`` store, so a source the
    /// controller keeps dropping is refused at the transport before its next
    /// INVITE is parsed. One drop is a strong signal over TCP, TLS, WS or WSS,
    /// whose handshake proved the address, and counts once over UDP, where a
    /// datagram can name any address. A no-op without ``failed_auth_ban``;
    /// ``trusted_cidrs`` are never scored; a refused drop scores nothing.
    #[pyo3(signature = (reason=None, *, ban=false))]
    fn drop<'py>(
        &self,
        py: Python<'py>,
        reason: Option<String>,
        ban: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if ban {
                call.drop_and_ban(reason.as_deref()).await
            } else {
                call.drop(reason.as_deref()).await
            }
            .map_err(to_pyerr)
        })
    }

    /// Give up on the dial ringing for this call and leave the caller alone.
    ///
    /// Every phone still ringing is CANCELled, each reported by
    /// ``DialBranchFailed`` with cause ``cancelled``, and the dial ends in
    /// ``DialFailed`` with code 487. The caller is exactly as the dial found
    /// it, still this app's, and free to be dialled for again. ``hangup`` ends
    /// the caller as well.
    ///
    /// ``reason`` is reported as the ``cause`` of a bridging dial's
    /// ``DialFailed`` (default ``cancelled``). Raises ``ControlError``
    /// (``invalid_state``) when nothing is ringing, and once a phone has
    /// answered and is being bridged.
    #[pyo3(signature = (reason=None))]
    fn cancel_dial<'py>(
        &self,
        py: Python<'py>,
        reason: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.cancel_dial(reason.as_deref()).await.map_err(to_pyerr)
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
    /// is a bare URI `str` or a dict
    /// `{"uri", "next_hop"?, "headers"?, "timeout"?, "reroute_after_progress"?}`.
    /// A target's `timeout` bounds the wait for it to show progress (a 101-199);
    /// one that has keeps the call past it, and the call then fails with 408,
    /// unless it sets `"reroute_after_progress": True`. That flag must be a
    /// `bool` (anything else raises `TypeError`) and is sent only when true.
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
    ///
    /// `repeat` is a total play count, or `"inf"` to play until stopped (music
    /// on hold; `stop` ends it). Any other value raises `ValueError`.
    #[pyo3(signature = (file=None, db_id=None, blob=None, repeat=None, start_ms=None, duration_ms=None, to_tag=None))]
    #[allow(clippy::too_many_arguments)]
    fn play<'py>(
        &self,
        py: Python<'py>,
        file: Option<String>,
        db_id: Option<u64>,
        blob: Option<Vec<u8>>,
        repeat: Option<Bound<'py, PyAny>>,
        start_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let source = build_play_source(file, db_id, blob)?;
        let options = PlayOptions {
            repeat: extract_play_repeat(repeat.as_ref())?,
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

    /// Silence the call's media in both directions on the media engine.
    ///
    /// A media gate, not a SIP hold: nothing is sent on either dialog, so no
    /// phone shows a held call. Raises ``ControlError`` (``invalid_state``) on
    /// a call the engine only relays; to hold one party of a bridge, use
    /// ``unbridge``.
    fn hold<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.hold().await.map_err(to_pyerr)
        })
    }

    /// Restore the call's media after a `hold`.
    fn unhold<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.unhold().await.map_err(to_pyerr)
        })
    }

    /// Attach a WebSocket audio stream to ``ws_uri``.
    ///
    /// ``mode`` picks one of two opposite operations:
    ///
    /// - ``"tee"`` (default) is additive: a copy of the call's decoded audio
    ///   streams to ``ws_uri`` while the call keeps relaying. Use it for
    ///   transcription, agent assist and compliance.
    /// - ``"bridge"`` is a takeover: the WebSocket server becomes the leg's far
    ///   side and the call's own media path is unwired. On a leg that already
    ///   has a bridge it re-points in place.
    ///
    /// ``mode`` always goes on the wire, ``"tee"`` included, so a server whose
    /// default moved can never turn a transcription into a takeover.
    ///
    /// The rest shape a **tee** only (the server refuses them alongside
    /// ``mode="bridge"``): ``direction`` is ``"both"`` (default) / ``"caller"`` /
    /// ``"callee"``; ``channels`` is ``1`` (mixed mono) or ``2`` (caller/callee
    /// stereo, only with ``"both"``); ``sample_rate`` is the L16 rate in Hz, a
    /// multiple of 1000 within 8000-48000. A bad ``mode`` / ``direction`` /
    /// ``channels`` raises ``ValueError`` before anything is sent.
    ///
    /// ``profile`` shapes a **bridge** only (refused on a tee): the name of a
    /// media profile on the server whose bridge settings (wire rate, noise
    /// suppression, echo cancellation, VAD, barge-in) the bridge runs with, as
    /// an ``answer`` with ``ws_uri`` would. Without it the bridge runs at the
    /// leg's own rate with uplink processing off.
    ///
    /// ``ws_uri`` may use ``{call_id}`` / ``{from_tag}`` / ``{from_user}`` /
    /// ``{to_user}``, which siphon expands before the engine sees it:
    /// ``{call_id}`` expands to the call's SIP Call-ID (``call.sip_call_id``),
    /// not the control-plane ``call_id``. siphon-rtp backend only: rtpengine /
    /// rtpproxy raise ``ControlError`` (``code == "unsupported_verb"``).
    ///
    /// .. code-block:: python
    ///
    ///     await call.stream_start("wss://ai.example/stream/{call_id}",
    ///                             direction="caller", sample_rate=16000)
    ///     await call.stream_start("wss://ai.example/agent", mode="bridge",
    ///                             profile="voice_ai")
    #[pyo3(signature = (ws_uri, direction=None, channels=None, *, mode="tee", sample_rate=None, profile=None))]
    #[allow(clippy::too_many_arguments)]
    fn stream_start<'py>(
        &self,
        py: Python<'py>,
        ws_uri: String,
        direction: Option<String>,
        channels: Option<u8>,
        mode: &str,
        sample_rate: Option<u32>,
        profile: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = StreamOptions {
            mode: extract_stream_mode(mode)?,
            direction: extract_stream_direction(direction)?,
            channels: extract_stream_channels(channels)?,
            sample_rate,
            profile,
        };
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.stream_start_with(&ws_uri, options)
                .await
                .map_err(to_pyerr)
        })
    }

    /// Detach the WebSocket stream of ``mode`` (``"tee"`` by default, sent
    /// explicitly).
    ///
    /// A tee detach is idempotent. A bridge detach is not: the engine refuses
    /// one where there is no relay to hand the call back to, and that raises
    /// ``ControlError`` rather than leaving a live call with no audio path.
    #[pyo3(signature = (*, mode="tee"))]
    fn stream_stop<'py>(&self, py: Python<'py>, mode: &str) -> PyResult<Bound<'py, PyAny>> {
        let mode = extract_stream_mode(mode)?;
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.stream_stop_with(mode).await.map_err(to_pyerr)
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

    /// Ring one or more targets as B-legs while the caller stays **unanswered**
    /// and this application keeps the channel.
    ///
    /// The difference from ``route()`` is who holds the call afterwards.
    /// ``route()`` hands it back to siphon, so the app gets
    /// ``StasisEnd{reason: routed}`` and loses it; there is then no way to say
    /// "ring the extension, and if nobody answers, voicemail" without answering
    /// the caller first — which starts billing before anyone picks up, records
    /// an unanswered call as answered, and denies the caller the callee's own
    /// ringback.
    ///
    /// The first 2xx answers the caller with the winner's SDP and the pair
    /// becomes an ordinary two-leg call, still owned by this app. A failure or a
    /// timeout arrives as a ``DialFailed`` event with the caller still ringing
    /// and still parked, so the app decides what happens next.
    ///
    /// Every branch is named on the event stream: ``DialBranch`` when it is
    /// created, then ``DialBranchFailed`` (with ``code``, ``reason`` and a
    /// ``cause`` of ``rejected`` / ``timeout`` / ``cancelled`` / ``unsent``) or
    /// ``DialAnswered``. Each carries ``leg_id`` and ``leg_sip_call_id``, the
    /// Call-ID the branch's INVITE went out with, and ``DialFailed`` lists every
    /// branch under ``branches``.
    ///
    /// Each target is a dict: ``{"uri": ..., "next_hop": ..., "headers": {...}}``
    /// is dialed as written and resolved by DNS, while
    /// ``{"aor": ..., "headers": {...}}`` is forked to **every** contact
    /// registered against it, each branch over that contact's own captured flow
    /// — the only way to reach a phone registered over TCP, TLS or WSS behind
    /// NAT. A bare string raises ``ValueError``: it does not say which was
    /// meant, and the wrong one places a call that connects to nothing while the
    /// trace looks healthy.
    ///
    /// Either form may carry ``"to"``, the branch's called party: its ``To``
    /// URI. The target's URI is the Request-URI, and without ``to`` the B-leg's
    /// ``To`` keeps the caller's user at the target's host, which is right for a
    /// forward and wrong for a divert: a next hop that routes on ``To`` serves
    /// the call as one to the original number and can send it straight back.
    /// siphon keeps it as the leg's dialog ``To``, so a ``headers`` override is
    /// no substitute.
    ///
    /// ``strategy`` is ``"parallel"`` or ``"sequential"`` and ``timeout`` is the
    /// ring timeout in seconds; each left out takes the server's own default
    /// (parallel, 30 s). ``headers`` is applied to every branch's INVITE.
    ///
    /// ``profile`` names a configured media profile and anchors both legs
    /// through it, so the caller and the phones never exchange media directly —
    /// what a carrier-delivered call to a ring group needs, since the carrier
    /// hands over plain RTP at a routable address and every phone answers from
    /// an address on its own LAN.
    ///
    /// ``from`` / ``from_display`` / ``p_asserted_identity`` / ``privacy``
    /// present a calling identity of the app's choosing. Without them a B-leg
    /// presents the caller's own ``From``, which on a call out to a trunk is the
    /// internal extension: a carrier that looks its account up by the ``From``
    /// user does not recognise it, challenges the INVITE, and keeps challenging
    /// however correct the digest is. A ``headers`` entry cannot do this —
    /// ``From`` is framework-managed on a B-leg and is rewritten after the fact.
    /// ``privacy="restricted"`` anonymises ``From`` and asserts ``Privacy: id``
    /// while ``p_asserted_identity`` keeps the real identity for the trusted
    /// next hop (RFC 3323 §4.1 / RFC 3325 §9.1 / TS 24.607).
    ///
    /// ``on_answer="bridge"`` rings phones for a caller the app already
    /// **answered** and anchored on the media engine (``answer_anchored()``),
    /// which is what lets it play a greeting and a menu first, and bridges the
    /// first phone to pick up to it. Each phone is a call siphon places itself,
    /// and none of the caller's INVITE headers reach it. ``ringback`` is what
    /// the caller hears while phones alert: a tone preset or cadence
    /// (``"ringback_eu"``, ``"425/1000,0/4000*inf"``), ``True`` for the default
    /// or ``False`` for none; left out, the server plays ``ringback_eu``. It
    /// raises ``ValueError`` without ``on_answer="bridge"``. An answer is kept
    /// only once its phone is bridged: a phone whose bridge fails is hung up
    /// (``DialBranchFailed`` cause ``bridge_failed``) and the dial goes on.
    /// ``DialAnswered`` names the bridged phone and a ``channel`` siphon minted
    /// for it; ``DialFailed`` carries a ``cause`` and leaves the caller answered
    /// and owned.
    ///
    /// Returns ``{"channel", "targets", "strategy", "timeout"}``, where
    /// ``targets`` counts the **branches** the server resolved — one AoR
    /// registered on three devices reports three. A bridge dial adds
    /// ``"on_answer"``, ``"group_id"``, ``"total_timeout"``, ``"ringback"`` and
    /// ``"branches"`` (one dict per phone, as its ``DialBranch`` event names
    /// it). Raises ``ControlError`` with ``code == "not_found"`` (the call is
    /// gone, or no target yielded a branch), ``"invalid_state"`` (already
    /// answered; for a bridge, ``details["reason"]`` says ``not_answered``,
    /// ``not_anchored``, ``already_bridged`` or ``dial_in_progress``),
    /// ``"bad_request"`` or ``"unsupported_verb"``.
    #[pyo3(signature = (
        targets,
        strategy=None,
        timeout=None,
        headers=None,
        profile=None,
        from_uri=None,
        from_display=None,
        p_asserted_identity=None,
        privacy=None,
        on_answer=None,
        ringback=None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn dial<'py>(
        &self,
        py: Python<'py>,
        targets: Vec<Bound<'py, PyAny>>,
        strategy: Option<String>,
        timeout: Option<u32>,
        headers: Option<Bound<'py, PyAny>>,
        profile: Option<String>,
        // `from` is a Python keyword, so the identity argument cannot be spelled
        // the way the wire spells it. Named for what it is instead of mangled.
        from_uri: Option<String>,
        from_display: Option<String>,
        p_asserted_identity: Option<String>,
        privacy: Option<String>,
        on_answer: Option<String>,
        ringback: Option<Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = DialOptions {
            strategy: extract_dial_strategy(strategy)?,
            timeout_secs: timeout,
            headers: headers
                .map(|headers| extract_headers(&headers))
                .transpose()?
                .unwrap_or_default(),
            profile,
            from: from_uri,
            from_display,
            p_asserted_identity,
            privacy: extract_privacy("dial", privacy)?,
            on_answer: extract_dial_on_answer(on_answer, ringback)?,
        };
        let dial_targets = extract_dial_targets(&targets)?;
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let dialing = call.dial(dial_targets, options).await.map_err(to_pyerr)?;
            let value = dialing_to_json(&dialing);
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Record this call's decoded audio to a wav file.
    ///
    /// Returns ``{"channel", "recording_id"}``. The ``recording_id`` is what a
    /// later ``record_stop()`` addresses and what the ``RecordingFinished``
    /// event carries. The reply is **not** the file: ``RecordingFinished`` fires
    /// when the file is *closed* and names its path, which is what an app that
    /// mails the audio has to wait for — acting on this reply races a
    /// half-written file.
    ///
    /// ``direction`` is ``"ingress"`` (the default: what the parties *sent*,
    /// which is what a recorded message is), ``"egress"`` or ``"both"``;
    /// ``channels`` is ``"mono"`` (default) or ``"stereo"``.
    /// ``max_duration_ms`` and ``silence_ms`` are the two stop conditions a
    /// voicemail greeting announces, and the engine evaluates both where the
    /// decoded audio already is. Each left out takes the server's own default.
    ///
    /// Not ``li.record()`` / SIPREC, which hands a recording *server* its own
    /// leg: this writes a file and works on a single-leg, engine-terminated
    /// call, which is what a voicemail box is. siphon-rtp backend only —
    /// rtpengine / rtpproxy raise ``ControlError`` with
    /// ``code == "unsupported_verb"``, and a call with no anchored media session
    /// raises ``"not_found"``.
    #[pyo3(signature = (direction=None, channels=None, max_duration_ms=None, silence_ms=None, path=None))]
    fn record_start<'py>(
        &self,
        py: Python<'py>,
        direction: Option<String>,
        channels: Option<String>,
        max_duration_ms: Option<u64>,
        silence_ms: Option<u64>,
        path: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let options = RecordOptions {
            direction: extract_record_direction(direction)?,
            channels: extract_record_channels(channels)?,
            max_duration_ms,
            silence_ms,
            path,
        };
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let recording = call.record_start(options).await.map_err(to_pyerr)?;
            let value = serde_json::json!({
                "channel": recording.channel,
                "recording_id": recording.recording_id,
            });
            attach_if_running(|py| json_to_py(py, &value))
                .unwrap_or_else(|| Err(interpreter_gone()))
        })
    }

    /// Stop the recording named by ``recording_id``, or **every** recording on
    /// this call when it is left out.
    ///
    /// Resolves once the engine has accepted the stop; the file is not closed
    /// yet. ``RecordingFinished`` says that, and carries the path and the reason
    /// (``stopped``, ``max_duration``, ``silence``, ``call_ended``, ``error``).
    #[pyo3(signature = (recording_id=None))]
    fn record_stop<'py>(
        &self,
        py: Python<'py>,
        recording_id: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let call = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            call.record_stop(recording_id.as_deref())
                .await
                .map_err(to_pyerr)
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
