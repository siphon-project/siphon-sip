//! PyO3 `b2bua` control namespace — imperative B2BUA call operations that act
//! immediately rather than via a deferred [`CallAction`](super::call::CallAction).
//!
//! Injected as `siphon.b2bua._control` at startup; the pure-Python
//! `_B2buaNamespace` forwards `b2bua.terminate(...)` to it. Stateless — it
//! reaches the running dispatcher through a process-global handle, so it works
//! from any context (event callbacks like `@rtpengine.on_dtmf`, timers, async
//! handlers) where the deferred `call.terminate()` is a silent no-op.

use pyo3::prelude::*;

/// Stateless imperative B2BUA control namespace (`siphon.b2bua._control`).
#[pyclass(name = "B2buaControl")]
pub struct PyB2buaControl;

impl Default for PyB2buaControl {
    fn default() -> Self {
        Self::new()
    }
}

impl PyB2buaControl {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyB2buaControl {
    /// Imperatively end a B2BUA call by its SIP Call-ID, sending an in-dialog
    /// BYE to every leg **now** (not deferred until a handler returns, the way
    /// `call.terminate()` is).
    ///
    /// Keyed by SIP Call-ID and backed by shared Rust dialog state, so it is
    /// cross-worker safe and works from an event callback (`@rtpengine.on_dtmf`,
    /// `@rtpengine.on_media_timeout`), a timer, or a normal handler — none of
    /// which give `call.terminate()` a handler-return to act on.
    ///
    /// Returns True if a matching call was found and torn down, False if the
    /// Call-ID is unknown / already gone (e.g. the caller hung up first) — never
    /// raises, so racing a caller-initiated BYE is a clean no-op.
    #[pyo3(signature = (call_id, reason="Normal Clearing"))]
    fn terminate(&self, call_id: &str, reason: &str) -> bool {
        crate::dispatcher::b2bua_terminate_call(call_id, Some(reason))
    }

    /// Imperatively send an outbound REFER on a live B2BUA call by SIP Call-ID.
    ///
    /// Refers the A-leg (the caller / IVR-connected party) to `target`.
    /// `replaces` is an attended-transfer Replaces dict (keys `call_id` /
    /// `from_tag` / `to_tag`, optional `early_only`) or `None` for a blind
    /// transfer. Works from any context — including event callbacks like
    /// `@rtpengine.on_dtmf` and timers — where the deferred `call.refer()` is a
    /// silent no-op (no handler-return to act on). Returns True if the call was
    /// found and the REFER emitted, False if the Call-ID is unknown / already
    /// gone. Never raises (except on a malformed `replaces` dict).
    /// Place an outbound call siphon owns, with no inbound INVITE behind it —
    /// the primitive under click-to-dial, callbacks and outbound notification.
    ///
    /// Returns immediately with the new leg's **SIP Call-ID** as soon as the
    /// INVITE is on the wire; it does *not* wait for the callee. Ringing and
    /// answer arrive later through the ordinary handlers — `@b2bua.on_answer`
    /// fires with `(call, reply)` when the callee answers, `@b2bua.on_failure`
    /// with `(call, code, reason)` when it rejects, and `@b2bua.on_bye` when
    /// either side hangs up. Feed the returned Call-ID to `b2bua.terminate()` /
    /// `b2bua.refer()` to drive the leg from anywhere.
    ///
    /// Exactly one media plan is required, because an INVITE with no offer and
    /// no way to answer the callee's leaves a connected call with no audio:
    ///   * `sdp="v=0..."` — your own offer, carried verbatim; or
    ///   * `media=True` — siphon anchors the leg on the configured media
    ///     backend (siphon-rtp), so `rtpengine.play_media()`, DTMF and the
    ///     WebSocket tee all work against it.
    ///
    /// ```python
    /// call_id = b2bua.originate(
    ///     to="sip:+14035551212@carrier.example",
    ///     from_uri="sip:+14035550100@siphon.example",
    ///     from_display="Reminders",
    ///     media=True,
    ///     headers={"X-Campaign": "reminder"},
    ///     timeout=30,
    /// )
    /// ```
    ///
    /// Raises `ValueError` when the target/identity URIs do not parse, no route
    /// exists, the media plan is not one the configured backend can serve, or
    /// the B2BUA is not running — never a silent `None` for a call that was
    /// never placed.
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (
        to,
        from_uri=None,
        from_display=None,
        to_display=None,
        next_hop=None,
        p_asserted_identity=None,
        privacy=None,
        headers=None,
        sdp=None,
        media=false,
        profile=None,
        ws_uri=None,
        timeout=30,
    ))]
    fn originate(
        &self,
        to: &str,
        from_uri: Option<&str>,
        from_display: Option<&str>,
        to_display: Option<&str>,
        next_hop: Option<&str>,
        p_asserted_identity: Option<&str>,
        privacy: Option<&str>,
        headers: Option<&Bound<'_, pyo3::types::PyDict>>,
        sdp: Option<&str>,
        media: bool,
        profile: Option<&str>,
        ws_uri: Option<&str>,
        timeout: u32,
    ) -> PyResult<String> {
        use pyo3::exceptions::PyValueError;

        let media_plan = match (sdp, media) {
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate takes either sdp= (your own offer) or media=True (siphon anchors the leg), not both",
                ));
            }
            (Some(sdp), false) if sdp.trim().is_empty() => {
                return Err(PyValueError::new_err(
                    "b2bua.originate sdp= must not be empty",
                ));
            }
            (Some(sdp), false) => crate::dispatcher::OriginateMedia::Offer(sdp.to_string()),
            (None, true) => crate::dispatcher::OriginateMedia::Anchor {
                profile: profile.unwrap_or("rtp_passthrough").to_string(),
                ws_uri: ws_uri.map(str::to_string),
            },
            (None, false) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate needs a media plan: sdp= (your own offer) or media=True (siphon anchors the leg)",
                ));
            }
        };

        let privacy = match privacy {
            None => None,
            Some(value) => Some(
                crate::sip::privacy::CallerIdPresentation::parse(value).ok_or_else(|| {
                    PyValueError::new_err(format!(
                        "b2bua.originate privacy= must be \"allowed\" or \"restricted\", got '{value}'"
                    ))
                })?,
            ),
        };

        let mut extra_headers = Vec::new();
        if let Some(headers) = headers {
            for (key, value) in headers.iter() {
                extra_headers.push((key.to_string(), value.to_string()));
            }
        }

        let params = crate::dispatcher::OriginateParams {
            to: to.to_string(),
            to_display: to_display.map(str::to_string),
            from: from_uri.map(str::to_string),
            from_display: from_display.map(str::to_string),
            next_hop: next_hop.map(str::to_string),
            p_asserted_identity: p_asserted_identity.map(str::to_string),
            privacy,
            headers: extra_headers,
            timeout_secs: timeout,
            media: media_plan,
        };
        crate::dispatcher::b2bua_originate(params)
            .map(|placed| placed.sip_call_id)
            .map_err(|error| PyValueError::new_err(error.to_string()))
    }

    /// Join two answered calls this process owns, so the two parties hear each
    /// other — the primitive under callback-and-connect and attended hand-off.
    ///
    /// `call_id` is the leg that keeps its media anchor (its ports, and anything
    /// attached to them); `with_call_id` is the leg joined to it. Both are SIP
    /// Call-IDs, so this works from an event callback or a timer where no `Call`
    /// object exists.
    ///
    /// Awaitable. It resolves once the media has been re-pointed and the first
    /// re-INVITE is on the wire — the same "the local action was performed"
    /// contract `originate` has. A bridge is two RFC 3261 §14 re-INVITEs across
    /// two dialogs, and whether the far ends accept them is a far-end outcome;
    /// on the control rail that arrives as `ChannelBridged` / `BridgeFailed`.
    ///
    /// `on_peer_hangup` decides what happens to the survivor when one party
    /// leaves: `"hangup"` (default) tears it down too, `"hold"` keeps it up and
    /// held so it can be bridged to somebody else.
    ///
    /// Raises `ValueError` — never a hollow success — when a leg is unknown, has
    /// not answered, is already bridged, has a re-INVITE outstanding, or the
    /// media backend cannot express the bridge. The message is prefixed with the
    /// stable cause token (`not_found`, `invalid_state`, `bad_request`,
    /// `unsupported_verb`, `unavailable`).
    #[pyo3(signature = (call_id, with_call_id, on_peer_hangup="hangup"))]
    fn bridge<'py>(
        &self,
        python: Python<'py>,
        call_id: &str,
        with_call_id: &str,
        on_peer_hangup: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        use pyo3::exceptions::PyValueError;
        let Some(policy) = crate::b2bua::bridge::PeerHangupPolicy::parse(on_peer_hangup) else {
            return Err(PyValueError::new_err(format!(
                "b2bua.bridge(on_peer_hangup=…) must be 'hangup' or 'hold' (got '{on_peer_hangup}')"
            )));
        };
        let params = crate::dispatcher::BridgeParams {
            anchor_sip_call_id: call_id.to_string(),
            peer_sip_call_id: with_call_id.to_string(),
            on_peer_hangup: policy,
        };
        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            crate::dispatcher::b2bua_bridge_calls(params)
                .await
                .map(|_| true)
                .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
        })
    }

    /// Break a bridge. Both legs stay answered, owned and held (RFC 3264 §8.4),
    /// so either can be bridged again or ended — an unbridge that hung both up
    /// would be indistinguishable from two `terminate` calls.
    ///
    /// Awaitable. Raises `ValueError` when the leg is unknown, is not bridged,
    /// or its bridge is still forming; the message carries the same stable cause
    /// token as `bridge`.
    #[pyo3(signature = (call_id, reason="unbridged"))]
    fn unbridge<'py>(
        &self,
        python: Python<'py>,
        call_id: &str,
        reason: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        use pyo3::exceptions::PyValueError;
        let call_id = call_id.to_string();
        let reason = reason.to_string();
        pyo3_async_runtimes::tokio::future_into_py(python, async move {
            crate::dispatcher::b2bua_unbridge_call(&call_id, &reason)
                .await
                .map(|_| true)
                .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
        })
    }

    #[pyo3(signature = (call_id, target, replaces=None))]
    fn refer(
        &self,
        call_id: &str,
        target: &str,
        replaces: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<bool> {
        let replaces = crate::script::api::call::parse_replaces_dict(replaces)?;
        let refer_to = crate::sip::headers::refer::ReferTo {
            uri: target.to_string(),
            replaces,
        };
        Ok(crate::dispatcher::b2bua_refer_call(call_id, refer_to))
    }
}
