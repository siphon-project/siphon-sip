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
    ///   * `sdp="v=0..."` — your own offer, carried verbatim as
    ///     `application/sdp`; or
    ///   * `body=…, content_type=…` — the same slot with the type spelled out,
    ///     for an INVITE whose offer travels as one part of a `multipart/*`
    ///     body (RFC 5621 §3) beside a part SIP does not interpret: ISUP on a
    ///     SIP-I trunk, a PIDF-LO location object, an operator-specific
    ///     document. You assemble the multipart, siphon carries it verbatim and
    ///     derives Content-Length from it. `body=` takes `str` or `bytes`, and
    ///     `content_type=` defaults to `application/sdp` (so `body=` alone is
    ///     `sdp=`); or
    ///   * `media=True` — siphon anchors the leg on the configured media
    ///     backend (siphon-rtp), so `rtpengine.play_media()`, DTMF and the
    ///     WebSocket tee all work against it.
    ///
    /// Whichever spelling, the body has to carry an SDP offer — bare
    /// `application/sdp`, or a `multipart/*` with an `application/sdp` part in
    /// it. One that carries none raises, because a callee that reads the INVITE
    /// as offerless offers in its own 2xx and this plan has nothing to answer
    /// that with (RFC 3261 §13.2.2.4).
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
    /// `session_timer={"expires": 1800, "min_se": 90, "refresher": "b2bua"}` runs
    /// an RFC 4028 session timer on the call over the `session_timer:` block,
    /// each key left out defaulting as in `call.session_timer()`. The INVITE asks
    /// for it and the callee's 2xx says who refreshes.
    ///
    /// `route=["<sip:orig@scscf.example.com;lr>"]` pre-loads a route set (RFC 3261
    /// §8.1.2): the entries go out as the INVITE's Route headers, in order, and
    /// its CANCEL and the ACK of a failure carry them too. With no `next_hop`
    /// the INVITE goes to the topmost entry. An application server originating
    /// a request on a user's or a service identity's behalf hands it to its
    /// S-CSCF this way, the session case in the Route entry (TS 24.229 §5.7.3);
    /// `next_hop` alone only says where the packet goes. Route is not accepted
    /// in `headers`.
    ///
    /// Raises `ValueError` when the target/identity URIs do not parse, no route
    /// exists, the media plan is not one the configured backend can serve, the
    /// body carries no offer, `session_timer` names an unknown key or refresher,
    /// or the B2BUA is not running — never a silent `None` for a call that was
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
        body=None,
        content_type=None,
        session_timer=None,
        route=Vec::new(),
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
        body: Option<&Bound<'_, pyo3::types::PyAny>>,
        content_type: Option<&str>,
        session_timer: Option<&Bound<'_, pyo3::types::PyDict>>,
        route: Vec<String>,
    ) -> PyResult<String> {
        use pyo3::exceptions::PyValueError;

        let session_timer = session_timer.map(session_timer_from_dict).transpose()?;
        let route = super::route_entries::route_set_from(&route)?;

        // `sdp=` and `body=` are one slot with two spellings — `sdp=` is the
        // body carried as application/sdp, `body=` is the body with its type
        // named — so supplying both leaves it ambiguous what goes on the wire.
        let supplied_offer = match (sdp, body) {
            (Some(_), Some(_)) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate takes either sdp= (an SDP offer) or body= (a body with its own content_type=), not both",
                ));
            }
            (Some(_), None) if content_type.is_some() => {
                return Err(PyValueError::new_err(
                    "b2bua.originate content_type= goes with body= — sdp= is application/sdp by definition",
                ));
            }
            (Some(sdp), None) => Some((sdp.as_bytes().to_vec(), "application/sdp".to_string())),
            (None, Some(body)) => Some((
                super::request::extract_body_bytes(body)?,
                content_type.unwrap_or("application/sdp").to_string(),
            )),
            (None, None) => None,
        };

        let media_plan = match (supplied_offer, media) {
            (Some(_), true) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate takes either your own offer (sdp= / body=) or media=True (siphon anchors the leg), not both",
                ));
            }
            (Some((body, _)), false) if body.iter().all(u8::is_ascii_whitespace) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate sdp= / body= must not be empty",
                ));
            }
            (Some((body, content_type)), false) => {
                crate::dispatcher::OriginateMedia::Offer { body, content_type }
            }
            (None, true) if content_type.is_some() => {
                return Err(PyValueError::new_err(
                    "b2bua.originate content_type= needs body= — media=True sends an offerless INVITE",
                ));
            }
            (None, true) => crate::dispatcher::OriginateMedia::Anchor {
                profile: profile.unwrap_or("rtp_passthrough").to_string(),
                ws_uri: ws_uri.map(str::to_string),
            },
            (None, false) => {
                return Err(PyValueError::new_err(
                    "b2bua.originate needs a media plan: sdp= / body= (your own offer) or media=True (siphon anchors the leg)",
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
            session_timer,
        };
        let placed = if route.is_empty() {
            crate::dispatcher::b2bua_originate(params)
        } else {
            crate::dispatcher::b2bua_originate_with_route(params, route)
        };
        placed
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
        crate::script::awaitable(python, async move {
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
        crate::script::awaitable(python, async move {
            crate::dispatcher::b2bua_unbridge_call(&call_id, &reason)
                .await
                .map(|_| true)
                .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
        })
    }

    /// Merge the call a REFER's `Replaces` names into a conference room on this
    /// node (RFC 4579 §5.5): seat its other leg in `conference_id` in place
    /// (siphon-rtp `conference_seat`, no SIP to that party) and BYE the named
    /// leg with `Reason: SIP;cause=200;text="Merged into conference"`.
    ///
    /// Awaitable; resolves to the status for `b2bua.complete_refer`: `200`,
    /// `481` (no confirmed dialog here matches, or no `Replaces`), `403` (the
    /// dialog is not the referrer's), `488` (the engine or the call's state
    /// refused the seat) or `501` (the backend cannot seat a call's leg). A
    /// refusal leaves the named call untouched. Raises `ValueError` outside
    /// `@b2bua.on_refer`, or for a `role` / `on_owner_leave` it does not know.
    #[pyo3(signature = (call, conference_id, role="talker", on_owner_leave="end"))]
    fn adopt_replaced<'py>(
        &self,
        python: Python<'py>,
        call: &Bound<'py, PyAny>,
        conference_id: String,
        role: &str,
        on_owner_leave: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let request = adopt_request(call, conference_id, role, on_owner_leave)?;
        crate::script::awaitable(python, async move {
            Ok(match request {
                Some(request) => crate::dispatcher::b2bua_adopt_replaced(request).await,
                None => 481,
            })
        })
    }

    /// Report the outcome of a REFER accepted with
    /// `call.accept_refer(mode="script")`: the NOTIFY that ends its
    /// subscription (RFC 3515 §2.4.5). `code` must be a final status, 200-699
    /// (`ValueError` otherwise). True once sent; False when no REFER on the
    /// call is awaiting its report.
    #[pyo3(signature = (call_id, code, reason=None))]
    fn complete_refer(&self, call_id: &str, code: u16, reason: Option<&str>) -> PyResult<bool> {
        if !(200..=699).contains(&code) {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "b2bua.complete_refer(code=…) reports a final status, 200-699 (got {code})"
            )));
        }
        if reason.is_some_and(|reason| reason.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)))
        {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "b2bua.complete_refer(reason=…) contains a line break or NUL",
            ));
        }
        match crate::dispatcher::b2bua_complete_refer(call_id, code, reason) {
            Ok(()) => Ok(true),
            Err(refusal) => {
                tracing::warn!(%call_id, code, "b2bua.complete_refer(): {refusal}");
                Ok(false)
            }
        }
    }

    /// Send an INFO (RFC 6086) in the caller's dialog of a call (on a call
    /// siphon answered itself, its only dialog), or with `leg="callee"` in
    /// the answered callee's, with `body` (str or bytes)
    /// of `content_type`, and any extra `headers` (a dict; the headers that
    /// place a request in its dialog are siphon's and refused). The CSeq is
    /// the dialog's, the request goes to the remote target through the route
    /// set, and on UDP it is retransmitted until answered.
    ///
    /// Awaitable: resolves to the final status code (an int), or with
    /// `with_body=True` to `(status, body bytes, content_type)`, or `None`
    /// when none arrives within `timeout_ms`. Raises `ValueError` when the call is
    /// unknown (`not_found`), a header may not be set (`bad_request`), or the
    /// call has no dialog yet (`invalid_state`).
    ///
    /// ```python
    /// status = await b2bua.send_info(call.call_id, body, "application/example+xml")
    /// ```
    #[pyo3(signature = (call_id, body=None, content_type=None, headers=None, timeout_ms=5000, leg="caller", with_body=false))]
    #[allow(clippy::too_many_arguments)]
    fn send_info<'py>(
        &self,
        python: Python<'py>,
        call_id: &str,
        body: Option<&Bound<'py, PyAny>>,
        content_type: Option<&str>,
        headers: Option<&Bound<'py, pyo3::types::PyDict>>,
        timeout_ms: u64,
        leg: &str,
        with_body: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        use pyo3::exceptions::PyValueError;
        let on_a_leg = match leg {
            "caller" => true,
            "callee" => false,
            other => {
                return Err(PyValueError::new_err(format!(
                    "b2bua.send_info(leg=…) is \"caller\" or \"callee\" (got {other:?})"
                )))
            }
        };
        let body: Vec<u8> = match body {
            None => Vec::new(),
            Some(value) => {
                if let Ok(text) = value.extract::<String>() {
                    text.into_bytes()
                } else {
                    value.extract::<Vec<u8>>().map_err(|_| {
                        PyValueError::new_err("b2bua.send_info(body=…) takes str or bytes")
                    })?
                }
            }
        };
        if content_type
            .is_some_and(|value| value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)))
        {
            return Err(PyValueError::new_err(
                "b2bua.send_info(content_type=…) contains a line break or NUL",
            ));
        }
        let mut extra = Vec::new();
        if let Some(headers) = headers {
            for (name, value) in headers.iter() {
                extra.push((name.extract::<String>()?, value.extract::<String>()?));
            }
        }
        let sent =
            crate::dispatcher::b2bua_send_info(call_id, on_a_leg, content_type, body, &extra)
                .map_err(|refusal| {
                    PyValueError::new_err(format!("b2bua.send_info(): {refusal}"))
                })?;
        crate::script::awaitable(python, async move {
            let waited =
                tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), sent.response)
                    .await;
            let answered = match waited {
                Ok(Ok(response)) => Some(response),
                // Timed out, or the wait was dropped with the dispatcher: a
                // late response is then absorbed as one to no request.
                _ => {
                    crate::dispatcher::forget_sent_info(&sent.branch);
                    None
                }
            };
            Ok(crate::script::Deferred::build(
                move |python| -> PyResult<Py<PyAny>> {
                    Ok(match answered {
                        None => python.None(),
                        Some(response) if with_body => (
                            response.status,
                            pyo3::types::PyBytes::new(python, &response.body),
                            response.content_type,
                        )
                            .into_pyobject(python)?
                            .into_any()
                            .unbind(),
                        Some(response) => {
                            response.status.into_pyobject(python)?.into_any().unbind()
                        }
                    })
                },
            ))
        })
    }

    /// The session in force toward one party of a call, by its SIP Call-ID:
    /// the description siphon last sent the caller, or with `leg="callee"` the
    /// answered callee, as text. `None` when the call or party is unknown or
    /// siphon has sent it none. What `b2bua.reoffer()` sends when given no
    /// `sdp`, and what a script edits when it re-offers one attribute changed.
    #[pyo3(signature = (call_id, leg="caller"))]
    fn session_sdp(&self, call_id: &str, leg: &str) -> PyResult<Option<String>> {
        let on_a_leg = match leg {
            "caller" => true,
            "callee" => false,
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "b2bua.session_sdp(leg=…) is \"caller\" or \"callee\" (got {other:?})"
                )))
            }
        };
        Ok(crate::dispatcher::b2bua_session_sdp(call_id, on_a_leg)
            .map(|sdp| String::from_utf8_lossy(&sdp).into_owned()))
    }

    /// Re-offer one party of a call by its SIP Call-ID: a re-INVITE in the
    /// caller's dialog (on a call siphon answered itself, its only dialog), or
    /// with `leg="callee"` in the answered callee's, carrying `sdp`, or the
    /// session in force toward that party when `sdp` is `None`. siphon puts its
    /// own `o=` on it at the dialog's next version (RFC 3264 §8). The other
    /// party is told nothing, and neither is the media engine where the call
    /// is anchored: the offer is the session in force, and the party's answer
    /// to it does not move the media.
    ///
    /// For telling a party something about the session it did not ask about:
    /// RFC 7866's `a=record`, when a recording starts or stops on its own.
    ///
    /// Awaitable: resolves to the final status code (an int), `491` without
    /// anything sent when an INVITE toward that party is already in progress
    /// (RFC 3261 §14.1: wait and send again), or `None` when no final response
    /// arrives within `timeout_ms`. Raises `ValueError` when the call is
    /// unknown (`not_found`), the party's dialog is not established or no
    /// session was ever sent it (`invalid_state`).
    ///
    /// ```python
    /// status = await b2bua.reoffer(call_id, sdp=session + "a=record:off\r\n")
    /// ```
    #[pyo3(signature = (call_id, sdp=None, leg="caller", timeout_ms=32000))]
    fn reoffer<'py>(
        &self,
        python: Python<'py>,
        call_id: &str,
        sdp: Option<String>,
        leg: &str,
        timeout_ms: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        use pyo3::exceptions::PyValueError;
        let on_a_leg = match leg {
            "caller" => true,
            "callee" => false,
            other => {
                return Err(PyValueError::new_err(format!(
                    "b2bua.reoffer(leg=…) is \"caller\" or \"callee\" (got {other:?})"
                )))
            }
        };
        let reoffered =
            crate::dispatcher::b2bua_reoffer(call_id, on_a_leg, sdp.map(String::into_bytes))
                .map_err(|refusal| PyValueError::new_err(format!("b2bua.reoffer(): {refusal}")))?;
        crate::script::awaitable(python, async move {
            let status = match reoffered {
                crate::dispatcher::Reoffered::Crossing => Some(491),
                crate::dispatcher::Reoffered::Sent { branch, status } => {
                    match tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), status)
                        .await
                    {
                        Ok(Ok(code)) => Some(code),
                        _ => {
                            crate::dispatcher::forget_reoffer(&branch);
                            None
                        }
                    }
                }
            };
            Ok(crate::script::Deferred::build(
                move |python| -> PyResult<Py<PyAny>> {
                    Ok(match status {
                        Some(code) => code.into_pyobject(python)?.into_any().unbind(),
                        None => python.None(),
                    })
                },
            ))
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

    /// Replace one leg of an answered call with a freshly dialed target,
    /// because *siphon* decided to — no REFER involved.
    ///
    /// This is the transfer siphon already knows how to run, reachable without
    /// a remote party asking for it. It dials `target` as a new leg on the same
    /// call, re-anchors the surviving party's media onto it, and when the target
    /// answers promotes it into the surviving pair and BYEs the leg it replaced.
    /// An IVR that has decided where a caller should go next, a controller
    /// handing a call from an AI to a human, a supervisor take-over: all of them
    /// were previously only expressible by hand-sequencing a hangup and a
    /// re-INVITE, which leaves the call's own state behind.
    ///
    /// **The replaced leg stays up while the target rings.** It is released only
    /// once the target answers, so the surviving party hears ringback instead of
    /// silence, and a target that rejects or never answers leaves the original
    /// call exactly as it was. `timeout` bounds the ring; `0` means no ring
    /// policy, only siphon's own guard against a target that answers nothing at
    /// all.
    ///
    /// Args:
    ///     call_id: SIP Call-ID of the call to act on.
    ///     target: URI to dial as the replacement.
    ///     next_hop: Steer egress without reshaping the R-URI, as on
    ///         ``call.dial()``.
    ///     replace_a_leg: ``False`` (default) replaces the callee and keeps the
    ///         caller; ``True`` does the reverse.
    ///     profile: Media profile for the pair this creates. Required when the
    ///         call is anchored with a direction-bound profile — the inherited
    ///         one describes the party that is leaving.
    ///     timeout: Seconds to wait for the target to answer.
    ///     number_policy: Reshape the target's number (and the triggered
    ///         INVITE's identity headers) the way ``call.dial(number_policy=…)``
    ///         does — an explicit named policy, else
    ///         ``b2bua.default_number_policy``, else no reshaping. A replacement
    ///         leg does not re-enter ``@b2bua.on_invite``, so this is where a
    ///         carrier's number format gets applied to it.
    ///     format: The inline form of the same thing, as on
    ///         ``rewrite_identities(format=…)``: ``"e164"``, ``"plain"``,
    ///         ``"international"`` or ``"national"``. Pass one or the other,
    ///         never both.
    ///
    /// Returns True once the INVITE is on the wire. It does **not** wait for the
    /// target: the replacement completes later, and `@b2bua.on_bye` fires for
    /// the leg that was replaced.
    ///
    /// Raises `ValueError` — never a hollow success — when the call is unknown,
    /// has not answered, has no peer leg to replace, already has a replacement
    /// in flight, or the target will not route. The message is prefixed with the
    /// stable cause token (`not_found`, `invalid_state`, `bad_request`,
    /// `unavailable`).
    ///
    /// ```python
    /// @rtpengine.on_dtmf
    /// def digit(call_id, from_tag, digit, duration_ms, volume):
    ///     if digit == "0":
    ///         b2bua.replace_peer(call_id, "sip:operator@pbx.example", timeout=45)
    /// ```
    #[pyo3(signature = (call_id, target, next_hop=None, replace_a_leg=false, profile=None, timeout=30, number_policy=None, format=None))]
    #[allow(clippy::too_many_arguments)]
    fn replace_peer(
        &self,
        call_id: &str,
        target: &str,
        next_hop: Option<&str>,
        replace_a_leg: bool,
        profile: Option<&str>,
        timeout: u32,
        number_policy: Option<&str>,
        format: Option<&str>,
    ) -> PyResult<bool> {
        use pyo3::exceptions::PyValueError;
        // Validate here so a typo raises on the spot, the way
        // `dial(number_policy=…)` and `accept_refer(…)` do, instead of silently
        // dialling the target unreshaped.
        let shape = crate::script::api::numbers::NumberShape::from_args(number_policy, format)?;
        crate::script::api::numbers::resolve_dial_shape(shape.as_ref())?;
        crate::dispatcher::b2bua_replace_peer(
            call_id,
            target,
            next_hop,
            replace_a_leg,
            profile,
            shape.as_ref(),
            timeout,
        )
        .map(|()| true)
        .map_err(|error| PyValueError::new_err(format!("{}: {error}", error.code())))
    }
}

/// The session timer `b2bua.originate(session_timer=...)` sets on the call: a dict
/// with `expires`, `min_se` and `refresher`, each key left out defaulting as in
/// `call.session_timer()`. `ValueError` for any other key, or a refresher that is
/// not `uac`, `uas` or `b2bua`.
/// The `ValueError` for an `adopt_replaced` argument it does not know.
fn refused(argument: &str, allowed: &str, got: &str) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!(
        "b2bua.adopt_replaced({argument}=…) is {allowed} (got {got:?})"
    ))
}

/// Read `b2bua.adopt_replaced`'s arguments: `None` for a REFER with no
/// `Replaces`, which names no dialog here (481).
fn adopt_request(
    call: &Bound<'_, PyAny>,
    conference_id: String,
    role: &str,
    on_owner_leave: &str,
) -> PyResult<Option<crate::dispatcher::AdoptRequest>> {
    use crate::rtpengine::backend::ConferenceRole;
    use pyo3::exceptions::PyValueError;
    let role = match role {
        "talker" => ConferenceRole::Talker,
        "listener" => ConferenceRole::Listener,
        "muted" => ConferenceRole::Muted,
        other => {
            return Err(refused(
                "role",
                "\"talker\", \"listener\" or \"muted\"",
                other,
            ))
        }
    };
    let ends_with_owner = match on_owner_leave {
        "end" => true,
        "keep" => false,
        other => return Err(refused("on_owner_leave", "\"end\" or \"keep\"", other)),
    };
    if conference_id.is_empty() {
        return Err(PyValueError::new_err(
            "b2bua.adopt_replaced(conference_id=…) names a room; it is empty",
        ));
    }
    let call = call
        .extract::<PyRef<'_, crate::script::api::call::PyCall>>()
        .map_err(|_| {
            PyValueError::new_err("b2bua.adopt_replaced(call=…) takes the Call of @b2bua.on_refer")
        })?;
    if call.refer_to_uri().is_none() {
        return Err(PyValueError::new_err(
            "b2bua.adopt_replaced() works on the call of an @b2bua.on_refer handler",
        ));
    }
    Ok(call
        .refer_for_adoption()
        .map(
            |(owner, replaces, referrer_on_a_leg)| crate::dispatcher::AdoptRequest {
                owner_call_id: owner.to_string(),
                referrer_on_a_leg,
                replaces: replaces.clone(),
                conference_id,
                role,
                ends_with_owner,
            },
        ))
}

fn session_timer_from_dict(
    dict: &Bound<'_, pyo3::types::PyDict>,
) -> PyResult<crate::script::api::call::SessionTimerOverride> {
    use crate::b2bua::session_timer::{SessionTimerField, SessionTimerFields};
    use pyo3::exceptions::PyValueError;

    let mut fields = SessionTimerFields::default();
    for (key, value) in dict.iter() {
        let key: String = key.extract()?;
        let field = SessionTimerField::named(&key)
            .map_err(|message| PyValueError::new_err(format!("b2bua.originate {message}")))?;
        match field {
            SessionTimerField::Expires => fields.expires = Some(value.extract()?),
            SessionTimerField::MinSe => fields.min_se = Some(value.extract()?),
            SessionTimerField::Refresher => fields.refresher = Some(value.extract()?),
        }
    }
    fields.build().map_err(PyValueError::new_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SessionRefresher;
    use crate::script::api::call::SessionTimerOverride;
    use pyo3::types::PyDict;
    use pyo3::PyTypeInfo;

    /// What a script calls is the pure-Python `siphon.b2bua.originate`, which
    /// hands its arguments on to this binding. Every argument the binding takes
    /// has to get through it, and arrive as itself.
    #[test]
    fn the_script_namespace_forwards_every_originate_argument() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::the_script_namespace_forwards_every_originate_argument"
            ),
            forwards_every_originate_argument,
        );
    }

    fn forwards_every_originate_argument() {
        pyo3::Python::initialize();
        Python::attach(|python| {
            crate::script::api::ensure_registry(python).expect("ensure registry");
            crate::script::api::install_siphon_module(python).expect("install siphon module");
            let globals = PyDict::new(python);
            globals
                .set_item("native", PyB2buaControl::type_object(python))
                .expect("set the binding's type");
            let code = std::ffi::CString::new(concat!(
                "import inspect, siphon\n",
                "native_names = [name for name in inspect.signature(native.originate).parameters][1:]\n",
                "wrapper_names = [name for name in inspect.signature(siphon.b2bua.originate).parameters]\n",
                "class Control:\n",
                "    def originate(self, *args, **kwargs):\n",
                "        self.received = inspect.signature(native.originate).bind(self, *args, **kwargs).arguments\n",
                "        return 'placed'\n",
                "control = Control()\n",
                "siphon.b2bua.__dict__['_control'] = control\n",
                "sent = {name: f'value-of-{name}' for name in native_names}\n",
                "siphon.b2bua.originate(**sent)\n",
                "received = {name: value for name, value in control.received.items() if name != 'self'}\n",
            ))
            .expect("CString");
            python
                .run(code.as_c_str(), Some(&globals), None)
                .expect("the forwarding probe runs");
            let names = |key: &str| -> Vec<String> {
                globals
                    .get_item(key)
                    .expect("get")
                    .expect("present")
                    .extract()
                    .expect("a list of names")
            };
            assert_eq!(names("wrapper_names"), names("native_names"));
            let sent: std::collections::HashMap<String, String> = globals
                .get_item("sent")
                .expect("get")
                .expect("present")
                .extract()
                .expect("a dict");
            let received: std::collections::HashMap<String, String> = globals
                .get_item("received")
                .expect("get")
                .expect("present")
                .extract()
                .expect("a dict");
            assert_eq!(received, sent);
        });
    }

    #[test]
    fn a_session_timer_dict_defaults_each_key_it_leaves_out() {
        pyo3::Python::initialize();
        Python::attach(|python| {
            let dict = PyDict::new(python);
            dict.set_item("expires", 90).expect("a dict item");
            assert_eq!(
                session_timer_from_dict(&dict).expect("a session timer"),
                SessionTimerOverride {
                    session_expires: 90,
                    min_se: 90,
                    refresher: SessionRefresher::B2bua,
                }
            );

            let dict = PyDict::new(python);
            dict.set_item("min_se", 120).expect("a dict item");
            dict.set_item("refresher", "UAS").expect("a dict item");
            assert_eq!(
                session_timer_from_dict(&dict).expect("a session timer"),
                SessionTimerOverride {
                    session_expires: 1800,
                    min_se: 120,
                    refresher: SessionRefresher::Uas,
                }
            );
        });
    }

    #[test]
    fn a_session_timer_dict_refuses_a_key_or_refresher_it_does_not_know() {
        pyo3::Python::initialize();
        Python::attach(|python| {
            let dict = PyDict::new(python);
            dict.set_item("interval", 90).expect("a dict item");
            let error = session_timer_from_dict(&dict).expect_err("an unknown key");
            assert!(error.to_string().contains("session_timer"), "{error}");

            let dict = PyDict::new(python);
            dict.set_item("refresher", "sometimes")
                .expect("a dict item");
            let error = session_timer_from_dict(&dict).expect_err("an unknown refresher");
            assert!(error.to_string().contains("refresher"), "{error}");
        });
    }

    /// `b2bua.adopt_replaced`'s arguments: what it refuses outright, a REFER
    /// with no `Replaces` (481, nothing to merge), and the request it builds.
    #[test]
    fn adopt_replaced_reads_its_arguments_and_the_refer() {
        use crate::script::api::call::PyCall;
        use std::sync::{Arc, Mutex};
        pyo3::Python::initialize();
        let invite = crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "INVITE sip:conf@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-adopt\r\n",
                "From: <sip:15550100001@example.com>;tag=a\r\n",
                "To: <sip:conf@example.com>\r\n",
                "Call-ID: conf@192.0.2.10\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("an INVITE");
        let call = |replaces: Option<crate::sip::headers::refer::Replaces>, in_refer: bool| {
            let mut call = PyCall::new(
                "owner".to_string(),
                Arc::new(Mutex::new(invite.clone())),
                "192.0.2.10".to_string(),
                "udp".to_string(),
            );
            if in_refer {
                call.set_refer_to("sip:15550100042@example.com".to_string(), replaces);
                call.set_refer_from_a_leg(true);
            }
            call
        };
        let replaces = crate::sip::headers::refer::Replaces {
            call_id: "held@192.0.2.10".into(),
            to_tag: "ours".into(),
            from_tag: "theirs".into(),
            early_only: false,
        };
        Python::attach(|python| {
            let bound = |call: PyCall| Bound::new(python, call).expect("a call").into_any();
            let refused = |call: PyCall, room: &str, role: &str, leave: &str| {
                adopt_request(&bound(call), room.to_string(), role, leave)
                    .expect_err("refused")
                    .to_string()
            };
            assert!(
                refused(call(Some(replaces.clone()), true), "room", "whisper", "end")
                    .contains("role")
            );
            assert!(refused(
                call(Some(replaces.clone()), true),
                "room",
                "talker",
                "linger"
            )
            .contains("on_owner_leave"));
            assert!(
                refused(call(Some(replaces.clone()), true), "", "talker", "end")
                    .contains("conference_id")
            );
            assert!(
                refused(call(Some(replaces.clone()), false), "room", "talker", "end")
                    .contains("on_refer")
            );
            let not_a_call = pyo3::types::PyString::new(python, "call").into_any();
            assert!(adopt_request(&not_a_call, "room".into(), "talker", "end").is_err());

            let blind = adopt_request(&bound(call(None, true)), "room".into(), "talker", "end")
                .expect("read");
            assert!(blind.is_none(), "no Replaces: nothing to merge, 481");

            let request = adopt_request(
                &bound(call(Some(replaces.clone()), true)),
                "room".into(),
                "muted",
                "keep",
            )
            .expect("read")
            .expect("a request");
            assert_eq!(request.owner_call_id, "owner");
            assert!(request.referrer_on_a_leg);
            assert_eq!(request.replaces, replaces);
            assert_eq!(request.conference_id, "room");
            assert_eq!(
                request.role,
                crate::rtpengine::backend::ConferenceRole::Muted
            );
            assert!(!request.ends_with_owner);
        });
    }
}
