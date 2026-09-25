//! The imperative call-control entry points the scripting and control-plane
//! layers call into: route, answer, progress, and the media handles.
use crate::dispatcher::*;

/// One routing target for [`b2bua_route_call`]. Built by the control adapter from
/// the `route` verb's `targets[]` — a bare URI (`ruri` only) or an object
/// carrying a per-target `next_hop` / `headers` / ring `timeout`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteTarget {
    /// The Request-URI for this carrier attempt.
    pub uri: String,
    /// Optional wire next-hop (steer egress without reshaping the R-URI).
    pub next_hop: Option<String>,
    /// Headers to inject on this attempt's B-leg INVITE.
    pub headers: Vec<(String, String)>,
    /// Per-attempt ring timeout (seconds); falls back to the call default.
    pub timeout_secs: Option<u32>,
    /// Fail this carrier over at its ring timeout even after it has shown
    /// progress. See [`crate::lcr::Route::reroute_after_progress`].
    pub reroute_after_progress: bool,
}

/// The failover queue a `route` verb's targets become: R-URI carriers, as
/// `call.route()` gets them. The command's `extra_headers` apply to every
/// attempt, and a target's own header overrides one on a key collision.
///
/// These are carriers from an out-of-process routing decision, so the LCR rule
/// applies: a carrier that has shown progress keeps the call past its ring
/// timeout, unless its target sets `reroute_after_progress`.
fn route_verb_routes(
    targets: Vec<RouteTarget>,
    extra_headers: &[(String, String)],
    default_timeout: u32,
) -> Vec<crate::lcr::Route> {
    targets
        .into_iter()
        .map(|target| {
            let mut headers: std::collections::HashMap<String, String> =
                extra_headers.iter().cloned().collect();
            headers.extend(target.headers);
            crate::lcr::Route {
                ruri: Some(target.uri),
                next_hop: target.next_hop,
                timeout_secs: Some(target.timeout_secs.unwrap_or(default_timeout)),
                headers,
                reroute_after_progress: target.reroute_after_progress,
                ..Default::default()
            }
        })
        .collect()
}

/// Why [`b2bua_route_call`] could not accept a return-control routing decision —
/// mapped to a typed control-plane error by the adapter (never a silent
/// pretend-success).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RouteError {
    /// A strategy other than sequential/single was requested. v1 runs the LCR
    /// sequential-failover engine only; parallel-fork return is a fast-follow.
    #[error("unsupported routing strategy '{0}' (v1 supports 'sequential'/'single')")]
    UnsupportedStrategy(String),
    /// The routing decision named no targets.
    #[error("route requires at least one target")]
    NoTargets,
}

/// Imperatively hand a *parked* (deferred-handover) controlled B2BUA call back to
/// siphon **with a routing decision** — the control-plane `route` verb.
///
/// The call is currently parked under external control (`CallState::Ringing`,
/// un-dialed, `control_app=Some`, `handoff_pending=true`, the A-leg INVITE
/// stored). This un-parks it: siphon runs its **normal B-leg dial with LCR
/// sequential failover** across `targets` — the shipped [`CallAction::RouteSequence`]
/// engine (`start_route_sequence` + [`b2bua_advance_route`], dialing via
/// `b2bua_send_b_leg_invite`) — and owns the call thereafter
/// (`@b2bua.on_failure` handles carrier failover). The control app is released:
/// the ControlBus channel drains and a `StasisEnd{reason:"routed"}` is emitted so
/// the app knows control returned (leak-critical).
///
/// v1 runs the sequential engine only; a strategy other than `sequential` /
/// `single` returns [`RouteError::UnsupportedStrategy`] rather than silently
/// doing sequential. Returns `Ok(true)` when the call was un-parked and the first
/// carrier dialed (or a clean 503 sent to the A-leg when no carrier was
/// routable), `Ok(false)` when the call / dispatcher is gone (never panics), and
/// `Err(..)` for an invalid decision. Safe to call from any thread (enters the
/// dispatcher runtime), mirroring [`b2bua_refer_call`] / [`b2bua_terminate_call`].
pub fn b2bua_route_call(
    sip_call_id: &str,
    targets: Vec<RouteTarget>,
    strategy: &str,
    extra_headers: &[(String, String)],
) -> Result<bool, RouteError> {
    // v1 scope: sequential / single-target only (the shipped RouteSequence
    // engine). Reject anything else with a typed error — never pretend to fork.
    if !(strategy.eq_ignore_ascii_case("sequential") || strategy.eq_ignore_ascii_case("single")) {
        return Err(RouteError::UnsupportedStrategy(strategy.to_string()));
    }
    if targets.is_empty() {
        return Err(RouteError::NoTargets);
    }

    let Some(control) = B2BUA_CONTROL.get() else {
        return Ok(false);
    };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread — establish the runtime.
    let _enter = control.runtime.enter();
    b2bua_route_call_with_state(sip_call_id, targets, extra_headers, &control.state)
}

/// [`b2bua_route_call`] past its argument checks, on a dispatcher already in
/// hand, from inside its runtime.
pub(crate) fn b2bua_route_call_with_state(
    sip_call_id: &str,
    targets: Vec<RouteTarget>,
    extra_headers: &[(String, String)],
    state: &DispatcherState,
) -> Result<bool, RouteError> {
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        warn!(%sip_call_id, "b2bua_route_call: no such call");
        return Ok(false);
    };

    // Clone the stored A-leg INVITE as the dial template (b2bua_advance_route
    // derives each B-leg INVITE from it). A handed-over call always stores it.
    let template = {
        let Some(invite_arc) = state
            .call_actors
            .get_call(&internal_call_id)
            .and_then(|call| call.a_leg_invite.clone())
        else {
            warn!(call_id = %internal_call_id, "b2bua_route_call: no stored A-leg INVITE to dial from");
            return Ok(false);
        };
        let Ok(invite) = invite_arc.lock() else {
            error!(call_id = %internal_call_id, "b2bua_route_call: invite lock poisoned");
            return Ok(false);
        };
        invite.clone()
    };

    // Build the failover queue from the targets (R-URI-only carriers).
    let default_timeout = 30u32;
    let routes = route_verb_routes(targets, extra_headers, default_timeout);

    // Release control ownership: drain the ControlBus channel + emit
    // StasisEnd{reason:"routed"} so the app knows control returned (leak-critical),
    // and clear the park state so a later B-leg ring-timeout takes the normal 408
    // path, not the parked-503 handoff default.
    if let Some(bus) = crate::control::ControlBus::global() {
        if let Some(channel_id) = bus.channel_id_for_sip_call_id(sip_call_id) {
            bus.release_channel(&channel_id, "routed");
        }
    }
    state.call_actors.release_control_owner(&internal_call_id);

    // RFC 3261 §8.2.2.3, checked as `call.route()` is, under the call's policy,
    // before any carrier is dialled: refused the way a route with no routable
    // carrier ends the call.
    let (script_shaped_headers, sec_agree_verified) = state
        .call_actors
        .get_call(&internal_call_id)
        .map(|call| (call.script_shaped_headers.clone(), call.sec_agree_verified))
        .unwrap_or_default();
    let unsupported = unhonourable_required_tags(
        &template.headers,
        &script_shaped_headers,
        &state.resolve_header_policy(&internal_call_id),
        sec_agree_verified,
    );
    if !unsupported.is_empty() {
        refuse_bad_extension(&internal_call_id, &template, unsupported, state);
        return Ok(true);
    }

    // Un-park: start the sequential-failover sequence and dial the first carrier.
    let carrier_count = routes.len();
    state.call_actors.start_route_sequence(
        &internal_call_id,
        crate::b2bua::actor::RouteSequenceState {
            pending: routes.into(),
            active: None,
            attempts: Vec::new(),
            active_since: None,
            active_progressed: false,
            active_legs_start: 0,
            send_socket: None,
            default_timeout,
        },
    );
    info!(
        call_id = %internal_call_id,
        carriers = carrier_count,
        "control plane: route — un-parked, dialing B-leg via LCR sequential failover"
    );
    let advanced = b2bua_advance_route(&internal_call_id, &template, state);
    // `template` is an owned clone, not a guard, so the hook is free to lock the
    // stored INVITE. Fired before the teardown below, which would take the call
    // out from under it.
    b2bua_dispatch_burned_routes(&internal_call_id, &advanced.burned, state);
    if !advanced.dialed {
        // No carrier was routable — answer the A-leg 503 and tear down, mirroring
        // the CallAction::RouteSequence "no routable carrier" arm.
        warn!(call_id = %internal_call_id, "control plane: route — no routable carrier, 503 to A-leg");
        b2bua_reject_call(&internal_call_id, 503, "No Route");
    }
    Ok(true)
}

/// Resolve the A-leg media session of a controlled B2BUA call into the tuple the
/// [`crate::rtpengine::MediaBackend`] keys on — `(backend, media_call_id, from_tag)`
/// — for the SIP control adapter's media verbs (`play` / `stop` / `dtmf` /
/// `hold` / `unhold` / `stream_start` / `stream_stop`).
///
/// The media backend does **not** key on the SIP Call-ID: it keys on the media
/// call-id ([`crate::rtpengine::session::MediaSession::rtpengine_id`], which a
/// siphon-terminated transfer can re-anchor to a fresh id) plus the A-leg SIP
/// From-tag. The control adapter only holds the SIP Call-ID
/// (`ChannelRef.sip_call_id`), so this reuses the exact resolution the dispatcher
/// itself uses for re-INVITE / SIPREC media rewriting:
/// `rtpengine_sessions.get(sip_call_id)` (the store is keyed by the A-leg SIP
/// Call-ID) → `session.rtpengine_id()` + `session.from_tag`.
///
/// Returns `None` — mapped by the adapter to a typed `not_found`, never a
/// fabricated call-id — when the dispatcher is not running, no media backend is
/// configured, or the call has no anchored media session (already torn down, or
/// never anchored). The accessor is **stateless** (a `OnceLock` read + a
/// `DashMap` get + an `Arc` clone): it adds no per-call store of its own, so it
/// needs no co-located leak test.
pub fn b2bua_media_target(
    sip_call_id: &str,
) -> Option<(Arc<crate::rtpengine::MediaBackend>, String, String)> {
    let control = B2BUA_CONTROL.get()?;
    let backend = control.state.rtpengine_set.clone()?;
    let session = control
        .state
        .rtpengine_sessions
        .as_ref()?
        .get(sip_call_id)?;
    Some((
        backend,
        session.rtpengine_id().to_string(),
        session.from_tag.clone(),
    ))
}

/// Record (or clear) the WebSocket **tee** attached to a control-plane channel's
/// media session.
///
/// The control rail reaches the session store through the B2BUA control handle
/// rather than holding one, so the tracking the script API does inline needs
/// this door. Keyed on the SIP Call-ID, which is the store key.
pub fn b2bua_media_set_ws_tee(sip_call_id: &str, ws_tee: Option<String>) {
    if let Some(control) = B2BUA_CONTROL.get() {
        if let Some(sessions) = control.state.rtpengine_sessions.as_ref() {
            sessions.set_ws_tee(sip_call_id, ws_tee);
        }
    }
}

/// Record (or clear) a mid-call WebSocket **takeover bridge** on a control-plane
/// channel's media session.  The twin of [`b2bua_media_set_ws_tee`].
pub fn b2bua_media_set_ws_bridge_attached(sip_call_id: &str, attached: bool) {
    if let Some(control) = B2BUA_CONTROL.get() {
        if let Some(sessions) = control.state.rtpengine_sessions.as_ref() {
            sessions.set_ws_bridge_attached(sip_call_id, attached);
        }
    }
}

/// Build and send a UAS response (final 2xx or provisional 1xx) for a B2BUA call
/// from an imperative `call.answer()` / `call.progress()`.
///
/// Unlike the bridged path, the script owns the A-leg dialog and answers it
/// directly. The response is built from `invite` (the A-leg INVITE, passed from
/// the `PyCall` because `a_leg_invite` isn't stored on the actor until after the
/// handler returns) and sent out the listener the INVITE arrived on. For any
/// code > 100 the To header is tagged with the A-leg dialog's `local_tag`
/// (RFC 3261 §12.1.1 — a dialog-creating 2xx and an early-dialog 18x both need
/// it, and it's what makes a later siphon-originated in-dialog BYE match the
/// caller instead of being 481-rejected).
///
/// `final_response` marks the call `Answered` and stamps the CDR answer time.
/// Returns `false` (never panics) if the call is gone or the dispatcher isn't
/// running.
pub fn b2bua_send_uas_response(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
    final_response: bool,
) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread (async-pool asyncio loop), so establish the runtime.
    let _enter = control.runtime.enter();
    send_uas_response(
        &control.state,
        internal_call_id,
        invite,
        code,
        reason,
        body,
        content_type,
        final_response,
    )
}

/// [`b2bua_send_uas_response`] on the dispatcher the caller already holds.
///
/// For a path inside the dispatcher that answers a call itself (the `Replaces`
/// takeover, `call.answer()` refused or answered on a dispatcher in hand), where
/// the tokio runtime is already current and reaching for the process-wide control
/// handle adds nothing. It is also what lets a test drive that path: the handle
/// is set once per process, and tests elsewhere rely on it being absent.
pub fn send_uas_response(
    state: &DispatcherState,
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
    final_response: bool,
) -> bool {
    // RFC 4028 §9: an INVITE asking for too brief a session interval is answered
    // 422, never 2xx, and the call ends.
    if final_response && (200..300).contains(&code) {
        if let Some(response) = session_interval_refusal(state, internal_call_id, invite) {
            end_failed_call(internal_call_id, FailedCallEnd::Refusal { response }, state);
            return false;
        }
    }
    let (transport, remote_addr, connection_id, local_addr, local_tag) =
        match state.call_actors.get_call(internal_call_id) {
            Some(call) => (
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.connection_id,
                call.a_leg_local_addr,
                call.a_leg.dialog.local_tag.clone(),
            ),
            None => return false,
        };

    // RFC 3261 §12.1.1: tag the To header with the A-leg dialog local_tag for any
    // dialog-establishing response (2xx) or early-dialog provisional (18x).
    let mut reply_headers: Vec<(crate::script::api::request::ReplyHeaderOp, String, String)> =
        Vec::new();
    if code > 100 {
        if let Some(to_value) = invite.headers.to() {
            if !to_value.contains(";tag=") {
                reply_headers.push((
                    crate::script::api::request::ReplyHeaderOp::Replace,
                    "To".to_string(),
                    crate::b2bua::actor::ensure_tag(to_value, Some(&local_tag)),
                ));
            }
        }
    }

    let mut response = build_response(
        invite,
        code,
        reason,
        state.server_header.as_deref(),
        &reply_headers,
    );

    // RFC 3261 §12.1.1 / §13.3.1.4: a UAS MUST put a Contact in a response that
    // establishes a dialog — the 2xx, and an 18x that opens an early one. It is
    // the remote target the UAC builds ACK / BYE / re-INVITE / PRACK against, so
    // without it a well-behaved UAC has nowhere to send them: it renders an
    // empty Request-URI and the in-dialog request is unparseable on arrival.
    // The relayed B-leg path already does this; UAS mode (`call.answer()` /
    // `call.progress()`, i.e. every single-leg answer including the voice-AI
    // one) had no B-leg 2xx to copy a Contact from and set none at all.
    //
    // Host and port are resolved exactly as the relayed path resolves them:
    // `a_leg_advertised_host` applies the advertised_address fallback and never
    // leaks an unspecified bind address, and the port is the listener the INVITE
    // actually arrived on — on a multi-homed host that is not `via_port()`, and
    // a Contact naming the wrong port strands every in-dialog request.
    if code > 100 {
        let host = state.a_leg_advertised_host(local_addr, &transport);
        let port = a_leg_advertised_port(local_addr, state.via_port(&transport));
        response.headers.set(
            "Contact",
            format!(
                "<sip:{}:{};transport={}>",
                host,
                port,
                transport.to_string().to_lowercase()
            ),
        );
    }

    if let Some(body_bytes) = body {
        if let Some(ct) = content_type {
            response.headers.set("Content-Type", ct.to_string());
        }
        response
            .headers
            .set("Content-Length", body_bytes.len().to_string());
        response.body = body_bytes;
    }
    if !final_response && (101..200).contains(&code) {
        // siphon's own provisional is reliable toward a caller that required
        // `100rel` (RFC 3262 §3), and waits behind an unacknowledged one.
        return send_a_leg_provisional(internal_call_id, response, false, None, state);
    }
    if final_response && (200..300).contains(&code) {
        // An answer siphon gives the caller itself is the session description in
        // force on the caller's dialog, under the `o=` it went out with. A
        // provisional's early media is not, until a 2xx confirms it. The 2xx answers
        // the caller's request for a session timer as well (RFC 4028 §9).
        negotiate_uas_answer_session_timer(
            internal_call_id,
            Some(&invite.headers),
            &mut response.headers,
            state,
        );
        adopt_sdp_sent_to_leg(
            state,
            internal_call_id,
            true,
            message_content_type(&response),
            &response.body,
        );
        // A locally-generated 2xx needs the same retransmission cover as a
        // relayed one: the B2BUA intercepts the A-leg INVITE before a server
        // transaction exists, so nothing under this recovers a lost 200 and the
        // caller would ring on until it gave up. Armed where the 2xx is actually
        // sent, which waits for the PRACK of a reliable provisional with SDP (RFC
        // 3262 §3), and cancelled by the caller's ACK in the A-leg ACK handler
        // (search `uas_2xx_retransmits`).
        answer_a_leg(
            internal_call_id,
            crate::b2bua::actor::HeldAnswer {
                response,
                relayed: false,
                deferred_refer: None,
            },
            state,
        );
    } else {
        if final_response {
            // A final failure: siphon's reliable provisionals to the caller stop
            // (RFC 3262 §3).
            end_a_leg_reliability(internal_call_id, state);
        }
        send_message_from(
            response,
            transport,
            remote_addr,
            connection_id,
            local_addr,
            state,
        );
    }

    if final_response {
        // Confirm the A-leg dialog and mark the CDR answered (tracked at INVITE
        // by cdr_track_b2bua_start) so a later BYE/terminate CDR shows duration.
        state
            .call_actors
            .set_state(internal_call_id, CallState::Answered);
        if crate::cdr::auto_emit_enabled() {
            cdr_mark_answer(state, internal_call_id, code);
        }
    }
    true
}

/// Imperatively send the final 2xx for a UAS-mode B2BUA call (`call.answer()`).
/// `code` must be 2xx. Returns `false` if the call is gone / dispatcher down.
pub fn b2bua_answer_call(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let _enter = control.runtime.enter();
    b2bua_answer_call_with_state(
        internal_call_id,
        invite,
        code,
        reason,
        body,
        content_type,
        &control.state,
    )
}

/// [`b2bua_answer_call`] on a dispatcher already in hand, from inside its
/// runtime.
pub(crate) fn b2bua_answer_call_with_state(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
    state: &DispatcherState,
) -> bool {
    // RFC 3261 §8.2.2.3: answering the call itself makes siphon the only UAS the
    // caller has, so a required extension siphon does not honour is refused
    // (`420`, or `494` for an unverified `sec-agree`), whatever the header
    // policy would have relayed to a callee.
    let sec_agree_verified = state
        .call_actors
        .get_call(internal_call_id)
        .is_some_and(|call| call.sec_agree_verified);
    let unsupported = unimplemented_required_tags(&invite.headers, sec_agree_verified);
    if !unsupported.is_empty() {
        refuse_bad_extension(internal_call_id, invite, unsupported, state);
        return false;
    }
    // After anchored early media the caller already holds siphon's SDP answer
    // from the 18x; a 2xx sent without a body repeats it (RFC 3264 §4) rather
    // than reaching the caller as a 200 that silently drops the session.
    let (body, content_type) = match body {
        Some(body) => (Some(body), content_type),
        None => match state.call_actors.early_media_anchor(internal_call_id) {
            Some(anchor) => (
                Some(anchor.answer_sdp.into_bytes()),
                Some("application/sdp"),
            ),
            None => (None, content_type),
        },
    };
    send_uas_response(
        state,
        internal_call_id,
        invite,
        code,
        reason,
        body,
        content_type,
        true,
    )
}

/// Answer a parked B2BUA call and anchor its media in one step — the control
/// plane's `answer(profile=…, ws_uri=…)`.
///
/// The same act `call.handover(answer=True, profile=…, ws_uri=…)` performs from
/// a routing script, reachable by an application that took the call **un**
/// -answered. Without it a controller could hold a call open (`ring`) and then
/// had no way to connect it: plain `answer` sends a 2xx with whatever body it
/// was given and anchors nothing, and answering first and attaching a bridge
/// afterwards is not the same thing — `received_from`, echo cancellation and
/// the VAD engine are properties of the answer, not of a bridge bolted on
/// after it.
///
/// Refuses a call that is already answered rather than putting a second final
/// response on one INVITE server transaction (RFC 3261 §17.2.1). On any media
/// failure the 2xx is never sent — [`answer_first_anchor`] only reaches
/// [`b2bua_answer_call`] once `answer_local` has returned an SDP — so the call
/// stays parked and the application can retry or reject it. Never a fake 200.
///
/// `Err` carries a short human reason for the control reply. Safe from any
/// thread: it enters the dispatcher runtime, like the other control-rail entry
/// points.
pub fn b2bua_answer_call_anchored(
    internal_call_id: &str,
    code: u16,
    reason: &str,
    profile: Option<&str>,
    ws_uri: Option<&str>,
) -> Result<(), String> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err("B2BUA is not running".to_string());
    };
    let state = &control.state;

    // The A-leg's source address (for the `received_from` gate) and its INVITE,
    // captured together so neither is read from a call the other outlived.
    let Some((source_ip, invite_arc)) =
        state
            .call_actors
            .get_call(internal_call_id)
            .and_then(|call| match (&call.state, call.a_leg_invite.as_ref()) {
                (CallState::Answered, _) | (_, None) => None,
                (_, Some(invite)) => {
                    Some((call.a_leg.transport.remote_addr.ip(), Arc::clone(invite)))
                }
            })
    else {
        // Answered, gone, or no stored INVITE — all three mean this verb has
        // nothing to answer, and the caller maps that to `not_found`.
        return Err("call is gone or already answered".to_string());
    };
    let Ok(invite) = invite_arc.lock() else {
        return Err("call invite lock poisoned".to_string());
    };

    // `answer_first_anchor` does a media round-trip under `block_in_place`; the
    // control apply task is on the runtime already, but an event callback or a
    // timer reaching this is not.
    let _enter = control.runtime.enter();
    answer_first_anchor(
        internal_call_id,
        &invite,
        source_ip,
        code,
        reason,
        profile,
        ws_uri,
        state,
    )
}

/// Open early media on a parked B2BUA call through the media engine — the
/// control plane's `progress(anchor=…, profile=…, ws_uri=…)`.
///
/// An 18x carrying the engine's SDP, so an application can play ringback or an
/// announcement before it answers — which needs an SDP the caller can be sent
/// before any B-leg has produced one. The anchor is kept on the call and the
/// later 2xx repeats its answer (RFC 3264 §4). Refuses an answered call, and on
/// a media failure sends nothing: the call stays parked and answerable.
pub fn b2bua_progress_call_anchored(
    internal_call_id: &str,
    code: u16,
    reason: &str,
    profile: Option<&str>,
    ws_uri: Option<&str>,
) -> Result<(), String> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err("B2BUA is not running".to_string());
    };
    let state = &control.state;

    let Some((source_ip, invite_arc)) =
        state
            .call_actors
            .get_call(internal_call_id)
            .and_then(|call| match (&call.state, call.a_leg_invite.as_ref()) {
                (CallState::Answered, _) | (_, None) => None,
                (_, Some(invite)) => {
                    Some((call.a_leg.transport.remote_addr.ip(), Arc::clone(invite)))
                }
            })
    else {
        return Err("call is gone or already answered".to_string());
    };
    let Ok(invite) = invite_arc.lock() else {
        return Err("call invite lock poisoned".to_string());
    };

    let _enter = control.runtime.enter();
    early_media_anchor_progress(
        internal_call_id,
        &invite,
        source_ip,
        code,
        reason,
        profile,
        ws_uri,
        state,
    )
}

/// The SDP answer an early-media anchor already sent on this call, if any.
///
/// What a 2xx after anchored early media has to repeat. The control adapter
/// reads it to refuse an `answer` whose own body would contradict an answer the
/// caller already holds.
pub fn b2bua_early_media_sdp(internal_call_id: &str) -> Option<String> {
    let control = B2BUA_CONTROL.get()?;
    control
        .state
        .call_actors
        .early_media_anchor(internal_call_id)
        .map(|anchor| anchor.answer_sdp)
}

/// The A-leg's local (UAS) To-tag for a live B2BUA call (`call.local_tag`).
///
/// siphon mints this tag with the A-leg dialog (`Dialog::from_inbound`), so it
/// exists before any response is sent, and stamps it on everything
/// `b2bua_send_uas_response` puts on the wire — it is the tag the far end sees.
/// It lives on the actor and never appears in the inbound INVITE the script API
/// holds, which is why reading it needs a door through the control handle
/// rather than a lookup on `PyCall`'s own message. Keyed on the internal call
/// id, like the other UAS-side entry points (`b2bua_answer_call`,
/// `b2bua_progress_call`).
///
/// `None` when the dispatcher is down or the call is gone.
pub fn b2bua_local_tag(internal_call_id: &str) -> Option<String> {
    let control = B2BUA_CONTROL.get()?;
    let call = control.state.call_actors.get_call(internal_call_id)?;
    Some(call.a_leg.dialog.local_tag.clone())
}

/// Imperatively send a provisional (1xx) for a UAS-mode B2BUA call
/// (`call.progress()`) — e.g. a 183 with early-media SDP. Does not answer the
/// call. Returns `false` if the call is gone / dispatcher down.
pub fn b2bua_progress_call(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> bool {
    b2bua_send_uas_response(
        internal_call_id,
        invite,
        code,
        reason,
        body,
        content_type,
        false,
    )
}

// ---------------------------------------------------------------------------
// dial — ring B-legs while the caller stays unanswered and controller-owned
// ---------------------------------------------------------------------------

/// One `dial` target: a URI to ring, or an AoR resolved against the registrar.
#[derive(Debug, Clone, Default)]
pub struct DialTarget {
    /// Request-URI for the B-leg.
    pub uri: String,
    /// Routing destination, when it differs from `uri` (a trunk, an outbound
    /// proxy). The R-URI keeps `uri`'s shape either way.
    pub next_hop: Option<String>,
    /// Captured inbound flow for a registered contact (RFC 5626 §5.3). The only
    /// way to reach a phone that registered over TCP, TLS or WebSocket behind
    /// NAT, which is why an AoR target resolves to one per contact.
    pub flow: Option<crate::script::api::registrar::PyFlow>,
    /// Route set for this branch, from the binding's Path (RFC 3327 §5.3).
    pub route: Vec<String>,
    /// Per-target headers, layered over the command's.
    pub headers: std::collections::HashMap<String, String>,
    /// Calling identity for this branch alone, overriding the dial's own.
    ///
    /// One dial can try two carriers that assigned different numbers, and the
    /// number a carrier will accept is a property of that carrier, not of the
    /// call. Without this a hunt across two trunks can only present one of
    /// them correctly, and the other challenges the INVITE and keeps
    /// challenging however correct the digest is.
    pub from: Option<String>,
    /// From display name for this branch alone. An empty string removes the
    /// caller's rather than presenting an empty one, as at dial level.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for this branch alone (RFC 3325 §9.1).
    pub p_asserted_identity: Option<String>,
    /// Calling-identity presentation for this branch alone (RFC 3323 §4.1).
    /// One carrier may be trusted with the real identity where another is not.
    pub privacy: Option<crate::sip::privacy::CallerIdPresentation>,
    /// The registered AoR this target is a contact of, when it came from an
    /// `{aor}` target ([`dial_targets_for_aor`]). What the branch's events name
    /// as the AoR it was dialled for; `None` for a URI dialled as written.
    pub aor: Option<String>,
}

impl DialTarget {
    /// This branch's effective identity: its own where it names one, the
    /// dial's otherwise.
    ///
    /// Resolved per field rather than all-or-nothing, so a target naming only
    /// a `from` still inherits the dial's `privacy`. Same precedence as
    /// `headers`, which a target already layers over the command's.
    fn shaping_over(&self, dial: &DialShaping) -> DialShaping {
        DialShaping {
            // Media is allocated once for the whole dial, so a branch cannot
            // pick its own profile.
            profile: dial.profile.clone(),
            from: self.from.clone().or_else(|| dial.from.clone()),
            from_display: self
                .from_display
                .clone()
                .or_else(|| dial.from_display.clone()),
            p_asserted_identity: self
                .p_asserted_identity
                .clone()
                .or_else(|| dial.p_asserted_identity.clone()),
            privacy: self.privacy.or(dial.privacy),
        }
    }
}

/// How a controller-issued `dial` presents itself and anchors its media.
///
/// Every field applies to the whole dial: each branch of a fork and each
/// attempt of a sequential hunt, not just the first one out.
#[derive(Debug, Clone, Default)]
pub struct DialShaping {
    /// Media profile to anchor both legs through. `None` passes the caller's
    /// own SDP to the phones and lets them negotiate with the caller directly.
    pub profile: Option<String>,
    /// Calling identity — the From URI (RFC 3261 §8.1.1.3).
    ///
    /// Without it a B-leg presents the caller's own From, which on a call out
    /// to a trunk is the internal extension. A carrier that looks its account
    /// up by the From user does not recognise that, so it challenges the INVITE
    /// and keeps challenging however correct the digest is.
    pub from: Option<String>,
    /// From display name. An empty string removes the caller's rather than
    /// presenting an empty one.
    pub from_display: Option<String>,
    /// `P-Asserted-Identity` for a trusted next hop (RFC 3325 §9.1). Injected
    /// after the header policy, so a preset that strips `P-*` at a trust
    /// boundary cannot silently drop an identity the controller named.
    pub p_asserted_identity: Option<String>,
    /// Calling-identity presentation (RFC 3323 §4.1 / TS 24.607). `Restricted`
    /// anonymises From and asserts `Privacy: id`, keeping the real identity in
    /// `P-Asserted-Identity` for the trusted next hop.
    pub privacy: Option<crate::sip::privacy::CallerIdPresentation>,
}

/// The `From` a dial's identity arguments shaped.
#[derive(Debug, Clone)]
struct ShapedFrom {
    /// The whole header value, dialog tag included.
    header: String,
    /// The host to pin, when `from` named one.
    host: Option<String>,
}

/// Shape the dial template's `From` from `shaping`.
///
/// `From` is framework-managed on a B-leg — the builder swaps in a fresh dialog
/// tag and, for topology hiding, rewrites the host to siphon's own advertised
/// address — so it cannot be set with a plain header injection: one written
/// without its tag drops the mandatory dialog tag (RFC 3261 §8.1.1.3), and the
/// host would be overwritten after the fact anyway. This goes through
/// [`NameAddr`], which round-trips the tag, and reports the host to pin the way
/// `call.set_from_host()` pins it.
fn apply_dial_identity(
    template: &mut SipMessage,
    shaping: &DialShaping,
) -> Result<Option<ShapedFrom>, String> {
    let shaped = shape_from(template, shaping)?;
    if let Some(shaped) = &shaped {
        template.headers.set("From", shaped.header.clone());
    }
    Ok(shaped)
}

/// The `From` `shaping` presents over `template`'s own, or `None` when it names
/// no identity and the template's stands.
fn shape_from(template: &SipMessage, shaping: &DialShaping) -> Result<Option<ShapedFrom>, String> {
    if shaping.from.is_none() && shaping.from_display.is_none() {
        return Ok(None);
    }
    let raw = template
        .headers
        .get("From")
        .or_else(|| template.headers.get("f"))
        .ok_or("the call has no From header to present an identity on")?;
    let mut nameaddr = crate::sip::headers::nameaddr::NameAddr::parse(raw)
        .map_err(|error| format!("cannot parse the call's From header: {error}"))?;
    let mut host = None;
    if let Some(from) = shaping.from.as_deref() {
        let uri = parse_uri_standalone(from)
            .map_err(|error| format!("dial from is not a SIP URI: {error}"))?;
        host = Some(uri.host.clone());
        nameaddr.uri = uri;
    }
    match shaping.from_display.as_deref() {
        Some(display) => {
            nameaddr.display_name = Some(display.to_string()).filter(|value| !value.is_empty());
        }
        // A display name is part of an identity. Keeping the caller's beside a
        // number the controller replaced would present "203" next to the
        // company's published number — the extension the `from` exists to hide.
        None if shaping.from.is_some() => nameaddr.display_name = None,
        None => {}
    }
    Ok(Some(ShapedFrom {
        header: nameaddr.to_string(),
        host,
    }))
}

/// The `From` each target presents where it names an identity of its own, in
/// target order, over the dial-shaped `template`.
///
/// A target's identity is shaped exactly as the dial's is — the whole URI with
/// its host pinned, the caller's display name dropped unless one is named —
/// resolved field by field over the dial's through
/// [`DialTarget::shaping_over`]. Every target is shaped before any branch is
/// sent, so an identity siphon cannot put on the wire refuses the dial before
/// anything rings rather than after the first phone already has.
fn branch_identities(
    targets: &[DialTarget],
    template: &SipMessage,
    shaping: &DialShaping,
) -> Result<Vec<Option<ShapedFrom>>, String> {
    targets
        .iter()
        .map(|target| {
            if target.from.is_none() && target.from_display.is_none() {
                return Ok(None);
            }
            shape_from(template, &target.shaping_over(shaping))
        })
        .collect()
}

/// The command headers with `P-Asserted-Identity` on them.
///
/// It rides with the per-branch headers because those are injected *after* the
/// header policy: an identity the controller named explicitly outranks a
/// preset's `P-*` strip set, the same way a script's `set_header` does. Any
/// asserted identity already in the command's own headers is replaced, so the
/// two spellings cannot both reach the wire in an undefined order.
fn dial_headers_with_asserted_identity(
    extra_headers: &[(String, String)],
    p_asserted_identity: Option<&str>,
) -> Vec<(String, String)> {
    let Some(identity) = p_asserted_identity else {
        return extra_headers.to_vec();
    };
    let mut headers: Vec<(String, String)> = extra_headers
        .iter()
        .filter(|(name, _)| !name.eq_ignore_ascii_case("P-Asserted-Identity"))
        .cloned()
        .collect();
    headers.push((
        "P-Asserted-Identity".to_string(),
        crate::sip::privacy::asserted_identity_value(identity),
    ));
    headers
}

/// The config spelling of a presentation, for the failover engine's routes.
const fn presentation_token(
    presentation: crate::sip::privacy::CallerIdPresentation,
) -> &'static str {
    match presentation {
        crate::sip::privacy::CallerIdPresentation::Allowed => "allowed",
        crate::sip::privacy::CallerIdPresentation::Restricted => "restricted",
    }
}

/// Why a `dial` could not be started.
#[derive(Debug)]
pub enum DialError {
    /// No target survived resolution.
    NoTargets,
    /// A strategy siphon does not implement.
    UnsupportedStrategy(String),
    /// The call is already answered, so there is no unanswered caller to hold.
    AlreadyAnswered,
    /// An AoR with no registered contact.
    NoContacts(String),
    /// The requested media path cannot be allocated safely.
    Media(String),
    /// An identity argument siphon cannot put on the wire.
    InvalidIdentity(String),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::NoTargets => write!(formatter, "dial requires at least one target"),
            DialError::UnsupportedStrategy(strategy) => {
                write!(formatter, "unsupported dial strategy '{strategy}'")
            }
            DialError::AlreadyAnswered => write!(
                formatter,
                "the call is already answered — dial rings a caller that is still waiting"
            ),
            DialError::NoContacts(aor) => {
                write!(formatter, "no registered contact for {aor}")
            }
            DialError::Media(reason) => write!(formatter, "{reason}"),
            DialError::InvalidIdentity(reason) => write!(formatter, "{reason}"),
        }
    }
}

/// Ring `targets` as B-legs of a controlled call, keeping the caller unanswered
/// and the call with its controller.
///
/// This is the verb form of a script's `call.dial()` / `call.fork()`, and the
/// difference from [`b2bua_route_call`] is ownership: `route` hands the call
/// back to siphon (the controller gets `StasisEnd{reason: routed}` and loses
/// it), which is no use to an application that wants "ring the extension, and
/// if nobody answers, voicemail". Here the controller keeps the channel
/// throughout: provisional responses and early media reach the caller as usual,
/// the first 2xx answers it and the pair becomes an ordinary two-leg call, and
/// a failure or timeout is reported as `DialFailed` with the caller still
/// ringing and still parked.
pub fn b2bua_dial_call(
    sip_call_id: &str,
    targets: Vec<DialTarget>,
    strategy: &str,
    timeout_secs: u32,
    extra_headers: &[(String, String)],
    shaping: &DialShaping,
) -> Result<bool, DialError> {
    let parallel = if strategy.eq_ignore_ascii_case("parallel") {
        true
    } else if strategy.eq_ignore_ascii_case("sequential") || strategy.eq_ignore_ascii_case("single")
    {
        false
    } else {
        return Err(DialError::UnsupportedStrategy(strategy.to_string()));
    };
    if targets.is_empty() {
        return Err(DialError::NoTargets);
    }

    let Some(control) = B2BUA_CONTROL.get() else {
        return Ok(false);
    };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread.
    let _enter = control.runtime.enter();
    b2bua_dial_call_with_state(
        sip_call_id,
        targets,
        parallel,
        timeout_secs,
        extra_headers,
        shaping,
        &control.state,
    )
}

/// [`b2bua_dial_call`] past its argument checks (`parallel` is the parsed
/// strategy), on a dispatcher already in hand, from inside its runtime.
pub(crate) fn b2bua_dial_call_with_state(
    sip_call_id: &str,
    targets: Vec<DialTarget>,
    parallel: bool,
    timeout_secs: u32,
    extra_headers: &[(String, String)],
    shaping: &DialShaping,
    state: &DispatcherState,
) -> Result<bool, DialError> {
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        warn!(%sip_call_id, "b2bua_dial_call: no such call");
        return Ok(false);
    };

    // Answering first is what `dial` exists to avoid — it starts billing before
    // anyone picks up and denies the caller the callee's own ringback — so a
    // call that is already answered is a caller error, not something to paper
    // over by dialling anyway.
    if state
        .call_actors
        .get_call(&internal_call_id)
        .map(|call| matches!(call.state, CallState::Answered))
        .unwrap_or(false)
    {
        return Err(DialError::AlreadyAnswered);
    }

    let mut template = {
        let Some(invite_arc) = state
            .call_actors
            .get_call(&internal_call_id)
            .and_then(|call| call.a_leg_invite.clone())
        else {
            warn!(call_id = %internal_call_id, "b2bua_dial_call: no stored A-leg INVITE to dial from");
            return Ok(false);
        };
        let Ok(invite) = invite_arc.lock() else {
            error!(call_id = %internal_call_id, "b2bua_dial_call: invite lock poisoned");
            return Ok(false);
        };
        invite.clone()
    };

    // RFC 3261 §8.2.2.3, checked as `call.dial()` is, under the call's policy.
    // A controller cannot change that policy, so no other dial could connect the
    // caller either: it is refused now, not reported as a dial to retry.
    let (script_shaped_headers, sec_agree_verified) = state
        .call_actors
        .get_call(&internal_call_id)
        .map(|call| (call.script_shaped_headers.clone(), call.sec_agree_verified))
        .unwrap_or_default();
    let unsupported = unhonourable_required_tags(
        &template.headers,
        &script_shaped_headers,
        &state.resolve_header_policy(&internal_call_id),
        sec_agree_verified,
    );
    if !unsupported.is_empty() {
        control_notify_channel_event(
            sip_call_id,
            "DialFailed",
            serde_json::json!({
                "code": unhonoured_tags_response(&unsupported).0,
                "reason": unhonoured_tags_response(&unsupported).1,
                "timed_out": false,
                "unsupported": unsupported.clone(),
                "branches": control_dial_branches_for_failure(&internal_call_id, state),
            }),
        );
        refuse_bad_extension(&internal_call_id, &template, unsupported, state);
        return Ok(true);
    }

    // The identity this dial presents, applied to the template before anything
    // is allocated or sent, and recorded on the call so the branches a
    // sequential hunt dials later carry it too.
    if let Some(shaped) =
        apply_dial_identity(&mut template, shaping).map_err(DialError::InvalidIdentity)?
    {
        let Some(mut call) = state.call_actors.get_call_mut(&internal_call_id) else {
            return Ok(false);
        };
        call.control_dial_from_header = Some(shaped.header);
        if let Some(host) = shaped.host {
            call.from_host_override = Some(host);
        }
    }
    let branch_froms =
        branch_identities(&targets, &template, shaping).map_err(DialError::InvalidIdentity)?;

    if let Some(profile) = shaping.profile.as_deref() {
        let source_ip = state
            .call_actors
            .get_call(&internal_call_id)
            .map(|call| call.a_leg.transport.remote_addr.ip())
            .ok_or_else(|| DialError::Media("call is gone".into()))?;
        template = control_dial_media_offer(&template, source_ip, profile, state)
            .map_err(DialError::Media)?;
        let Some(mut call) = state.call_actors.get_call_mut(&internal_call_id) else {
            release_failed_call_media(sip_call_id, state);
            return Ok(false);
        };
        call.control_dial_media = true;
        // One allocation serves every branch: they are all offered this body,
        // and the attempts a sequential hunt makes later are rebuilt from the
        // stored A-leg INVITE, which keeps the caller's own offer so a failed
        // dial is still answerable into voicemail.
        call.control_dial_offer = Some(template.body.clone());
    }

    let extra_headers =
        dial_headers_with_asserted_identity(extra_headers, shaping.p_asserted_identity.as_deref());

    // The controller has acted, so the handoff deadline no longer applies: what
    // bounds the call now is the dial's own timeout.
    state.call_actors.mark_controller_acted(&internal_call_id);
    // Ownership is deliberately NOT released — that is the whole difference
    // from `route`.
    state.call_actors.set_control_dial(&internal_call_id, true);
    // Which registered AoR each `{aor}` target's contacts belong to, so every
    // branch this dial places — a sequential hunt's later attempts included —
    // names the AoR it was dialled for. Replaced per dial: a second dial on the
    // channel names only its own.
    if let Some(mut call) = state.call_actors.get_call_mut(&internal_call_id) {
        call.control_dial_aors = targets
            .iter()
            .filter_map(|target| Some((target.uri.clone(), target.aor.clone()?)))
            .collect();
    }

    let sent = if parallel {
        dial_parallel(
            &internal_call_id,
            &targets,
            &branch_froms,
            &extra_headers,
            &template,
            shaping,
            state,
        )
    } else {
        dial_sequential(
            &internal_call_id,
            targets,
            branch_froms,
            timeout_secs,
            &extra_headers,
            &template,
            shaping,
            state,
        )
    };

    if sent == 0 {
        release_control_dial_media(&internal_call_id, state);
        // Nothing reached the wire, so nothing will ever answer. Report it now
        // rather than leaving the caller in ringback for the full timeout.
        state.call_actors.set_control_dial(&internal_call_id, false);
        warn!(call_id = %internal_call_id, "control plane: dial — no branch could be sent");
        control_notify_channel_event(
            sip_call_id,
            "DialFailed",
            serde_json::json!({
                "code": 503,
                "reason": "no branch could be sent",
                "timed_out": false,
                "branches": control_dial_branches_for_failure(&internal_call_id, state),
            }),
        );
        return Ok(true);
    }

    set_b2bua_answer_deadline(&internal_call_id, timeout_secs, state);
    info!(
        call_id = %internal_call_id,
        branches = sent,
        strategy = if parallel { "parallel" } else { "sequential" },
        "control plane: dial — ringing while the caller stays unanswered"
    );
    Ok(true)
}

/// Ring every target at once (RFC 3261 §16.7 aggregation applies as it does for
/// a script's `call.fork`). Returns how many branches reached the wire.
fn dial_parallel(
    call_id: &str,
    targets: &[DialTarget],
    branch_froms: &[Option<ShapedFrom>],
    extra_headers: &[(String, String)],
    template: &SipMessage,
    shaping: &DialShaping,
    state: &DispatcherState,
) -> usize {
    let mut sent = 0usize;
    for (target, branch_from) in targets.iter().zip(branch_froms) {
        let branch = target.shaping_over(shaping);
        let headers = merged_headers(
            extra_headers,
            &target.headers,
            branch.p_asserted_identity.as_deref(),
        );
        // A branch naming its own identity presents it whole — URI, display
        // name and pinned host — on a template of its own. The dial's identity
        // is already on the shared template, so only a target that asked to
        // differ costs a clone.
        let branch_template = branch_from.as_ref().map(|shaped| {
            let mut own = template.clone();
            own.headers.set("From", shaped.header.clone());
            own
        });
        // Its number also goes through the tag-preserving substitution a
        // per-carrier LCR route uses, which carries it onto an asserted
        // identity the header policy let through.
        let caller_id = target
            .from
            .as_deref()
            .map(calling_number_of)
            .filter(|number| !number.is_empty());
        if b2bua_send_b_leg_invite(
            call_id,
            &target.uri,
            target.next_hop.as_deref(),
            target.flow.as_ref(),
            &target.route,
            None,
            None,
            branch_template.as_ref().unwrap_or(template),
            None,
            None,
            caller_id.as_deref(),
            branch.privacy,
            branch_from
                .as_ref()
                .and_then(|shaped| shaped.host.as_deref()),
            &headers,
            state,
        ) {
            sent += 1;
        }
    }
    sent
}

/// A sequential `dial` as a failover queue.
///
/// Its targets are phones being hunted, and a phone that rings sends a 180, so
/// each target moves on when `timeout_secs` passes whether it rang or not:
/// every route sets `reroute_after_progress`, where an LCR carrier that has
/// shown progress would keep the call.
fn sequential_dial_routes(
    targets: Vec<DialTarget>,
    branch_froms: Vec<Option<ShapedFrom>>,
    timeout_secs: u32,
    extra_headers: &[(String, String)],
    shaping: &DialShaping,
) -> Vec<crate::lcr::Route> {
    targets
        .into_iter()
        .zip(branch_froms)
        .map(|(target, branch_from)| {
            let branch = target.shaping_over(shaping);
            // A target's own identity rides the route's per-carrier fields,
            // which is what they are for: `caller_id` substitutes the calling
            // number for this carrier alone, tag-preserving, and reaches
            // `P-Asserted-Identity` with it. The dial's own identity is already
            // on the template, so a route only carries what differs.
            let caller_id = target
                .from
                .as_deref()
                .map(calling_number_of)
                .filter(|number| !number.is_empty());
            crate::lcr::Route {
                ruri: Some(target.uri),
                next_hop: target.next_hop,
                timeout_secs: Some(timeout_secs),
                headers: merged_headers(
                    extra_headers,
                    &target.headers,
                    branch.p_asserted_identity.as_deref(),
                )
                .into_iter()
                .collect(),
                reroute_after_progress: true,
                caller_id,
                // The failover engine applies this per attempt, after the
                // number policy, which is where CLIR belongs: the presentation
                // has to survive every hop of the hunt, not just the first.
                caller_id_presentation: branch
                    .privacy
                    .map(|presentation| presentation_token(presentation).to_string()),
                // The rest of the target's identity — the host its `from` named
                // and the display name — which a number cannot carry.
                from_host: branch_from.as_ref().and_then(|shaped| shaped.host.clone()),
                presented_from: branch_from.map(|shaped| shaped.header),
                ..Default::default()
            }
        })
        .collect()
}

/// The calling number inside a dial identity, for the per-carrier substitution
/// `crate::lcr::Route::caller_id` performs.
///
/// That field substitutes a *number*, not a URI: it is applied by
/// `set_calling_number`, which keeps the From's host and dialog tag. A target
/// naming a full `sip:` URI therefore contributes its user part here, and the
/// host it named is pinned separately for the branch (see
/// [`branch_identities`]).
fn calling_number_of(from: &str) -> String {
    parse_uri_standalone(from)
        .ok()
        .and_then(|uri| uri.user.clone())
        .unwrap_or_else(|| from.to_string())
}

/// Try the targets in order, advancing on failure, via the same failover engine
/// the LCR path uses — but with the call still owned by its controller, so the
/// exhausted sequence reports `DialFailed` rather than failing the caller.
fn dial_sequential(
    call_id: &str,
    targets: Vec<DialTarget>,
    branch_froms: Vec<Option<ShapedFrom>>,
    timeout_secs: u32,
    extra_headers: &[(String, String)],
    template: &SipMessage,
    shaping: &DialShaping,
    state: &DispatcherState,
) -> usize {
    let routes =
        sequential_dial_routes(targets, branch_froms, timeout_secs, extra_headers, shaping);
    state.call_actors.start_route_sequence(
        call_id,
        crate::b2bua::actor::RouteSequenceState {
            pending: routes.into(),
            active: None,
            attempts: Vec::new(),
            active_since: None,
            active_progressed: false,
            active_legs_start: 0,
            send_socket: None,
            default_timeout: timeout_secs,
        },
    );
    let advanced = b2bua_advance_route(call_id, template, state);
    b2bua_dispatch_burned_routes(call_id, &advanced.burned, state);
    usize::from(advanced.dialed)
}

/// Command headers, with the target's own overriding on a key collision, and
/// this branch's asserted identity last.
///
/// `P-Asserted-Identity` rides here rather than being set on the template
/// because per-branch headers are injected *after* the header policy: an
/// identity named for this carrier outranks a preset's `P-*` strip set, the
/// same way the dial's own does.
fn merged_headers(
    extra_headers: &[(String, String)],
    target_headers: &std::collections::HashMap<String, String>,
    p_asserted_identity: Option<&str>,
) -> Vec<(String, String)> {
    let mut merged: std::collections::HashMap<String, String> =
        extra_headers.iter().cloned().collect();
    merged.extend(target_headers.clone());
    if let Some(identity) = p_asserted_identity {
        // Replace rather than add: the two spellings must not both reach the
        // wire in an undefined order.
        merged.retain(|name, _| !name.eq_ignore_ascii_case("P-Asserted-Identity"));
        merged.insert(
            "P-Asserted-Identity".to_string(),
            crate::sip::privacy::asserted_identity_value(identity),
        );
    }
    merged.into_iter().collect()
}

/// Report a controller-owned dial outcome and hand the decision back.
///
/// Returns `true` when the failure was the controller's to act on, which is the
/// caller's signal to stop: the caller is left unanswered, parked and owned, so
/// nothing may be forwarded to it and the call must not be torn down.
pub fn report_control_dial_failure(
    call_id: &str,
    status_code: u16,
    reason: &str,
    timed_out: bool,
    state: &DispatcherState,
) -> bool {
    if !state.call_actors.is_control_dial(call_id) {
        return false;
    }
    // An answered call is past the point a dial outcome means anything.
    if state
        .call_actors
        .get_call(call_id)
        .map(|call| matches!(call.state, CallState::Answered))
        .unwrap_or(false)
    {
        state.call_actors.set_control_dial(call_id, false);
        return false;
    }

    state.call_actors.set_control_dial(call_id, false);
    release_control_dial_media(call_id, state);
    // The rung legs are done; the caller is not. Dropping them here is what
    // lets the controller dial again on the same channel.
    state.call_actors.clear_b_legs(call_id);

    let Some(sip_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return false;
    };
    info!(
        call_id = %call_id,
        status_code,
        timed_out,
        "control plane: dial failed — the caller stays unanswered and parked"
    );
    control_notify_channel_event(
        &sip_call_id,
        "DialFailed",
        serde_json::json!({
            "code": status_code,
            "reason": reason,
            "timed_out": timed_out,
            "branches": control_dial_branches_for_failure(call_id, state),
        }),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_target(
        uri: &str,
        timeout_secs: Option<u32>,
        reroute_after_progress: bool,
    ) -> RouteTarget {
        RouteTarget {
            uri: uri.to_string(),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs,
            reroute_after_progress,
        }
    }

    /// A `route` verb hands siphon carriers from an out-of-process routing
    /// decision, so each is on the LCR progress rule unless its target opts out.
    #[test]
    fn route_verb_targets_carry_their_reroute_after_progress() {
        let routes = route_verb_routes(
            vec![
                route_target("sip:+15550100042@carrier-a.example.com", Some(6), false),
                route_target("sip:+15550100042@carrier-b.example.com", None, true),
            ],
            &[],
            30,
        );
        assert_eq!(routes.len(), 2);
        assert!(!routes[0].reroute_after_progress);
        assert_eq!(routes[0].timeout_secs, Some(6));
        assert!(routes[1].reroute_after_progress);
        assert_eq!(routes[1].timeout_secs, Some(30));
    }

    /// A sequential `dial` hunts through phones, each of which sends a 180 when
    /// it rings, so every target moves on at the dial's timeout.
    #[test]
    fn a_sequential_dial_hunts_whether_a_target_rang_or_not() {
        let targets = ["sip:1001@pbx.example.com", "sip:1002@pbx.example.com"]
            .into_iter()
            .map(|uri| DialTarget {
                uri: uri.to_string(),
                ..Default::default()
            })
            .collect();
        let routes = sequential_dial_routes(
            targets,
            vec![None, None],
            20,
            &[("X-Hunt".to_string(), "desk".to_string())],
            &DialShaping::default(),
        );
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.reroute_after_progress));
        assert!(routes.iter().all(|route| route.timeout_secs == Some(20)));
        assert_eq!(
            routes[0].headers.get("X-Hunt").map(String::as_str),
            Some("desk")
        );
    }

    /// CLIR has to survive the whole hunt, not just its first attempt, so the
    /// presentation rides on every route the failover engine takes.
    #[test]
    fn a_sequential_dial_carries_its_presentation_on_every_route() {
        let targets = ["sip:1001@pbx.example.com", "sip:1002@pbx.example.com"]
            .into_iter()
            .map(|uri| DialTarget {
                uri: uri.to_string(),
                ..Default::default()
            })
            .collect();
        let routes = sequential_dial_routes(
            targets,
            vec![None, None],
            20,
            &[],
            &DialShaping {
                privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
                ..Default::default()
            },
        );
        assert!(routes
            .iter()
            .all(|route| route.caller_id_presentation.as_deref() == Some("restricted")));

        let unspecified = sequential_dial_routes(
            vec![DialTarget {
                uri: "sip:1001@pbx.example.com".to_string(),
                ..Default::default()
            }],
            vec![None],
            20,
            &[],
            &DialShaping::default(),
        );
        assert!(unspecified[0].caller_id_presentation.is_none());
    }

    /// A target's own identity wins over the dial's, field by field.
    ///
    /// One dial can try two carriers that assigned different numbers, and the
    /// number a carrier accepts is a property of that carrier. Resolved per
    /// field rather than all-or-nothing, so a target naming only a `from`
    /// still inherits the dial's presentation — the same precedence `headers`
    /// already uses.
    #[test]
    fn a_target_identity_overrides_the_dials_field_by_field() {
        let dial = DialShaping {
            from: Some("sip:2025550100@pbx.example.com".to_string()),
            from_display: Some("Main Line".to_string()),
            p_asserted_identity: Some("sip:2025550100@pbx.example.com".to_string()),
            privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
            ..Default::default()
        };

        // Names its own number only: everything else comes from the dial.
        let partial = DialTarget {
            uri: "sip:carrier-a.example".to_string(),
            from: Some("sip:2025550199@carrier-a.example".to_string()),
            ..Default::default()
        };
        let shaped = partial.shaping_over(&dial);
        assert_eq!(
            shaped.from.as_deref(),
            Some("sip:2025550199@carrier-a.example"),
            "the target's own number must win"
        );
        assert_eq!(
            shaped.from_display.as_deref(),
            Some("Main Line"),
            "a field the target did not name is inherited"
        );
        assert_eq!(
            shaped.privacy,
            Some(crate::sip::privacy::CallerIdPresentation::Restricted)
        );

        // Names nothing: the dial's identity throughout.
        let inherited = DialTarget {
            uri: "sip:carrier-b.example".to_string(),
            ..Default::default()
        };
        let shaped = inherited.shaping_over(&dial);
        assert_eq!(shaped.from, dial.from);
        assert_eq!(shaped.p_asserted_identity, dial.p_asserted_identity);
    }

    /// Two carriers, two numbers, one hunt: each route carries its own.
    ///
    /// This is the case the whole-dial identity could not express — a
    /// sequential hunt across trunks that assigned different numbers could
    /// only present one of them correctly, and the other kept challenging the
    /// INVITE however correct the digest was.
    #[test]
    fn a_hunt_across_two_carriers_presents_each_carriers_own_number() {
        let targets = vec![
            DialTarget {
                uri: "sip:+15550100@carrier-a.example".to_string(),
                from: Some("sip:2025550111@carrier-a.example".to_string()),
                ..Default::default()
            },
            DialTarget {
                uri: "sip:+15550100@carrier-b.example".to_string(),
                from: Some("sip:2025550222@carrier-b.example".to_string()),
                p_asserted_identity: Some("sip:2025550222@carrier-b.example".to_string()),
                privacy: Some(crate::sip::privacy::CallerIdPresentation::Allowed),
                ..Default::default()
            },
        ];
        let dial = DialShaping {
            from: Some("sip:2025550100@pbx.example.com".to_string()),
            privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
            ..Default::default()
        };
        let branch_froms = branch_identities(
            &targets,
            &from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag"),
            &dial,
        )
        .expect("both identities are SIP URIs");
        let routes = sequential_dial_routes(targets, branch_froms, 20, &[], &dial);

        // `caller_id` substitutes a number, not a URI, so each route carries
        // its own carrier's user part.
        assert_eq!(routes[0].caller_id.as_deref(), Some("2025550111"));
        assert_eq!(routes[1].caller_id.as_deref(), Some("2025550222"));
        // The second carrier is trusted with the identity; the first inherits
        // the dial's restriction.
        assert_eq!(
            routes[0].caller_id_presentation.as_deref(),
            Some("restricted")
        );
        assert_eq!(routes[1].caller_id_presentation.as_deref(), Some("allowed"));
        assert_eq!(
            routes[1]
                .headers
                .get("P-Asserted-Identity")
                .map(String::as_str),
            Some("<sip:2025550222@carrier-b.example>"),
            "a branch's asserted identity rides its own headers, as a name-addr"
        );
        // Each route pins its own carrier's host, and presents no display name
        // since neither the target nor the dial named one.
        assert_eq!(routes[0].from_host.as_deref(), Some("carrier-a.example"));
        assert_eq!(routes[1].from_host.as_deref(), Some("carrier-b.example"));
        assert_eq!(
            routes[0].presented_from.as_deref(),
            Some("<sip:2025550111@carrier-a.example>;tag=caller-tag")
        );
    }

    /// The calling number inside an identity, for the per-carrier
    /// substitution: a URI contributes its user part, and anything that is not
    /// a URI is taken as the number it already is.
    #[test]
    fn a_dial_identity_yields_the_number_to_substitute() {
        assert_eq!(
            calling_number_of("sip:2025550111@carrier.example"),
            "2025550111"
        );
        assert_eq!(calling_number_of("2025550111"), "2025550111");
    }

    fn from_template(from: &str) -> SipMessage {
        parse_sip_message_bytes(
            format!(
                concat!(
                    "INVITE sip:1001@pbx.example.com SIP/2.0\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-identity\r\n",
                    "From: {from}\r\n",
                    "To: <sip:1001@pbx.example.com>\r\n",
                    "Call-ID: identity@192.0.2.10\r\n",
                    "CSeq: 1 INVITE\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n",
                ),
                from = from
            )
            .as_bytes(),
        )
        .expect("the template parses")
    }

    /// The dialog tag is the thing a `From` rewrite must never drop (RFC 3261
    /// §8.1.1.3) — a `From` written without it breaks every in-dialog request
    /// that follows, and only on the ACK, long after the rewrite looked fine.
    #[test]
    fn a_presented_identity_keeps_the_dialog_tag_and_reports_the_host_to_pin() {
        let mut template = from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag");
        let shaped = apply_dial_identity(
            &mut template,
            &DialShaping {
                from: Some("sip:15550100042@trunk.example.com".to_string()),
                from_display: Some("Example Ltd".to_string()),
                ..Default::default()
            },
        )
        .expect("a well-formed URI")
        .expect("something was shaped");
        assert_eq!(
            shaped.header,
            "\"Example Ltd\" <sip:15550100042@trunk.example.com>;tag=caller-tag"
        );
        assert_eq!(shaped.host.as_deref(), Some("trunk.example.com"));
        assert_eq!(
            template.headers.get("From").map(String::as_str),
            Some(shaped.header.as_str())
        );
    }

    /// Replacing the number while keeping "203" beside it would present the
    /// extension the `from` exists to hide.
    #[test]
    fn a_presented_identity_without_a_display_name_drops_the_callers() {
        let mut template = from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag");
        let shaped = apply_dial_identity(
            &mut template,
            &DialShaping {
                from: Some("sip:15550100042@trunk.example.com".to_string()),
                ..Default::default()
            },
        )
        .expect("a well-formed URI")
        .expect("something was shaped");
        assert_eq!(
            shaped.header,
            "<sip:15550100042@trunk.example.com>;tag=caller-tag"
        );
    }

    /// An empty display name removes the caller's rather than presenting an
    /// empty one, and leaves the URI alone.
    #[test]
    fn an_empty_display_name_removes_the_callers_and_keeps_the_uri() {
        let mut template = from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag");
        let shaped = apply_dial_identity(
            &mut template,
            &DialShaping {
                from_display: Some(String::new()),
                ..Default::default()
            },
        )
        .expect("no URI to parse")
        .expect("something was shaped");
        assert_eq!(shaped.header, "<sip:203@pbx.example.com>;tag=caller-tag");
        assert!(
            shaped.host.is_none(),
            "no host was named, so none is pinned"
        );
    }

    /// A dial that names no identity leaves the template exactly as it found
    /// it — every unshaped dial still presents the caller.
    #[test]
    fn a_dial_that_names_no_identity_shapes_nothing() {
        let mut template = from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag");
        let before = template.headers.get("From").cloned();
        assert!(apply_dial_identity(&mut template, &DialShaping::default())
            .expect("nothing to parse")
            .is_none());
        assert_eq!(template.headers.get("From").cloned(), before);
    }

    /// A URI siphon cannot put on the wire is an error, and the template is
    /// left alone: the caller is still parked and the controller still owns the
    /// decision, which beats ringing a phone under a broken identity.
    #[test]
    fn an_unparseable_presented_identity_is_an_error_that_changes_nothing() {
        let mut template = from_template("\"203\" <sip:203@pbx.example.com>;tag=caller-tag");
        let before = template.headers.get("From").cloned();
        assert!(apply_dial_identity(
            &mut template,
            &DialShaping {
                from: Some("not a uri".to_string()),
                from_display: Some("Example Ltd".to_string()),
                ..Default::default()
            },
        )
        .is_err());
        assert_eq!(template.headers.get("From").cloned(), before);
    }

    /// The asserted identity the controller named replaces one the command's
    /// own headers carried, whatever case that one was spelled in — two
    /// spellings of a single-value header reaching the wire in an order a
    /// HashMap decides is not a thing to leave to chance (RFC 3325 §9.1).
    #[test]
    fn a_named_asserted_identity_replaces_one_in_the_command_headers() {
        let headers = dial_headers_with_asserted_identity(
            &[
                ("X-Account".to_string(), "42".to_string()),
                (
                    "p-asserted-identity".to_string(),
                    "<sip:203@pbx.example.com>".to_string(),
                ),
            ],
            Some("<sip:15550100042@trunk.example.com>"),
        );
        assert_eq!(
            headers,
            vec![
                ("X-Account".to_string(), "42".to_string()),
                (
                    "P-Asserted-Identity".to_string(),
                    "<sip:15550100042@trunk.example.com>".to_string()
                ),
            ]
        );
    }

    /// Naming none leaves the command's headers exactly as they were.
    #[test]
    fn no_named_asserted_identity_leaves_the_command_headers_alone() {
        let given = [(
            "p-asserted-identity".to_string(),
            "<sip:203@pbx.example.com>".to_string(),
        )];
        assert_eq!(
            dial_headers_with_asserted_identity(&given, None),
            given.to_vec()
        );
    }
}
