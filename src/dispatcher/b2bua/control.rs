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
        }
    }
}

/// Resolve an AoR to one dial target per registered contact, each carrying its
/// own flow and Path route set.
///
/// This is what makes a phone on TCP, TLS or WSS reachable: such a contact is
/// only reachable over the connection it registered on, so DNS-resolving its
/// Contact URI (what `originate` does with a bare URI) reaches nothing. Mirrors
/// what a script gets from `call.fork(registrar.lookup(aor))`.
pub fn dial_targets_for_aor(aor: &str) -> Result<Vec<DialTarget>, DialError> {
    let Some(registrar) = crate::script::api::registrar_arc() else {
        return Err(DialError::NoContacts(aor.to_string()));
    };
    let contacts = registrar.lookup(aor);
    if contacts.is_empty() {
        return Err(DialError::NoContacts(aor.to_string()));
    }
    Ok(contacts
        .into_iter()
        .map(|contact| {
            // Each branch carries the route set of its *own* binding (RFC 3327
            // §5.3); a shared one would put every branch through the first
            // binding's proxy chain.
            let path: Vec<String> = contact.path.iter().map(|value| value.to_string()).collect();
            let route = crate::proxy::core::route_set_from_path(&path)
                .map(|value| vec![value])
                .unwrap_or_default();
            // The captured inbound flow, same view the scripting API hands to
            // `call.fork` — `None` for a binding whose socket has gone, which
            // then falls back to resolving the Contact URI.
            let flow = contact
                .flow()
                .map(|flow| crate::script::api::registrar::PyFlow {
                    transport: flow.transport.as_scheme().to_string(),
                    source_addr: flow.source_addr,
                    local_addr: flow.local_addr,
                    connection_id: flow.connection_id,
                });
            DialTarget {
                uri: contact.uri.to_string(),
                next_hop: None,
                flow,
                route,
                headers: std::collections::HashMap::new(),
            }
        })
        .collect())
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

    let template = {
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
            }),
        );
        refuse_bad_extension(&internal_call_id, &template, unsupported, state);
        return Ok(true);
    }

    // The controller has acted, so the handoff deadline no longer applies: what
    // bounds the call now is the dial's own timeout.
    state.call_actors.mark_controller_acted(&internal_call_id);
    // Ownership is deliberately NOT released — that is the whole difference
    // from `route`.
    state.call_actors.set_control_dial(&internal_call_id, true);

    let sent = if parallel {
        dial_parallel(&internal_call_id, &targets, extra_headers, &template, state)
    } else {
        dial_sequential(
            &internal_call_id,
            targets,
            timeout_secs,
            extra_headers,
            &template,
            state,
        )
    };

    if sent == 0 {
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
    extra_headers: &[(String, String)],
    template: &SipMessage,
    state: &DispatcherState,
) -> usize {
    let mut sent = 0usize;
    for target in targets {
        let headers = merged_headers(extra_headers, &target.headers);
        if b2bua_send_b_leg_invite(
            call_id,
            &target.uri,
            target.next_hop.as_deref(),
            target.flow.as_ref(),
            &target.route,
            None,
            None,
            template,
            None,
            None,
            None,
            None,
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
    timeout_secs: u32,
    extra_headers: &[(String, String)],
) -> Vec<crate::lcr::Route> {
    targets
        .into_iter()
        .map(|target| crate::lcr::Route {
            ruri: Some(target.uri),
            next_hop: target.next_hop,
            timeout_secs: Some(timeout_secs),
            headers: merged_headers(extra_headers, &target.headers)
                .into_iter()
                .collect(),
            reroute_after_progress: true,
            ..Default::default()
        })
        .collect()
}

/// Try the targets in order, advancing on failure, via the same failover engine
/// the LCR path uses — but with the call still owned by its controller, so the
/// exhausted sequence reports `DialFailed` rather than failing the caller.
fn dial_sequential(
    call_id: &str,
    targets: Vec<DialTarget>,
    timeout_secs: u32,
    extra_headers: &[(String, String)],
    template: &SipMessage,
    state: &DispatcherState,
) -> usize {
    let routes = sequential_dial_routes(targets, timeout_secs, extra_headers);
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

/// Command headers, with the target's own overriding on a key collision.
fn merged_headers(
    extra_headers: &[(String, String)],
    target_headers: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut merged: std::collections::HashMap<String, String> =
        extra_headers.iter().cloned().collect();
    merged.extend(target_headers.clone());
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
        let routes =
            sequential_dial_routes(targets, 20, &[("X-Hunt".to_string(), "desk".to_string())]);
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().all(|route| route.reroute_after_progress));
        assert!(routes.iter().all(|route| route.timeout_secs == Some(20)));
        assert_eq!(
            routes[0].headers.get("X-Hunt").map(String::as_str),
            Some("desk")
        );
    }
}
