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
    let state = &control.state;
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

    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread — establish the runtime.
    let _enter = control.runtime.enter();

    // Build the failover queue from the targets (R-URI-only carriers, mirroring
    // call.rs's call.route() / fork(strategy="sequential") construction). A
    // command-level `extra_headers` set applies to every attempt; a per-target
    // header overrides it on key collision.
    let default_timeout = 30u32;
    let routes: Vec<crate::lcr::Route> = targets
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
                ..Default::default()
            }
        })
        .collect();

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

    // Un-park: start the sequential-failover sequence and dial the first carrier.
    let carrier_count = routes.len();
    state.call_actors.start_route_sequence(
        &internal_call_id,
        crate::b2bua::actor::RouteSequenceState {
            pending: routes.into(),
            active: None,
            attempts: Vec::new(),
            active_since: None,
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
    let state = &control.state;
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
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread (async-pool asyncio loop), so establish the runtime.
    let _enter = control.runtime.enter();

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
    // A locally-generated 2xx needs the same retransmission cover as a relayed
    // one: the B2BUA intercepts the A-leg INVITE before a server transaction
    // exists, so nothing under this recovers a lost 200 and the caller would
    // ring on until it gave up. Cancelled by the caller's ACK in the late-ACK
    // handler (search `uas_2xx_retransmits`).
    let retransmit = if final_response && (200..300).contains(&code) {
        Some(response.clone())
    } else {
        None
    };
    send_message_from(
        response,
        transport,
        remote_addr,
        connection_id,
        local_addr,
        state,
    );
    if let Some(retransmit) = retransmit {
        arm_b2bua_2xx_retransmit(
            internal_call_id,
            retransmit,
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
    // After anchored early media the caller already holds siphon's SDP answer
    // from the 18x; a 2xx sent without a body repeats it (RFC 3264 §4) rather
    // than reaching the caller as a 200 that silently drops the session.
    let (body, content_type) = match body {
        Some(body) => (Some(body), content_type),
        None => match B2BUA_CONTROL.get().and_then(|control| {
            control
                .state
                .call_actors
                .early_media_anchor(internal_call_id)
        }) {
            Some(anchor) => (
                Some(anchor.answer_sdp.into_bytes()),
                Some("application/sdp"),
            ),
            None => (None, content_type),
        },
    };
    b2bua_send_uas_response(
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
