//! Ending a call from anywhere other than a BYE on the wire: a script
//! `call.terminate()`, a control-plane hangup, a timer, a failed transfer.
use crate::dispatcher::*;

/// Stop and tear down any SIPREC recording sessions for a B2BUA call: send the
/// SRC-side BYE to each SRS and unsubscribe the RTPEngine media fork. Shared by
/// the inbound-BYE teardown ([`handle_b2bua_bye`]) and the framework-initiated
/// teardown ([`b2bua_terminate_call_inner`]).
pub fn b2bua_stop_siprec(internal_call_id: &str, state: &DispatcherState) {
    // Collect RTPEngine subscribe info before stop_recording cleans up sessions.
    let siprec_infos = state
        .recording_manager
        .active_session_infos(internal_call_id);
    let bye_messages = state
        .recording_manager
        .stop_recording(internal_call_id, state.local_addr);
    for (bye_msg, destination, transport) in bye_messages {
        let data = Bytes::from(bye_msg.to_bytes());
        let target = RelayTarget {
            address: destination,
            transport: Some(transport),
            server_name: None,
        };
        send_to_target(
            data,
            &target,
            transport,
            ConnectionId::default(),
            None,
            state,
        );
    }
    // RTPEngine unsubscribe: stop media forking for each recording session.
    if let Some(ref rtpengine_set) = state.rtpengine_set {
        for (original_call_id, original_from_tag, original_to_tag) in siprec_infos {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set
                    .unsubscribe(&original_call_id, &original_from_tag, &original_to_tag)
                    .await
                {
                    warn!(
                        call_id = %original_call_id,
                        "SIPREC: RTPEngine unsubscribe failed: {error}"
                    );
                }
            });
        }
    }
}

/// Build an RFC 3326 `Reason:` header value for a graceful, script-initiated
/// call teardown. Q.850 cause 16 = normal call clearing; the script-supplied
/// text rides along in `text=` (embedded quotes stripped so the header stays
/// well-formed).
pub fn format_normal_clearing_reason(reason: &str) -> String {
    let text = reason.replace('"', "");
    format!("Q.850;cause=16;text=\"{text}\"")
}

/// Full B2BUA call teardown initiated by the framework — session-timer expiry or
/// an imperative `b2bua.terminate` — NOT by an inbound BYE. Sends an in-dialog
/// BYE to BOTH legs from stored dialog state (a single-leg UAS call degrades to
/// just the A-leg), emits Rf ACR-STOP + a CDR + stops SIPREC (matching the
/// inbound-BYE teardown in [`handle_b2bua_bye`] so those per-call stores drain
/// here too), tears down media, and removes all dialog/registry state.
///
/// `reason_header` is a full RFC 3326 `Reason:` value added to each BYE and
/// recorded as the CDR `sip_reason`. `disconnect_initiator` is the CDR
/// disconnecting side (`"b2bua"` for a script terminate, `"timeout"` for
/// session-timer expiry). Returns `true` if the call existed.
pub fn b2bua_terminate_call_inner(
    internal_call_id: &str,
    reason_header: Option<&str>,
    disconnect_initiator: &str,
    state: &DispatcherState,
) -> bool {
    let (a_leg, winner_b_leg, sip_call_id) = match state.call_actors.get_call(internal_call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (call.a_leg.clone(), b_leg, call.a_leg.dialog.call_id.clone())
        }
        None => return false,
    };

    // Rf ACR-STOP (TS 32.299 §6.2.2). A framework-initiated teardown maps to the
    // Diameter "normal" cause (None → 0); the RFC 3326 Reason on the BYE is
    // informational only here (its Q.850 cause is not a SIP status).
    spawn_rf_b2bua_stop(state, internal_call_id, None);
    spawn_ro_b2bua_stop(state, internal_call_id, None);

    // CDR (cdr.auto_emit): write the record with the framework as the
    // disconnecting side and the Reason header as sip_reason.
    if crate::cdr::auto_emit_enabled() {
        cdr_finalize(
            &state.cdr_sessions,
            internal_call_id,
            disconnect_initiator,
            None,
            reason_header.map(|r| r.to_string()),
        );
    }

    // Build + send BYE to each leg using the shared build_b2bua_bye helper.
    // Destination derived from the dialog route set (RFC 3261 §12.2.1.1) — see
    // resolve_in_dialog_destination for why the cached transport.remote_addr is
    // wrong for routes that don't match the original INVITE next-hop.
    let build_bye = |leg: &Leg| -> Option<SipMessage> {
        let mut bye = build_b2bua_bye(leg, state)?;
        if let Some(reason) = reason_header {
            bye.headers.add("Reason", reason.to_string());
        }
        Some(bye)
    };
    if let Some(bye_msg) = build_bye(&a_leg) {
        let (destination, transport) = resolve_in_dialog_destination(
            &a_leg.dialog.route_set,
            state,
            a_leg.transport.remote_addr,
            a_leg.transport.transport,
        );
        // Source the framework BYE from the A-leg's anchored socket (Via matches).
        send_message_from(
            bye_msg,
            transport,
            destination,
            a_leg.transport.connection_id,
            a_leg.transport.local_addr,
            state,
        );
    }
    if let Some(b_leg) = &winner_b_leg {
        if let Some(bye_msg) = build_bye(b_leg) {
            // A 2xx that carried the offer and is still waiting for the caller's
            // answer is ACKed first, every stream rejected (RFC 3261 §13.2.2.4,
            // §15). Sourced from the B-leg's anchored socket (Via matches).
            let held_ack = take_held_ack_rejecting_offer(internal_call_id, state);
            send_bye_to_b_leg(b_leg, bye_msg, held_ack, state);
        }
    }

    // Safety-net RTPEngine cleanup.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(session.rtpengine_id(), &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "safety-net RTPEngine delete: call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                    }
                }
            });
        }
    }

    // SIPREC: stop any active recording sessions for this call.
    b2bua_stop_siprec(internal_call_id, state);

    // A bridged partner loses its other half here (idempotent: the half is
    // already gone when this teardown *is* the peer-hangup policy acting).
    b2bua_bridge_peer_left(&sip_call_id, state);

    // Control plane: emit StasisEnd + drop the channel if this call was
    // controlled (no-op otherwise).
    control_notify_terminated(&sip_call_id, reason_header.unwrap_or("terminated"));

    state
        .call_actors
        .set_state(internal_call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors and cleans up the
    // registry. A 2xx to a re-INVITE still in flight is ACKed from the response
    // itself when it arrives (`ack_late_2xx_after_teardown`).
    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
    true
}

/// Tear down a call whose transfer collapsed after the referrer had already
/// left, WITHOUT generating any further BYE.
///
/// The BYE-sending half of [`b2bua_terminate_call_inner`] is deliberately not
/// reused here: that helper BYEs the A-leg and the winning B-leg unconditionally,
/// and on this path one of those two is the referrer whose dialog is already
/// terminated — an in-dialog BYE addressed to it would be answered 481 (RFC 3261
/// §12.2.2). The caller has already released the one leg that is still up, so
/// this is the cleanup tail only: accounting, media, recording, actor removal.
pub fn b2bua_release_transferred_call(internal_call_id: &str, state: &DispatcherState) {
    let Some(sip_call_id) = state
        .call_actors
        .get_call(internal_call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return;
    };

    // Rf/Ro ACR-STOP (TS 32.299 §6.2.2) — framework-initiated teardown, so the
    // Diameter "normal" cause, same as the session-timer path.
    spawn_rf_b2bua_stop(state, internal_call_id, None);
    spawn_ro_b2bua_stop(state, internal_call_id, None);

    if crate::cdr::auto_emit_enabled() {
        cdr_finalize(&state.cdr_sessions, internal_call_id, "b2bua", None, None);
    }

    // Safety-net RTPEngine cleanup. Keyed on the A-leg Call-ID (the store key);
    // a transfer that never completed leaves the pre-transfer anchor in place,
    // and the fresh survivor↔target anchor offered in phase 1 is dropped by the
    // engine's own timeout since the target never answered.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(session.rtpengine_id(), &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "safety-net RTPEngine delete: call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                    }
                }
            });
        }
    }

    b2bua_stop_siprec(internal_call_id, state);
    control_notify_terminated(&sip_call_id, "transfer_failed");

    state
        .call_actors
        .set_state(internal_call_id, CallState::Terminated);
    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
}

/// Emit a control-plane `StasisEnd` for a controlled call at teardown (no-op
/// when the control plane isn't configured or the call isn't controlled).
pub fn control_notify_terminated(sip_call_id: &str, reason: &str) {
    if let Some(bus) = crate::control::ControlBus::global() {
        bus.on_call_terminated(sip_call_id, reason);
    }
}

/// [`control_notify_terminated`] carrying the SIP cause. Used by the originate
/// paths, where the controller has no other way to learn *why* the leg it
/// placed died — there is no A-leg the callee's final was relayed to.
pub fn control_notify_terminated_with_cause(
    sip_call_id: &str,
    reason: &str,
    code: Option<u16>,
    response: Option<&str>,
) {
    if let Some(bus) = crate::control::ControlBus::global() {
        bus.on_call_terminated_with_cause(sip_call_id, reason, code, response);
    }
}

/// Push a lifecycle event to the control channel owning `sip_call_id`, if the
/// call is controlled. A no-op when control is not configured / the call is
/// uncontrolled — never blocks the signalling path.
pub fn control_notify_channel_event(sip_call_id: &str, event: &str, payload: serde_json::Value) {
    crate::control::notify_channel_event(sip_call_id, event, payload);
}

/// Forward an in-band DTMF digit the media engine detected on a controlled
/// B2BUA call's leg to the owning control connection as a `ChannelDtmfReceived`
/// event, so an external IVR / AI app collects digits off the event stream.
///
/// **Additive** — this runs *next to*, never in place of, the Python
/// `@rtpengine.on_dtmf` dispatch, and fires independently of whether any Python
/// handler is registered. A no-op when the control plane isn't configured or the
/// call isn't controlled. `dtmf.call_id` is the media call-id, which equals the
/// SIP Call-ID the control bus keys the channel on for every control-anchored
/// call (see [`crate::control::ControlBus::forward_dtmf`]).
pub fn control_forward_dtmf(dtmf: &crate::rtpengine::events::DtmfEvent) {
    if let Some(bus) = crate::control::ControlBus::global() {
        bus.forward_dtmf(
            &dtmf.call_id,
            &dtmf.digit,
            dtmf.duration_ms,
            dtmf.volume,
            &dtmf.from_tag,
        );
    }
}

/// Imperatively reject / tear down a *controlled* B2BUA call that has not been
/// answered (a parked call the app declined, the handoff deadline elapsing, or a
/// hangup of an unanswered call). Sends a final non-2xx to the A-leg (tagged to
/// the A-leg dialog), finalizes the CDR as failed, emits `StasisEnd`, and removes
/// the call. Returns `false` (never panics) when the call is gone / dispatcher
/// down. Distinct from [`b2bua_terminate_call`] (which BYEs an *answered* call).
pub fn b2bua_reject_call(internal_call_id: &str, code: u16, reason: &str) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let state = &control.state;
    let (invite_arc, transport, remote_addr, connection_id, local_addr, local_tag, sip_call_id) =
        match state.call_actors.get_call(internal_call_id) {
            Some(call) => (
                call.a_leg_invite.clone(),
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.connection_id,
                call.a_leg_local_addr,
                call.a_leg.dialog.local_tag.clone(),
                call.a_leg.dialog.call_id.clone(),
            ),
            None => return false,
        };
    let Some(invite_arc) = invite_arc else {
        return false;
    };
    let _enter = control.runtime.enter();
    let Ok(invite) = invite_arc.lock() else {
        error!(call_id = %internal_call_id, "b2bua_reject_call: invite lock poisoned");
        return false;
    };

    // RFC 3261 §12.1.1: tag the To header with the A-leg dialog local_tag so the
    // final response terminates the same dialog the 180 opened.
    let mut reply_headers: Vec<(crate::script::api::request::ReplyHeaderOp, String, String)> =
        Vec::new();
    if let Some(to_value) = invite.headers.to() {
        if !to_value.contains(";tag=") {
            reply_headers.push((
                crate::script::api::request::ReplyHeaderOp::Replace,
                "To".to_string(),
                crate::b2bua::actor::ensure_tag(to_value, Some(&local_tag)),
            ));
        }
    }
    let response = build_response(
        &invite,
        code,
        reason,
        state.server_header.as_deref(),
        &reply_headers,
    );
    drop(invite);
    send_message_from(
        response,
        transport,
        remote_addr,
        connection_id,
        local_addr,
        state,
    );

    if crate::cdr::auto_emit_enabled() {
        cdr_finalize_b2bua_fail(state, internal_call_id, code);
    }
    // The final non-2xx this path just sent *is* the cause, and it is the only
    // record of it: nothing else reports which status ended a call the app
    // declined, the handoff deadline degraded (503), or an unanswered hangup
    // closed (603). RFC 3261 §8.1.3.4 leaves the meaning to the code plus the
    // reason phrase, so both go out.
    control_notify_terminated_with_cause(&sip_call_id, reason, Some(code), Some(reason));

    // Release any Ro reservation on the call. A script is free to
    // `call.ro_authorize()` and then `call.handover(...)`, which parks a call
    // holding a reservation with no B-leg behind it — and every way out of that
    // park that is not an answer lands here: the app declined, the handoff
    // deadline degraded, an unanswered hangup closed it, or `b2bua_route_call`
    // found no routable carrier. Same pre-answer window as the undialled paths,
    // and the final non-2xx just sent is the only status there is to report.
    spawn_ro_b2bua_stop(
        state,
        internal_call_id,
        crate::diameter::rf::sip_status_to_cause_code(code),
    );

    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
    true
}

/// Terminate a call due to session timer expiry (RFC 4028) — BYE both legs and
/// run the full framework teardown (Rf ACR-STOP + CDR + SIPREC + media), the
/// same funnel the imperative `b2bua.terminate` uses.
pub fn b2bua_session_timer_terminate(call_id: &str, state: &DispatcherState) {
    // Q.850 cause 102 = "recovery on timer expiry".
    b2bua_terminate_call_inner(
        call_id,
        Some("Q.850;cause=102;text=\"Session timer expired\""),
        "timeout",
        state,
    );
}

/// Terminate a call that has hit its maximum answered duration — BYE both legs
/// through the same framework teardown as the session timer (Rf/Ro ACR-STOP,
/// CDR, SIPREC, media release, `StasisEnd`).
///
/// Deliberately does not fire `@b2bua.on_bye`: no framework-initiated teardown
/// does (session-timer expiry, `call.terminate()`, `b2bua.terminate()`), and
/// `ByeInitiator.side` is defined as which *peer* sent the BYE. The CDR is the
/// record — `disconnect_initiator="timeout"`, with the Reason text below as
/// `sip_reason`, which is what separates this from a session-timer expiry.
pub fn b2bua_max_duration_terminate(call_id: &str, state: &DispatcherState) {
    // Q.850 cause 102 = "recovery on timer expiry" — the same class as the
    // session timer, since this too is a local timer ending an established
    // call rather than anything either peer did.
    b2bua_terminate_call_inner(
        call_id,
        Some("Q.850;cause=102;text=\"Maximum call duration exceeded\""),
        "timeout",
        state,
    );
}

/// End a call whose 2xx the caller never ACKed (RFC 3261 §13.3.1.4) — BYE both
/// legs through the same framework teardown as the session timer and the
/// maximum call duration (Rf/Ro ACR-STOP, CDR, SIPREC, media release,
/// `StasisEnd`). Returns `false` when the call is already gone, so a call torn
/// down another way is never sent a second BYE.
///
/// §13.3.1.4 is explicit that the dialog is confirmed by then and the session
/// SHOULD be ended with a BYE, and §15 allows that BYE once the 2xx has gone
/// 64*T1 without its ACK. Like the other timer teardowns, no Python handler
/// fires; the CDR records `disconnect_initiator="timeout"` with the Reason below.
pub fn b2bua_unacked_answer_terminate(call_id: &str, state: &DispatcherState) -> bool {
    // Q.850 cause 102 = "recovery on timer expiry". A local timer ended an
    // established call and neither party hung up, which is the case the session
    // timer and the maximum call duration already report with 102. Not 16
    // (normal clearing): nothing about this ending was normal. The text names
    // the timer, so a CDR tells it apart from those two.
    b2bua_terminate_call_inner(
        call_id,
        Some("Q.850;cause=102;text=\"No ACK received\""),
        "timeout",
        state,
    )
}

/// Handle to the running dispatcher, published once at startup so imperative
/// script APIs (e.g. `b2bua.terminate`) can reach dialog state and the tokio
/// runtime from any thread — an event-callback driver, a timer, or an async-pool
/// loop, none of which are tokio workers.
pub struct B2buaControlHandle {
    pub state: Arc<DispatcherState>,
    pub runtime: tokio::runtime::Handle,
}

pub static B2BUA_CONTROL: std::sync::OnceLock<B2buaControlHandle> = std::sync::OnceLock::new();

/// Imperatively tear down a B2BUA call identified by its SIP Call-ID, sending a
/// BYE to every leg and running the full teardown ([`b2bua_terminate_call_inner`]).
///
/// Safe to call from any thread/context (event callbacks like `@rtpengine.on_dtmf`,
/// timers, async handlers) — unlike the deferred `call.terminate()`, which only
/// applies when its own handler returns. Returns `false` (never panics) when the
/// call-id is unknown / already gone or the dispatcher is not running, so an IVR
/// that races a caller-initiated BYE is a clean no-op.
pub fn b2bua_terminate_call(sip_call_id: &str, reason: Option<&str>) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let Some(internal_call_id) = control.state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return false;
    };
    // The caller may be on a thread with no tokio context (async-pool asyncio
    // loop, rtpengine event driver); enter the runtime so the teardown's
    // tokio::spawn calls (RTPEngine delete, Rf ACR-STOP, SIPREC unsubscribe) are
    // valid.
    let _enter = control.runtime.enter();
    let reason_header = reason.map(format_normal_clearing_reason);
    b2bua_terminate_call_inner(
        &internal_call_id,
        reason_header.as_deref(),
        "b2bua",
        &control.state,
    )
}
