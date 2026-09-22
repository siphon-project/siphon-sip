//! CANCEL of an unanswered B2BUA call (RFC 3261 §9).
//!
//! The only teardown that on_failure and on_bye never cover: neither fires for
//! a call the caller abandoned before any final response.

use crate::dispatcher::*;

/// Handle CANCEL for a B2BUA call — cancel all pending B-legs.
pub fn handle_b2bua_cancel(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA CANCEL: no matching call");
            let response = build_response(
                &message,
                481,
                "Call/Transaction Does Not Exist",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            return;
        }
    };

    // We need a mutable handle: per-leg we either (a) send the CANCEL
    // immediately from the stashed B-leg INVITE, or (b) flag the leg
    // with pending_cancel=true so the CANCEL is emitted the moment
    // b2bua_send_b_leg_invite finishes stashing the INVITE (race
    // between the upstream CANCEL and the script's call.dial() actually
    // putting the B-leg INVITE on the wire).
    let mut call = match state.call_actors.get_call_mut(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Only cancel if call is still in Calling or Ringing state
    if call.state != CallState::Calling && call.state != CallState::Ringing {
        // Unless the callee answered and the caller's 2xx is still held for a
        // PRACK (RFC 3262 §3), or for the 200 answering an offer in one (§5):
        // the caller has had no final response, so its
        // CANCEL still ends the call (RFC 3261 §9.2). The teardown sends the
        // caller its 487 and the callee, which answered, a BYE.
        let answer_held = call.a_leg_reliability.holds_answer() || call.prack_bridge.holds_answer();
        drop(call);
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        if answer_held {
            info!(call_id = %call_id, "B2BUA CANCEL: the caller's 2xx was still held for its PRACK — ending the call");
            // The answer never reached the caller, so it does not stand.
            cdr_clear_b2bua_answer(state, &call_id);
            b2bua_terminate_call_inner(
                &call_id,
                Some("SIP;cause=487;text=\"Request Terminated\""),
                "caller",
                state,
            );
        } else {
            debug!(call_id = %call_id, "B2BUA CANCEL: call already answered/terminated");
        }
        return;
    }

    // Send 200 OK to CANCEL (on the socket the CANCEL arrived on — the same
    // listener the INVITE landed on, per RFC 3261 §9: the caller sends CANCEL to
    // the INVITE's next hop). Pins the source port for multi-homed UDP.
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Send CANCEL to all pending B-legs.
    //
    // RFC 3261 §9.1 — the CANCEL on each B-leg MUST share the *B-leg
    // INVITE*'s topmost Via branch and CSeq sequence number, NOT the
    // inbound A-leg CANCEL's.  Rebuild from the stashed B-leg INVITE
    // ([Leg::b_leg_invite], populated at the end of
    // [b2bua_send_b_leg_invite]).  Legs whose INVITE hasn't been sent
    // yet get marked pending_cancel; the CANCEL drains automatically
    // once the stash lands.
    let mut bleg_targets: Vec<(SipMessage, Transport, SocketAddr, Option<SocketAddr>)> = Vec::new();
    let pending: Vec<bool> = (0..call.b_legs.len())
        .map(|index| call.is_pending_branch(index))
        .collect();
    for (index, b_leg) in call.b_legs.iter_mut().enumerate() {
        // A fork branch that already has its final response, or was CANCELled
        // when a sibling declined, has nothing left to cancel (RFC 3261 §9.1).
        if !pending.get(index).copied().unwrap_or(false) {
            continue;
        }
        match b_leg.b_leg_invite.as_ref() {
            Some(invite_arc) => {
                let invite = match invite_arc.lock() {
                    Ok(guard) => guard.clone(),
                    Err(_) => {
                        warn!(call_id = %call_id, "B2BUA CANCEL: b_leg_invite mutex poisoned, skipping leg");
                        continue;
                    }
                };
                match build_cancel_from_invite(&invite) {
                    Some(cancel_msg) => {
                        bleg_targets.push((
                            cancel_msg,
                            b_leg.transport.transport,
                            b_leg.transport.remote_addr,
                            b_leg.transport.local_addr,
                        ));
                    }
                    None => {
                        warn!(call_id = %call_id, "B2BUA CANCEL: failed to build CANCEL from stashed INVITE");
                    }
                }
            }
            None => {
                // Race: CANCEL arrived before this B-leg's INVITE was
                // actually sent.  Defer — b2bua_send_b_leg_invite drains
                // pending_cancel after stashing b_leg_invite.
                debug!(
                    call_id = %call_id,
                    leg_id = %b_leg.id,
                    "B2BUA CANCEL: deferred (b_leg_invite not yet stashed)"
                );
                b_leg.pending_cancel = true;
            }
        }
    }

    // Send Cancel to all B-leg actor handles
    for handle in call.b_leg_handles.iter().flatten() {
        let _ = handle.tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }

    // RFC 3262 §3: the 487 below is the caller's final response, so siphon's
    // reliable provisionals to it stop being retransmitted. No 2xx is held for a
    // PRACK here: holding one leaves the call answered, which returned above.
    let _ = call.a_leg_reliability.finish();

    // Send 487 Request Terminated to A-leg for the original INVITE.
    // Capture the stored A-leg INVITE + source before dropping the call ref so
    // @b2bua.on_cancel can run after the lock is released (no DashMap reentry).
    let a_leg = call.a_leg.clone();
    let cancel_a_leg_invite = call.a_leg_invite.clone();
    let cancel_a_leg_source_ip = call.a_leg.transport.remote_addr.ip().to_string();
    let cancel_a_leg_transport = format!("{}", call.a_leg.transport.transport).to_lowercase();
    let cancel_a_leg_flow = py_flow_from_leg(&call.a_leg.transport);
    drop(call);

    // Emit the prepared CANCELs after dropping the call lock so the
    // outbound path doesn't reenter the DashMap.
    for (cancel_msg, b_transport, b_dest, b_local) in bleg_targets {
        send_b2bua_to_bleg(cancel_msg, b_transport, b_dest, b_local, state);
    }

    // The 487 to the A-leg leaves on the socket the CANCEL (== the INVITE) arrived
    // on, so a multi-homed UDP host answers with a consistent source port.
    let response_487 = build_response(
        &message,
        487,
        "Request Terminated",
        state.server_header.as_deref(),
        &[],
    );
    send_message_from(
        response_487,
        a_leg.transport.transport,
        a_leg.transport.remote_addr,
        a_leg.transport.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Fire @b2bua.on_cancel before tearing the call out of the registry so a
    // script can release per-call resources (rtpengine media, QoS) that no BYE
    // will ever clear — the only teardown signal for a cancelled-before-answer
    // B2BUA call (RFC 3261 §9). A 2xx that races this CANCEL is independently
    // ACK+BYE'd by handle_zombie_cancelled_2xx and never delivered on_answer,
    // so this only ever fires for a genuinely abandoned call.
    run_b2bua_cancel_handlers(
        &call_id,
        cancel_a_leg_invite,
        cancel_a_leg_source_ip,
        cancel_a_leg_transport,
        cancel_a_leg_flow,
        state,
    );

    // Control plane: a handed-over call CANCELled before the controller acted is
    // the same teardown the answered/failed paths hook — emit StasisEnd + drop
    // the ControlBus channel so the owning app learns to abort and no owner
    // entry leaks (keyed on the A-leg Call-ID == this CANCEL's Call-ID; no-op for
    // an uncontrolled call). The cause is 487: RFC 3261 §9.2 has the UAS answer
    // the CANCELled INVITE `487 Request Terminated`, which is the status the
    // caller saw — an app that branches on the code must read the same one.
    control_notify_terminated_with_cause(
        &sip_call_id,
        "cancelled",
        Some(487),
        Some("Request Terminated"),
    );

    // LCR: the carrier that was ringing when the caller gave up, and every
    // carrier burned on the way to it, before the record is closed. The answer
    // path and the exhausted-sequence path both stamp these; this one did not,
    // and it is the only teardown where the carrier in flight is neither a
    // winner nor a failed attempt — so a cancelled call named no carrier
    // anywhere on the CDR feed, leaving nothing to reconcile the charging
    // record against.
    if let Some(route) = state.call_actors.active_route(&call_id) {
        cdr_stamp_route_fields(state, &call_id, &route.cdr_fields);
    }
    cdr_stamp_route_attempts(state, &call_id);

    // CDR: the caller CANCELled before answer (cdr.auto_emit) → 487.
    cdr_finalize_b2bua_fail(state, &call_id, 487);

    // Release any Ro reservation made by `call.ro_authorize()` — a
    // cancelled-before-answer call held a reservation with no BYE to close it
    // (CCR-TERMINATION reports ~0 usage). The caller gave up before answer, so
    // the cause is the 487 the A-leg was answered with.
    spawn_ro_b2bua_stop(
        state,
        &call_id,
        crate::diameter::rf::sip_status_to_cause_code(487),
    );

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call_after_cancel sends Shutdown to remaining actors, cleans the
    // registry, and preserves still-pending B-legs as zombie-cancelled entries
    // so a 2xx that raced this CANCEL (RFC 3261 §9.1) can still be ACKed + BYEd
    // by handle_response → handle_zombie_cancelled_2xx instead of being dropped
    // as an unknown branch (which leaves the callee retransmitting 200 OK then
    // BYEing the half-open dialog).
    if state.call_actors.remove_call_after_cancel(&call_id) {
        schedule_zombie_cancelled_cleanup(state.call_actors.clone());
    }
    state.call_event_receivers.remove(&call_id);
}

/// Fire `@b2bua.on_cancel` handlers for an unanswered call (Calling/Ringing)
/// that was CANCELled.
///
/// Fire-and-forget cleanup — the 487 to the A-leg has already been sent and
/// the call is being torn down regardless. This is the B2BUA teardown signal
/// that `on_failure` (B-leg error) and `on_bye` (answered call) never cover,
/// so a script can release per-call resources that no BYE will clear
/// (rtpengine media, QoS). Mirrors the `on_bye` PyCall construction.
pub fn run_b2bua_cancel_handlers(
    call_id: &str,
    a_leg_invite: Option<Arc<std::sync::Mutex<SipMessage>>>,
    a_leg_source_ip: String,
    a_leg_transport: String,
    a_leg_flow: Option<crate::script::api::registrar::PyFlow>,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaCancel);
    if handlers.is_empty() {
        return;
    }

    let invite_arc = match &a_leg_invite {
        Some(arc) => Arc::clone(arc),
        None => {
            warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_cancel");
            return;
        }
    };

    let py_call = PyCall::new(
        call_id.to_string(),
        invite_arc,
        a_leg_source_ip,
        a_leg_transport,
    )
    .with_flow(a_leg_flow);

    Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for on_cancel: {error}");
                return;
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async B2BUA on_cancel", &error);
                        }
                    }
                }
                Err(error) => {
                    record_script_error("B2BUA on_cancel", &error);
                }
            }
        }
    });
}
