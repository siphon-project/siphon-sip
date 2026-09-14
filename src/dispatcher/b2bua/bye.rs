//! In-dialog BYE on a bridged call, and the RFC 4028 session-timer sweep
//! that ends one nothing refreshed.
use crate::dispatcher::*;

/// Handle a BYE for a B2BUA call — bridge to the other leg.
pub fn handle_b2bua_bye(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            // Lost a race with a concurrent teardown — the dispatch gate saw
            // this call, and it is gone by now. Same answer as the no-dialog-leg
            // arm below: 481, never a silent drop (RFC 3261 §15.1.2).
            warn!(sip_call_id = %sip_call_id, "B2BUA BYE: no matching call — 481");
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

    // In-dialog direction by dialog identity (RFC 3261 §12 — Call-ID + From-tag),
    // never by source socket: a peer that reconnects per transaction (TLS) or
    // rebinds its NAT port sends the BYE from a different address than its
    // INVITE. A Call-ID that matches no live dialog leg is answered 481 here,
    // before the Python on_bye handlers + CDR finalize below, so a stray BYE
    // can't close a CDR with a bogus direction.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA BYE: Call-ID matches no dialog leg — 481");
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

    // The referrer of an in-flight siphon-terminated transfer hanging up is NOT
    // the end of this call (RFC 5589 §7: the transferor is free to end its
    // dialog as soon as the REFER is accepted — Microsoft Teams BYEs within a
    // few hundred ms of the 202, long before the target answers). The surviving
    // party is still up and is waiting to be bridged to the transfer target, so
    // everything below — @b2bua.on_bye, the ACR-STOP/CDR close, the BYE
    // generated at the far leg, the rtpengine teardown and `remove_call` —
    // would destroy exactly the state the transfer needs to finish. Answer the
    // BYE and keep the call.
    //
    // Left in place deliberately: the referrer's `Leg` stays on the actor until
    // the target resolves, because `promote_transfer_target` swaps the target
    // into its slot and the old anchor keyed on the A-leg Call-ID is what the
    // media re-anchor reads. Only the subscription is flagged, which is what
    // suppresses the NOTIFY + BYE aimed at a dialog that no longer exists.
    if state
        .call_actors
        .mark_transfer_referrer_gone(&call_id, from_a_leg)
    {
        let bye_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(
            bye_response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        info!(
            call_id = %call_id,
            referrer_on_a_leg = from_a_leg,
            "B2BUA REFER (terminate): referrer hung up mid-transfer — call kept for the pending target"
        );
        return;
    }

    // Extract the rest from the DashMap ref and drop it before entering Python
    let (a_leg_invite, a_leg_source_ip, a_leg_transport, a_leg_call_id, a_leg_flow) =
        match state.call_actors.get_call(&call_id) {
            Some(call) => (
                call.a_leg_invite.clone(),
                call.a_leg.transport.remote_addr.ip().to_string(),
                format!("{}", call.a_leg.transport.transport).to_lowercase(),
                call.a_leg.dialog.call_id.clone(),
                py_flow_from_leg(&call.a_leg.transport),
            ),
            None => return,
        };

    // A bridged partner loses its other half here — before the StasisEnd, so
    // the controller sees the bridge end before the channel does.
    b2bua_bridge_peer_left(&a_leg_call_id, state);

    // Control plane: emit StasisEnd if this call was controlled (keyed on the
    // A-leg Call-ID, so a BYE from either leg reaches the owning app). No-op
    // otherwise.
    control_notify_terminated(&a_leg_call_id, "bye");

    // Invoke @b2bua.on_bye handlers with (PyCall, PyByeInitiator)
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaBye);
    if !handlers.is_empty() {
        let side = if from_a_leg {
            "a".to_string()
        } else {
            "b".to_string()
        };

        if let Some(invite_arc) = &a_leg_invite {
            let py_call = PyCall::new(
                call_id.clone(),
                Arc::clone(invite_arc),
                a_leg_source_ip,
                a_leg_transport,
            )
            .with_flow(a_leg_flow);
            let initiator = PyByeInitiator { side };

            Python::attach(|python| {
                let call_obj = match Py::new(python, py_call) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyCall for on_bye: {error}");
                        return;
                    }
                };
                let initiator_obj = match Py::new(python, initiator) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyByeInitiator: {error}");
                        return;
                    }
                };

                for handler in &handlers {
                    let callable = handler.callable.bind(python);
                    match callable.call1((call_obj.bind(python), initiator_obj.bind(python))) {
                        Ok(ret) => {
                            if handler.is_async {
                                if let Err(error) = run_coroutine(python, &ret) {
                                    record_script_error("async B2BUA on_bye", &error);
                                }
                            }
                        }
                        Err(error) => {
                            record_script_error("B2BUA on_bye", &error);
                        }
                    }
                }
            });
        } else {
            warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_bye");
        }
    }

    // Rf ACR-STOP on B2BUA BYE (TS 32.299 §6.2.2).  Fire before the
    // 200 OK is sent so the accounting record reflects the moment the
    // proxy committed to tearing the call down; the SIP path is
    // unaffected (spawn is fire-and-forget per §6.5).
    let disconnect_cause = parse_reason_cause(&message);
    spawn_rf_b2bua_stop(state, &call_id, disconnect_cause);
    spawn_ro_b2bua_stop(state, &call_id, disconnect_cause);

    // CDR: write the call record on BYE (cdr.auto_emit). `from_a_leg` gives the
    // disconnecting side (caller vs callee).
    cdr_finalize_b2bua_stop(state, &call_id, from_a_leg, &message);

    // Re-acquire the call ref for BYE bridging
    let call = match state.call_actors.get_call(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Send 200 OK to the BYE sender on the socket the BYE arrived on (multi-homed
    // UDP source-port parity — the in-dialog BYE now lands on the A-leg's anchored
    // listener after the Contact fix, so its 200 must leave from there too).
    let bye_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        bye_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Forward BYE to the other leg with full B2BUA header rewriting:
    // - Dialog headers (Call-ID, From/To tags)
    // - From URI host (topology hiding)
    // - CSeq (independent per dialog, RFC 3261)
    // - Max-Forwards (decrement per RFC 7332)
    if from_a_leg {
        // BYE from A → generate new B-leg BYE from stored dialog state.
        // A B2BUA MUST NOT forward the A-leg BYE — it generates a fresh request
        // using only B-leg dialog identifiers, route set, and Contact.
        if let Some(winner_index) = call.winner {
            if let Some(b_leg) = call.b_legs.get(winner_index) {
                if let Some(bye) = build_b2bua_bye(b_leg, state) {
                    // RFC 3261 §12.2.1.1: next hop is the first Route URI, not
                    // the cached destination of the original INVITE (which may
                    // have traversed nodes — e.g. an IMS I-CSCF — that don't
                    // Record-Route and so aren't in the dialog route set).
                    let (destination, transport) = resolve_in_dialog_destination(
                        &b_leg.dialog.route_set,
                        state,
                        b_leg.transport.remote_addr,
                        b_leg.transport.transport,
                    );
                    debug!(call_id = %call_id, %destination, "B2BUA: sending BYE to B-leg");
                    send_b2bua_to_bleg(
                        bye,
                        transport,
                        destination,
                        b_leg.transport.local_addr,
                        state,
                    );
                } else {
                    warn!(call_id = %call_id, "B2BUA: failed to build B-leg BYE");
                }
            } else {
                warn!(call_id = %call_id, "B2BUA: no winning B-leg for BYE");
            }
        } else {
            warn!(call_id = %call_id, "B2BUA: no winner set for BYE");
        }
    } else {
        // BYE from B → generate new A-leg BYE from stored dialog state.
        if let Some(bye) = build_b2bua_bye(&call.a_leg, state) {
            let (destination, transport) = resolve_in_dialog_destination(
                &call.a_leg.dialog.route_set,
                state,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.transport,
            );
            // Source the siphon-originated BYE from the A-leg's anchored socket so a
            // strict peer sees it from the port the dialog runs on (Via matches — see
            // build_b2bua_bye). No-op for single-listener hosts.
            send_message_from(
                bye,
                transport,
                destination,
                call.a_leg.transport.connection_id,
                call.a_leg.transport.local_addr,
                state,
            );
        }
    }

    // The rtpengine session is keyed by the A-leg Call-ID (the store key), which
    // is NOT the incoming BYE's Call-ID when the BYE comes from the B-leg (or from
    // the survivor/target after a terminate-transfer re-anchor). Capture it before
    // dropping the call so the safety-net delete below hits the right key.
    let media_key = call.a_leg.dialog.call_id.clone();
    drop(call);

    // Safety-net: if an RTPEngine media session exists for this call but the
    // script didn't delete it, clean up in the background.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&media_key) {
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
    b2bua_stop_siprec(&call_id, state);

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors and cleans up the
    // registry. A 2xx to a re-INVITE still in flight is ACKed from the response
    // itself when it arrives (`ack_late_2xx_after_teardown`).
    state.call_actors.remove_call(&call_id);
    state.call_event_receivers.remove(&call_id);
}

/// Sweep all active calls for session timer expiry (RFC 4028).
///
/// Called every ~5 seconds from a background task. For each call:
/// - If `elapsed > session_expires`: tear down the call (both legs).
/// - If `elapsed > session_expires / 2` and refresher is "b2bua": send refresh re-INVITE.
pub fn session_timer_sweep(state: &DispatcherState) {
    let now = std::time::Instant::now();

    // Collect calls needing action (avoid holding DashMap ref during send)
    let mut calls_to_refresh: Vec<String> = Vec::new();
    let mut calls_to_terminate: Vec<String> = Vec::new();

    // Iterate all calls — only look at Answered calls with a session timer
    for entry in state.call_actors.iter_calls() {
        let call = entry.value();
        if call.state != CallState::Answered {
            continue;
        }
        if let Some(ref timer) = call.session_timer {
            let elapsed = now.duration_since(timer.last_refresh);
            let expires = std::time::Duration::from_secs(timer.session_expires as u64);
            let half_expires = expires / 2;

            if elapsed >= expires {
                // Session expired — terminate
                calls_to_terminate.push(call.id.clone());
            } else if elapsed >= half_expires && timer.refresher == "b2bua" {
                // Time to refresh
                calls_to_refresh.push(call.id.clone());
            }
        }
    }

    // Send refresh re-INVITEs
    for call_id in calls_to_refresh {
        b2bua_send_refresh_reinvite(&call_id, state);
    }

    // Terminate expired calls
    for call_id in calls_to_terminate {
        info!(call_id = %call_id, "B2BUA: session timer expired, terminating call");
        b2bua_session_timer_terminate(&call_id, state);
    }
}
