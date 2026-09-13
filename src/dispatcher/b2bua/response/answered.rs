//! The B-leg answered: `@b2bua.on_answer`, the session timer, and turning
//! the B-leg 2xx into the A-leg's.

use crate::dispatcher::*;

/// A 2xx (or a retransmit of one) on the B-leg: run `@b2bua.on_answer`,
/// negotiate the session timer, and relay the answer to the A-leg.
pub fn b_leg_answered(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) {
    // --- 2xx answer handling ---
    if (200..300).contains(&status_code) {
        // Atomically claim the answer. Under load, two B-leg 200s for the same
        // call (the answer plus a retransmit, or a fork glare) can be processed
        // concurrently; `snapshot.call_state` is snapshotted at the top of this function
        // and only flipped to Answered below, so both could pass a stale
        // "not answered" check and both forward to the A-leg — delivering a
        // duplicate 200 to a caller that already ACKed (the "Dead call
        // (successful)" the UAC logs, and an occasional failed call when a
        // forward lands after the A-leg freed its state). Claim under the
        // per-call lock so exactly one 2xx wins and forwards; the rest are
        // absorbed here. A FirstWin also sets the winner + Answered (replacing
        // the set_winner below). `None` = no matched B-leg (defensive) — fall
        // back to the pre-atomic snapshot check.
        if absorb_answered_retransmit(call_id, message, state, snapshot) {
            return;
        }

        // (siphon-terminated transfer-target responses are intercepted earlier,
        // before the class match, so they never reach this normal-answer path.)

        // 2xx — this is the winning answer; the winner + Answered state were
        // claimed atomically above (try_win), so there is nothing to set here.

        // Record the winning B-leg's own raw endpoint SDP (its 200 answer,
        // captured before the @b2bua.on_answer script / rtpengine rewrite below)
        // so a later siphon-terminated transfer where this leg is the survivor
        // can offer its real media to the transfer target.
        if !message.body.is_empty() {
            state
                .call_actors
                .set_leg_last_sdp(call_id, false, &message.body);
        }

        // CDR: stamp the answer time (cdr.auto_emit).
        cdr_mark_b2bua_answer(state, call_id, status_code);

        // LCR: auto-stamp the winning carrier's cdr_fields onto the CDR, and
        // record it on the Ro session so every later CCR in that session names
        // the carrier that actually carried the call. Under sequential failover
        // that is not necessarily the one the CCR-INITIAL was built for, so it
        // cannot be inferred from the initial request.
        if let Some(route) = state.call_actors.active_route(call_id) {
            cdr_stamp_route_fields(state, call_id, &route.cdr_fields);
            ro_stamp_winning_carrier(state, call_id, &route.carrier_id);
        }
        cdr_stamp_route_attempts(state, call_id);

        // Charging is NOT reported here. Both emissions below moved to after
        // @b2bua.on_answer, because the handler is where the media backend is
        // driven and so where a call that can never carry audio is found out:
        // reporting the answer first billed a call siphon was about to fail.
        // See the failure gate under the handler block.

        // Wrap the 200 OK in Arc<Mutex<>> so Python handlers can modify SDP in-place
        let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));

        // A `call.refer()` issued from @b2bua.on_answer, held until the A-leg
        // 2xx has been sent (see where it is taken, further down).
        let mut deferred_outbound_refer: Option<crate::sip::headers::refer::ReferTo> = None;

        // Set when an @b2bua.on_answer handler raised, or asked for the call to
        // be terminated. Either way the A-leg is failed instead of answered —
        // see the gate below the handler block.
        let mut answer_handler_raised = false;
        let mut answer_wants_terminate = false;

        // Invoke @b2bua.on_answer handlers with (PyCall, PyReply)
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaAnswer);
        if !handlers.is_empty() {
            if let Some(invite_arc) = &snapshot.a_leg_invite {
                let mut py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    snapshot.a_leg.transport.remote_addr.ip().to_string(),
                    format!("{}", snapshot.a_leg.transport.transport).to_lowercase(),
                )
                .with_flow(py_flow_from_leg(&snapshot.a_leg.transport));
                // LCR: surface the carrier that won as `call.active_route` so the
                // script can stamp it onto a CDR / charging record, and the
                // carriers it had to burn to get there as `call.route_attempts`
                // — an answered call that failed over used to record that
                // nowhere.
                if let Some(route) = state.call_actors.active_route(call_id) {
                    py_call.set_active_route(route);
                }
                py_call.set_route_attempts(state.call_actors.route_attempts(call_id));
                let py_reply = PyReply::new(Arc::clone(&response_arc))
                    .with_a_leg(Arc::clone(invite_arc))
                    .with_response_source(response_source.ip().to_string(), response_source.port());

                // `raised` reports whether ANY handler failed — a construction
                // error for the Python objects counts, since a handler that was
                // never called cannot have made the media decision the call
                // depends on.
                let (answer_action, raised) =
                    Python::attach(|python| -> (Option<CallAction>, bool) {
                        let call_obj = match Py::new(python, py_call) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyCall for on_answer: {error}");
                                return (None, true);
                            }
                        };
                        let reply_obj = match Py::new(python, py_reply) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for on_answer: {error}");
                                return (None, true);
                            }
                        };

                        let mut raised = false;
                        for handler in &handlers {
                            let callable = handler.callable.bind(python);
                            match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async B2BUA on_answer handler error: {error}");
                                            raised = true;
                                        }
                                    }
                                }
                                Err(error) => {
                                    record_script_error("B2BUA on_answer", &error);
                                    raised = true;
                                }
                            }
                        }
                        let borrowed = call_obj.borrow(python);
                        (Some(borrowed.action().clone()), raised)
                    });
                answer_handler_raised = raised;

                // Deferred call.refer() from @b2bua.on_answer: an outbound
                // REFER to the A-leg (the connected caller).
                //
                // NOT sent here. The A-leg 200 OK is only forwarded further
                // down this function, so emitting the REFER at this point put
                // it on the wire *ahead of the answer*: the caller received an
                // in-dialog REFER for a dialog it did not yet consider
                // established (RFC 3261 §13.2.2.4 — the UAC confirms the dialog
                // on the 2xx), which a real UA answers 481. Carried to after
                // the 2xx send instead.
                match classify_answer_action(answer_action) {
                    AnswerAction::DeferRefer(refer_to) => {
                        deferred_outbound_refer = Some(refer_to);
                    }
                    AnswerAction::Terminate => answer_wants_terminate = true,
                    AnswerAction::Connect => {}
                    AnswerAction::Inapplicable(action) => warn!(
                        call_id = %call_id,
                        action = ?action,
                        "B2BUA: this call action has no effect from @b2bua.on_answer and was ignored"
                    ),
                }
            } else {
                warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_answer");
            }
        }

        // A failed @b2bua.on_answer must not resolve to a connected call.
        //
        // The handler is where the media backend is driven, so a media session
        // that could not be built — a codec the engine will not bridge, an
        // engine that refused the answer — surfaces here as a raise, and it
        // surfaces BEFORE the A-leg 2xx goes out further down this function.
        // Swallowing it answered the caller anyway and started the charging
        // clock on a call with no media path in either direction, which then
        // billed until the far end gave up. A raise is therefore a decision to
        // fail the call, and `call.terminate()` says the same thing explicitly.
        if answer_handler_raised || answer_wants_terminate {
            let cause = if answer_handler_raised {
                "@b2bua.on_answer handler raised"
            } else {
                "@b2bua.on_answer called call.terminate()"
            };
            b2bua_fail_after_answer(
                call_id,
                cause,
                &snapshot.a_leg,
                snapshot.a_leg_invite.as_ref(),
                snapshot.a_leg_local_addr,
                snapshot.b_leg_index,
                message,
                state,
            );
            return;
        }

        // Rf ACR-START on B2BUA call answer (TS 32.299 §6.2.2).
        // Fire-and-forget per TS 32.299 §6.5.
        //
        // Reported here, after the gate above, rather than on arrival of the
        // 2xx: an answer siphon is about to turn into a failure is not an
        // answer, and a CDF/OCS that was told otherwise had no later record
        // correcting it.
        if let Some(invite_arc) = &snapshot.a_leg_invite {
            spawn_rf_b2bua_start(state, call_id, invite_arc);
        }
        // Ro is not *started* here — prepaid reserve-before-connect means the
        // CCR-INITIAL already fired in `@b2bua.on_invite` via
        // `call.ro_authorize()`, before the B-leg was dialed, and the re-auth
        // loop it armed keeps running. But the answer is what starts the
        // chargeable clock (TS 32.260 §5), so report it: a CCR-UPDATE carrying
        // Time-Stamps tells the OCS when charging actually began, and under
        // `ro.charge_from: answer` it is also what stops ring time being billed.
        spawn_ro_b2bua_answer(state, call_id);

        // Resolve SRS URI from config when li.record() was called
        let li_srs_uri = if snapshot.li_record {
            state.li_siprec_srs_uri.as_deref()
        } else {
            None
        };

        // RFC 4028: Activate session timer from negotiated 200 OK headers
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                // Parse Session-Expires from 200 OK (e.g. "1800;refresher=uas")
                let Ok(response_lock) = response_arc.lock() else {
                    error!("response_arc lock poisoned during session timer parsing");
                    return;
                };
                let (negotiated_expires, negotiated_refresher) =
                    if let Some(se_header) = response_lock.headers.get("Session-Expires") {
                        let parts: Vec<&str> = se_header.split(';').collect();
                        let expires = parts[0]
                            .trim()
                            .parse::<u32>()
                            .unwrap_or(timer_config.session_expires);
                        let refresher = parts
                            .iter()
                            .find(|p| p.trim().starts_with("refresher="))
                            .map(|p| p.trim().trim_start_matches("refresher=").to_string())
                            .unwrap_or_else(|| "b2bua".to_string());
                        (expires, refresher)
                    } else {
                        // Remote didn't include Session-Expires — use our config defaults
                        (timer_config.session_expires, "b2bua".to_string())
                    };
                drop(response_lock);

                let timer_state = crate::b2bua::actor::SessionTimerState {
                    session_expires: negotiated_expires,
                    refresher: negotiated_refresher.clone(),
                    last_refresh: std::time::Instant::now(),
                };
                state.call_actors.set_session_timer(call_id, timer_state);

                debug!(
                    call_id = %call_id,
                    session_expires = negotiated_expires,
                    refresher = %negotiated_refresher,
                    "B2BUA: session timer activated"
                );
            }
        }

        // Extract the (possibly SDP-modified) response and forward to A-leg
        let mut response = match Arc::try_unwrap(response_arc) {
            Ok(mutex) => mutex
                .into_inner()
                .unwrap_or_else(|error| error.into_inner()),
            Err(arc) => arc
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
        };

        // Inject session timer headers into the response forwarded to the A-leg.
        // RFC 4028 §7.4/§9: a UAS MUST NOT drive a session timer (least of all
        // `refresher=uac`) toward a UAC that did not advertise `Supported: timer`
        // (or `Require: timer`) — the refresh it would expect never comes and the
        // call is torn down at expiry. So only inject when the A-leg INVITE
        // advertised timer support; otherwise leave the response untouched.
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                let a_leg_supports_timer = snapshot
                    .a_leg_invite
                    .as_ref()
                    .and_then(|arc| arc.lock().ok())
                    .map(|invite| {
                        let has = |name: &str| {
                            invite
                                .headers
                                .get_all(name)
                                .map(|values| {
                                    values
                                        .iter()
                                        .any(|v| v.to_ascii_lowercase().contains("timer"))
                                })
                                .unwrap_or(false)
                        };
                        has("Supported") || has("Require")
                    })
                    .unwrap_or(false);
                if a_leg_supports_timer {
                    if response.headers.get("Supported").is_none() {
                        response.headers.add("Supported", "timer".to_string());
                    }
                    if response.headers.get("Session-Expires").is_none() {
                        response.headers.add(
                            "Session-Expires",
                            format!("{};refresher=uac", timer_config.session_expires),
                        );
                    }
                }
            }
        }

        let b_leg_record_routes = prepare_a_leg_answer(call_id, &mut response, state, snapshot);

        // Late ACK pattern (RFC 3261 §14.1 compliant): do NOT ACK the B-leg
        // immediately. Instead, forward the 200 OK to A-leg and wait for A-leg's
        // ACK before ACKing B-leg. This keeps the B-leg INVITE transaction alive,
        // preventing the B-leg from sending re-INVITEs before the A-leg has ACKed.
        // The B-leg will retransmit 200 OK (Timer G) — we absorb those silently
        // until A-leg ACKs and we send our ACK to B-leg.
        ack_b_leg_2xx(call_id, message, state, snapshot, &b_leg_record_routes);

        // Extract SDP body before forwarding (needed for SIPREC)
        let sdp_body = response.body.clone();

        // Clone the sanitized 2xx before it is moved into send_message so the
        // A-leg retransmit is byte-identical (RFC 3261 §13.3.1.4).
        let retransmit_2xx = response.clone();

        // Pin the reply egress socket to the listener the A-leg INVITE arrived on
        // (`snapshot.a_leg_local_addr`) so a multi-homed UDP host answers on the same port
        // it received on — a peer doing symmetric signalling drops a 2xx sourced
        // from a different local port. No-op for TCP/TLS/WS/WSS (routed by the
        // accepted connection) and for a single-listener host (`udp_by_local` empty).
        send_message_from(
            response,
            snapshot.a_leg.transport.transport,
            snapshot.a_leg.transport.remote_addr,
            snapshot.a_leg.transport.connection_id,
            snapshot.a_leg_local_addr,
            state,
        );

        // Arm A-leg 2xx retransmission — the B2BUA has no IST for the A-leg, so
        // nothing else recovers a lost 200. Cancelled by the caller's ACK in the
        // late-ACK handler (search `uas_2xx_retransmits`). Done before the SIPREC
        // block below so its early returns can't skip it.
        arm_b2bua_2xx_retransmit(
            call_id,
            retransmit_2xx,
            snapshot.a_leg.transport.transport,
            snapshot.a_leg.transport.remote_addr,
            snapshot.a_leg.transport.connection_id,
            snapshot.a_leg_local_addr,
            state,
        );

        // A `call.refer()` deferred from @b2bua.on_answer, now that the answer
        // it depends on is on the wire. Emitting it up where the handler ran
        // sent it ahead of the 2xx, so the caller saw an in-dialog REFER for a
        // dialog it had not yet confirmed. Still before the SIPREC block, whose
        // early returns would otherwise skip it.
        if let Some(refer_to) = deferred_outbound_refer.take() {
            b2bua_send_outbound_refer(state, call_id, /*on_a_leg=*/ true, &refer_to);
        }

        // SIPREC: start recording if configured for this call
        start_li_recording(call_id, state, snapshot, li_srs_uri, &sdp_body);
    } // end 2xx guard
}

/// A 2xx that arrives for a call already answered: re-ACK and re-send the
/// stored A-leg 2xx (RFC 3261 §13.3.1.4) rather than answering twice.
pub fn absorb_answered_retransmit(
    call_id: &str,
    message: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let already_answered: Option<bool> = match snapshot
        .b_leg_index
        .map(|idx| state.call_actors.try_win(call_id, idx))
    {
        Some(crate::b2bua::actor::WinOutcome::FirstWin) => None,
        Some(crate::b2bua::actor::WinOutcome::AlreadyAnswered { b_leg_acked }) => Some(b_leg_acked),
        None if snapshot.call_state == CallState::Answered => Some(true),
        None => {
            state.call_actors.set_state(call_id, CallState::Answered);
            None
        }
    };
    if let Some(b_leg_acked) = already_answered {
        // Retransmit of the winning B-leg's 200 (it hasn't received our ACK
        // yet), or a losing fork branch. Re-ACK only once the B-leg ACK has
        // gone out (late-ACK complete); while still awaiting the A-leg ACK,
        // absorb silently.
        if !b_leg_acked {
            debug!(
                call_id = %call_id,
                "B2BUA: absorbing 200 OK retransmission (waiting for A-leg ACK)"
            );
            return true;
        }
        debug!(
            call_id = %call_id,
            "B2BUA: absorbing 200 OK retransmission (already answered)"
        );
        // Re-send ACK to B-leg to stop retransmissions
        if let Some((b_dest, b_transport)) = snapshot.b_leg_dest {
            if let Some((ref b_cid, ref _b_ftag)) = snapshot.b_leg_dialog {
                // Build a clean ACK from scratch — do NOT clone the 200 OK
                // (cloning leaks response headers like User-Agent, Contact,
                // Allow, Supported, etc. from the remote UA).
                let request_uri = message
                    .headers
                    .get("Contact")
                    .or_else(|| message.headers.get("m"))
                    .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                    .and_then(|u| parse_uri_standalone(&u).ok())
                    .or_else(|| {
                        snapshot
                            .b_leg_remote_contact
                            .as_deref()
                            .and_then(|u| parse_uri_standalone(u).ok())
                    })
                    .or_else(|| {
                        snapshot
                            .b_leg_target
                            .as_deref()
                            .and_then(|u| parse_uri_standalone(u).ok())
                    })
                    .unwrap_or_else(|| SipUri::new("invalid".to_string()));
                let transport_str = format!("{}", b_transport).to_uppercase();
                // Sent-by of the leg this ACK goes back on — the flow socket
                // when the leg was dialled over one.
                let (outbound_host, outbound_port) =
                    b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
                let cseq_num = message
                    .headers
                    .cseq()
                    .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                    .unwrap_or_else(|| "1".to_string());
                let from = message.headers.from().cloned().unwrap_or_default();
                let to = message.headers.to().cloned().unwrap_or_default();
                let ack = match SipMessageBuilder::new()
                    .request(Method::Ack, request_uri)
                    .via(format!(
                        "SIP/2.0/{} {}:{};branch={}",
                        transport_str,
                        outbound_host,
                        outbound_port,
                        TransactionKey::generate_branch(),
                    ))
                    .from(from.to_string())
                    .to(to.to_string())
                    .call_id(b_cid.clone())
                    .cseq(format!("{} ACK", cseq_num))
                    .header("Max-Forwards", "70".to_string())
                    .content_length(0)
                    .build()
                {
                    Ok(ack) => ack,
                    Err(error) => {
                        error!("B2BUA ACK for 200 OK retransmission build failed: {error}");
                        return true;
                    }
                };
                send_b2bua_to_bleg(ack, b_transport, b_dest, snapshot.b_leg_local_addr, state);
            }
        }
        return true;
    }

    false
}

/// RFC 3261 §13.2.2.4: ACK the B-leg's 2xx, or defer it until the A-leg
/// ACKs when the call is not media-anchored.
pub fn ack_b_leg_2xx(
    call_id: &str,
    message: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
    b_leg_record_routes: &[String],
) {
    if let Some((b_dest, b_transport)) = snapshot.b_leg_dest {
        if let Some((ref b_cid, ref _b_ftag)) = snapshot.b_leg_dialog {
            let ack_uri = message
                .headers
                .get("Contact")
                .or_else(|| message.headers.get("m"))
                .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                .and_then(|u| parse_uri_standalone(&u).ok())
                .or_else(|| {
                    snapshot
                        .b_leg_remote_contact
                        .as_deref()
                        .and_then(|u| parse_uri_standalone(u).ok())
                })
                .or_else(|| {
                    snapshot
                        .b_leg_target
                        .as_deref()
                        .and_then(|u| parse_uri_standalone(u).ok())
                })
                .unwrap_or_else(|| SipUri::new("invalid".to_string()));
            let transport_str = format!("{}", b_transport).to_uppercase();
            let cseq_num = message
                .headers
                .cseq()
                .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                .unwrap_or_else(|| "1".to_string());
            let from = message.headers.from().cloned().unwrap_or_default();
            let to = message.headers.to().cloned().unwrap_or_default();

            // Build B-leg Route set from Record-Route (reversed per RFC 3261 §12.2.1.1).
            // Flatten BEFORE reversing — see flatten_record_route_headers comment.
            let b_leg_routes = uac_route_set_from_record_routes(b_leg_record_routes);

            // Sent-by of the leg this ACK goes back on — the flow socket when
            // the leg was dialled over one, so the ACK is consistent with the
            // INVITE that drew this 2xx and leaves the same way (below).
            let (ack_via_host, ack_via_port) =
                b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
            let mut ack_builder = SipMessageBuilder::new()
                .request(Method::Ack, ack_uri)
                .via(format!(
                    "SIP/2.0/{} {}:{};branch={}",
                    transport_str,
                    ack_via_host,
                    ack_via_port,
                    TransactionKey::generate_branch(),
                ))
                .from(from.to_string())
                .to(to.to_string())
                .call_id(b_cid.clone())
                .cseq(format!("{} ACK", cseq_num))
                .header("Max-Forwards", "70".to_string());

            // Add Route headers from reversed B-leg Record-Route
            for route in &b_leg_routes {
                ack_builder = ack_builder.header("Route", route.clone());
            }

            if let Ok(ack) = ack_builder.content_length(0).build() {
                // ACK to 2xx is end-to-end and follows the dialog route set
                // (RFC 3261 §13.2.2.4). Use the first Route URI as next hop
                // rather than the cached B-leg destination, which may be an
                // upstream that doesn't Record-Route (e.g. IMS I-CSCF).
                let (ack_dest, ack_transport) =
                    resolve_in_dialog_destination(&b_leg_routes, state, b_dest, b_transport);
                if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                    call.pending_b_leg_ack = Some((ack, ack_transport, ack_dest));
                }
                debug!(call_id = %call_id, destination = %ack_dest, "B2BUA: deferred B-leg ACK until A-leg ACKs");
            }
        }
    }
}

/// Start the SIPREC recording session for a call `li.record()` marked,
/// once the A-leg 2xx is on the wire (RFC 7866).
pub fn start_li_recording(
    call_id: &str,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
    li_srs_uri: Option<&str>,
    sdp_body: &[u8],
) {
    if let Some(srs_uri) = li_srs_uri {
        let sdp = &sdp_body;
        if let Some(invite_arc) = &snapshot.a_leg_invite {
            let Ok(invite) = invite_arc.lock() else {
                error!(call_id = %call_id, "invite_arc lock poisoned during SIPREC start");
                return;
            };
            let caller_uri = invite
                .headers
                .get("From")
                .map(|from| from.to_string())
                .unwrap_or_default();
            let callee_uri = invite
                .headers
                .get("To")
                .map(|to| to.to_string())
                .unwrap_or_default();
            drop(invite);

            // RTPEngine subscribe: fork media to the recording leg.
            // Uses SIPREC-mode subscribe with from-tags containing both
            // monologue tags so RTPEngine returns a combined SDP with
            // 2 m= lines (one per call direction).
            let a_sip_call_id = snapshot.a_leg.dialog.call_id.clone();

            // Look up the MediaSession to get both monologue tags that
            // RTPEngine knows about (from_tag = A-leg, to_tag = B-leg).
            let media_tags: Option<(String, String)> = state
                .rtpengine_sessions
                .as_ref()
                .and_then(|sessions| sessions.get(&a_sip_call_id))
                .and_then(|session| {
                    session
                        .to_tag
                        .as_ref()
                        .map(|to_tag| (session.from_tag.clone(), to_tag.clone()))
                });

            // Look up the SIPREC SRC RTPEngine profile for additional subscribe flags.
            let siprec_src_profile =
                state
                    .li_siprec_rtpengine_profile
                    .as_deref()
                    .and_then(|name| {
                        state
                            .rtpengine_profiles
                            .as_ref()
                            .and_then(|registry| registry.get(name).cloned())
                    });
            let siprec_src_flags = siprec_src_profile.as_ref().map(|profile| &profile.offer);

            let (mut caller_sdp, mut callee_sdp, subscriber_to_tag) = if let Some(
                ref rtpengine_set,
            ) = state.rtpengine_set
            {
                // Build from-tags list with both monologue tags.
                let from_tags: Vec<&str> = match &media_tags {
                    Some((from_tag, to_tag)) => {
                        vec![from_tag.as_str(), to_tag.as_str()]
                    }
                    None => {
                        warn!(call_id = %call_id, "SIPREC: no MediaSession tags found, subscribe may return only 1 stream");
                        vec![]
                    }
                };

                let result = tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(
                        rtpengine_set.subscribe_request_siprec(
                            &a_sip_call_id,
                            &from_tags,
                            siprec_src_flags,
                        ),
                    )
                });
                match result {
                    Ok((sdp, to_tag)) => {
                        debug!(call_id = %call_id, sdp_len = sdp.len(), subscriber_to_tag = %to_tag, "SIPREC: subscribe_request_siprec OK");
                        // Fix direction (recvonly→sendonly) and add a=label per m= section.
                        let processed = crate::siprec::fix_siprec_subscribe_sdp(&sdp);
                        // Split the dual-m= SDP into per-direction parts so
                        // start_recording builds a proper 2-stream INVITE.
                        let (sdp1, sdp2) = crate::siprec::split_dual_sdp(&processed);
                        let has_two = sdp1 != sdp2;
                        if has_two {
                            (Some(sdp1), Some(sdp2), Some(to_tag))
                        } else {
                            // Single m= line — split returned two identical copies.
                            (Some(sdp1), None, Some(to_tag))
                        }
                    }
                    Err(error) => {
                        warn!(call_id = %call_id, %error, "SIPREC: subscribe_request_siprec failed");
                        (None, None, None)
                    }
                }
            } else {
                (None, None, None)
            };

            // Sanitize the subscribe SDPs to hide the original call's identity
            // (o=/s= lines may leak FreeSWITCH, Oracle, etc.).
            let local_ip = state.local_addr.ip().to_string();
            if let Some(ref mut sdp_bytes) = caller_sdp {
                sanitize_sdp_identity(sdp_bytes, "siphon", Some(&local_ip));
            }
            if let Some(ref mut sdp_bytes) = callee_sdp {
                sanitize_sdp_identity(sdp_bytes, "siphon", Some(&local_ip));
            }

            // For unsubscribe on BYE: SIPREC-mode uses empty from-tag and
            // the subscriber to-tag returned by RTPEngine.
            let tags_for_unsubscribe = subscriber_to_tag
                .as_ref()
                .map(|tt| (String::new(), tt.clone()));
            let tags_ref = tags_for_unsubscribe
                .as_ref()
                .map(|(ft, tt)| (ft.as_str(), tt.as_str()));
            if let Some((_session_id, rec_invite, destination, transport)) =
                state.recording_manager.start_recording(
                    call_id,
                    srs_uri,
                    &caller_uri,
                    &callee_uri,
                    sdp,
                    state.local_addr,
                    caller_sdp.as_deref(),
                    callee_sdp.as_deref(),
                    Some(&a_sip_call_id),
                    tags_ref,
                    state.user_agent_header.as_deref(),
                )
            {
                let data = Bytes::from(rec_invite.to_bytes());
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
        }
    }
}

/// Turn the B-leg 2xx into the A-leg's answer: rewrite the dialog headers
/// back to the A-leg's identifiers, restore its Via and CSeq (RFC 3261
/// §8.2.6.2), sanitize, and persist both dialog route sets. Returns the
/// B-leg Record-Route set, which the B-leg ACK needs (§12.1.1).
pub fn prepare_a_leg_answer(
    call_id: &str,
    response: &mut SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> Vec<String> {
    // Rewrite B-leg dialog headers back to A-leg identifiers.
    // The To-tag MUST be rewritten to A-leg's local_tag (RFC 3261 §12.2.1.1):
    // B-leg 2xx carries the B-leg far end's tag in To, but the A-leg far
    // end will store whatever it sees there as its dialog's remote-tag and
    // match in-dialog requests against it. Without this rewrite, the BYE
    // we later send toward A — built with snapshot.a_leg.dialog.local_tag (the
    // freshly generated sb-... tag) in its From — would mismatch the
    // stored remote tag and get 481 Call/Transaction Does Not Exist.
    if let Some((ref b_cid, ref b_ftag)) = snapshot.b_leg_dialog {
        crate::b2bua::actor::Dialog::rewrite_headers(
            response,
            &snapshot.a_leg.dialog.call_id,
            b_ftag,
            snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            Some(&snapshot.a_leg.dialog.local_tag),
        );
        let _ = (b_cid,); // Call-ID already set by rewrite_dialog_headers
    }

    // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
    // The B-leg response only carries our Via; the A-leg caller expects its own.
    // Also restore the A-leg's original CSeq (RFC 3261 §8.2.6.2 — response
    // CSeq MUST equal the request CSeq). The B-leg response carries the B-leg
    // CSeq which is in an independent numbering space.
    if let Some(invite_arc) = &snapshot.a_leg_invite {
        if let Ok(invite) = invite_arc.lock() {
            if let Some(vias) = invite.headers.get_all("Via") {
                response.headers.set_all("Via", vias.clone());
            }
            if let Some(cseq) = invite.headers.cseq() {
                response.headers.set("CSeq", cseq.clone());
            }
            // RFC 3261 §8.2.6.2: the response From MUST equal the request
            // From, and the response To MUST equal the request To plus the
            // dialog tag. The cloned B-leg 2xx carries the B-leg dialog's
            // From/To URIs (siphon's B-leg identity and the B-leg contact
            // host) — restore the A-leg caller's own From verbatim and its
            // To with siphon's A-leg tag (the rewrite_headers tag-swap above
            // only fixed the tags, not the URIs).
            //
            // From the arrival snapshot, not this INVITE: the stored INVITE
            // is the buffer the script reshapes for the B-leg, so echoing it
            // returned the caller a rewritten form of its own identity. It
            // stays the fallback for a call with no snapshot.
            if let Some(from) = snapshot
                .a_leg
                .stored_from
                .as_ref()
                .or(invite.headers.from())
            {
                response.headers.set("From", from.clone());
            }
            if let Some(to) = snapshot.a_leg.stored_to.as_ref().or(invite.headers.to()) {
                response.headers.set(
                    "To",
                    crate::b2bua::actor::ensure_tag(to, Some(&snapshot.a_leg.dialog.local_tag)),
                );
            }
        }
    }

    // Extract B-leg Record-Route BEFORE sanitization — needed for B-leg ACK Route set.
    // Per RFC 3261 §12.1.1, the ACK route set is the Record-Route from the 200 OK reversed.
    let b_leg_record_routes = response
        .headers
        .get_all("Record-Route")
        .cloned()
        .unwrap_or_default();

    // Sanitize B-leg headers before forwarding to A-leg
    sanitize_b2bua_response(
        response,
        state,
        snapshot.a_leg.transport.transport,
        snapshot.a_leg_local_addr,
        snapshot.a_leg_supports_100rel,
        call_id,
    );

    // Own the o= identity toward the A-leg on the answer it receives (RFC
    // 3264 §8): the first SDP siphon emits toward the caller fixes the leg's
    // stable session-id; a later re-anchor (transfer, hold) then presents a
    // strictly greater version under the same session-id.
    if !response.body.is_empty() {
        if let Some((sess_id, version)) = state.call_actors.reserve_leg_sdp_version(call_id, true) {
            stamp_sdp_origin(&mut response.body, &state.sdp_name, sess_id, version, None);
            response
                .headers
                .set("Content-Length", response.body.len().to_string());
        }
    }

    // Restore A-leg Record-Route from the stored INVITE (same pattern as Via).
    // sanitize_b2bua_response strips all Record-Route (B-leg path). The A-leg
    // 200 OK must contain the A-leg Record-Route so the UAC can build its route set.
    if let Some(ref invite_arc) = snapshot.a_leg_invite {
        if let Ok(invite) = invite_arc.lock() {
            if let Some(rrs) = invite.headers.get_all("Record-Route") {
                response.headers.set_all("Record-Route", rrs.clone());
            }
        }
    }

    // Persist dialog route sets for in-dialog requests (BYE, re-INVITE).
    // Must happen before we consume the Record-Routes for ACK building.
    {
        // B-leg route set from B-leg 200 OK Record-Route, reversed per RFC 3261
        // §12.1.1. Reversal MUST happen after flattening — multiple URIs sharing one
        // header line stay in wire order until then.
        let b_routes = uac_route_set_from_record_routes(&b_leg_record_routes);
        // A-leg route set from stored INVITE's Record-Route (in order for UAS)
        let a_routes = snapshot
            .a_leg_invite
            .as_ref()
            .and_then(|arc| arc.lock().ok())
            .and_then(|invite| invite.headers.get_all("Record-Route").cloned())
            .map(|rrs| flatten_record_route_headers(&rrs))
            .unwrap_or_default();

        if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
            if let Some(winner) = call.winner {
                if let Some(b_leg) = call.b_legs.get_mut(winner) {
                    debug!(
                        call_id = %call_id,
                        b_routes_count = b_routes.len(),
                        "B2BUA: stored B-leg dialog route set",
                    );
                    b_leg.dialog.route_set = b_routes.clone();
                }
            }
            debug!(
                call_id = %call_id,
                a_routes_count = a_routes.len(),
                "B2BUA: stored A-leg dialog route set",
            );
            call.a_leg.dialog.route_set = a_routes;
        }
    }

    b_leg_record_routes
}
