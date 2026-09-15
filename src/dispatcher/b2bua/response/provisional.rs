//! The B-leg is ringing: relay the provisional, anchoring early media when
//! it carries SDP.

use crate::dispatcher::*;

/// A 1xx on the B-leg: mark the call ringing and relay the provisional to
/// the A-leg, anchoring early media when the response carries SDP. On an LCR
/// attempt it is also the carrier's progress, which keeps the carrier past its
/// ring timeout. A 1xx on a leg that has already ended is dropped.
pub fn b_leg_provisional(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) {
    // --- 1xx provisional handling ---
    {
        // Drop a provisional on a leg that is no longer waiting for its final
        // response: an LCR carrier settled by its failure, a fork branch that
        // failed, a leg siphon CANCELled once it is no longer kept answerable
        // apart from the call. Its INVITE transaction is over, so this is a
        // straggler, reordered on the way or sent after the leg's own final
        // response. Relaying it would show the caller an early dialog nothing
        // will confirm, recording it could read as progress, and anchoring its
        // SDP would open media that goes nowhere. A response takes no ACK, so it
        // is only dropped. Checked before the call is marked ringing, so a
        // straggler cannot move it to Ringing either. The same check already
        // kept a reliable one from being PRACKed (`auto_prack_b_leg`).
        if snapshot
            .b_leg_index
            .is_some_and(|index| state.call_actors.is_ended_branch(call_id, index))
        {
            debug!(call_id = %call_id, branch = %branch, status = status_code,
                "B2BUA: dropping a provisional from a leg that already ended");
            return;
        }

        // Drop a stray provisional that arrives after the call is already
        // answered — e.g. a carrier's 180 reordered behind its 200, or a losing
        // fork branch's late 18x. A B2BUA must not forward a provisional after
        // the final response, nor downgrade the confirmed dialog back to Ringing
        // (RFC 3261 §12.1). This MUST be an atomic check-and-set, not the
        // `snapshot.call_state` snapshot taken ~1600 lines earlier: under multi-worker
        // dispatch a B-leg's 180 and 200 (received in order over one TCP/UDP
        // flow) are processed on different workers concurrently, so a late 180
        // that reads a stale "not answered" snapshot would be forwarded behind
        // its 200 and abort the A-leg UAC (which already ACKed/BYE'd). Deciding
        // under the per-call lock drops the provisional that lost the race.
        if !state.call_actors.try_mark_ringing(call_id) {
            debug!(call_id = %call_id, status = status_code,
        "B2BUA: dropping provisional received after answer");
            return;
        }

        // An LCR carrier that sends a 101-199 is working on the call, so its
        // route's timer stops bounding the ring (RFC 3261 §16.7 step 2, Timer C)
        // and the attempt's deadline moves to the sequence's ring bound.
        // Recorded before any handler runs, so the sweep sees it at once.
        if state
            .call_actors
            .record_route_progress(call_id, branch, status_code)
        {
            debug!(call_id = %call_id, status = status_code,
                "LCR: carrier in flight showed progress");
        }

        // Whether the callee sent this provisional reliably (RFC 3262 §3), read
        // off the wire before a script or the sanitizing below touches it.
        let callee_sent_reliably = crate::sip::headers::rseq::requires_100rel(&message.headers)
            && crate::sip::headers::rseq::parse_rseq(&message.headers).is_some();

        // Invoke @b2bua.on_early_media handlers when provisional has SDP body.
        // This lets scripts process early media through RTPEngine before forwarding.
        let has_sdp_body = !message.body.is_empty();
        // Headers @b2bua.on_early_media set or removed on the response, which
        // reach the caller as the script left them.
        let mut reply_shaped_headers: Vec<String> = Vec::new();
        if has_sdp_body {
            let engine_state = state.engine.state();
            let handlers = engine_state.handlers_for(&HandlerKind::B2buaEarlyMedia);
            if !handlers.is_empty() {
                if let Some(invite_arc) = &snapshot.a_leg_invite {
                    let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));
                    let py_call = PyCall::new(
                        call_id.to_string(),
                        Arc::clone(invite_arc),
                        snapshot.a_leg.transport.remote_addr.ip().to_string(),
                        format!("{}", snapshot.a_leg.transport.transport).to_lowercase(),
                    )
                    .with_flow(py_flow_from_leg(&snapshot.a_leg.transport));
                    let py_reply = PyReply::new(Arc::clone(&response_arc))
                        .with_a_leg(Arc::clone(invite_arc))
                        .with_response_source(
                            response_source.ip().to_string(),
                            response_source.port(),
                        );

                    reply_shaped_headers = Python::attach(|python| -> Vec<String> {
                        let call_obj = match Py::new(python, py_call) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyCall for on_early_media: {error}");
                                return Vec::new();
                            }
                        };
                        let reply_obj = match Py::new(python, py_reply) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for on_early_media: {error}");
                                return Vec::new();
                            }
                        };

                        for handler in &handlers {
                            let callable = handler.callable.bind(python);
                            match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            record_script_error(
                                                "async B2BUA on_early_media",
                                                &error,
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    record_script_error("B2BUA on_early_media", &error);
                                }
                            }
                        }
                        let reply = reply_obj.borrow(python);
                        reply.script_shaped_headers().to_vec()
                    });

                    // Replace message with potentially modified version (e.g. RTPEngine-rewritten SDP)
                    if let Ok(modified) = response_arc.lock() {
                        *message = modified.clone();
                    };
                } else {
                    warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_early_media");
                }
            }
        }

        // Rewrite B-leg dialog headers back to A-leg identifiers.
        // For provisional responses that carry a To-tag (early dialogs —
        // 180/183 with tag), the rewrite ensures A-leg's view of the early
        // dialog matches its later view of the confirmed dialog (200 OK).
        if let Some((ref _b_cid, ref b_ftag)) = snapshot.b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message,
                &snapshot.a_leg.dialog.call_id,
                b_ftag,
                snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&snapshot.a_leg.dialog.local_tag),
            );
        }
        // Replace B-leg Via(s) and CSeq with A-leg originals from stored INVITE
        // (RFC 3261 §8.2.6.2 — response CSeq MUST equal request CSeq).
        if let Some(invite_arc) = &snapshot.a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    message.headers.set_all("Via", vias.clone());
                }
                if let Some(cseq) = invite.headers.cseq() {
                    message.headers.set("CSeq", cseq.clone());
                }
                // The caller's own From and To, keeping whatever early-dialog
                // To-tag the rewrite above established.
                echo_caller_identity(message, &snapshot.a_leg, &invite, RelayedToTag::AsRelayed);
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response_keeping(
            message,
            state,
            snapshot.a_leg.transport.transport,
            snapshot.a_leg_local_addr,
            call_id,
            &reply_shaped_headers,
        );
        // `media.sdp_strip_attributes`, after `@b2bua.on_early_media` had the
        // media engine rewrite the early media SDP.
        strip_relayed_sdp_attributes(message, state);
        // The early media answer as the caller receives it, which is the session
        // description in force on the caller's dialog when this leg's 2xx carries
        // none.
        if let (Some(index), Some(sdp)) = (
            snapshot.b_leg_index,
            sdp_in_body(message_content_type(message), &message.body),
        ) {
            state
                .call_actors
                .set_b_leg_early_answer(call_id, index, sdp);
        }
        // To the caller: reliably on siphon's own numbering when it asked for
        // that (RFC 3262 §3), after the PRACK of a reliable one before it.
        send_a_leg_provisional(call_id, message.clone(), callee_sent_reliably, state);
    }
}
