//! The B-leg is ringing: relay the provisional, anchoring early media when
//! it carries SDP.

use crate::dispatcher::*;

/// A 1xx on the B-leg: mark the call ringing and relay the provisional to
/// the A-leg, anchoring early media when the response carries SDP.
pub fn b_leg_provisional(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) {
    // --- 1xx provisional handling ---
    {
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

        // Invoke @b2bua.on_early_media handlers when provisional has SDP body.
        // This lets scripts process early media through RTPEngine before forwarding.
        let has_sdp_body = !message.body.is_empty();
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

                    Python::attach(|python| {
                        let call_obj = match Py::new(python, py_call) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyCall for on_early_media: {error}");
                                return;
                            }
                        };
                        let reply_obj = match Py::new(python, py_reply) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for on_early_media: {error}");
                                return;
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
                // RFC 3261 §8.2.6.2: response From/To URIs MUST echo the A-leg
                // request's, not the cloned B-leg dialog's. Restore the A-leg
                // From verbatim; restore the A-leg To URI while preserving
                // whatever early-dialog To-tag the rewrite above established (a
                // plain 180 has none, an early-dialog 18x carries siphon's tag).
                //
                // From the arrival snapshot for the same reason as the 2xx path:
                // the stored INVITE is the script's B-leg shaping buffer, so a
                // provisional echoed the caller a rewritten form of its own
                // identity — and inconsistently with the 2xx that followed.
                if let Some(from) = snapshot
                    .a_leg
                    .stored_from
                    .as_ref()
                    .or(invite.headers.from())
                {
                    message.headers.set("From", from.clone());
                }
                if let Some(to) = snapshot.a_leg.stored_to.as_ref().or(invite.headers.to()) {
                    let existing_tag = message
                        .headers
                        .to()
                        .and_then(|value| {
                            crate::sip::headers::nameaddr::NameAddr::parse(value).ok()
                        })
                        .and_then(|name_addr| name_addr.tag);
                    message.headers.set(
                        "To",
                        crate::b2bua::actor::ensure_tag(to, existing_tag.as_deref()),
                    );
                }
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(
            message,
            state,
            snapshot.a_leg.transport.transport,
            snapshot.a_leg_local_addr,
            snapshot.a_leg_supports_100rel,
            call_id,
        );
        // Pin the reply egress socket to the A-leg INVITE's arrival listener
        // (`snapshot.a_leg_local_addr`) so a multi-homed UDP host answers on the port it
        // received on. No-op for stream transports and single-listener hosts.
        send_message_from(
            message.clone(),
            snapshot.a_leg.transport.transport,
            snapshot.a_leg.transport.remote_addr,
            snapshot.a_leg.transport.connection_id,
            snapshot.a_leg_local_addr,
            state,
        );
    }
}
