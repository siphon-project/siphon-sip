//! Responses to an UPDATE siphon forwarded between the two legs (RFC 3311).

use crate::dispatcher::*;

/// A response to an UPDATE siphon forwarded between the legs (RFC 3311).
/// Returns `true` when the response was consumed here.
pub fn forward_update_response(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // Detect UPDATE responses: target_uri starts with "update:".
    // Mirrors the re-INVITE response routing — but no ACK is sent (RFC 3311
    // §5.4: UPDATE is a non-INVITE transaction). Body-aware media handling
    // matches the request side: SDP rewrite via rtpengine.answer only when
    // the response carries SDP (session-timer refresh has empty body).
    let update_direction = snapshot
        .b_leg_target
        .as_deref()
        .and_then(|t| t.strip_prefix("update:"));

    if let Some(direction) = update_direction {
        let is_a2b = direction == "a2b";

        // The response as the responder sent it: its Session-Expires decides the
        // session timer of the responder's dialog.
        let responder_headers = message.headers.clone();

        // An UPDATE siphon originated (a session refresh) has no originator to
        // relay the response to, which its tracking leg says by carrying no stored
        // Via. Its response only moves the session timer on.
        if snapshot.b_leg_stored_vias.is_empty() {
            if let Some(index) = snapshot.b_leg_index {
                if (200..300).contains(&status_code) {
                    state.call_actors.set_b_leg_target_uri(
                        call_id,
                        index,
                        format!("update_done:{direction}"),
                    );
                } else if status_code >= 300 {
                    state.call_actors.remove_b_leg(call_id, index);
                }
            }
            session_timer_on_response(
                call_id,
                !is_a2b,
                &snapshot.branch,
                status_code,
                &responder_headers,
                snapshot.b_leg_request_session_expires,
                state,
            );
            debug!(
                call_id = %call_id,
                status = status_code,
                direction = direction,
                "B2BUA: absorbed the response to a siphon-originated UPDATE"
            );
            return true;
        }

        // 4th element: the responder leg's anchored egress socket (see the
        // re-INVITE response path above).
        let (resp_dest, resp_transport, resp_conn_id, resp_local_addr) = if is_a2b {
            (
                snapshot.a_leg.transport.remote_addr,
                snapshot.a_leg.transport.transport,
                snapshot.a_leg.transport.connection_id,
                snapshot.a_leg_local_addr,
            )
        } else {
            match state.call_actors.get_call(call_id) {
                Some(call) => {
                    let winner = call.winner.and_then(|i| call.b_legs.get(i));
                    if let Some(b) = winner {
                        (
                            b.transport.remote_addr,
                            b.transport.transport,
                            ConnectionId::default(),
                            b.transport.local_addr,
                        )
                    } else {
                        warn!(call_id = %call_id, "B2BUA UPDATE response: no winning B-leg");
                        return true;
                    }
                }
                None => return true,
            }
        };

        if is_a2b {
            if let Some((ref _b_cid, ref b_ftag)) = snapshot.b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &snapshot.a_leg.dialog.call_id,
                    b_ftag,
                    snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&snapshot.a_leg.dialog.local_tag),
                );
            }
        } else if let Some(call) = state.call_actors.get_call(call_id) {
            if let Some(winner) = call.winner.and_then(|i| call.b_legs.get(i)) {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &winner.dialog.call_id,
                    snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    &winner.dialog.local_tag,
                    winner.dialog.remote_tag.as_deref(),
                );
            }
        }

        // Restore originator's Via, CSeq and From/To (RFC 3261 §8.2.6.2). The
        // rewrite above swaps the dialog tags but leaves the responder-dialog
        // URIs on a header the originator must see echoed from its own UPDATE.
        message
            .headers
            .set_all("Via", snapshot.b_leg_stored_vias.clone());
        if let Some(ref cseq) = snapshot.b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }
        if let Some(ref from) = snapshot.b_leg_stored_from {
            message.headers.set("From", from.clone());
        }
        if let Some(ref to) = snapshot.b_leg_stored_to {
            message.headers.set("To", to.clone());
        }

        // A-facing (is_a2b) response: anchor Contact to the A-leg's arrival socket;
        // B-facing: leave it to via_port (the B-side advertised address).
        sanitize_b2bua_response(
            message,
            state,
            resp_transport,
            if is_a2b {
                snapshot.a_leg_local_addr
            } else {
                None
            },
            call_id,
        );

        // RTPEngine answer for UPDATE 2xx with SDP body (codec/precondition
        // re-negotiation). Empty-body 2xx (session-timer refresh) bypasses.
        if (200..300).contains(&status_code) && !message.body.is_empty() {
            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) = (
                &state.rtpengine_set,
                &state.rtpengine_sessions,
                &state.rtpengine_profiles,
            ) {
                let a_sip_call_id = &snapshot.a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        // Same rule as the re-INVITE answer above: a B→A answer must name the callee
                        // as offerer, and a 2xx cannot be refused, so an unnameable pair leaves the
                        // SDP alone rather than attributing it to the wrong party.
                        if let Some((answer_from, answer_to)) = session.answer_tags(is_a2b) {
                            let mut answer_flags = profile.answer.clone();
                            if answer_flags.carry_received_from {
                                answer_flags.received_from = Some(response_source.ip());
                            }
                            match tokio::task::block_in_place(|| {
                                tokio::runtime::Handle::current().block_on(rtpengine_set.answer(
                                    session.rtpengine_id(),
                                    answer_from,
                                    answer_to,
                                    &message.body,
                                    &answer_flags,
                                ))
                            }) {
                                Ok(rewritten_sdp) => {
                                    message.body = rewritten_sdp;
                                    message
                                        .headers
                                        .set("Content-Length", message.body.len().to_string());
                                    debug!(call_id = %call_id, "RTPEngine: rewrote UPDATE response SDP (answer)");
                                }
                                Err(error) => {
                                    warn!(call_id = %call_id, "RTPEngine answer for UPDATE failed: {error}");
                                }
                            }
                        } else {
                            error!(
                                call_id = %call_id,
                                "UPDATE from the callee answered on a media session with no \
                                 recorded answerer tag — leaving the answer SDP unanchored rather \
                                 than naming the caller to the media engine"
                            );
                        }
                    }
                }
            }
        }

        // Own the o= identity toward the UPDATE originator on the relayed answer
        // (RFC 3264 §8), after any rtpengine rewrite. Offerer = A-leg when is_a2b.
        if (200..300).contains(&status_code) && !message.body.is_empty() {
            if let Some((sess_id, version)) =
                state.call_actors.reserve_leg_sdp_version(call_id, is_a2b)
            {
                stamp_sdp_origin(&mut message.body, &state.sdp_name, sess_id, version, None);
                message
                    .headers
                    .set("Content-Length", message.body.len().to_string());
            }
        }

        // `media.sdp_strip_attributes`, last: after the media engine answer and
        // the o= stamp.
        strip_relayed_sdp_attributes(message, state);

        if (200..300).contains(&status_code) {
            // The responder took the offer (when the UPDATE carried one), so it is
            // the session description in force on the responder's dialog, and the
            // answer relayed back is in force on the originator's.
            if let Some(offer) = &snapshot.b_leg_offered_sdp {
                state
                    .call_actors
                    .set_leg_sent_sdp(call_id, !is_a2b, offer.clone());
            }
            record_sdp_sent_to_leg(
                state,
                call_id,
                is_a2b,
                message_content_type(message),
                &message.body,
            );

            // The 2xx refreshes both dialogs the UPDATE crossed: the responder's
            // from its own 2xx (RFC 4028 §7.2), and the originator's with siphon's
            // answer on the copy relayed there (§9).
            session_timer_on_response(
                call_id,
                !is_a2b,
                &snapshot.branch,
                status_code,
                &responder_headers,
                snapshot.b_leg_request_session_expires,
                state,
            );
            negotiate_relayed_session_timer(
                call_id,
                is_a2b,
                snapshot.b_leg_session_refresh_request.as_ref(),
                &mut message.headers,
                state,
            );

            // Mark the UPDATE entry done so retransmitted 2xx can be absorbed.
            if let Some(idx) = snapshot.b_leg_index {
                state.call_actors.set_b_leg_target_uri(
                    call_id,
                    idx,
                    format!("update_done:{}", direction),
                );
            }
        } else if status_code >= 300 {
            // Non-2xx UPDATE — no ACK (UPDATE is non-INVITE), just remove the
            // tracking entry. The responder's non-INVITE server transaction
            // self-terminates (RFC 3261 §17.2.2).
            if let Some(idx) = snapshot.b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
            // A 422 still teaches the responder's dialog its Min-SE (RFC 4028 §7.4).
            session_timer_on_response(
                call_id,
                !is_a2b,
                &snapshot.branch,
                status_code,
                &responder_headers,
                snapshot.b_leg_request_session_expires,
                state,
            );
        }

        // Forward response to the originator.
        if is_a2b {
            // A→B UPDATE: the response goes to the A-leg — pin its arrival socket.
            send_message_from(
                message.clone(),
                resp_transport,
                resp_dest,
                resp_conn_id,
                resp_local_addr,
                state,
            );
        } else {
            send_b2bua_to_bleg(
                message.clone(),
                resp_transport,
                resp_dest,
                resp_local_addr,
                state,
            );
        }

        debug!(
            call_id = %call_id,
            status = status_code,
            direction = direction,
            "B2BUA: forwarded UPDATE response"
        );
        return true;
    }

    false
}
