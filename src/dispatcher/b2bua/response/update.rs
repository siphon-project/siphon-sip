//! Responses to an UPDATE siphon forwarded between the two legs (RFC 3311).

use crate::dispatcher::*;

/// A response to an UPDATE siphon forwarded between the legs (RFC 3311).
/// Returns `true` when the response was consumed here.
pub fn forward_update_response(
    call_id: &str,
    message: &mut SipMessage,
    mut status_code: u16,
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
            if (200..300).contains(&status_code) {
                mark_tracking_leg_done(
                    call_id,
                    snapshot,
                    format!("update_done:{direction}"),
                    state,
                );
            } else if status_code >= 300 {
                state.call_actors.remove_b_leg_on(call_id, &snapshot.branch);
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

        // Nobody has answered the call: the UPDATE crossed between the two
        // early dialogs, which run no session timer yet (RFC 4028 §7.1 starts it
        // with the 2xx of the INVITE).
        let on_early_dialog = state
            .call_actors
            .get_call(call_id)
            .is_some_and(|call| call.winner.is_none());

        // The callee's early dialog is gone, not the caller's: the caller is
        // asked to offer again rather than told its own dialog ended
        // (`early_update_refusal_for_caller`).
        if let Some((status, retry_after)) = (is_a2b && on_early_dialog)
            .then(|| early_update_refusal_for_caller(status_code))
            .flatten()
        {
            debug!(
                call_id = %call_id,
                callee_status = status_code,
                status,
                "B2BUA: the callee's early dialog is gone for the caller's UPDATE; the caller's own stays"
            );
            message.start_line = StartLine::Response(StatusLine {
                version: Version::sip_2_0(),
                status_code: status,
                reason_phrase: "Server Internal Error".to_string(),
            });
            message.headers.remove("Content-Type");
            message.body.clear();
            message.headers.set("Content-Length", "0".to_string());
            if retry_after {
                message.headers.set("Retry-After", random_retry_after());
            }
            status_code = status;
        }

        // The response goes back where the UPDATE came from (RFC 3261 §18.2.2):
        // before the answer that need not be the hop the originator's INVITE
        // arrived from, or was sent to, and the INVITE's own responses and
        // CANCEL stay with the INVITE.
        // 4th element: the responder leg's anchored egress socket (see the
        // re-INVITE response path above).
        let source = snapshot.b_leg_request_source.as_ref();
        let (resp_dest, resp_transport, resp_conn_id, resp_local_addr) = if is_a2b {
            match source {
                Some(source) => (
                    source.remote_addr,
                    source.transport,
                    source.connection_id,
                    source.local_addr,
                ),
                None => (
                    snapshot.a_leg.transport.remote_addr,
                    snapshot.a_leg.transport.transport,
                    snapshot.a_leg.transport.connection_id,
                    snapshot.a_leg_local_addr,
                ),
            }
        } else {
            match state.call_actors.get_call(call_id) {
                Some(call) => {
                    // The callee's position is read and used under one hold of the
                    // call's lock: the winner, or on the early dialog the leg the
                    // caller's session is shared with.
                    let callee = call.bridged_b_leg_index().and_then(|i| call.b_legs.get(i));
                    if let Some(b) = callee {
                        let (remote_addr, transport) = source
                            .map(|source| (source.remote_addr, source.transport))
                            .unwrap_or((b.transport.remote_addr, b.transport.transport));
                        (
                            remote_addr,
                            transport,
                            ConnectionId::default(),
                            b.transport.local_addr,
                        )
                    } else {
                        // The callee that sent the UPDATE is off the call: there
                        // is nobody to relay the response to.
                        warn!(call_id = %call_id, "B2BUA UPDATE response: no B-leg to relay it to");
                        drop(call);
                        state.call_actors.remove_b_leg_on(call_id, &snapshot.branch);
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
            // The callee's position is read and used under one hold of the call's lock.
            if let Some(winner) = call.bridged_b_leg_index().and_then(|i| call.b_legs.get(i)) {
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
                    // Shaped for the party the answer is relayed to, the one that
                    // offered, by its own side of the profile.
                    if let Some(shape) = session.party_shape(is_a2b).resolve(profiles) {
                        // Same rule as the re-INVITE answer above: a B→A answer must name the callee
                        // as offerer, and a 2xx cannot be refused, so an unnameable pair leaves the
                        // SDP alone rather than attributing it to the wrong party.
                        if let Some((answer_from, answer_to)) = session.answer_tags(is_a2b) {
                            let mut answer_flags = shape;
                            // The answering party's own policy, as on a
                            // re-INVITE's answer.
                            session.party_ingress(!is_a2b).stamp_ingress(
                                &mut answer_flags,
                                profiles,
                                response_source.ip(),
                            );
                            if let Some(responder_call_id) = responder_headers.call_id() {
                                answer_flags.stamp_sip_call_id(responder_call_id);
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
            let identity = if is_a2b {
                state.call_actors.reserve_leg_sdp_version(call_id, true)
            } else {
                update_bridged_callee(state, call_id, |leg| {
                    let identity = (leg.dialog.sdp_session_id, leg.dialog.sdp_version);
                    leg.dialog.sdp_version += 1;
                    identity
                })
            };
            if let Some((sess_id, version)) = identity {
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
            let answer = sdp_in_body(message_content_type(message), &message.body);
            if is_a2b {
                if let Some(offer) = snapshot.b_leg_offered_sdp.clone() {
                    update_bridged_callee(state, call_id, |leg| {
                        leg.dialog.last_sent_sdp = Some(offer)
                    });
                }
                if let Some(answer) = answer {
                    state.call_actors.set_leg_sent_sdp(call_id, true, answer);
                }
            } else {
                if let Some(offer) = snapshot.b_leg_offered_sdp.clone() {
                    state.call_actors.set_leg_sent_sdp(call_id, true, offer);
                }
                if let Some(answer) = answer {
                    update_bridged_callee(state, call_id, |leg| {
                        leg.dialog.last_sent_sdp = Some(answer)
                    });
                }
            }

            // The 2xx refreshes both dialogs the UPDATE crossed: the responder's
            // from its own 2xx (RFC 4028 §7.2), and the originator's with siphon's
            // answer on the copy relayed there (§9).
            if !on_early_dialog {
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
            }

            // Mark the UPDATE entry done so retransmitted 2xx can be absorbed.
            mark_tracking_leg_done(call_id, snapshot, format!("update_done:{direction}"), state);
        } else if status_code >= 300 {
            // Non-2xx UPDATE — no ACK (UPDATE is non-INVITE), just remove the
            // tracking entry. The responder's non-INVITE server transaction
            // self-terminates (RFC 3261 §17.2.2).
            state.call_actors.remove_b_leg_on(call_id, &snapshot.branch);
            // A 422 still teaches the responder's dialog its Min-SE (RFC 4028 §7.4).
            if !on_early_dialog {
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

/// Change the callee's leg an UPDATE crossed to or from, under the call's lock:
/// the winner, or on the early dialog the leg the caller's session is shared
/// with. `None`, with nothing changed, when the call or that leg is gone.
fn update_bridged_callee<T>(
    state: &DispatcherState,
    call_id: &str,
    update: impl FnOnce(&mut Leg) -> T,
) -> Option<T> {
    let mut call = state.call_actors.get_call_mut(call_id)?;
    let index = call.bridged_b_leg_index()?;
    call.b_legs.get_mut(index).map(update)
}
