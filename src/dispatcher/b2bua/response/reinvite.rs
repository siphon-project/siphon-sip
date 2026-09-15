//! Responses to a re-INVITE siphon forwarded between the two legs.

use crate::dispatcher::*;

/// A response to a re-INVITE siphon forwarded between the legs. Returns
/// `true` when the response was consumed here.
pub fn forward_reinvite_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // Detect re-INVITE responses: target_uri starts with "reinvite:".
    // Re-INVITE tracking legs don't have actors — handled directly below.
    let reinvite_direction = snapshot
        .b_leg_target
        .as_deref()
        .and_then(|t| t.strip_prefix("reinvite:"));

    if let Some(direction) = reinvite_direction {
        let is_a2b = direction == "a2b";

        // Determine where to route the response: back to the leg that sent the re-INVITE.
        // A→B re-INVITE: response goes to A-leg, rewrite B-leg→A-leg headers
        // B→A re-INVITE: response goes to B-leg, rewrite A-leg→B-leg headers
        // The 4th element is the responder leg's anchored egress socket, so the
        // forwarded response leaves from the same socket that leg is bridged on
        // (A-leg: its arrival listener; B-leg: its flow socket, when dialled
        // with `call.dial(flow=…)`).
        let (resp_dest, resp_transport, resp_conn_id, resp_local_addr) = if is_a2b {
            (
                snapshot.a_leg.transport.remote_addr,
                snapshot.a_leg.transport.transport,
                snapshot.a_leg.transport.connection_id,
                snapshot.a_leg_local_addr,
            )
        } else {
            // B→A: send response to winning B-leg
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
                        warn!(call_id = %call_id, "B2BUA re-INVITE response: no winning B-leg");
                        return true;
                    }
                }
                None => return true,
            }
        };

        // A siphon-originated re-INVITE (session-timer refresh / transfer media
        // re-anchor) has no originator leg — its tracking entry carries empty
        // stored Vias. Its response is absorbed (only used to ACK the responder),
        // so it must NOT be rewritten to the snapshot.a_leg identity nor Contact-sanitized:
        // the ACK is built from the responder's own 200. Only a bridged re-INVITE
        // (a real originator leg) rewrites the response identity.
        let is_bridged_reinvite = !snapshot.b_leg_stored_vias.is_empty();

        // The responder's OWN From/To, captured before the rewrite below edits
        // them in place — the same "capture before we overwrite it" the CSeq and
        // Contact below already do, and for the same consumer: the 2xx ACK that
        // goes back to the responder.
        //
        // That ACK is part of the responder's dialog, so RFC 3261 §13.2.2.4 /
        // §12.2.1.1 want the tags that dialog was established with. Building it
        // from `message` after the rewrite sent the *originator's* tag pair to
        // the responder — an A-leg tag pair on the B-leg dialog — which the
        // responder cannot match to the transaction it just answered, so it
        // retransmits its 200 until the ACK is repeated by the retransmission
        // handler. Only visible on a bridged re-INVITE: the siphon-originated
        // one skips the rewrite entirely, which is why the session-timer and
        // transfer re-anchor refreshes were unaffected.
        let responder_from = message.headers.from().cloned();
        let responder_to = message.headers.to().cloned();

        if is_bridged_reinvite && is_a2b {
            // A→B: response from B-leg → rewrite B-leg identifiers back to A-leg
            if let Some((ref _b_cid, ref b_ftag)) = snapshot.b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &snapshot.a_leg.dialog.call_id,
                    b_ftag,
                    snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&snapshot.a_leg.dialog.local_tag),
                );
            }
        } else if is_bridged_reinvite {
            // B→A: response from A-leg → rewrite A-leg identifiers back to B-leg
            if let Some(call) = state.call_actors.get_call(call_id) {
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
        }

        // Capture responder's CSeq before we overwrite it with the originator's.
        // The ACK sent to the responder must use the responder's CSeq (the one used
        // in the forwarded re-INVITE), not the originator's.
        let responder_cseq_num = message
            .headers
            .cseq()
            .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
            .unwrap_or_else(|| "1".to_string());

        // Replace Via(s) and CSeq — restore the originator's Via headers and CSeq
        // from the re-INVITE (stored_vias/stored_cseq), NOT from the initial INVITE.
        // Both A→B and B→A use stored values captured when the re-INVITE arrived.
        message
            .headers
            .set_all("Via", snapshot.b_leg_stored_vias.clone());
        // Restore originator's CSeq (RFC 3261 §8.2.6.2 — response CSeq MUST
        // match the request being responded to, which is the originator's re-INVITE).
        if let Some(ref cseq) = snapshot.b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }
        // ...and its From/To, from the same capture and under the same MUST.
        // The rewrite above swaps the tags but leaves the responder-dialog URIs,
        // so a hold/resume answered on the far leg came back to the originator
        // naming the far leg's host — its own re-INVITE's To answered with a
        // different URI than it sent. Only for a bridged re-INVITE: a
        // siphon-originated one is absorbed, not forwarded, and its ACK is built
        // from the responder's untouched 200.
        if is_bridged_reinvite {
            if let Some(ref from) = snapshot.b_leg_stored_from {
                message.headers.set("From", from.clone());
            }
            if let Some(ref to) = snapshot.b_leg_stored_to {
                message.headers.set("To", to.clone());
            }
        }

        // The responder's OWN Contact, taken before the sanitize below overwrites
        // it. That rewrite points Contact at siphon, which is right for the copy
        // forwarded to the other leg — in-dialog requests have to come back here
        // — but the ACK goes back to the responder, and RFC 3261 §13.2.2.4 wants
        // its Request-URI to be that party's remote target. Reading it afterwards
        // addressed the ACK to siphon's own URI, so the responder did not accept
        // it and retransmitted its 200 until the retransmission handler above
        // sent a second, correct ACK. Self-correcting, at the cost of a
        // retransmit and the delay before it.
        //
        // The siphon-originated case was safe only because its response skips
        // sanitize entirely; the bridged case — every ordinary hold and resume —
        // was not.
        let responder_contact = message
            .headers
            .get("Contact")
            .or_else(|| message.headers.get("m"))
            .cloned();

        // A-facing (is_a2b) response: anchor Contact to the A-leg's arrival socket;
        // B-facing: leave it to via_port (the B-side advertised address). Skipped
        // for a siphon-originated re-INVITE — its response is absorbed, not
        // forwarded, and the ACK needs the responder's own Contact intact.
        if is_bridged_reinvite {
            sanitize_b2bua_response(
                message,
                state,
                resp_transport,
                if is_a2b {
                    snapshot.a_leg_local_addr
                } else {
                    None
                },
                snapshot.a_leg_supports_100rel,
                call_id,
            );
        }

        rewrite_reinvite_answer_sdp(
            call_id,
            message,
            status_code,
            response_source,
            state,
            snapshot,
            is_a2b,
            is_bridged_reinvite,
        );

        // The route set the re-INVITE itself carried, stored on the tracking leg
        // when it was sent. The ACK is its own request and has to carry the
        // dialog's route set (RFC 3261 §12.2.1.1) or it reaches the responder
        // without the state tokens the proxies in between put in their
        // Record-Route — signalling survives on a lenient proxy, but one that
        // keys media on that token never opens the path, so the call answers
        // silent. It cannot be rebuilt from the response: a mid-dialog 2xx does
        // not re-advertise Record-Route the way an initial INVITE's does
        // (§12.1.2). Read off the *tracking* leg rather than the winning B-leg
        // because a transfer promotes legs while its re-anchor re-INVITE is in
        // flight, so the winner is not reliably the party this ACK addresses.
        let responder_route_set: Vec<String> = snapshot
            .b_leg_index
            .and_then(|index| {
                state.call_actors.get_call(call_id).and_then(|call| {
                    call.b_legs
                        .get(index)
                        .map(|leg| leg.dialog.route_set.clone())
                })
            })
            .unwrap_or_default();

        // Helper: build and send ACK to the responder of the re-INVITE.
        // For 2xx: ACK uses a NEW branch (end-to-end, RFC 3261 §13.2.2.4).
        // For non-2xx: ACK uses the SAME branch (hop-by-hop, RFC 3261 §17.1.1.3).
        let send_reinvite_ack = |ack_branch: String, state: &DispatcherState| {
            if let Some((responder_dest, responder_transport)) = snapshot.b_leg_dest {
                if let Some((ref responder_cid, ref _responder_ftag)) = snapshot.b_leg_dialog {
                    let transport_str = format!("{}", responder_transport).to_uppercase();
                    // ACK Via sent-by: the responder's anchored listener. When the
                    // responder is the A-leg (B→A re-INVITE, !is_a2b) that's the
                    // arrival socket on a multi-homed host; when it is the B-leg,
                    // the flow socket the leg was dialled over (`b_leg_sent_by`).
                    let (outbound_host, outbound_port) = if is_a2b {
                        b_leg_sent_by(snapshot.b_leg_local_addr, state, &responder_transport)
                    } else {
                        (
                            state.a_leg_advertised_host(
                                snapshot.a_leg.transport.local_addr,
                                &responder_transport,
                            ),
                            a_leg_advertised_port(
                                snapshot.a_leg.transport.local_addr,
                                state
                                    .listen_addrs
                                    .get(&responder_transport)
                                    .map(|a| a.port())
                                    .unwrap_or(state.local_addr.port()),
                            ),
                        )
                    };
                    // Use the responder's CSeq (captured before originator CSeq restoration).
                    let cseq_num = responder_cseq_num.clone();
                    // The responder's own dialog identity, captured before the
                    // originator rewrite (RFC 3261 §12.2.1.1 — this ACK belongs
                    // to the responder's dialog, not the originator's). Reading
                    // `message` here sent it the far leg's tag pair.
                    let from = responder_from.clone().unwrap_or_default();
                    let to = responder_to.clone().unwrap_or_default();
                    // RURI: the responder's own Contact as it arrived (RFC 3261
                    // §12.2.1.1), captured above before sanitize rewrote it to
                    // siphon's address — reading `message` here addressed the ACK
                    // to ourselves. Falls back to the stored remote_contact.
                    let ack_uri = responder_contact
                        .as_deref()
                        .map(crate::b2bua::actor::extract_contact_uri)
                        .and_then(|u| parse_uri_standalone(&u).ok())
                        .or_else(|| {
                            if is_a2b {
                                snapshot
                                    .b_leg_remote_contact
                                    .as_deref()
                                    .and_then(|u| parse_uri_standalone(u).ok())
                            } else {
                                snapshot
                                    .a_leg
                                    .dialog
                                    .remote_contact
                                    .as_deref()
                                    .and_then(|u| parse_uri_standalone(u).ok())
                            }
                        })
                        .unwrap_or_else(|| {
                            SipUri::new(responder_dest.ip().to_string())
                                .with_port(responder_dest.port())
                        });
                    let Some(ack) = build_reinvite_ack(ReinviteAck {
                        request_uri: ack_uri,
                        via_transport: &transport_str,
                        via_host: &outbound_host,
                        via_port: outbound_port,
                        branch: &ack_branch,
                        from: from.as_str(),
                        to: to.as_str(),
                        call_id: responder_cid,
                        cseq_number: &cseq_num,
                        route_set: &responder_route_set,
                    }) else {
                        return;
                    };
                    // With a route set the ACK goes to its first hop, not the
                    // cached leg address (RFC 3261 §12.2.1.1) — the same
                    // resolution the re-INVITE used. A no-op when the route set
                    // is empty or still resolves to the established peer.
                    let (ack_dest, ack_transport) = resolve_in_dialog_destination(
                        &responder_route_set,
                        state,
                        responder_dest,
                        responder_transport,
                    );
                    if is_a2b {
                        send_b2bua_to_bleg(
                            ack,
                            ack_transport,
                            ack_dest,
                            snapshot.b_leg_local_addr,
                            state,
                        );
                    } else {
                        // ACK to the A-leg responder — source it from the A-leg's
                        // anchored socket (multi-homed source-port parity; Via above
                        // matches). No-op for single-listener hosts.
                        send_message_from(
                            ack,
                            ack_transport,
                            ack_dest,
                            snapshot.a_leg.transport.connection_id,
                            snapshot.a_leg.transport.local_addr,
                            state,
                        );
                    }
                }
            }
        };

        if (200..300).contains(&status_code) {
            // ACK the responder with a new branch (end-to-end ACK for 2xx)
            send_reinvite_ack(TransactionKey::generate_branch(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                "B2BUA: sent ACK to responder for re-INVITE 2xx"
            );

            // Reset session timer on successful re-INVITE
            state.call_actors.reset_session_timer(call_id);

            // Mark the re-INVITE B-leg entry as done (not removed!) so that
            // retransmitted 200 OKs can still be matched and re-ACKed.
            // The entry will be cleaned up when the call terminates.
            if let Some(idx) = snapshot.b_leg_index {
                state.call_actors.set_b_leg_target_uri(
                    call_id,
                    idx,
                    format!("reinvite_done:{}", direction),
                );
            }
            // RFC 3261 §14.1: the re-INVITE toward the target leg has
            // completed — clear the pending flag so a subsequent re-INVITE
            // (from either side) is allowed to start. `is_a2b` means the
            // re-INVITE was forwarded TOWARD the B-leg, so the pending flag
            // was set on the B-leg.
            state
                .call_actors
                .set_pending_reinvite(call_id, /*on_a_leg=*/ !is_a2b, false);
        } else if status_code >= 300 {
            // Non-2xx: ACK is hop-by-hop — reuse the SAME branch as the
            // forwarded re-INVITE (RFC 3261 §17.1.1.3).
            send_reinvite_ack(branch.to_string(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                status = status_code,
                "B2BUA: sent ACK to responder for re-INVITE non-2xx"
            );

            // Remove the re-INVITE B-leg entry — no retransmission expected
            // since the IST will transition Completed→Confirmed on our ACK.
            if let Some(idx) = snapshot.b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
            // Clear pending-reinvite on the target leg (see comment above).
            state
                .call_actors
                .set_pending_reinvite(call_id, /*on_a_leg=*/ !is_a2b, false);
        }

        // Forward the response to the originator — but ONLY for a bridged
        // re-INVITE (one leg originated it, the other must see the response). A
        // siphon-originated re-INVITE (session-timer refresh, transfer media
        // re-anchor) has no originator leg — its tracking entry carries no
        // stored Via — so the responder is already ACKed above and the response
        // is absorbed rather than forwarded as a spurious one to the far leg.
        if snapshot.b_leg_stored_vias.is_empty() {
            debug!(
                call_id = %call_id,
                direction = direction,
                "B2BUA: absorbing siphon-originated re-INVITE response (no originator to forward to)"
            );
        } else if is_a2b {
            // A→B re-INVITE: the response goes to the A-leg — pin its arrival socket.
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
            "B2BUA: forwarded re-INVITE response"
        );
        return true;
    }

    false
}

/// The SDP half of a forwarded re-INVITE answer: remember the answerer's own
/// endpoint SDP raw, push the answer through rtpengine, and own the `o=`
/// identity toward the originator (RFC 3264 §8).
pub fn rewrite_reinvite_answer_sdp(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
    is_a2b: bool,
    is_bridged_reinvite: bool,
) {
    // Track the ANSWERER's own endpoint SDP — raw, before the rtpengine
    // rewrite just below — so a later siphon-terminated transfer offers this
    // leg's *current* media if it turns out to be the survivor.
    //
    // The offer side of a re-INVITE was already tracked, but only for the leg
    // that offered (`handle_b2bua_reinvite`). A leg that merely *answers* kept
    // whatever it had answered the ORIGINAL INVITE with, which goes wrong the
    // moment the two disagree: a call that starts `a=recvonly` and is later
    // re-INVITEd to `sendrecv` leaves the answering leg still remembered as
    // `sendonly`, and the transfer then offers the target that stale
    // direction. Both surviving parties end up half-duplex — one able only to
    // send, the other only to receive — with no hold signalled anywhere for
    // either of them to display.
    //
    // Which leg goes stale depends on who offered the re-INVITE, which is why
    // this only broke transfers initiated from one side.
    if (200..300).contains(&status_code) && !message.body.is_empty() {
        state
            .call_actors
            .set_leg_last_sdp(call_id, !is_a2b, &message.body);
    }

    // RTPEngine: rewrite re-INVITE 2xx response SDP through answer.
    // Mirrors the offer processing done on the request side.
    if (200..300).contains(&status_code) && !message.body.is_empty() {
        if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) = (
            &state.rtpengine_set,
            &state.rtpengine_sessions,
            &state.rtpengine_profiles,
        ) {
            let a_sip_call_id = &snapshot.a_leg.dialog.call_id;
            if let Some(session) = media_sessions.get(a_sip_call_id) {
                if let Some(profile) = profiles.get(&session.profile) {
                    // The answer comes from the opposite side of the offer, and the engine keys
                    // the exchange on the offerer. A B→A answer must therefore name the callee
                    // as offerer: the caller's tag would claim the exchange ran the other way
                    // round and re-point the wrong leg's media. A 2xx cannot be refused, so when
                    // the pair cannot be named the SDP is left alone and the gap is logged.
                    if let Some((answer_from, answer_to)) = session.answer_tags(is_a2b) {
                        let mut answer_flags = profile.answer.clone();
                        // Pin the answering party's ingress to where its own 2xx arrived from,
                        // as the offer side now does for the offerer.
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
                                debug!(call_id = %call_id, "RTPEngine: rewrote re-INVITE response SDP (answer)");
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, "RTPEngine answer for re-INVITE failed: {error}");
                            }
                        }
                    } else {
                        error!(
                            call_id = %call_id,
                            "re-INVITE from the callee answered on a media session with no \
                             recorded answerer tag — leaving the answer SDP unanchored rather \
                             than naming the caller to the media engine"
                        );
                    }
                }
            }
        }
    }

    // Own the o= identity toward the re-INVITE originator on the relayed
    // answer (RFC 3264 §8): the offerer is the A-leg when is_a2b, else the
    // winning B-leg. Stamped after any rtpengine rewrite. Only for bridged
    // re-INVITEs — a siphon-originated re-INVITE response is absorbed, not
    // forwarded.
    if is_bridged_reinvite && (200..300).contains(&status_code) && !message.body.is_empty() {
        if let Some((sess_id, version)) = state.call_actors.reserve_leg_sdp_version(call_id, is_a2b)
        {
            stamp_sdp_origin(&mut message.body, &state.sdp_name, sess_id, version, None);
            message
                .headers
                .set("Content-Length", message.body.len().to_string());
        }
    }

    // `media.sdp_strip_attributes`, last: after the media engine answer and the
    // o= stamp. Only a bridged re-INVITE's response is forwarded; the response
    // to a siphon-originated one is absorbed.
    if is_bridged_reinvite {
        strip_relayed_sdp_attributes(message, state);
    }
}
