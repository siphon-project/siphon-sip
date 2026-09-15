//! The checks `handle_b2bua_response` runs before classifying a response:
//! the auto-PRACK it owes a reliable provisional, the retransmits it
//! absorbs, and the leg actor it feeds.

use crate::dispatcher::*;

/// A response on a fork branch siphon has CANCELled because another branch
/// answered, or one declined with a 6xx.
///
/// None of it may reach the call, which is answered or about to be torn down: a
/// 1xx is dropped, the ordinary 487 is ACKed (RFC 3261 §17.1.1.3), and a 2xx
/// that crossed the CANCEL is ACKed and its dialog released with a BYE
/// (§13.2.2.4, §15). That is the handling the branch gets once the call is
/// gone, so it is the same code. Returns `true` when the response was this.
pub fn absorb_cancelled_branch_response(
    call_id: &str,
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    if !state.call_actors.is_cancelled_branch(branch) {
        return false;
    }
    if status_code < 200 {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: dropping a provisional from a cancelled fork branch"
        );
    } else if status_code < 300 {
        if let Some((leg, first_2xx)) = state.call_actors.zombie_cancelled_for_2xx(branch) {
            handle_zombie_cancelled_2xx(leg, first_2xx, message, state);
        }
    } else if let Some((leg, invite_ruri)) = state.call_actors.zombie_cancelled_for_non2xx(branch) {
        handle_zombie_cancelled_non2xx(&leg, invite_ruri.as_deref(), message, status_code, state);
    }
    true
}

/// RFC 3262 §3: answer a reliable provisional from the B-leg with a PRACK of
/// our own, built from the B-leg dialog state. The caller never sees the
/// callee's `Require: 100rel` / `RSeq`: reliability toward the caller is
/// siphon's own ([`send_a_leg_provisional`]).
pub fn auto_prack_b_leg(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // RFC 3262 PRACK for the B-leg side: a reliable provisional from the callee
    // (`Require: 100rel` + `RSeq: <n>`) is PRACKed by siphon on the callee's
    // early dialog. Reliability is per leg: the callee's markers are removed in
    // `sanitize_b2bua_response`, and a provisional reaches the caller reliably on
    // siphon's own numbering when the caller asked for that. siphon's PRACK then
    // waits for the caller's PRACK of that copy, so whatever the caller's PRACK
    // carries crosses on it (RFC 3262 §5, `hold_or_send_callee_prack`). The
    // callee's response to it is told by its branch (`PRACK_BRANCH_PREFIX`).
    //
    // Returns `true` for a retransmission of a reliable provisional already
    // received, which is discarded.
    let needs_prack = (100..200).contains(&status_code)
        && status_code != 100
        && crate::sip::headers::rseq::requires_100rel(&message.headers);
    if !needs_prack {
        return false;
    }
    let (Some(rseq), Some(idx)) = (
        crate::sip::headers::rseq::parse_rseq(&message.headers),
        snapshot.b_leg_index,
    ) else {
        return false;
    };
    // No PRACK for a leg that has ended. It is the check `b_leg_provisional`
    // drops the provisional on, so siphon never PRACKs a provisional it does not
    // relay.
    //
    // A final response is already in (a failed fork branch, an LCR carrier
    // settled by its failure, the winner's 2xx): the INVITE client transaction is
    // over (RFC 3261 §17.1.1.2), and a non-2xx final ended every early dialog it
    // opened (§12.3). The far end has no unacknowledged provisional left for a
    // PRACK to match and answers it 481 (RFC 3262 §3).
    //
    // siphon CANCELled the leg and its 487 is not back yet: the transaction still
    // lives, so RFC 3262 §4 on its own would PRACK. siphon does not. The far end
    // answers the CANCEL with a 487 at once (RFC 3261 §9.2), may do so with a
    // provisional unacknowledged (RFC 3262 §3), and sends no provisional after a
    // final (RFC 3261 §17.2.1), so that 487 is what stops the retransmissions. A
    // PRACK can only leave behind the CANCEL, reaches the far end after the 487
    // in the ordinary case, and meets the same 481. Were the CANCEL lost, the far
    // end rejects the INVITE after 64*T1 without its PRACK (RFC 3262 §3), which
    // ends the leg siphon was ending anyway. While the branch is kept answerable,
    // `absorb_cancelled_branch_response` already dropped the provisional before
    // this runs; this covers the leg once it is not.
    if state.call_actors.is_ended_branch(call_id, idx) {
        debug!(
            call_id = %call_id,
            rseq = rseq.response_number,
            "B2BUA: no PRACK for a reliable provisional from a leg that already ended"
        );
        return false;
    }

    // RFC 3262 §4 + RFC 3261 §12.1.2: this reliable provisional establishes (or
    // refreshes) an early dialog. Build the PRACK from THIS response's remote
    // target — Contact (→ Request-URI), To (carries the early-dialog remote tag),
    // and Record-Route (reversed → route set) — rather than from the single
    // per-Leg Dialog, so a downstream fork producing several early dialogs on
    // this one INVITE branch PRACKs each to its OWN remote target instead of
    // collapsing them onto the first dialog's Contact. Without the Contact the
    // Request-URI falls back to the To AoR, which an IMS I-CSCF treats as an
    // initial terminating request and rejects 482 Loop Detected.
    let target = early_dialog_target_from_response(message);
    // The early dialog is keyed by its remote To-tag; dedup PRACK per tag
    // (forked dialogs have independent RSeq spaces, RFC 3262 §3). A missing tag
    // (malformed reliable 1xx) degrades to one shared key.
    let early_to_tag = crate::b2bua::actor::extract_to_tag(message);
    let dedup_key = early_to_tag.as_deref().unwrap_or("");

    // RFC 3262 §4: "Once a reliable provisional response is received,
    // retransmissions of that response MUST be discarded." The callee is
    // retransmitting because siphon's PRACK is in flight, lost, or still waiting
    // for the caller's. The PRACK has its own retransmissions, and the caller has
    // siphon's copy on siphon's own timer, so relaying it again would only show
    // the caller a new reliable provisional.
    if !state
        .call_actors
        .try_mark_prack_acked(call_id, idx, dedup_key, rseq.response_number)
    {
        debug!(
            call_id = %call_id,
            rseq = rseq.response_number,
            "B2BUA: discarding a retransmission of a reliable provisional (RFC 3262 §4)"
        );
        return true;
    }

    // Establish the FIRST early dialog's remote target on the canonical Dialog
    // (§12.1.2 — set once, not updated by later provisionals) so the eventual
    // 2xx / BYE / re-INVITE have a target before answer. The confirming 2xx
    // refreshes remote_tag / remote_contact to the winning dialog.
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(leg) = call.b_legs.get_mut(idx) {
            if leg.dialog.remote_tag.is_none() {
                if let Some(ref tag) = early_to_tag {
                    leg.dialog.remote_tag = Some(tag.clone());
                }
            }
            if leg.dialog.remote_contact.is_none() {
                if let Some(ref contact) = target.remote_contact {
                    leg.dialog.remote_contact = Some(contact.clone());
                }
            }
            if leg.dialog.route_set.is_empty() && !target.route_set.is_empty() {
                leg.dialog.route_set = target.route_set.clone();
            }
        }
    }

    // CSeq number + method from the 1xx (it echoes the INVITE's), for the RAck.
    let cseq_number: u32 = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse().ok())
        .unwrap_or(1);
    let cseq_method = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1))
        .map(str::to_string)
        .unwrap_or_else(|| "INVITE".to_string());
    // SDP in a reliable provisional to an INVITE siphon sent without one is the
    // callee's offer, which the PRACK answers (RFC 3262 §5).
    let invite_carried_no_offer = snapshot
        .b_leg_stored_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok())
        .is_some_and(|invite| invite.body.is_empty());
    let offer = (invite_carried_no_offer && !message.body.is_empty()).then(|| message.body.clone());
    hold_or_send_callee_prack(
        call_id,
        crate::b2bua::actor::HeldCalleePrack {
            b_leg_index: idx,
            to_tag: dedup_key.to_string(),
            rseq: rseq.response_number,
            cseq_number,
            cseq_method,
            remote_contact: target.remote_contact,
            to_header: target.to_header,
            route_set: target.route_set,
            offer: None,
        },
        offer,
        state,
    );
    false
}

/// A retransmitted 200 OK for a re-INVITE already completed: re-ACK the
/// responder to stop the retransmissions, and do not forward it again.
pub fn absorb_completed_reinvite_retransmit(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // Handle retransmitted 200 OK for already-completed re-INVITEs.
    // The entry was marked "reinvite_done:<dir>" after the first 200 OK was processed.
    // Just re-ACK the responder to stop retransmissions — don't forward again.
    if let Some(done_direction) = snapshot
        .b_leg_target
        .as_deref()
        .and_then(|t| t.strip_prefix("reinvite_done:"))
    {
        if (200..300).contains(&status_code) {
            let is_a2b = done_direction == "a2b";
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
                    let cseq_num = message
                        .headers
                        .cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    // RURI: extract Contact from the 200 OK message directly
                    // (RFC 3261 §12.2.1.1), with fallback to stored remote_contact.
                    let ack_uri = message
                        .headers
                        .get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
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
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, ack_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            outbound_host,
                            outbound_port,
                            TransactionKey::generate_branch(),
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(responder_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for re-INVITE 2xx retransmit build failed: {error}");
                            return true;
                        }
                    };
                    if is_a2b {
                        send_b2bua_to_bleg(
                            ack,
                            responder_transport,
                            responder_dest,
                            snapshot.b_leg_local_addr,
                            state,
                        );
                    } else {
                        // ACK to the A-leg responder — source it from the A-leg's
                        // anchored socket (multi-homed source-port parity; Via above
                        // matches). No-op for single-listener hosts.
                        send_message_from(
                            ack,
                            responder_transport,
                            responder_dest,
                            snapshot.a_leg.transport.connection_id,
                            snapshot.a_leg.transport.local_addr,
                            state,
                        );
                    }
                    debug!(
                        call_id = %call_id,
                        "B2BUA: re-ACKed retransmitted 200 OK for completed re-INVITE"
                    );
                }
            }
        } else {
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: absorbing retransmitted non-2xx for completed re-INVITE"
            );
        }
        return true;
    }

    false
}

/// A retransmitted response for an UPDATE already completed. RFC 3311 §5.4
/// has no ACK for UPDATE, so the duplicate is simply absorbed.
pub fn absorb_completed_update_retransmit(
    call_id: &str,
    status_code: u16,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // Handle retransmitted responses for already-completed UPDATEs.
    // Per RFC 3311 §5.4 there is no ACK for UPDATE — just absorb the dup
    // and let the responder's non-INVITE server transaction stop on its own.
    if snapshot
        .b_leg_target
        .as_deref()
        .is_some_and(|t| t.starts_with("update_done:"))
    {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: absorbing retransmitted response for completed UPDATE"
        );
        return true;
    }

    false
}

/// A retransmitted response for a forwarded REFER, NOTIFY or INFO whose final
/// response was already relayed.
///
/// Absorbed, never answered: none of these is an INVITE, so there is no ACK to
/// send (RFC 3261 §17.1.2) and nothing to relay a second time. Without this a
/// duplicate fell through to the INVITE-answer path, which read it as a
/// retransmitted INVITE 2xx and ACKed it with the pseudo-leg's marker as the
/// Request-URI.
pub fn absorb_completed_forward_retransmit(
    call_id: &str,
    status_code: u16,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    if snapshot
        .b_leg_target
        .as_deref()
        .is_some_and(crate::b2bua::actor::ForwardedMarker::is_done_target)
    {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: absorbing retransmitted response for a completed forwarded request"
        );
        return true;
    }

    false
}

/// A response to one of a bridge's own re-INVITEs, which drives the bridge's
/// next step rather than being forwarded to an originator leg.
pub fn dispatch_bridge_reinvite_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // A response to one of a bridge's own re-INVITEs. Checked before the
    // `reinvite:` arm because a bridged pair has no originator leg to forward
    // the answer to: both sides are the A-leg of their own call actor, so the
    // response is absorbed and drives the bridge's next step instead.
    if let Some(stage) = snapshot
        .b_leg_target
        .as_deref()
        .and_then(|t| t.strip_prefix("bridge:"))
    {
        handle_bridge_reinvite_response(
            call_id,
            stage,
            branch,
            message,
            status_code,
            snapshot,
            state,
        );
        return true;
    }

    false
}

/// A retransmitted 200 for a bridge re-INVITE already handled: re-ACK so the
/// responder's transaction stops, and do not re-run the bridge step.
pub fn absorb_completed_bridge_retransmit(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    // A retransmitted 200 for a bridge re-INVITE already handled: re-ACK it so
    // the responder's transaction stops, and do not re-run the bridge step.
    if snapshot
        .b_leg_target
        .as_deref()
        .is_some_and(|t| t.starts_with("bridge_done:"))
    {
        if (200..300).contains(&status_code) {
            if let Some(ack) = build_ack_for_owned_leg(
                &snapshot.a_leg,
                message,
                &TransactionKey::generate_branch(),
                state,
            ) {
                let (destination, transport) = resolve_in_dialog_destination(
                    &snapshot.a_leg.dialog.route_set,
                    state,
                    snapshot.a_leg.transport.remote_addr,
                    snapshot.a_leg.transport.transport,
                );
                send_message_from(
                    ack,
                    transport,
                    destination,
                    snapshot.a_leg.transport.connection_id,
                    snapshot.a_leg.transport.local_addr,
                    state,
                );
            }
        }
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA bridge: absorbed a retransmitted re-INVITE response"
        );
        return true;
    }

    false
}

/// Feed the response to the B-leg actor so its own state machine advances,
/// and, on a 2xx, learn the dialog's remote tag and target off it (RFC 3261
/// §12.1.2) into the authoritative `CallActor`.
pub fn feed_leg_actor_and_learn_dialog(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) {
    // Route response through B-leg actor for classification.
    // The actor classifies the SIP response into a CallEvent (Provisional,
    // Answered, Failed). We send the message, block-recv the event, then
    // use the event to drive response handling below.
    // Re-INVITE tracking legs and retry legs may not have actors — fall
    // back to raw status_code classification in that case.
    // Kept for its side effects, not its value: the response still has to reach
    // the leg actor so its own state machine advances, and the event it emits
    // still has to be consumed so the per-call channel drains. What comes back
    // is deliberately unused — see the classification note below.
    let _actor_event: Option<CallEvent> = if let Some(handle_tx) = &snapshot.b_leg_handle_tx {
        let leg_transport = snapshot
            .b_leg_dest
            .map(|(addr, transport)| LegTransport {
                remote_addr: addr,
                connection_id: ConnectionId::default(),
                transport,
                local_addr: None,
            })
            .unwrap_or_else(|| LegTransport {
                remote_addr: state.local_addr,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            });
        match handle_tx.try_send(crate::b2bua::actor::LegMessage::SipInbound {
            message: message.clone(),
            source: leg_transport,
        }) {
            Ok(()) => {
                // Temporarily extract receiver to block on it.
                // Safe: dispatcher processes messages sequentially.
                // Skip stale CallEvent::Terminated from a superseded leg's
                // actor (401/407/422 retry → replace_b_leg) — see
                // recv_b_leg_classification_event for why consuming one here
                // would misclassify the B-leg 200 OK as provisional.
                if let Some((_, mut rx)) = state.call_event_receivers.remove(call_id) {
                    let event = recv_b_leg_classification_event(&mut rx);
                    state.call_event_receivers.insert(call_id.to_string(), rx);
                    event
                } else {
                    None
                }
            }
            Err(_) => {
                debug!(call_id = %call_id, "B2BUA: actor mailbox full, classifying directly");
                None
            }
        }
    } else {
        None
    };

    // On 2xx: sync remote_tag and remote_contact from response back to canonical CallActor.
    // The LegActor extracts this on its clone, but we need to update the
    // authoritative copy in the CallActorStore.
    // Driven by the 2xx itself. The dialog state a B-leg needs for every request
    // siphon later builds toward it (BYE, re-INVITE, UPDATE) comes from the 2xx
    // that establishes the dialog (RFC 3261 §12.1.2) — not from an actor event
    // that may describe a different response entirely (see the classification
    // note below).
    if (200..300).contains(&status_code) {
        if let Some(idx) = snapshot.b_leg_index {
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                if let Some(b_leg) = call.b_legs.get_mut(idx) {
                    if let Some(to_tag) = crate::b2bua::actor::extract_to_tag(message) {
                        // Splice the to-tag into remote_to_uri so in-dialog
                        // requests (UPDATE, re-INVITE, BYE) toward this leg
                        // can build a proper tagged To: header (RFC 3261
                        // §12.1.1). remote_to_uri was captured from the
                        // outbound INVITE which had no tag yet.
                        if let Some(ref to_uri) = b_leg.dialog.remote_to_uri {
                            if !to_uri.contains(";tag=") {
                                b_leg.dialog.remote_to_uri =
                                    Some(format!("{};tag={}", to_uri.trim_end(), to_tag));
                            }
                        }
                        b_leg.dialog.remote_tag = Some(to_tag);
                    }
                    // Capture B-leg's remote Contact (RFC 3261 §12.1.2: remote target from 2xx)
                    if let Some(contact) = message
                        .headers
                        .get("Contact")
                        .or_else(|| message.headers.get("m"))
                    {
                        b_leg.dialog.remote_contact =
                            Some(crate::b2bua::actor::extract_contact_uri(contact));
                    }
                }
            }
        }
    }
}
