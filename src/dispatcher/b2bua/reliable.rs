//! RFC 3262 toward the caller.
//!
//! siphon is the caller's UAS, so a provisional reaches the caller reliably on
//! siphon's own `RSeq` numbering, is retransmitted until the caller's PRACK, and
//! that PRACK is answered here. A 2xx that must not overtake a reliable
//! provisional waits for its PRACK, and a caller that never PRACKs is refused.
//! The callee's reliable provisionals are the B-leg's: siphon PRACKs them there
//! ([`auto_prack_b_leg`]) and none of their reliability reaches the caller.
//!
//! What goes out when is decided by the call's
//! [`crate::b2bua::actor::ALegReliableProvisionals`]; this puts it on the wire.

use std::time::Instant;

use crate::b2bua::actor::{
    sends_reliably, AnswerStep, HeldAnswer, Offered, PrackOutcome, ProvisionalSend,
};
use crate::dispatcher::*;

/// The status a caller that never PRACKs is refused with: RFC 3262 §3 has the
/// UAS "reject the original request with a 5xx response".
const UNACKNOWLEDGED_STATUS: u16 = 500;

/// What siphon needs of a call to reach its caller once the call's lock is
/// released.
struct CallerRoute {
    sip_call_id: String,
    local_tag: String,
    transport: Transport,
    remote_addr: SocketAddr,
    connection_id: ConnectionId,
    /// The listener the caller's INVITE arrived on, so a multi-homed UDP host
    /// answers on the port it received on. `None` for stream transports and a
    /// single-listener host, where it makes no difference.
    local_addr: Option<SocketAddr>,
    invite: Option<Arc<Mutex<SipMessage>>>,
    li_record: bool,
    winner_branch: Option<String>,
}

impl CallerRoute {
    fn of(call: &crate::b2bua::actor::CallActor) -> CallerRoute {
        CallerRoute {
            sip_call_id: call.a_leg.dialog.call_id.clone(),
            local_tag: call.a_leg.dialog.local_tag.clone(),
            transport: call.a_leg.transport.transport,
            remote_addr: call.a_leg.transport.remote_addr,
            connection_id: call.a_leg.transport.connection_id,
            local_addr: call.a_leg_local_addr,
            invite: call.a_leg_invite.clone(),
            li_record: call.li_record,
            winner_branch: call
                .winner
                .and_then(|index| call.b_legs.get(index))
                .map(|leg| leg.branch.clone()),
        }
    }

    fn retransmit_route(&self) -> ReliableProvisionalRoute {
        ReliableProvisionalRoute {
            transport: self.transport,
            destination: self.remote_addr,
            connection_id: self.connection_id,
            source_local_addr: self.local_addr,
        }
    }

    /// Whether `inbound` came over this route, so a response to it can leave in
    /// one ordered group with what siphon sends the caller next.
    fn carried(&self, inbound: &InboundMessage) -> bool {
        inbound.transport == self.transport
            && inbound.remote_addr == self.remote_addr
            && inbound.connection_id == self.connection_id
    }
}

/// Send `response`, a 101-199 for the caller's INVITE already carrying the
/// caller's dialog identifiers, to the caller of `call_id`.
///
/// It goes out reliably (RFC 3262 §3) when the caller required `100rel`, or
/// supports it and either the callee sent this provisional reliably
/// (`callee_sent_reliably`, `false` for siphon's own provisional) or it carries
/// SDP: with siphon's
/// next `RSeq` on the caller's dialog, retransmitted until the caller's PRACK.
/// While a reliable provisional before it is unacknowledged it waits, and goes
/// out when that PRACK arrives. Returns `false` when the call is gone.
pub fn send_a_leg_provisional(
    call_id: &str,
    response: SipMessage,
    callee_sent_reliably: bool,
    state: &DispatcherState,
) -> bool {
    let now = Instant::now();
    let Some((route, messages)) = state.call_actors.get_call_mut(call_id).map(|mut call| {
        let reliable = sends_reliably(
            call.a_leg_requires_100rel,
            call.a_leg_supports_100rel,
            callee_sent_reliably,
            crate::b2bua::actor::carries_session_description(&response),
        );
        let route = CallerRoute::of(&call);
        let messages = match call.a_leg_reliability.offer(response, reliable, now) {
            Offered::Send(send) => prepare_provisionals(vec![send], &route, state),
            Offered::Queued => {
                debug!(
                    call_id = %call_id,
                    "B2BUA: provisional for the caller waits for the PRACK of the reliable one before it (RFC 3262 §3)"
                );
                Vec::new()
            }
            Offered::AfterFinal => {
                debug!(
                    call_id = %call_id,
                    "B2BUA: dropping a provisional for a caller that already has its final response"
                );
                Vec::new()
            }
        };
        (route, messages)
    }) else {
        return false;
    };
    send_to_caller(messages, &route, state);
    true
}

/// Stamp each provisional with its reliability, siphon's `RSeq` or none, and arm
/// the retransmissions of a reliable one before it is sent, so a PRACK racing
/// the send finds it armed. Runs under the call's lock, which a PRACK takes too.
fn prepare_provisionals(
    sends: Vec<ProvisionalSend>,
    route: &CallerRoute,
    state: &DispatcherState,
) -> Vec<SipMessage> {
    sends
        .into_iter()
        .map(
            |ProvisionalSend {
                 mut response,
                 rseq,
                 stop,
             }| {
                crate::sip::headers::rseq::set_reliability(&mut response.headers, rseq);
                if let (Some(rseq), Some(stop)) = (rseq, stop) {
                    // A reliable provisional opens an early dialog, which the
                    // caller's PRACK names by siphon's tag (RFC 3262 §4).
                    if let Some(to) = response.headers.to().cloned() {
                        if !to.contains(";tag=") {
                            response.headers.set(
                                "To",
                                crate::b2bua::actor::ensure_tag(&to, Some(&route.local_tag)),
                            );
                        }
                    }
                    let cseq_number = response
                        .headers
                        .cseq()
                        .and_then(|cseq| cseq.split_whitespace().next())
                        .and_then(|number| number.parse().ok())
                        .unwrap_or(1);
                    arm_reliable_provisional_retransmit_on(
                        route.sip_call_id.clone(),
                        rseq,
                        cseq_number,
                        response.clone(),
                        route.retransmit_route(),
                        stop,
                        state,
                    );
                }
                response
            },
        )
        .collect()
}

/// Put `messages` on the wire to the caller, several as one ordered group: sent
/// apart on UDP they can overtake each other.
fn send_to_caller(messages: Vec<SipMessage>, route: &CallerRoute, state: &DispatcherState) {
    if messages.len() > 1 {
        send_messages_in_order_from(
            messages,
            route.transport,
            route.remote_addr,
            route.connection_id,
            route.local_addr,
            state,
        );
    } else if let Some(message) = messages.into_iter().next() {
        send_message_from(
            message,
            route.transport,
            route.remote_addr,
            route.connection_id,
            route.local_addr,
            state,
        );
    }
}

/// The caller's 2xx for `call_id` is ready: send it, or hold it while a reliable
/// provisional that carried SDP awaits its PRACK (RFC 3262 §3, §5), in which
/// case it follows that PRACK's 200.
pub fn answer_a_leg(call_id: &str, answer: HeldAnswer, state: &DispatcherState) {
    let Some((route, step)) = state.call_actors.get_call_mut(call_id).map(|mut call| {
        (
            CallerRoute::of(&call),
            call.a_leg_reliability.answer(Box::new(answer)),
        )
    }) else {
        warn!(call_id = %call_id, "B2BUA: the call was gone before its answer went to the caller");
        return;
    };
    match step {
        AnswerStep::Send(answer) => {
            deliver_a_leg_answer(call_id, answer, Vec::new(), &route, state)
        }
        AnswerStep::Held => debug!(
            call_id = %call_id,
            "B2BUA: the caller's 2xx waits for the PRACK of a reliable provisional (RFC 3262 §3)"
        ),
    }
}

/// Send the caller's 2xx after `leading`, and what follows an answer.
///
/// An answer relayed from the callee starts the charging and SIPREC, which
/// siphon's own answer does not. Arming its retransmission here, when it is
/// actually sent, is what puts it under the 64*T1 unACKed sweep and the RFC 3261
/// §15 BYE hold; a 2xx still held is under neither.
fn deliver_a_leg_answer(
    call_id: &str,
    answer: Box<HeldAnswer>,
    mut leading: Vec<SipMessage>,
    route: &CallerRoute,
    state: &DispatcherState,
) {
    let HeldAnswer {
        response,
        relayed,
        deferred_refer,
    } = *answer;
    // Kept for SIPREC, which offers the answer's SDP.
    let sdp_body = response.body.clone();
    // Clone the 2xx so the retransmit is byte-identical (RFC 3261 §13.3.1.4).
    let retransmit = response.clone();

    // From the listener the caller's INVITE arrived on: a peer doing symmetric
    // signalling drops a 2xx sourced from a different local port.
    leading.push(response);
    send_to_caller(leading, route, state);

    // The B2BUA has no INVITE server transaction for the caller, so nothing else
    // recovers a lost 2xx. Cancelled by the caller's ACK in the late-ACK handler
    // (search `uas_2xx_retransmits`).
    arm_b2bua_2xx_retransmit(
        call_id,
        retransmit,
        route.transport,
        route.remote_addr,
        route.connection_id,
        route.local_addr,
        state,
    );

    if relayed {
        // Rf ACR-START on the answer (TS 32.299 §6.2.2), fire-and-forget per
        // §6.5. Reported now the caller has the 2xx: an answer siphon could still
        // turn into a failure is not an answer, and a CDF/OCS that was told
        // otherwise had no later record correcting it.
        if let Some(invite) = &route.invite {
            spawn_rf_b2bua_start(state, call_id, invite);
        }
        // Ro is not *started* here — prepaid reserve-before-connect means the
        // CCR-INITIAL already fired in `@b2bua.on_invite` via
        // `call.ro_authorize()`. But the answer is what starts the chargeable
        // clock (TS 32.260 §5), so report it: a CCR-UPDATE carrying Time-Stamps
        // tells the OCS when charging began, and under `ro.charge_from: answer`
        // it is also what stops ring time being billed.
        spawn_ro_b2bua_answer(state, call_id);
    }

    // A `call.refer()` deferred from @b2bua.on_answer, now that the answer it
    // depends on is on the wire: a REFER ahead of the 2xx is for a dialog the
    // caller has not confirmed (RFC 3261 §13.2.2.4), which a real UA answers 481.
    if let Some(refer_to) = deferred_refer {
        b2bua_send_outbound_refer(state, call_id, /*on_a_leg=*/ true, &refer_to);
    }

    // SIPREC, when `li.record()` marked the call and an SRS is configured.
    if relayed && route.li_record {
        let srs_uri = state.li_siprec_srs_uri.as_deref();
        let snapshot = route
            .winner_branch
            .as_deref()
            .and_then(|branch| b_leg_response_snapshot(call_id, branch, state));
        if let (Some(srs_uri), Some(snapshot)) = (srs_uri, snapshot) {
            start_li_recording(call_id, state, &snapshot, Some(srs_uri), &sdp_body);
        }
    }
}

/// Answer a PRACK from a B2BUA caller (RFC 3262 §3).
///
/// Matched on its `RAck` against the reliable provisionals siphon sent on the
/// caller's dialog, which the PRACK names by siphon's To-tag: 200 for the one
/// awaiting it, and whatever that PRACK released goes out right behind the 200
/// (the next provisional, or the held 2xx); 200 again for a retransmission of a
/// PRACK already answered; 481 for one that matches nothing. None is relayed to
/// the callee, whose provisionals siphon PRACKs on the B-leg itself.
pub fn handle_b2bua_prack(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let reply = |status_code: u16, reason: &str| {
        build_response(
            &message,
            status_code,
            reason,
            state.server_header.as_deref(),
            &[],
        )
    };
    let to_inbound = |response: SipMessage| {
        // On the PRACK's arrival socket (multi-homed UDP source-port parity).
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
    };
    let Some(rack) = crate::sip::headers::rseq::parse_rack(&message.headers) else {
        // RFC 3262 §7.2: every PRACK carries an RAck.
        to_inbound(reply(400, "Bad Request"));
        return;
    };
    let sip_call_id = message.headers.call_id().cloned().unwrap_or_default();
    let to_tag = crate::b2bua::actor::extract_to_tag(&message);
    let now = Instant::now();

    let decided = state
        .call_actors
        .find_by_sip_call_id(&sip_call_id)
        .and_then(|call_id| {
            let mut call = state.call_actors.get_call_mut(&call_id)?;
            let route = CallerRoute::of(&call);
            let on_the_callers_dialog = rack.method.eq_ignore_ascii_case("INVITE")
                && to_tag.as_deref() == Some(route.local_tag.as_str());
            let outcome = if on_the_callers_dialog {
                call.a_leg_reliability
                    .acknowledge(rack.response_number, rack.cseq_number, now)
            } else {
                PrackOutcome::Unmatched
            };
            let decision = match outcome {
                PrackOutcome::Acknowledged {
                    rseq,
                    release,
                    answer,
                } => {
                    if let Some((_, entry)) = state
                        .reliable_provisionals
                        .remove(&(route.sip_call_id.clone(), rseq))
                    {
                        entry.cancel.notify_one();
                    }
                    Some((prepare_provisionals(release, &route, state), answer))
                }
                PrackOutcome::AlreadyAcknowledged => Some((Vec::new(), None)),
                PrackOutcome::Unmatched => None,
            };
            Some((call_id, route, decision))
        });

    match decided {
        Some((call_id, route, Some((released, answer)))) => {
            debug!(
                call_id = %call_id,
                rseq = rack.response_number,
                "B2BUA: the caller's PRACK acknowledges a reliable provisional — 200 OK"
            );
            let mut messages = Vec::with_capacity(released.len() + 2);
            let ok = reply(200, "OK");
            if route.carried(&inbound) {
                messages.push(ok);
            } else {
                to_inbound(ok);
            }
            messages.extend(released);
            match answer {
                Some(answer) => deliver_a_leg_answer(&call_id, answer, messages, &route, state),
                None => send_to_caller(messages, &route, state),
            }
        }
        Some((call_id, _, None)) => {
            debug!(
                call_id = %call_id,
                rseq = rack.response_number,
                "B2BUA: the caller's PRACK matches no reliable provisional on its dialog — 481"
            );
            to_inbound(reply(481, "Call/Transaction Does Not Exist"));
        }
        None => {
            // The call ended between the lookup that routed this PRACK here and
            // now: a provisional it acknowledges is still answered.
            if !answer_prack_of_tracked_provisional(&inbound, &message, state) {
                to_inbound(reply(481, "Call/Transaction Does Not Exist"));
            }
        }
    }
}

/// Answer `message`, a PRACK, 200 and stop the retransmissions when it
/// acknowledges a reliable provisional still tracked for them: a script's
/// `reply(reliable=True)`, or a provisional to a B2BUA caller whose call has
/// ended, which the UAS "MUST be prepared to process PRACK requests for" (RFC
/// 3262 §3). Returns `false`, sending nothing, when it matches none.
pub fn answer_prack_of_tracked_provisional(
    inbound: &InboundMessage,
    message: &SipMessage,
    state: &DispatcherState,
) -> bool {
    let Some(rack) = crate::sip::headers::rseq::parse_rack(&message.headers) else {
        return false;
    };
    let sip_call_id = message.headers.call_id().cloned().unwrap_or_default();
    let key = (sip_call_id, rack.response_number);
    let matched = state
        .reliable_provisionals
        .get(&key)
        .map(|entry| Arc::clone(entry.value()))
        .filter(|entry| entry.cseq_num == rack.cseq_number);
    let Some(entry) = matched else {
        return false;
    };
    state.reliable_provisionals.remove(&key);
    entry.cancel.notify_one();
    debug!(
        call_id = %key.0, rseq = rack.response_number,
        "PRACK matches our reliable 1xx — cancelling retransmits and sending 200 OK"
    );
    let response = build_response(message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    true
}

/// A final response other than siphon's 2xx is about to go to the caller of
/// `call_id`: nothing more is sent to it reliably or queued, and the
/// retransmissions of an unacknowledged reliable provisional stop (RFC 3262 §3),
/// though its PRACK is still answered. A 2xx held for a PRACK now never goes
/// out, so the callee's dialog it came from is ACKed and BYEd (RFC 3261
/// §13.2.2.4, §15).
pub fn end_a_leg_reliability(call_id: &str, state: &DispatcherState) {
    let Some((held, winner)) = state.call_actors.get_call_mut(call_id).map(|mut call| {
        let held = call.a_leg_reliability.finish();
        let winner = call
            .winner
            .and_then(|index| call.b_legs.get(index).cloned());
        (held, winner)
    }) else {
        return;
    };
    release_held_answer(call_id, held, winner, state);
}

/// Release the callee's dialog behind a relayed 2xx that will never reach the
/// caller. The callee's 2xx was ACKed when it arrived, or its ACK still waits for
/// the caller's answer, so the dialog gets a BYE after whatever it is still owed
/// ([`send_or_hold_bye`]: a delayed offer's ACK goes first, every stream
/// rejected).
fn release_held_answer(
    call_id: &str,
    held: Option<Box<HeldAnswer>>,
    winner: Option<crate::b2bua::actor::Leg>,
    state: &DispatcherState,
) {
    if !held.is_some_and(|held| held.relayed) {
        return;
    }
    let Some(leg) = winner else {
        warn!(
            call_id = %call_id,
            "B2BUA: the answered B-leg is gone — its dialog cannot be released and may linger"
        );
        return;
    };
    match build_b2bua_bye(&leg, state) {
        Some(bye) => send_or_hold_bye(call_id, &leg, bye, ByeSender::BLeg, state),
        None => warn!(
            call_id = %call_id,
            "B2BUA: could not build the BYE for the answered B-leg behind a held 2xx"
        ),
    }
}

/// A teardown is about to BYE the caller's dialog while the caller's 2xx is still
/// held for a PRACK (RFC 3262 §3). The caller has had no final response on that
/// dialog, only provisionals, so it gets `487 Request Terminated` to its INVITE
/// ("terminated by a BYE or CANCEL request", RFC 3261 §21.4.26) instead of a BYE
/// for a dialog it never saw confirmed, and the held 2xx is dropped for good.
/// Returns `false`, doing nothing, for any other dialog or call.
pub fn end_held_answer_for_caller(
    internal_call_id: &str,
    leg: &Leg,
    state: &DispatcherState,
) -> bool {
    let Some((a_leg, invite, local_addr)) = state
        .call_actors
        .get_call_mut(internal_call_id)
        .and_then(|mut call| {
            if call.a_leg.dialog.call_id != leg.dialog.call_id
                || !call.a_leg_reliability.holds_answer()
            {
                return None;
            }
            let _dropped = call.a_leg_reliability.finish();
            Some((
                call.a_leg.clone(),
                call.a_leg_invite.clone(),
                call.a_leg_local_addr,
            ))
        })
    else {
        return false;
    };
    info!(
        call_id = %internal_call_id,
        "B2BUA: the call ended while the caller's 2xx waited for its PRACK — 487 instead of a BYE"
    );
    if let Some(response) = a_leg_final_response(
        internal_call_id,
        &a_leg,
        invite.as_ref(),
        487,
        "Request Terminated",
        state,
    ) {
        send_message_from(
            response,
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            local_addr,
            state,
        );
    }
    true
}

/// Refuse every caller that has let a reliable provisional go unacknowledged for
/// 64*T1 (RFC 3262 §3). Runs on the dispatcher's fast call-lifetime interval.
pub fn check_b2bua_prack_timeouts(state: &DispatcherState) {
    check_b2bua_prack_timeouts_at(state, Instant::now());
}

/// [`check_b2bua_prack_timeouts`] as of `now`, which is how a test steps past
/// 64*T1 without waiting it out.
pub fn check_b2bua_prack_timeouts_at(state: &DispatcherState, now: Instant) {
    let overdue: Vec<String> = state
        .call_actors
        .iter_calls()
        .filter(|entry| entry.value().a_leg_reliability.overdue(now))
        .map(|entry| entry.key().clone())
        .collect();
    for call_id in overdue {
        refuse_unacknowledging_caller(&call_id, now, state);
    }
}

/// RFC 3262 §3: "If a reliable provisional response is retransmitted for 64*T1
/// seconds without reception of a corresponding PRACK, the UAS SHOULD reject the
/// original request with a 5xx response."
///
/// It is a teardown, so it takes the call over first, the claim
/// [`CallActorStore::claim_teardown`] makes, under the same lock that re-checks
/// the deadline: a call another teardown already has is left to that one, and a
/// PRACK that arrived meanwhile keeps the call. The callee is let go next: still
/// ringing, it is CANCELled (RFC 3261 §9.1); answered, with its 2xx held for this
/// PRACK, its dialog is BYEd and the answer no longer stands. The caller then
/// gets the 5xx, without `@b2bua.on_failure`, since routing the call elsewhere
/// cannot make the caller PRACK.
fn refuse_unacknowledging_caller(call_id: &str, now: Instant, state: &DispatcherState) {
    let Some((sip_call_id, rseq, held, winner, handles)) = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut call| {
            // Re-checked under the lock: the PRACK may have arrived since the
            // sweep read the call, or another teardown may have taken it.
            if !call.a_leg_reliability.overdue(now) || call.teardown_claimed {
                return None;
            }
            call.teardown_claimed = true;
            let rseq = call.a_leg_reliability.unacknowledged_rseq();
            let held = call.a_leg_reliability.finish();
            for b_leg in &call.b_legs {
                state.b2bua_retransmits.disarm_branch(&b_leg.branch);
            }
            let handles: Vec<_> = call
                .b_leg_handles
                .iter()
                .flatten()
                .map(|handle| handle.tx.clone())
                .collect();
            let winner = call
                .winner
                .and_then(|index| call.b_legs.get(index).cloned());
            Some((
                call.a_leg.dialog.call_id.clone(),
                rseq,
                held,
                winner,
                handles,
            ))
        })
    else {
        return;
    };
    warn!(
        call_id = %call_id,
        rseq = ?rseq,
        "B2BUA: the caller did not PRACK a reliable provisional within 64*T1 — refusing the call {UNACKNOWLEDGED_STATUS} (RFC 3262 §3)"
    );
    if let Some(rseq) = rseq {
        if let Some((_, entry)) = state.reliable_provisionals.remove(&(sip_call_id, rseq)) {
            entry.cancel.notify_one();
        }
    }
    if held.is_some() {
        release_held_answer(call_id, held, winner, state);
        cdr_clear_b2bua_answer(state, call_id);
    } else {
        for handle in &handles {
            let _ = handle.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(&cancelled, state);
    }
    end_call_without_rerouting(call_id, UNACKNOWLEDGED_STATUS, state);
}
