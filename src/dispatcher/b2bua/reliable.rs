//! RFC 3262 toward the caller.
//!
//! siphon is the caller's UAS, so a provisional reaches the caller reliably on
//! siphon's own `RSeq` numbering, is retransmitted until the caller's PRACK, and
//! that PRACK is answered here. A 2xx that must not overtake a reliable
//! provisional waits for its PRACK, and a caller that never PRACKs is refused.
//! The callee's reliable provisionals are the B-leg's: siphon PRACKs them there
//! ([`auto_prack_b_leg`]), once the caller has PRACKed siphon's copy when there
//! is one, and that PRACK carries what the caller's did ([`bridge_caller_prack`]).
//!
//! What goes out when is decided by the call's
//! [`crate::b2bua::actor::ALegReliableProvisionals`]; this puts it on the wire.

use std::time::Instant;

use crate::b2bua::actor::{
    sends_reliably, AnswerStep, HeldAnswer, HeldCalleePrack, Offered, PrackOutcome,
    ProvisionalSend, RequestSource,
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
/// SDP: with siphon's next `RSeq` on the caller's dialog, retransmitted until the
/// caller's PRACK. While a reliable provisional before it is unacknowledged it
/// waits, and goes out when that PRACK arrives. `link` names the PRACK siphon
/// holds for the callee's reliable provisional this copies, which the caller's
/// PRACK of this copy releases, and which goes to the callee at once when the
/// caller will never PRACK it. Returns `false` when the call is gone.
pub fn send_a_leg_provisional(
    call_id: &str,
    response: SipMessage,
    callee_sent_reliably: bool,
    link: Option<u64>,
    state: &DispatcherState,
) -> bool {
    let now = Instant::now();
    let Some((route, messages, unanswered)) =
        state.call_actors.get_call_mut(call_id).map(|mut call| {
            let reliable = sends_reliably(
                call.a_leg_requires_100rel,
                call.a_leg_supports_100rel,
                callee_sent_reliably,
                crate::b2bua::actor::carries_session_description(&response),
            );
            let route = CallerRoute::of(&call);
            let offered =
                call.a_leg_reliability
                    .offer(response, reliable, link.filter(|_| reliable), now);
            let unanswered =
                link.filter(|_| !reliable || matches!(offered, Offered::AfterFinal));
            let messages = match offered {
                Offered::Send(send) => prepare_provisionals(vec![send], &route, state, &mut call),
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
            (route, messages, unanswered)
        })
    else {
        return false;
    };
    send_to_caller(messages, &route, state);
    if let Some(link) = unanswered {
        release_unanswered_callee_prack(call_id, link, state);
    }
    true
}

/// Stamp each provisional with its reliability, siphon's `RSeq` or none, and arm
/// the retransmissions of a reliable one before it is sent, so a PRACK racing
/// the send finds it armed. The SDP a reliable one carries is recorded on the
/// caller's dialog ([`record_caller_session`]). Runs under the call's lock, which
/// a PRACK takes too.
fn prepare_provisionals(
    sends: Vec<ProvisionalSend>,
    route: &CallerRoute,
    state: &DispatcherState,
    call: &mut crate::b2bua::actor::CallActor,
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
                    record_caller_session(call, rseq, &response);
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

/// Record the session description a reliable provisional `rseq` carries to the
/// caller (RFC 3262 §5). To a caller whose INVITE offered it is the answer, in
/// force on the caller's dialog as it goes. To an INVITE without SDP the first one
/// is siphon's offer, in force once the caller's PRACK of it answers
/// ([`handle_b2bua_prack`]). Once a session is in force, SDP in a later
/// provisional changes nothing.
///
/// A provisional goes to the caller with the `o=` session id and version the
/// callee gave its SDP, so the dialog adopts them
/// ([`Dialog::adopt_sent_sdp`](crate::b2bua::actor::Dialog::adopt_sent_sdp)): a
/// session refresh toward the caller offers the session it has, not a new one.
fn record_caller_session(
    call: &mut crate::b2bua::actor::CallActor,
    rseq: u32,
    response: &SipMessage,
) {
    if call.a_leg.dialog.last_sent_sdp.is_some() {
        return;
    }
    let Some(session) = sdp_in_body(message_content_type(response), &response.body) else {
        return;
    };
    // The caller's own SDP is on its leg from the INVITE when the INVITE had one.
    if call.a_leg.last_sdp.is_some() {
        let origin = sdp_origin_identity(&session);
        call.a_leg.dialog.adopt_sent_sdp(session, origin);
    } else {
        call.a_leg_reliability.note_offer_to_caller(rseq, session);
    }
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
    answer_a_leg_after(call_id, answer, state, || {});
}

/// [`answer_a_leg`], running `before_answer` in between: when the 2xx goes out now,
/// after it is registered as waiting for the caller's ACK and before it is sent;
/// when it is held, or the call is gone, at once. `b_leg_answered` ACKs the callee
/// there, so a callee that BYEs the moment it is ACKed finds the caller's 2xx
/// waiting for its ACK, and its BYE to the caller is held behind that ACK (RFC
/// 3261 §15).
pub fn answer_a_leg_after(
    call_id: &str,
    answer: HeldAnswer,
    state: &DispatcherState,
    before_answer: impl FnOnce(),
) {
    let Some((route, step)) = state.call_actors.get_call_mut(call_id).map(|mut call| {
        let step = match call.a_leg_reliability.answer(Box::new(answer)) {
            // An offer the caller's PRACK carried is still with the callee: the
            // 2xx follows the 200 that answers that PRACK (RFC 3262 §5), so no
            // final response lands on an offer the caller has no answer to yet.
            AnswerStep::Send(answer) if call.prack_bridge.offer_pending() => {
                call.prack_bridge.defer_answer(answer);
                AnswerStep::Held
            }
            step => step,
        };
        (CallerRoute::of(&call), step)
    }) else {
        warn!(call_id = %call_id, "B2BUA: the call was gone before its answer went to the caller");
        before_answer();
        return;
    };
    match step {
        AnswerStep::Send(answer) => {
            deliver_a_leg_answer_after(call_id, answer, Vec::new(), &route, state, before_answer)
        }
        AnswerStep::Held => {
            before_answer();
            debug!(
                call_id = %call_id,
                "B2BUA: the caller's 2xx waits for a PRACK of a reliable provisional (RFC 3262 §3), or for the 200 answering an offer in one (§5)"
            );
        }
    }
}

/// Send the caller's 2xx after `leading`, and what follows an answer.
///
/// An answer relayed from the callee starts the charging and SIPREC, which
/// siphon's own answer does not. Registering it here, when it is about to be sent,
/// is what puts it under the 64*T1 unACKed sweep and the RFC 3261 §15 BYE hold; a
/// 2xx still held is under neither.
fn deliver_a_leg_answer(
    call_id: &str,
    answer: Box<HeldAnswer>,
    leading: Vec<SipMessage>,
    route: &CallerRoute,
    state: &DispatcherState,
) {
    deliver_a_leg_answer_after(call_id, answer, leading, route, state, || {});
}

/// [`deliver_a_leg_answer`], running `before_send` once the 2xx is registered as
/// waiting for the caller's ACK and before anything is sent.
fn deliver_a_leg_answer_after(
    call_id: &str,
    answer: Box<HeldAnswer>,
    mut leading: Vec<SipMessage>,
    route: &CallerRoute,
    state: &DispatcherState,
    before_send: impl FnOnce(),
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

    // Waiting for the caller's ACK before it or anything else goes out, so a BYE
    // for the caller's dialog handled on another worker meanwhile is held behind
    // that ACK (RFC 3261 §15). The B2BUA has no INVITE server transaction for the
    // caller, so nothing else recovers a lost 2xx; the caller's ACK cancels it in
    // the late-ACK handler (search `uas_2xx_retransmits`).
    let unacked = register_unacked_answer(call_id, &response, state);
    before_send();

    // From the listener the caller's INVITE arrived on: a peer doing symmetric
    // signalling drops a 2xx sourced from a different local port.
    leading.push(response);
    send_to_caller(leading, route, state);
    // The caller has its final response, so the PRACKs siphon still holds for the
    // caller's go to their callees now (RFC 3262 §4).
    release_held_callee_pracks(call_id, state);

    start_2xx_retransmits(
        unacked,
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

/// What a caller's PRACK matched, decided under the call's lock.
enum CallerPrack {
    /// It acknowledged siphon's reliable provisional `rseq`, releasing what waited
    /// for that PRACK, and the callee's PRACK held for the provisional.
    Acknowledged {
        rseq: u32,
        released: Vec<SipMessage>,
        answer: Option<Box<HeldAnswer>>,
        held: Option<HeldCalleePrack>,
    },
    /// A retransmission of a PRACK already answered, with the 200 that answered
    /// it when that one carried the callee's answer to an offer.
    Retransmitted(Option<SipMessage>),
    /// A retransmission of a PRACK whose offer the callee has not answered yet.
    OfferPending,
    Unmatched,
}

/// Answer a PRACK from a B2BUA caller (RFC 3262 §3, §5).
///
/// Matched on its `RAck` against the reliable provisionals siphon sent on the
/// caller's dialog, which the PRACK names by siphon's To-tag. The one awaiting it
/// gets its 200, and whatever that PRACK released goes out right behind the 200
/// (the next provisional, or the held 2xx). The PRACK siphon held for the callee's
/// provisional goes to the callee now, carrying what the caller's carried
/// ([`bridge_caller_prack`]); when that is an offer, the 200 waits for the
/// callee's answer. A retransmission of a PRACK already answered gets its 200
/// again, and is absorbed while its offer waits; one that matches nothing gets
/// 481.
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
                    link,
                } => {
                    if let Some((_, entry)) = state
                        .reliable_provisionals
                        .remove(&(route.sip_call_id.clone(), rseq))
                    {
                        entry.cancel.notify_one();
                    }
                    // RFC 3262 §5: the answer this PRACK carries puts siphon's offer
                    // in the provisional it acknowledges in force on the caller's
                    // dialog, with the `o=` it went with.
                    if !message.body.is_empty() {
                        if let Some(offer) = call.a_leg_reliability.take_answered_offer(rseq) {
                            let origin = sdp_origin_identity(&offer);
                            call.a_leg.dialog.adopt_sent_sdp(offer, origin);
                        }
                    }
                    let released = prepare_provisionals(release, &route, state, &mut call);
                    CallerPrack::Acknowledged {
                        rseq,
                        released,
                        answer,
                        held: link.and_then(|link| call.prack_bridge.take(link)),
                    }
                }
                PrackOutcome::AlreadyAcknowledged => {
                    let answered = call
                        .prack_bridge
                        .answered_response(rack.response_number)
                        .filter(|answered| answered.headers.cseq() == message.headers.cseq());
                    let same_transaction = call
                        .prack_bridge
                        .offer_waits_on(rack.response_number, message.headers.cseq());
                    match answered {
                        // A retransmission of a PRACK already answered gets that
                        // answer again (RFC 3261 §17.2.2).
                        Some(answered) => CallerPrack::Retransmitted(Some(answered)),
                        // A retransmission of the PRACK whose offer the callee has
                        // still waits for the callee's answer.
                        None if same_transaction => CallerPrack::OfferPending,
                        // A new PRACK for the same provisional with an offer in it
                        // is a new offer, which needs an answer or a refusal
                        // (RFC 3264 §4): the caller offering again after a refusal,
                        // or one crossing an offer still out. It goes the way an
                        // offer in a PRACK after the 2xx does.
                        None if !message.body.is_empty() => CallerPrack::Acknowledged {
                            rseq: rack.response_number,
                            released: Vec::new(),
                            answer: None,
                            held: None,
                        },
                        // One without an offer, such as the PRACK sent again without
                        // the offer a refusal turned down (RFC 6337 §2.3), gets a 200
                        // of its own.
                        None => CallerPrack::Retransmitted(None),
                    }
                }
                PrackOutcome::Unmatched => CallerPrack::Unmatched,
            };
            Some((call_id, route, decision))
        });

    match decided {
        Some((
            call_id,
            route,
            CallerPrack::Acknowledged {
                rseq,
                released,
                answer,
                held,
            },
        )) => {
            let bridged = match held {
                Some(held) => bridge_caller_prack(&call_id, held, &message, &inbound, rseq, state),
                // No PRACK of siphon's waits for this one: the provisional was
                // siphon's own, or its PRACK went to the callee with the caller's
                // 2xx. An offer in it goes to the callee in an UPDATE, or is
                // refused without changing the session.
                None if !message.body.is_empty() => {
                    carry_late_prack_offer(&call_id, &message, &inbound, rseq, state)
                }
                None => CallerPrackBridged::Answer,
            };
            match bridged {
                CallerPrackBridged::Answer => {
                    debug!(
                        call_id = %call_id,
                        rseq,
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
                        Some(answer) => {
                            deliver_a_leg_answer(&call_id, answer, messages, &route, state)
                        }
                        None => send_to_caller(messages, &route, state),
                    }
                }
                CallerPrackBridged::WaitForCallee => {
                    debug!(
                        call_id = %call_id,
                        rseq,
                        "B2BUA: the caller's PRACK carries an offer; its 200 waits for the callee's answer (RFC 3262 §5)"
                    );
                    send_to_caller(released, &route, state);
                    defer_released_answer(&call_id, answer, state);
                }
                CallerPrackBridged::Fail {
                    answer: prack_answer,
                    status,
                } => {
                    let mut ok = reply(200, "OK");
                    if let Some(sdp) = prack_answer {
                        set_sdp_body(&mut ok, sdp, "application/sdp");
                    }
                    to_inbound(ok);
                    defer_released_answer(&call_id, answer, state);
                    if let Some(refusal) = claim_refusal(&call_id, state, |_| true) {
                        carry_out_refusal(
                            &call_id,
                            refusal,
                            status,
                            "the caller's PRACK could not complete the offer/answer exchange with the callee (RFC 3262 §5)",
                            state,
                        );
                    }
                }
                CallerPrackBridged::Refuse {
                    status,
                    retry_after,
                } => {
                    let mut refusal = reply(status, prack_refusal_reason(status));
                    if let Some(retry_after) = retry_after {
                        refusal.headers.set("Retry-After", retry_after);
                    }
                    // A retransmission of this PRACK gets the same refusal.
                    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
                        call.prack_bridge.record_answered(rseq, refusal.clone());
                    }
                    to_inbound(refusal);
                    send_to_caller(released, &route, state);
                    defer_released_answer(&call_id, answer, state);
                }
            }
        }
        Some((call_id, _, CallerPrack::OfferPending)) => debug!(
            call_id = %call_id,
            rseq = rack.response_number,
            "B2BUA: absorbing a retransmitted PRACK whose offer the callee has not answered yet"
        ),
        Some((call_id, _, CallerPrack::Retransmitted(answered))) => {
            debug!(
                call_id = %call_id,
                rseq = rack.response_number,
                "B2BUA: the caller retransmitted a PRACK already answered — 200 OK again"
            );
            to_inbound(answered.unwrap_or_else(|| reply(200, "OK")));
        }
        Some((call_id, _, CallerPrack::Unmatched)) => {
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

/// The caller's 2xx a PRACK released while that PRACK's own exchange with the
/// callee is still open: it waits for the 200 that answers the PRACK.
fn defer_released_answer(call_id: &str, answer: Option<Box<HeldAnswer>>, state: &DispatcherState) {
    let Some(answer) = answer else {
        return;
    };
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        call.prack_bridge.defer_answer(answer);
    }
}

/// Send the caller's 2xx `answer`, which waited behind the 200 answering a PRACK.
pub fn deliver_deferred_answer(call_id: &str, answer: Box<HeldAnswer>, state: &DispatcherState) {
    let Some(route) = state
        .call_actors
        .get_call(call_id)
        .map(|call| CallerRoute::of(&call))
    else {
        return;
    };
    deliver_a_leg_answer(call_id, answer, Vec::new(), &route, state);
}

/// Send `response`, answering a caller's PRACK that arrived over `source`, then
/// the caller's 2xx `answer` that PRACK released, if any: as one ordered group
/// when the PRACK came over the caller's own route, since sent apart on UDP they
/// can overtake each other.
pub fn send_caller_prack_response(
    call_id: &str,
    response: SipMessage,
    source: &RequestSource,
    answer: Option<Box<HeldAnswer>>,
    state: &DispatcherState,
) {
    let route = state
        .call_actors
        .get_call(call_id)
        .map(|call| CallerRoute::of(&call));
    let on_route = route.as_ref().is_some_and(|route| {
        route.transport == source.transport
            && route.remote_addr == source.remote_addr
            && route.connection_id == source.connection_id
    });
    let mut leading = Vec::with_capacity(1);
    if on_route {
        leading.push(response);
    } else {
        send_message_from(
            response,
            source.transport,
            source.remote_addr,
            source.connection_id,
            Some(source.local_addr),
            state,
        );
    }
    let Some(route) = route else {
        return;
    };
    match answer {
        Some(answer) => deliver_a_leg_answer(call_id, answer, leading, &route, state),
        None => send_to_caller(leading, &route, state),
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
                || !(call.a_leg_reliability.holds_answer() || call.prack_bridge.holds_answer())
            {
                return None;
            }
            let _dropped = call.a_leg_reliability.finish();
            let _deferred = call.prack_bridge.take_deferred_answer();
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
/// 64*T1 (RFC 3262 §3), and fail every call whose callee has left an offer
/// siphon's PRACK carried unanswered as long (§5). Runs on the dispatcher's fast
/// call-lifetime interval.
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
    let unanswered: Vec<String> = state
        .call_actors
        .iter_calls()
        .filter(|entry| entry.value().prack_bridge.offer_overdue(now))
        .map(|entry| entry.key().clone())
        .collect();
    for call_id in unanswered {
        fail_overdue_prack_offer(&call_id, now, state);
    }
}

/// RFC 3262 §3: "If a reliable provisional response is retransmitted for 64*T1
/// seconds without reception of a corresponding PRACK, the UAS SHOULD reject the
/// original request with a 5xx response."
///
/// The deadline is re-checked under the lock that claims the call, so a PRACK
/// that arrived meanwhile keeps the call.
fn refuse_unacknowledging_caller(call_id: &str, now: Instant, state: &DispatcherState) {
    let Some(refusal) = claim_refusal(call_id, state, |call| call.a_leg_reliability.overdue(now))
    else {
        return;
    };
    carry_out_refusal(
        call_id,
        refusal,
        UNACKNOWLEDGED_STATUS,
        "the caller did not PRACK a reliable provisional within 64*T1 (RFC 3262 §3)",
        state,
    );
}

/// A teardown a call's PRACKs make certain, taken over by [`claim_refusal`] and
/// carried out by [`carry_out_refusal`].
pub struct Refusal {
    sip_call_id: String,
    rseq: Option<u32>,
    held: Option<Box<HeldAnswer>>,
    winner: Option<Leg>,
}

/// Take `call_id` over for a teardown its PRACKs make certain, with the claim
/// [`CallActorStore::claim_teardown`] makes, when `condition` holds under the same
/// lock. `None`, changing nothing, for a call another teardown already has, one
/// `condition` no longer holds for, or one that is gone; `condition` only runs on
/// a call no teardown has claimed.
///
/// Nothing more goes to the caller reliably, and a callee still ringing is
/// CANCELled (RFC 3261 §9.1) on the spot. A 2xx held for a PRACK, or deferred
/// behind one, no longer stands.
pub fn claim_refusal(
    call_id: &str,
    state: &DispatcherState,
    condition: impl FnOnce(&mut crate::b2bua::actor::CallActor) -> bool,
) -> Option<Refusal> {
    let mut call = state.call_actors.get_call_mut(call_id)?;
    if call.teardown_claimed || !condition(&mut call) {
        return None;
    }
    call.teardown_claimed = true;
    let rseq = call.a_leg_reliability.unacknowledged_rseq();
    let held = call
        .a_leg_reliability
        .finish()
        .or_else(|| call.prack_bridge.take_deferred_answer());
    for b_leg in &call.b_legs {
        state.b2bua_retransmits.disarm_branch(&b_leg.branch);
    }
    if held.is_none() {
        for handle in call.b_leg_handles.iter().flatten() {
            let _ = handle.tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
    }
    let winner = call
        .winner
        .and_then(|index| call.b_legs.get(index).cloned());
    Some(Refusal {
        sip_call_id: call.a_leg.dialog.call_id.clone(),
        rseq,
        held,
        winner,
    })
}

/// Carry out `refusal`, logged with `reason`. The callee is let go: still ringing,
/// its CANCEL goes out; answered, with its 2xx held for a PRACK, its dialog is
/// BYEd and the answer no longer stands. The caller then gets `status_code`,
/// without `@b2bua.on_failure`, since routing the call elsewhere cannot complete
/// the caller's PRACKs.
pub fn carry_out_refusal(
    call_id: &str,
    refusal: Refusal,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let Refusal {
        sip_call_id,
        rseq,
        held,
        winner,
    } = refusal;
    warn!(
        call_id = %call_id,
        rseq = ?rseq,
        "B2BUA: {reason} — refusing the call {status_code}"
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
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(call_id, &cancelled, state);
    }
    end_call_without_rerouting(call_id, status_code, state);
}
