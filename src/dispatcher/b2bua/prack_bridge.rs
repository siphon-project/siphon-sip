//! Offer and answer in PRACK across the B2BUA (RFC 3262 §5, RFC 3264).
//!
//! A callee's reliable provisional that reaches the caller reliably is PRACKed by
//! siphon only when the caller PRACKs siphon's copy, and siphon's PRACK carries
//! what the caller's did: the answer to an offer the callee made in that
//! provisional, through the media engine on an anchored call; or a new offer from
//! the caller, whose answer the callee returns in the 200 to siphon's PRACK and
//! siphon returns in the 200 to the caller's. What stays is decided by the call's
//! [`crate::b2bua::actor::PrackBridge`]; this puts it on the wire.

use std::time::Instant;

use crate::b2bua::actor::{HeldCalleePrack, PendingPrackOffer, RequestSource};
use crate::dispatcher::*;

/// The status a caller that PRACKs the callee's offer without an answer is
/// refused with: its request did not complete the offer/answer exchange.
const NO_ANSWER_IN_PRACK_STATUS: u16 = 488;

/// The status the call fails with when an offer a PRACK carried cannot be
/// answered: the callee refused it or never answered, or the media engine refused
/// it.
const PRACK_OFFER_FAILED_STATUS: u16 = 500;

/// What the caller's PRACK comes to once its body has crossed.
pub enum CallerPrackBridged {
    /// Answer the caller's PRACK 200 now, without a body.
    Answer,
    /// The callee has the caller's offer: the 200 to the caller's PRACK waits for
    /// its answer.
    WaitForCallee,
    /// The exchange cannot complete: answer the caller's PRACK 200, with `answer`
    /// when it carried an offer, and refuse the call `status`.
    Fail {
        answer: Option<Vec<u8>>,
        status: u16,
    },
}

/// Hold siphon's PRACK for a callee's reliable provisional until the caller PRACKs
/// siphon's copy, or send it now when the caller will not.
///
/// A caller that neither supports nor requires `100rel` never PRACKs, so siphon's
/// PRACK goes out at once, and an offer the callee made in the provisional, which
/// that caller cannot answer, is answered with every stream rejected (RFC 3264
/// §6). `offer` is the provisional's SDP when the INVITE siphon sent carried none.
pub fn hold_or_send_callee_prack(
    call_id: &str,
    prack: HeldCalleePrack,
    offer: Option<Vec<u8>>,
    state: &DispatcherState,
) {
    let Some(mut call) = state.call_actors.get_call_mut(call_id) else {
        return;
    };
    if call.a_leg_supports_100rel || call.a_leg_requires_100rel {
        call.prack_bridge.hold(prack, offer);
        debug!(
            call_id = %call_id,
            "B2BUA: the PRACK for the callee's reliable provisional waits for the caller's (RFC 3262 §5)"
        );
        return;
    }
    let offer = call.prack_bridge.offer_from(offer);
    drop(call);
    let body = offer.map(|offer| {
        warn!(
            call_id = %call_id,
            "B2BUA: the callee offered in a reliable provisional to a caller that cannot PRACK it; \
             answering the offer with every stream rejected"
        );
        (rejecting_answer(&offer), "application/sdp".to_string())
    });
    send_callee_prack(call_id, &prack, body, state);
}

/// Send siphon's PRACK for `held` to the callee, carrying `body` (the SDP and its
/// Content-Type) when there is one, with siphon's own identity and the configured
/// attributes stripped. Returns the callee dialog's Call-ID and the PRACK's CSeq
/// number, which the callee's response echoes; `None` when it could not be sent.
pub fn send_callee_prack(
    call_id: &str,
    held: &HeldCalleePrack,
    body: Option<(Vec<u8>, String)>,
    state: &DispatcherState,
) -> Option<(String, u32)> {
    let cseq = state
        .call_actors
        .next_b_leg_local_cseq(call_id, held.b_leg_index)?;
    let target = EarlyDialogTarget {
        remote_contact: held.remote_contact.clone(),
        to_header: held.to_header.clone(),
        route_set: held.route_set.clone(),
    };
    let (prack, leg) = {
        let mut call = state.call_actors.get_call_mut(call_id)?;
        let leg = call.b_legs.get_mut(held.b_leg_index)?;
        let mut prack = build_b2bua_prack(
            leg,
            state,
            &target,
            held.rseq,
            held.cseq_number,
            &held.cseq_method,
            cseq,
        )?;
        if let Some((mut sdp, content_type)) = body {
            let transport = leg.transport.transport;
            stamp_b_leg_origin(&mut sdp, &content_type, leg, &transport, state);
            set_sdp_body(&mut prack, sdp, &content_type);
        }
        (prack, leg.clone())
    };
    // PRACK follows this early dialog's route set (RFC 3262 §4, RFC 3261
    // §12.2.1.1), from the reliable provisional's Record-Route; without one it goes
    // to the leg's cached destination.
    let (destination, transport) = resolve_in_dialog_destination(
        &target.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    debug!(
        call_id = %call_id,
        rseq = held.rseq,
        %destination,
        with_body = !prack.body.is_empty(),
        "B2BUA: sending the callee's PRACK"
    );
    send_b2bua_to_bleg(
        prack,
        transport,
        destination,
        leg.transport.local_addr,
        state,
    );
    Some((leg.dialog.call_id, cseq))
}

/// The link siphon's copy of a callee's reliable provisional carries to the PRACK
/// held for it, read off the callee's response before it is rewritten for the
/// caller.
pub fn callee_prack_link(
    call_id: &str,
    b_leg_index: Option<usize>,
    response: &SipMessage,
    state: &DispatcherState,
) -> Option<u64> {
    let index = b_leg_index?;
    let rseq = crate::sip::headers::rseq::parse_rseq(&response.headers)?.response_number;
    let to_tag = crate::b2bua::actor::extract_to_tag(response).unwrap_or_default();
    state
        .call_actors
        .get_call(call_id)?
        .prack_bridge
        .link_for(index, &to_tag, rseq)
}

/// A held PRACK whose provisional the caller will never PRACK: sent now, with
/// every stream rejected when the callee offered.
pub fn release_unanswered_callee_prack(call_id: &str, link: u64, state: &DispatcherState) {
    let held = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut call| call.prack_bridge.take(link));
    if let Some(held) = held {
        let body = held
            .offer
            .as_deref()
            .map(|offer| (rejecting_answer(offer), "application/sdp".to_string()));
        send_callee_prack(call_id, &held, body, state);
    }
}

/// Carry the caller's PRACK `caller_prack`, which acknowledged siphon's copy of
/// the callee's provisional as `a_leg_rseq`, on siphon's PRACK `held` (RFC 3262
/// §5).
///
/// - The callee offered: the caller's PRACK must carry the answer. It goes to the
///   callee, through the media engine when the offer is anchored there. Without
///   one, or with one the engine refuses, the callee gets every stream rejected
///   and the call fails.
/// - It did not, and the caller's PRACK carries no body: siphon's goes without one.
/// - It did not, and the caller's PRACK carries an offer: it goes to the callee,
///   through the media engine when the call is anchored, and the 200 to the
///   caller's PRACK waits for the callee's answer.
///
/// An offer or answer that crosses is recorded as its leg's last SDP, as one in an
/// UPDATE is, so a later session refresh offers what was agreed.
pub fn bridge_caller_prack(
    call_id: &str,
    held: HeldCalleePrack,
    caller_prack: &SipMessage,
    inbound: &InboundMessage,
    a_leg_rseq: u32,
    state: &DispatcherState,
) -> CallerPrackBridged {
    let content_type = caller_prack
        .headers
        .get("Content-Type")
        .or_else(|| caller_prack.headers.get("c"))
        .cloned()
        .unwrap_or_else(|| "application/sdp".to_string());
    let rejecting = |offer: &[u8]| Some((rejecting_answer(offer), "application/sdp".to_string()));
    match (held.offer.as_deref(), caller_prack.body.is_empty()) {
        (Some(offer), true) => {
            warn!(
                call_id = %call_id,
                "B2BUA: the caller PRACKed the callee's offer without an answer (RFC 3262 §5); \
                 rejecting the offer toward the callee and refusing the call"
            );
            send_callee_prack(call_id, &held, rejecting(offer), state);
            CallerPrackBridged::Fail {
                answer: None,
                status: NO_ANSWER_IN_PRACK_STATUS,
            }
        }
        (Some(offer), false) => {
            let answer = match anchored_answer(call_id, caller_prack, state) {
                AnchoredAnswer::NotAnchored => caller_prack.body.clone(),
                AnchoredAnswer::Rewritten(answer) => answer,
                AnchoredAnswer::Refused => {
                    warn!(
                        call_id = %call_id,
                        "B2BUA: the media engine refused the caller's answer to the callee's early offer; \
                         rejecting the offer toward the callee and refusing the call"
                    );
                    send_callee_prack(call_id, &held, rejecting(offer), state);
                    return CallerPrackBridged::Fail {
                        answer: None,
                        status: PRACK_OFFER_FAILED_STATUS,
                    };
                }
            };
            state.call_actors.set_leg_last_sdp(call_id, false, offer);
            state
                .call_actors
                .set_leg_last_sdp(call_id, true, &caller_prack.body);
            send_callee_prack(call_id, &held, Some((answer, content_type)), state);
            CallerPrackBridged::Answer
        }
        (None, true) => {
            send_callee_prack(call_id, &held, None, state);
            CallerPrackBridged::Answer
        }
        (None, false) => {
            let offer = match anchored_caller_offer(call_id, caller_prack, inbound, state) {
                Anchoring::NotAnchored => caller_prack.body.clone(),
                Anchoring::Rewritten(offer) => offer,
                Anchoring::Refused => {
                    send_callee_prack(call_id, &held, None, state);
                    return CallerPrackBridged::Fail {
                        answer: Some(rejecting_answer(&caller_prack.body)),
                        status: PRACK_OFFER_FAILED_STATUS,
                    };
                }
            };
            let Some((b_leg_call_id, b_leg_cseq)) =
                send_callee_prack(call_id, &held, Some((offer, content_type)), state)
            else {
                return CallerPrackBridged::Fail {
                    answer: Some(rejecting_answer(&caller_prack.body)),
                    status: PRACK_OFFER_FAILED_STATUS,
                };
            };
            state
                .call_actors
                .set_leg_last_sdp(call_id, true, &caller_prack.body);
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.prack_bridge.begin_offer(PendingPrackOffer {
                    caller_prack: caller_prack.clone(),
                    source: RequestSource {
                        transport: inbound.transport,
                        remote_addr: inbound.remote_addr,
                        connection_id: inbound.connection_id,
                        local_addr: inbound.local_addr,
                    },
                    a_leg_rseq,
                    b_leg_call_id,
                    b_leg_cseq,
                    offer: caller_prack.body.clone(),
                    sent_at: Instant::now(),
                });
            }
            CallerPrackBridged::WaitForCallee
        }
    }
}

/// A response to a PRACK siphon sent a callee, recognised by the branch prefix
/// siphon gives those ([`PRACK_BRANCH_PREFIX`]) and matched to its call by the
/// callee dialog's Call-ID.
///
/// The final response to a PRACK that carried the caller's offer answers the
/// caller's PRACK: a 2xx with the callee's answer, through the media engine on an
/// anchored call, goes to the caller in the 200 to its PRACK, followed by the
/// caller's 2xx when that PRACK released it. Anything else leaves the caller's
/// offer unanswerable, so the caller's PRACK is answered with every stream
/// rejected and the call fails. Every other response to siphon's PRACK is
/// absorbed.
pub fn handle_callee_prack_response(
    message: &SipMessage,
    status_code: u16,
    source: SocketAddr,
    state: &DispatcherState,
) {
    if status_code < 200 {
        return;
    }
    let Some(b_leg_call_id) = message.headers.call_id().cloned() else {
        return;
    };
    let Some(call_id) = state.call_actors.find_by_sip_call_id(&b_leg_call_id) else {
        debug!(%b_leg_call_id, status = status_code, "B2BUA: response to a PRACK for a call that has ended");
        return;
    };
    let Some(cseq) = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse::<u32>().ok())
    else {
        return;
    };
    let pending = state
        .call_actors
        .get_call_mut(&call_id)
        .and_then(|mut call| {
            if call.teardown_claimed {
                return None;
            }
            call.prack_bridge.take_offer(&b_leg_call_id, cseq)
        });
    let Some(pending) = pending else {
        debug!(call_id = %call_id, status = status_code, "B2BUA: absorbing the callee's response to siphon's PRACK");
        return;
    };

    if (200..300).contains(&status_code) && !message.body.is_empty() {
        let answer = match anchored_answer_to_caller_offer(&call_id, message, source, state) {
            Anchoring::NotAnchored => Some(message.body.clone()),
            Anchoring::Rewritten(answer) => Some(answer),
            Anchoring::Refused => None,
        };
        if let Some(mut answer) = answer {
            state
                .call_actors
                .set_leg_last_sdp(&call_id, false, &message.body);
            let content_type = message
                .headers
                .get("Content-Type")
                .or_else(|| message.headers.get("c"))
                .cloned()
                .unwrap_or_else(|| "application/sdp".to_string());
            let host = state
                .a_leg_advertised_host(Some(pending.source.local_addr), &pending.source.transport);
            own_sdp_toward_leg(
                &mut answer,
                &content_type,
                state,
                &call_id,
                true,
                Some(&host),
            );
            let mut ok = build_response(
                &pending.caller_prack,
                200,
                "OK",
                state.server_header.as_deref(),
                &[],
            );
            set_sdp_body(&mut ok, answer, &content_type);
            let deferred = state
                .call_actors
                .get_call_mut(&call_id)
                .and_then(|mut call| {
                    call.prack_bridge
                        .record_answered(pending.a_leg_rseq, ok.clone());
                    call.prack_bridge.take_deferred_answer()
                });
            debug!(call_id = %call_id, "B2BUA: the callee answered the offer in the caller's PRACK — 200 OK with its answer");
            send_caller_prack_response(&call_id, ok, &pending.source, deferred, state);
            // A 2xx that came in while that 200 was on its way waited for it.
            let late = state
                .call_actors
                .get_call_mut(&call_id)
                .and_then(|mut call| call.prack_bridge.finish_answering());
            if let Some(answer) = late {
                deliver_deferred_answer(&call_id, answer, state);
            }
            return;
        }
    }

    debug!(
        call_id = %call_id,
        status = status_code,
        "B2BUA: the callee did not answer the offer siphon's PRACK carried"
    );
    answer_caller_prack_rejecting(&pending, state);
    // A 2xx waiting behind that 200 stays for the refusal to release.
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        if let Some(answer) = call.prack_bridge.finish_answering() {
            call.prack_bridge.defer_answer(answer);
        }
    }
    if let Some(refusal) = claim_refusal(&call_id, state, |_| true) {
        carry_out_refusal(
            &call_id,
            refusal,
            PRACK_OFFER_FAILED_STATUS,
            "the callee did not answer the offer siphon's PRACK carried (RFC 3262 §5)",
            state,
        );
    }
}

/// Fail a call whose callee has let the offer siphon's PRACK carried go
/// unanswered for 64*T1, on the call's teardown claim. The caller's PRACK still
/// gets its 200, with every stream of its offer rejected.
pub fn fail_overdue_prack_offer(call_id: &str, now: Instant, state: &DispatcherState) {
    let mut pending = None;
    let Some(refusal) = claim_refusal(call_id, state, |call| {
        pending = call.prack_bridge.take_overdue_offer(now);
        pending.is_some()
    }) else {
        return;
    };
    if let Some(pending) = pending {
        answer_caller_prack_rejecting(&pending, state);
    }
    carry_out_refusal(
        call_id,
        refusal,
        PRACK_OFFER_FAILED_STATUS,
        "the callee never answered the offer siphon's PRACK carried within 64*T1 (RFC 3262 §5)",
        state,
    );
}

/// The caller's PRACK is owed its 2xx (RFC 3262 §3), and a 2xx to a PRACK with an
/// offer carries an answer (§5): one rejecting every stream (RFC 3264 §6).
fn answer_caller_prack_rejecting(pending: &PendingPrackOffer, state: &DispatcherState) {
    let mut ok = build_response(
        &pending.caller_prack,
        200,
        "OK",
        state.server_header.as_deref(),
        &[],
    );
    set_sdp_body(&mut ok, rejecting_answer(&pending.offer), "application/sdp");
    send_message_from(
        ok,
        pending.source.transport,
        pending.source.remote_addr,
        pending.source.connection_id,
        Some(pending.source.local_addr),
        state,
    );
}

/// How an in-dialog offer or answer crosses the media engine.
enum Anchoring {
    /// The call's media is not anchored: the SDP goes as written.
    NotAnchored,
    /// The engine's SDP.
    Rewritten(Vec<u8>),
    /// The engine refused, or the session cannot name the party.
    Refused,
}

/// Send the caller's offer from its PRACK to the media engine as a re-offer from
/// the caller's side, when the call is anchored.
fn anchored_caller_offer(
    call_id: &str,
    caller_prack: &SipMessage,
    inbound: &InboundMessage,
    state: &DispatcherState,
) -> Anchoring {
    let (Some(backend), Some(sessions), Some(profiles)) = (
        &state.rtpengine_set,
        &state.rtpengine_sessions,
        &state.rtpengine_profiles,
    ) else {
        return Anchoring::NotAnchored;
    };
    let Some(a_leg_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return Anchoring::NotAnchored;
    };
    let Some(session) = sessions.get(&a_leg_call_id) else {
        return Anchoring::NotAnchored;
    };
    let Some(profile) = profiles.get(&session.profile) else {
        return Anchoring::NotAnchored;
    };
    let Some(offer_tag) = session.offer_tag(true) else {
        return Anchoring::Refused;
    };
    let mut flags = profile.offer.clone();
    if flags.carry_received_from {
        flags.received_from = Some(inbound.remote_addr.ip());
    }
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.reoffer(
            session.rtpengine_id(),
            offer_tag,
            &caller_prack.body,
            &flags,
        ))
    }) {
        Ok(offer) => Anchoring::Rewritten(offer),
        Err(error) => {
            warn!(call_id = %call_id, "RTPEngine offer for the caller's PRACK offer failed: {error}");
            Anchoring::Refused
        }
    }
}

/// Send the callee's answer to the caller's PRACK offer to the media engine, when
/// the call is anchored.
fn anchored_answer_to_caller_offer(
    call_id: &str,
    response: &SipMessage,
    source: SocketAddr,
    state: &DispatcherState,
) -> Anchoring {
    let (Some(backend), Some(sessions), Some(profiles)) = (
        &state.rtpengine_set,
        &state.rtpengine_sessions,
        &state.rtpengine_profiles,
    ) else {
        return Anchoring::NotAnchored;
    };
    let Some(a_leg_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return Anchoring::NotAnchored;
    };
    let Some(session) = sessions.get(&a_leg_call_id) else {
        return Anchoring::NotAnchored;
    };
    let Some(profile) = profiles.get(&session.profile) else {
        return Anchoring::NotAnchored;
    };
    let Some((answer_from, answer_to)) = session.answer_tags(true) else {
        return Anchoring::Refused;
    };
    let mut flags = profile.answer.clone();
    if flags.carry_received_from {
        flags.received_from = Some(source.ip());
    }
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer(
            session.rtpengine_id(),
            answer_from,
            answer_to,
            &response.body,
            &flags,
        ))
    }) {
        Ok(answer) => Anchoring::Rewritten(answer),
        Err(error) => {
            warn!(call_id = %call_id, "RTPEngine answer for the callee's PRACK answer failed: {error}");
            Anchoring::Refused
        }
    }
}
