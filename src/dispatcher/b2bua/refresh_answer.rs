//! The offerless re-INVITE of a call the engine anchors, answered from the
//! session in force: the `200` repeats it, which makes it an offer (RFC 3261
//! §14.1), and the caller's ACK carries the answer (RFC 3264 §4).
//!
//! The `200` is put under the retransmission and 64*T1 machinery the initial
//! 2xx uses ([`register_unacked_answer`]), so a lost one is repeated and a
//! caller that never ACKs has its call ended (§13.3.1.4).

use super::ack::{MEDIA_ANCHOR_FAILED_REASON, NO_ANSWER_IN_ACK_REASON};
use crate::dispatcher::*;

/// Answer an offerless re-INVITE with the session in force toward the caller
/// and wait for the ACK that answers it. 488 when no session is in force.
pub(super) fn answer_offerless_refresh(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) {
    let in_force = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg.dialog.last_sent_sdp.clone());
    let Some(sdp) = in_force else {
        warn!(%call_id, "B2BUA: an offerless re-INVITE on a leg with no session in force: 488");
        let response = build_response(
            message,
            488,
            "Not Acceptable Here",
            state.identity.load().server.as_deref(),
            &[],
        );
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );
        return;
    };
    let response = super::reinvite_in::build_one_legged_ok(
        inbound,
        message,
        call_id,
        sdp,
        &crate::b2bua::reoffer::AnswerExtras::default(),
        state,
    );
    if let Some(cseq) = cseq_number(message) {
        state.call_actors.expect_refresh_answer(
            call_id,
            crate::b2bua::actor::PendingRefreshAnswer::new(
                cseq,
                top_via_branch(message).unwrap_or_default(),
                response.clone(),
            ),
        );
    }
    // Registered before it is sent: from here a BYE for the dialog waits for
    // the ACK, and the sweep holds the 200 to its deadline.
    let unacked = register_unacked_answer(call_id, &response, state);
    send_message_from(
        response.clone(),
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    start_2xx_retransmits(
        unacked,
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// A re-INVITE from the caller while the offer its refresh's `200` made is
/// still outstanding (RFC 3261 §14.1, §14.2): answered here, `491 Request
/// Pending`, and never taken for an exchange of its own. `true` when it was
/// answered. A re-INVITE from the callee meets the same exchange on the
/// pending re-INVITE guard the ordinary path takes ([`expect_refresh_answer`]
/// holds the caller's leg on it).
pub(super) fn answer_outstanding_refresh(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    state: &DispatcherState,
) -> bool {
    if state.call_actors.refresh_in_progress(call_id).is_none() {
        return false;
    }
    debug!(%call_id, "B2BUA: re-INVITE during an offerless refresh's offer: 491");
    let response = build_response(
        message,
        491,
        "Request Pending",
        state.identity.load().server.as_deref(),
        &[],
    );
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

/// The topmost Via branch of `message`, the transaction it belongs to.
pub(super) fn top_via_branch(message: &SipMessage) -> Option<String> {
    message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|via| via.branch)
}

/// The number in a request's `CSeq`.
pub(super) fn cseq_number(message: &SipMessage) -> Option<u32> {
    message
        .headers
        .cseq()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The caller's ACK to the `200` of an offerless re-INVITE, which repeated the
/// session in force (RFC 3261 §14.1: an offer in a 2xx is answered in the ACK,
/// RFC 3264 §4). The answer is the caller's media as it now stands, so the
/// engine is told it the way a re-INVITE carrying it would be, and nothing is
/// relayed to the other party. A no-op unless this ACK answers such an offer.
///
/// An ACK with no answer, or an engine that refuses it, ends the call with a
/// BYE, as on the initial delayed offer.
pub(super) fn complete_refresh_answer(call_id: &str, ack: &SipMessage, state: &DispatcherState) {
    let Some(cseq) = cseq_number(ack) else {
        return;
    };
    if !state.call_actors.claim_refresh_answer(call_id, cseq) {
        return;
    }
    let Some(answer) = sdp_in_body(message_content_type(ack), &ack.body) else {
        warn!(call_id = %call_id, "B2BUA: the caller ACKed the session refresh's offer without an answer (RFC 3264 §4); ending the call");
        b2bua_terminate_call_inner(call_id, Some(NO_ANSWER_IN_ACK_REASON), "b2bua", state);
        return;
    };
    let Some((a_leg_call_id, source)) = state.call_actors.get_call(call_id).map(|call| {
        (
            call.a_leg.dialog.call_id.clone(),
            call.a_leg.transport.remote_addr.ip(),
        )
    }) else {
        return;
    };
    match super::reinvite_in::reoffer_through_media_engine(
        state,
        &a_leg_call_id,
        true,
        source,
        &a_leg_call_id,
        &answer,
    ) {
        ReofferOutcome::Rewritten(_) | ReofferOutcome::NotAnchored => {
            state.call_actors.set_leg_last_sdp(call_id, true, &answer);
            state.call_actors.finish_refresh_answer(call_id);
        }
        ReofferOutcome::NoOfferTag | ReofferOutcome::Failed(_) => {
            warn!(call_id = %call_id, "B2BUA: the media engine refused the caller's answer to the session refresh's offer; ending the call");
            b2bua_terminate_call_inner(call_id, Some(MEDIA_ANCHOR_FAILED_REASON), "b2bua", state);
        }
    }
}
