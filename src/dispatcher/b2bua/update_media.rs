//! The offer and the answer of an UPDATE through the media engine anchoring
//! the call (RFC 3311).
//!
//! An UPDATE siphon relays between the legs and one it answers itself on the
//! callee's early dialog ([`answer_callee_early_update`]) take the same two
//! steps: the offer goes to the engine as a re-offer from the offering party's
//! side, and what the other party's side answers completes it.
use crate::dispatcher::*;

/// Put `offer`, the session description `message` carries, through the media
/// engine anchoring the call whose caller's dialog is `a_leg_call_id`: from
/// the caller when `from_a_leg`, else from the callee. On a call that is not
/// anchored `offer` stays as it is.
///
/// Returns `false` when the engine cannot take the offer. The UPDATE has then
/// been refused 488 here, and nothing of it may go on.
pub fn update_offer_through_media_engine(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    a_leg_call_id: &str,
    from_a_leg: bool,
    offer: &mut Vec<u8>,
    state: &DispatcherState,
) -> bool {
    let offerer_sip_call_id = message
        .headers
        .get("Call-ID")
        .map(String::as_str)
        .unwrap_or_default();
    // Through the media engine, as a re-INVITE's offer goes: named by the
    // offering party's own tag, pinned by its own policy, and shaped for the
    // party it is relayed to.
    match reoffer_through_media_engine(
        state,
        a_leg_call_id,
        from_a_leg,
        inbound.remote_addr.ip(),
        offerer_sip_call_id,
        offer,
    ) {
        ReofferOutcome::NotAnchored => true,
        ReofferOutcome::Rewritten(rewritten_sdp) => {
            *offer = rewritten_sdp;
            debug!(call_id = %call_id, "RTPEngine: rewrote UPDATE SDP (offer)");
            true
        }
        ReofferOutcome::NoOfferTag => {
            warn!(
                call_id = %call_id,
                "B2BUA UPDATE from the callee on a media session with no recorded \
                 answerer tag — rejecting with 488 rather than naming the caller to \
                 the media engine"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, None);
            false
        }
        ReofferOutcome::Failed(error) => {
            error!(
                call_id = %call_id,
                "RTPEngine offer for UPDATE failed: {error} — rejecting the \
                 UPDATE with 488 rather than forwarding SDP that routes both \
                 parties around the anchor"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, None);
            false
        }
    }
}

/// What the media engine made of the answer to an UPDATE's offer.
pub enum UpdateAnswerOutcome {
    /// The call's media is not anchored: the answer goes on as it is.
    NotAnchored,
    /// The engine's answer, facing the party that offered.
    Rewritten(Vec<u8>),
    /// The engine session has no tag for the callee, which offered, so the two
    /// parties cannot be named to the engine without claiming the callee is
    /// the caller.
    NoAnswererTag,
    /// The engine refused the answer.
    Failed(String),
}

/// Put `answer`, the session description that answers an UPDATE's offer,
/// through the media engine anchoring the call whose caller's dialog is
/// `a_leg_call_id`. `is_a2b` says the caller made the offer, so the callee
/// answers, and the other way. Media ingress is pinned to `answered_from`
/// where the answering party's own policy asks for it, and the answer is filed
/// under `answerer_sip_call_id`, the Call-ID of the answering party's dialog.
///
/// The command is shaped for the party the engine's result goes to, the one
/// that offered, by its own side of the profile.
pub fn update_answer_through_media_engine(
    state: &DispatcherState,
    a_leg_call_id: &str,
    is_a2b: bool,
    answered_from: std::net::IpAddr,
    answerer_sip_call_id: Option<&str>,
    answer: &[u8],
) -> UpdateAnswerOutcome {
    let (Some(rtpengine_set), Some(media_sessions), Some(profiles)) = (
        &state.rtpengine_set,
        &state.rtpengine_sessions,
        &state.rtpengine_profiles,
    ) else {
        return UpdateAnswerOutcome::NotAnchored;
    };
    let Some(session) = media_sessions.get(a_leg_call_id) else {
        return UpdateAnswerOutcome::NotAnchored;
    };
    let Some(mut answer_flags) = session.party_shape(is_a2b).resolve(profiles) else {
        return UpdateAnswerOutcome::NotAnchored;
    };
    // Same rule as a re-INVITE's answer: a B→A answer must name the callee as
    // offerer, so an unnameable pair is never attributed to the wrong party.
    let Some((answer_from, answer_to)) = session.answer_tags(is_a2b) else {
        return UpdateAnswerOutcome::NoAnswererTag;
    };
    // The answering party's own policy, as on a re-INVITE's answer.
    session
        .party_ingress(!is_a2b)
        .stamp_ingress(&mut answer_flags, profiles, answered_from);
    if let Some(answerer_sip_call_id) = answerer_sip_call_id {
        answer_flags.stamp_sip_call_id(answerer_sip_call_id);
    }
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(rtpengine_set.answer(
            session.rtpengine_id(),
            answer_from,
            answer_to,
            answer,
            &answer_flags,
        ))
    }) {
        Ok(rewritten_sdp) => UpdateAnswerOutcome::Rewritten(rewritten_sdp),
        Err(error) => UpdateAnswerOutcome::Failed(error.to_string()),
    }
}
