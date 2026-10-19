//! A callee's UPDATE with an offer that siphon answers itself (RFC 3311 §5,
//! RFC 3312 §5.2, RFC 3264 §8).
//!
//! A caller that has not had the answer to its INVITE reliably takes it in its
//! 2xx, and its dialog can be sent no offer before (RFC 3311 §5.1). The callee
//! meanwhile may have its answer, be PRACKed, and send an UPDATE with a new
//! offer: the completion of the precondition exchange on its side (RFC 3312
//! §5), a changed address or port. On the callee's dialog siphon is the UAC
//! and owes that UPDATE an answer, and refusing it until the caller's dialog
//! catches up refuses it for as long as the call rings.
//!
//! So siphon answers it, with what the caller would say:
//!
//! * the caller's own session description, as the answer to the offer
//!   ([`answer_from`]): the formats both have, the direction the offer leaves.
//!   The caller's media did not change, so this is the stream siphon's INVITE
//!   offered the callee, with whatever of it the callee now offers;
//! * the precondition status of a party with nothing to reserve
//!   ([`precondition`]), since the caller's leg negotiated none;
//! * through the media engine on an anchored call, by the two steps a relayed
//!   UPDATE takes ([`update_offer_through_media_engine`],
//!   [`update_answer_through_media_engine`]): the callee's offer as a re-offer
//!   from its side, and the caller's description as the answer that completes
//!   it. The callee is answered with the engine's description toward it. No
//!   script handler runs, as none does for a relayed UPDATE.
//!
//! The caller is brought up to date where its dialog can be: the callee's
//! description as the offer left it, shaped as the answer to the caller's
//! INVITE and without the callee's precondition attributes, is kept on the
//! callee's leg ([`Leg::record_early_answer_revision`]) and goes in the
//! caller's 2xx (`prepare_a_leg_answer`). siphon adds it to no provisional:
//! what the caller is shown before the answer stays the script's to decide.
//!
//! What this cannot answer for the caller is still refused, as it was: a
//! caller's leg with preconditions of its own, which only the caller can
//! report on; streams that are keyed, use ICE or are grouped; an offer with no
//! format of the caller's; an anchored session that names another callee.
use crate::dispatcher::*;
use crate::media::answer::answer_from;
use crate::media::precondition;
use crate::media::sdp::SdpBody;

const SDP: &str = "application/sdp";

/// What the call holds of its caller when a callee's UPDATE is answered.
struct Caller {
    /// The caller's own session description, as it offered it.
    description: Vec<u8>,
    /// The Call-ID of the caller's dialog, which names the media session.
    sip_call_id: String,
    transport: LegTransport,
}

fn parsed(sdp: &[u8]) -> SdpBody {
    SdpBody::parse(&String::from_utf8_lossy(sdp))
}

/// Answer `message`, an UPDATE with an offer from the callee whose leg rides
/// Via `branch`, on that callee's early dialog, and keep what the offer changes
/// for the caller's 2xx.
///
/// `Err` says why siphon cannot answer it for the caller. Nothing was sent or
/// changed then, and the UPDATE is the caller's of this function to refuse.
/// `Ok` means the UPDATE has its final response: the 200 with the answer, or a
/// 488 when the media engine anchoring the call would not take the exchange.
pub fn answer_callee_early_update(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    branch: &str,
    state: &DispatcherState,
) -> Result<(), &'static str> {
    let offer = sdp_in_body(message_content_type(message), &message.body)
        .ok_or("the UPDATE's body carries no session description")?;
    let caller = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| {
            Some(Caller {
                description: call.a_leg.last_sdp.clone()?,
                sip_call_id: call.a_leg.dialog.call_id.clone(),
                transport: call.a_leg.transport.clone(),
            })
        })
        .ok_or("the call holds no session description of the caller's")?;
    let callee_dialog = message
        .typed_from()
        .ok()
        .flatten()
        .and_then(|from| from.tag);

    // Everything that can refuse the offer, before the media engine or the
    // call is touched.
    let offered = parsed(&offer);
    let callers = parsed(&caller.description);
    if callers
        .media_sections
        .iter()
        .any(precondition::uses_preconditions)
    {
        return Err("the caller's leg negotiates preconditions of its own");
    }
    if offered.media_sections.len() < callers.media_sections.len() {
        return Err("the offer has fewer streams than the session (RFC 3264 §8)");
    }
    let status = offered
        .media_sections
        .iter()
        .map(precondition::answered_by_a_party_with_nothing_to_reserve)
        .collect::<Result<Vec<_>, _>>()?;
    answer_from(&offered, &callers)?;
    answer_from(&callers, &offered)?;
    let anchored_for_another = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(&caller.sip_call_id))
        .is_some_and(|session| session.to_tag != callee_dialog);
    if anchored_for_another {
        return Err("the call's media session does not name this callee's dialog");
    }

    // The offer as the caller would be relayed it: siphon's identity on it,
    // and the media engine's description toward the caller.
    let mut toward_caller = offer.clone();
    let caller_host =
        state.a_leg_advertised_host(caller.transport.local_addr, &caller.transport.transport);
    hide_sdp_identity(&mut toward_caller, state, Some(&caller_host));
    if !update_offer_through_media_engine(
        inbound,
        message,
        call_id,
        &caller.sip_call_id,
        false,
        &mut toward_caller,
        state,
    ) {
        return Ok(());
    }
    let relayed = parsed(&toward_caller);

    // What the caller's 2xx carries: the callee's description as the answer to
    // the caller's INVITE, without preconditions the caller never negotiated.
    // What the callee is answered: the caller's own description.
    let (mut for_caller, callers_answer) = match (
        answer_from(&callers, &relayed),
        answer_from(&relayed, &callers),
    ) {
        (Ok(for_caller), Ok(callers_answer)) => (for_caller, callers_answer),
        (Err(why), _) | (_, Err(why)) => {
            error!(
                call_id = %call_id,
                "B2BUA UPDATE on the early dialog: the media engine's offer toward the \
                 caller cannot be answered for it ({why}) — rejecting the UPDATE with 488"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, None);
            return Ok(());
        }
    };
    for section in &mut for_caller.media_sections {
        precondition::remove_preconditions(section);
    }
    let mut for_caller = for_caller.to_string().into_bytes();
    crate::media::body::strip_sdp_attributes(SDP, &mut for_caller, &state.sdp_strip_attributes);

    let callers_answer = callers_answer.to_string().into_bytes();
    let toward_callee = match update_answer_through_media_engine(
        state,
        &caller.sip_call_id,
        false,
        caller.transport.remote_addr.ip(),
        Some(&caller.sip_call_id),
        &callers_answer,
    ) {
        UpdateAnswerOutcome::NotAnchored => callers_answer,
        UpdateAnswerOutcome::Rewritten(rewritten_sdp) => {
            debug!(call_id = %call_id, "RTPEngine: rewrote the answer to an UPDATE siphon answers");
            rewritten_sdp
        }
        UpdateAnswerOutcome::NoAnswererTag => {
            error!(
                call_id = %call_id,
                "B2BUA UPDATE on the early dialog: the media session has no recorded answerer \
                 tag to answer the callee's offer under — rejecting the UPDATE with 488"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, None);
            return Ok(());
        }
        UpdateAnswerOutcome::Failed(error) => {
            error!(
                call_id = %call_id,
                "RTPEngine answer for an UPDATE siphon answers failed: {error} — rejecting the \
                 UPDATE with 488 rather than answering with media the engine does not relay"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, None);
            return Ok(());
        }
    };

    // The precondition status goes on last: it is siphon's own, whatever the
    // engine carried through of the caller's description.
    let mut answer = parsed(&toward_callee);
    for (index, section) in answer.media_sections.iter_mut().enumerate() {
        precondition::remove_preconditions(section);
        if section.port == 0 {
            continue;
        }
        for value in status.get(index).into_iter().flatten() {
            section.other_attrs.push(format!("a={value}"));
        }
    }
    let mut answer = answer.to_string().into_bytes();

    // The exchange is done on the callee's dialog: its description and
    // siphon's are the ones in force there, and the caller's 2xx owes the
    // caller the callee's.
    let committed = state.call_actors.update_b_leg_on(call_id, branch, |leg| {
        let transport = leg.transport.transport;
        stamp_b_leg_origin(&mut answer, SDP, leg, &transport, state);
        leg.last_sdp = Some(offer);
        leg.dialog.last_sent_sdp = Some(answer.clone());
        leg.record_early_answer_revision(for_caller, callee_dialog);
        leg.dialog.local_contact.clone()
    });
    let Some(local_contact) = committed else {
        // The callee's leg left the call while its offer was with the engine.
        warn!(call_id = %call_id, "B2BUA UPDATE on the early dialog: the callee's leg is gone — 481");
        let response = build_response(
            message,
            481,
            "Call/Transaction Does Not Exist",
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
        return Ok(());
    };

    info!(
        call_id = %call_id,
        "B2BUA UPDATE on the early dialog answered for the caller, which takes the answer to \
         its INVITE in the 2xx (RFC 3311 §5.1, RFC 3261 §13.2.1)"
    );
    let mut response = build_response(
        message,
        200,
        "OK",
        state.identity.load().server.as_deref(),
        &[],
    );
    // A target refresh request is answered with siphon's own target on the
    // dialog (RFC 3311 §5.2, RFC 3261 §12.2.2).
    if let Some(contact) = local_contact {
        response.headers.set("Contact", contact);
    }
    set_sdp_body(&mut response, answer, SDP);
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    Ok(())
}
