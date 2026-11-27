//! Answering a caller's INVITE that carries no SDP (a delayed offer, RFC 3261
//! §13.2.1) with media anchored on the engine.
//!
//! The engine makes the offer (`offer_local`) and siphon puts it in the 2xx.
//! The caller's answer comes in its ACK (RFC 3264 §4) and completes the
//! engine call with `answer`, after which the call behaves as an
//! `answer_local` one. Until then the engine call is pending and takes
//! almost nothing, so [`PendingLocalOffer`] sits on the call from the 2xx to
//! the ACK and a control verb that needs the engine waits on it.
//!
//! An answer the engine refuses leaves its call pending: the call is ended
//! with a BYE, and the engine call deleted by the teardown. So is an ACK that
//! carries no answer, the same protocol error [`send_delayed_offer_ack`]
//! ends a relayed delayed offer for, and a 2xx that is never ACKed (the 64*T1
//! sweep).

use super::ack::{MEDIA_ANCHOR_FAILED_REASON, NO_ANSWER_IN_ACK_REASON};
use crate::b2bua::actor::PendingLocalOffer;
use crate::dispatcher::*;

/// Whether an INVITE carries no offer, so its 2xx has to.
pub(super) fn carries_no_offer(invite: &SipMessage) -> bool {
    invite.body.iter().all(u8::is_ascii_whitespace)
}

/// Why an engine that cannot make an offer cannot answer such a call.
fn offer_local_refusal(error: crate::rtpengine::RtpEngineError) -> String {
    match error {
        crate::rtpengine::RtpEngineError::Unsupported { .. } => {
            "the caller's INVITE carries no SDP (RFC 3261 §13.2.1) and the media engine does not \
             list offer_local, so it cannot make the offer the 2xx has to carry: it needs a \
             siphon-rtp that does (0.30 or later)"
                .to_string()
        }
        other => format!("offer_local failed: {other}"),
    }
}

/// Answer a parked call whose INVITE carries no SDP, anchored: the engine's
/// offer goes in the 2xx and the call waits for the ACK's answer.
///
/// On any failure nothing stays behind: the 2xx is not sent and the engine
/// call, when one was made, is deleted, so the call stays parked and
/// answerable.
#[allow(clippy::too_many_arguments)]
pub(super) fn answer_first_delayed_offer(
    call_id: &str,
    invite: &SipMessage,
    source_ip: std::net::IpAddr,
    code: u16,
    reason: &str,
    profile: Option<&str>,
    ws_uri: Option<&str>,
    media_flags: Option<&crate::rtpengine::media_flags::MediaFlags>,
    headers: &[(String, String)],
    state: &DispatcherState,
) -> Result<(), String> {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return Err(
            "answer-first requires a media backend (media.backend), none configured".to_string(),
        );
    };
    let Some(registry) = state.rtpengine_profiles.as_ref() else {
        return Err("answer-first requires media profiles, none configured".to_string());
    };
    let plan = answer_first_prepare(
        invite,
        source_ip,
        backend,
        registry,
        profile,
        ws_uri,
        media_flags,
    )?;
    let Some(to_tag) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.local_tag.clone())
    else {
        return Err("call is gone".to_string());
    };

    let offer_sdp = crate::script::blocking::block_on_released(backend.offer_local(
        &plan.media_call_id,
        &plan.from_tag,
        &plan.flags,
    ))
    .map_err(offer_local_refusal)?;

    // A teardown that landed while the engine made the offer has released the
    // call and found no session: the allocation is released here instead.
    if !super::dial_media::commit_media_session(
        state,
        call_id,
        crate::rtpengine::session::MediaSession {
            rtpengine_call_id: plan.media_call_id.clone(),
            call_id: plan.media_call_id.clone(),
            from_tag: plan.from_tag.clone(),
            to_tag: None,
            profile: plan.profile_name.clone(),
            ws_uri: plan.flags.ws_uri.clone(),
            ws_tee: plan.flags.ws_tee.clone(),
            ws_bridge_attached: false,
            ws_split_attached: false,
            bridge_sides: None,
            created_at: std::time::Instant::now(),
        },
    ) {
        return Err("the call ended while the media engine was making its offer".to_string());
    }
    // On the call before the 2xx leaves: the ACK can be back before this
    // returns.
    state.call_actors.set_pending_local_offer(
        call_id,
        PendingLocalOffer::new(
            plan.media_call_id.clone(),
            plan.from_tag.clone(),
            to_tag,
            plan.profile_name.clone(),
            offer_sdp.clone(),
            plan.flags.clone(),
        ),
    );
    if b2bua_answer_call_with_state(
        call_id,
        invite,
        code,
        reason,
        Some(offer_sdp.into_bytes()),
        Some("application/sdp"),
        headers,
        state,
    ) {
        return Ok(());
    }
    state.call_actors.finish_pending_local_offer(call_id);
    release_unanswered_offer(&plan.media_call_id, state);
    Err(format!(
        "failed to send {code} {reason} (call gone / dispatcher down)"
    ))
}

/// Delete the engine call an offer made for a 2xx that never left.
fn release_unanswered_offer(media_call_id: &str, state: &DispatcherState) {
    let (Some(backend), Some(sessions)) = (
        state.rtpengine_set.as_ref(),
        state.rtpengine_sessions.as_ref(),
    ) else {
        return;
    };
    let Some(session) = sessions.remove(media_call_id) else {
        return;
    };
    let backend = Arc::clone(backend);
    tokio::spawn(async move {
        if let Err(error) = backend
            .delete(session.rtpengine_id(), &session.from_tag)
            .await
        {
            if !error.is_call_not_found() {
                warn!(call_id = %session.call_id, "deleting the engine call of an unsent delayed-offer 2xx failed: {error}");
            }
        }
    });
}

/// The caller's ACK to a 2xx that carried the engine's offer: apply its answer
/// and complete the engine call. A no-op unless this call is waiting for one.
///
/// An ACK with no SDP, or an answer the engine refuses, ends the call with a
/// BYE; the teardown deletes the engine call, which the refusal left pending.
pub(super) fn complete_local_offer(call_id: &str, ack: &SipMessage, state: &DispatcherState) {
    let Some(pending) = state.call_actors.claim_pending_local_offer(call_id) else {
        return;
    };
    let outcome = apply_answer(&pending, ack, state);
    // Dropped after the call is settled either way: a verb waiting on the
    // answer then finds the engine call answered, or the call gone.
    match outcome {
        Ok(answer) => {
            // The caller's own description of its media, which its INVITE did
            // not carry: what a later bridge or transfer offers from. Set before
            // the waiting verbs are released.
            state.call_actors.set_leg_last_sdp(call_id, true, &answer);
            state.call_actors.finish_pending_local_offer(call_id);
        }
        Err((message, reason)) => {
            warn!(call_id = %call_id, "B2BUA: {message}; ending the call");
            b2bua_terminate_call_inner(call_id, Some(reason), "b2bua", state);
        }
    }
    drop(pending);
}

/// Send the ACK's answer to the engine, recording the call as the one the
/// engine answered itself when it takes it. The error is what to log and the
/// Q.850 `Reason` the teardown carries.
fn apply_answer(
    pending: &PendingLocalOffer,
    ack: &SipMessage,
    state: &DispatcherState,
) -> Result<Vec<u8>, (String, &'static str)> {
    let Some(answer) = sdp_in_body(message_content_type(ack), &ack.body) else {
        return Err((
            "the caller ACKed the engine's offer without an answer (RFC 3264 §4)".to_string(),
            NO_ANSWER_IN_ACK_REASON,
        ));
    };
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return Err((
            "the media backend is gone".to_string(),
            MEDIA_ANCHOR_FAILED_REASON,
        ));
    };
    crate::script::blocking::block_on_released(backend.complete_offer_local(
        &pending.engine_call_id,
        &pending.caller_tag,
        &pending.to_tag,
        &answer,
        &pending.flags,
    ))
    .map_err(|error| {
        (
            format!("the media engine refused the caller's answer to its offer: {error}"),
            MEDIA_ANCHOR_FAILED_REASON,
        )
    })?;
    // A WebSocket takeover is its own far side; nothing can be dialled behind it.
    if pending.flags.ws_uri.is_none() {
        if let Some(sessions) = state.rtpengine_sessions.as_ref() {
            sessions.record_local_answer(&pending.engine_call_id, &pending.offer_sdp);
        }
    }
    Ok(answer)
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
    if !state.call_actors.take_refresh_answer(call_id, cseq) {
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
        }
        ReofferOutcome::NoOfferTag | ReofferOutcome::Failed(_) => {
            warn!(call_id = %call_id, "B2BUA: the media engine refused the caller's answer to the session refresh's offer; ending the call");
            b2bua_terminate_call_inner(call_id, Some(MEDIA_ANCHOR_FAILED_REASON), "b2bua", state);
        }
    }
}
