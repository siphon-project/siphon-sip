//! Dialling a callee behind an answer siphon already gave the caller.
//!
//! A script, or a controller, answers the caller's INVITE in early media with
//! the media engine's own answer (`answer_local`, an announcement), then dials
//! the callee and puts the caller through. The caller holds that answer for the
//! rest of the call: RFC 3261 §13.2.1 has a UAC take the first SDP it receives
//! as the answer and ignore SDP in later responses to the same INVITE, RFC 6337
//! §3.1.1 asks a 2xx to repeat an answer previewed in an unreliable 18x exactly,
//! and RFC 3264 §8 changes an answer only through a new offer. So the caller's
//! answer never changes and the engine re-points the media behind it:
//!
//! - every 18x with SDP siphon sends the caller itself is held
//!   ([`hold_early_answer`]), with whether it is the engine's own answer;
//! - a dial on such a call offers the callee a far leg the engine binds behind
//!   the caller's answer (`offer_far`, [`invite_for_dial`]), never the caller's
//!   own offer;
//! - the callee's first SDP completes it (`answer`, [`complete_far_leg`]), and
//!   the caller is sent the held answer byte for byte, or no SDP once it has it
//!   reliably ([`present_held_answer`]);
//! - a callee that refuses, or a dial that ends unanswered, drops the far leg
//!   and leaves the caller on the engine's pipeline ([`release_far_leg`]), for
//!   another prompt, another dial, or the failure.
//!
//! An answer that is not the engine's (SDP a script took from elsewhere) cannot
//! have a callee connected behind it, and a dial on it is refused
//! ([`dial_refusal`]). A parallel fork is refused too: the engine holds one far
//! leg at a time.

use tracing::{debug, info, warn};

use crate::b2bua::actor::{extract_to_tag, FarLeg};
use crate::dispatcher::DispatcherState;
use crate::sip::message::SipMessage;

use super::{message_content_type, remove_body};
use crate::dispatcher::sanitize::sdp_in_body;

/// The engine call a held answer is on, as the media store names it.
struct HeldSession {
    engine_call_id: String,
    from_tag: String,
    profile: String,
}

/// Run a media engine round trip on the SIP-processing path, as the other
/// B2BUA answer paths do (`anchor_a_leg`).
fn engine_round_trip<T>(future: impl std::future::Future<Output = T>) -> T {
    crate::script::blocking::block_on_released(future)
}

/// The SIP Call-ID the caller's media session is stored under.
fn caller_sip_call_id(invite: &SipMessage) -> Option<String> {
    invite.headers.call_id().cloned()
}

/// Hold `body`, an SDP answer siphon is sending the caller in an 18x of its own,
/// unless the call already holds one: the first answer is the one in force.
pub fn hold_early_answer(state: &DispatcherState, call_id: &str, invite: &SipMessage, body: &[u8]) {
    if state.call_actors.early_media_anchor(call_id).is_some() {
        return;
    }
    let answer_sdp = String::from_utf8_lossy(body).into_owned();
    let session = caller_sip_call_id(invite).and_then(|sip_call_id| {
        let sessions = state.rtpengine_sessions.as_ref()?;
        let local = sessions.local_answer(&sip_call_id)?;
        let session = sessions.get(&sip_call_id)?;
        (local == answer_sdp && session.to_tag.is_none()).then_some(session)
    });
    let anchor = crate::b2bua::actor::EarlyMediaAnchor {
        engine: session.is_some(),
        profile: session.map(|session| session.profile).unwrap_or_default(),
        answer_sdp,
        far: None,
    };
    debug!(call_id = %call_id, engine = anchor.engine, "B2BUA: holding siphon's own early answer to the caller");
    state.call_actors.set_early_media_anchor(call_id, anchor);
}

/// Why a dial cannot go out on this call, or `None` when it can. `fork` says
/// whether it rings several targets at once.
pub fn dial_refusal(state: &DispatcherState, call_id: &str, fork: bool) -> Option<String> {
    let anchor = state.call_actors.early_media_anchor(call_id)?;
    if !anchor.engine {
        return Some(
            "the caller already holds an early answer that is not a media engine session, so \
             no callee can be connected behind it; answer it with rtpengine.answer_local (or \
             call.progress(anchor=True)) before dialling"
                .to_string(),
        );
    }
    if fork {
        return Some(
            "the caller holds siphon's own early answer, and the media engine connects one \
             callee behind it at a time; dial or route the targets in sequence"
                .to_string(),
        );
    }
    None
}

/// The engine call behind the held answer.
fn held_session(state: &DispatcherState, invite: &SipMessage) -> Result<HeldSession, String> {
    let sip_call_id = caller_sip_call_id(invite).ok_or("the INVITE has no Call-ID")?;
    let session = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(&sip_call_id))
        .ok_or("the caller's media session is gone")?;
    Ok(HeldSession {
        engine_call_id: session.rtpengine_id().to_string(),
        from_tag: session.from_tag.clone(),
        profile: session.profile.clone(),
    })
}

/// The flags of one half of a media profile.
fn profile_flags(
    state: &DispatcherState,
    profile: &str,
    answer: bool,
) -> Result<crate::rtpengine::NgFlags, String> {
    let entry = state
        .rtpengine_profiles
        .as_ref()
        .and_then(|profiles| profiles.get(profile))
        .ok_or_else(|| format!("unknown media profile '{profile}'"))?;
    Ok(if answer {
        entry.answer.clone()
    } else {
        entry.offer.clone()
    })
}

/// `invite` with `body` as its SDP.
fn with_sdp(invite: &SipMessage, body: &[u8]) -> SipMessage {
    let mut copy = invite.clone();
    copy.body = body.to_vec();
    copy.headers
        .set("Content-Type", "application/sdp".to_string());
    copy.headers
        .set("Content-Length", copy.body.len().to_string());
    copy
}

/// The INVITE a dial on `call_id` sends the callee: `None` for a call that holds
/// no engine answer, which dials the caller's INVITE as it always has.
///
/// On a call holding the engine's early answer it carries the engine's offer for
/// the far leg. A far leg offered and not yet answered is offered again to the
/// next target of a sequence; one a callee's SDP already completed is dropped
/// and a fresh one offered, since the engine relays the caller to that callee.
pub fn invite_for_dial(
    state: &DispatcherState,
    call_id: &str,
    invite: &SipMessage,
) -> Result<Option<SipMessage>, String> {
    let Some(anchor) = state.call_actors.early_media_anchor(call_id) else {
        return Ok(None);
    };
    if let Some(refusal) = dial_refusal(state, call_id, false) {
        return Err(refusal);
    }
    match &anchor.far {
        Some(far) if far.answered_by.is_none() => {
            return Ok(Some(with_sdp(invite, &far.offer_sdp)))
        }
        Some(_) => release_far_leg(state, call_id, invite),
        None => {}
    }
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("no media backend is configured")?;
    let session = held_session(state, invite)?;
    let mut flags = profile_flags(state, &session.profile, false)?;
    if let Some(sip_call_id) = caller_sip_call_id(invite) {
        flags.stamp_sip_call_id(&sip_call_id);
    }
    let offer_sdp =
        engine_round_trip(backend.offer_far(&session.engine_call_id, &session.from_tag, &flags))
            .map_err(|error| format!("offer_far failed: {error}"))?;
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(anchor) = call.early_media_anchor.as_mut() {
            anchor.far = Some(FarLeg {
                offer_sdp: offer_sdp.clone(),
                answered_by: None,
            });
        }
    }
    info!(call_id = %call_id, "B2BUA: dialling behind the caller's early answer on an engine far leg");
    Ok(Some(with_sdp(invite, &offer_sdp)))
}

/// Complete the far leg with the callee's first SDP, in `response`. `Ok(true)`
/// when this call dials behind a held engine answer (whatever the response
/// carried), `Ok(false)` when it does not, and the engine's refusal otherwise.
pub fn complete_far_leg(
    state: &DispatcherState,
    call_id: &str,
    invite: &SipMessage,
    response: &SipMessage,
) -> Result<bool, String> {
    let Some(anchor) = state.call_actors.early_media_anchor(call_id) else {
        return Ok(false);
    };
    let Some(far) = anchor.far.filter(|_| anchor.engine) else {
        return Ok(false);
    };
    if far.answered_by.is_some() {
        return Ok(true);
    }
    let Some(sdp) = sdp_in_body(message_content_type(response), &response.body) else {
        return Ok(true);
    };
    let to_tag = extract_to_tag(response).ok_or("the callee's response has no To tag")?;
    let backend = state
        .rtpengine_set
        .as_ref()
        .ok_or("no media backend is configured")?;
    let session = held_session(state, invite)?;
    let mut flags = profile_flags(state, &session.profile, true)?;
    if let Some(sip_call_id) = response.headers.call_id() {
        flags.stamp_sip_call_id(sip_call_id);
    }
    engine_round_trip(backend.answer(
        &session.engine_call_id,
        &session.from_tag,
        &to_tag,
        &sdp,
        &flags,
    ))
    .map_err(|error| format!("the engine refused the callee's answer: {error}"))?;
    if let (Some(sessions), Some(sip_call_id)) = (
        state.rtpengine_sessions.as_ref(),
        caller_sip_call_id(invite),
    ) {
        sessions.set_to_tag(&sip_call_id, to_tag.clone());
    }
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(far) = call
            .early_media_anchor
            .as_mut()
            .and_then(|anchor| anchor.far.as_mut())
        {
            far.answered_by = Some(to_tag);
        }
    }
    info!(call_id = %call_id, "B2BUA: the callee is connected behind the caller's early answer");
    Ok(true)
}

/// Put the held answer in `response`, a callee's 18x or 2xx relayed to the
/// caller, in place of the callee's SDP. Returns `false`, leaving the response
/// alone, on a call that holds no answer the engine dials behind.
///
/// A 2xx carries the held answer unchanged (RFC 6337 §3.1.1). An 18x carries it
/// too, unless the caller already holds it reliably, when it carries none: a
/// completed offer/answer exchange is not repeated in a provisional (RFC 3262
/// §5). Either way the same `o=` session id and version reach the caller.
pub fn present_held_answer(
    state: &DispatcherState,
    call_id: &str,
    response: &mut SipMessage,
    final_response: bool,
) -> bool {
    let Some((answer_sdp, held_reliably)) = state.call_actors.get_call(call_id).and_then(|call| {
        let anchor = call.early_media_anchor.as_ref()?;
        (anchor.engine && anchor.far.is_some()).then(|| {
            (
                anchor.answer_sdp.clone(),
                call.a_leg.dialog.last_sent_sdp.is_some(),
            )
        })
    }) else {
        return false;
    };
    if !final_response && held_reliably {
        remove_body(response);
    } else {
        response.body = answer_sdp.into_bytes();
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", response.body.len().to_string());
    }
    true
}

/// Drop the far leg of a dial that is over without the caller connected, so the
/// engine holds the caller alone on its pipeline again. A no-op on a call that
/// holds no far leg.
pub fn release_far_leg(state: &DispatcherState, call_id: &str, invite: &SipMessage) {
    let far = state
        .call_actors
        .get_call_mut(call_id)
        .and_then(|mut call| {
            call.early_media_anchor
                .as_mut()
                .and_then(|anchor| anchor.far.take())
        });
    let Some(far) = far else {
        return;
    };
    let (Some(backend), Ok(session)) = (state.rtpengine_set.as_ref(), held_session(state, invite))
    else {
        return;
    };
    // The engine takes any tag for a far leg nobody answered.
    let to_tag = far.answered_by.unwrap_or_else(|| "unanswered".to_string());
    if let Err(error) = engine_round_trip(backend.delete_far_leg(
        &session.engine_call_id,
        &session.from_tag,
        &to_tag,
    )) {
        warn!(call_id = %call_id, %error, "B2BUA: the engine did not release the far leg");
    }
    if let (Some(sessions), Some(sip_call_id)) = (
        state.rtpengine_sessions.as_ref(),
        caller_sip_call_id(invite),
    ) {
        sessions.clear_to_tag(&sip_call_id);
    }
    debug!(call_id = %call_id, "B2BUA: far leg released; the caller is back on the engine's pipeline");
}

/// [`release_far_leg`] for `call_id`, read off the call's stored INVITE.
pub fn release_far_leg_of(state: &DispatcherState, call_id: &str) {
    let invite = state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone())
        .and_then(|invite| invite.lock().ok().map(|guard| guard.clone()));
    if let Some(invite) = invite {
        release_far_leg(state, call_id, &invite);
    }
}
