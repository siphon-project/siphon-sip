//! `b2bua.adopt_replaced`: merge a call this node holds into a conference room
//! on this same node.
//!
//! A client merging two calls (RFC 4579 §5.5, TS 24.147) REFERs the focus
//! inside the conference dialog with a `Refer-To` whose `Replaces` (RFC 3891)
//! names its own dialog with the far party. When that dialog is one leg of a
//! call this node holds, nothing can carry the `Replaces` out over SIP: the
//! node would have to INVITE itself. Instead the call's *other* leg is seated
//! in the room in place with siphon-rtp `conference_seat` (same ports, same
//! session, no SIP toward the far party), and the named leg is sent its BYE.
//!
//! The call stays a call: its actor, its Ro session, its maximum duration, its
//! session timer and its CDR all continue, with the far party as its one SIP
//! leg. A re-INVITE or UPDATE from the far party is then answered against the
//! session in force (`answer_unanchored_reoffer`), and every way a call ends
//! (the far party's BYE, credit, `max_call_duration_secs`, the seat's
//! `media_timeout`) ends it, the engine `delete` taking the seat out. With
//! `on_owner_leave="end"` the call also ends with the conference dialog that
//! adopted it, the referrer paying for the far leg; that link is kept in the
//! call store, not in the script, since module state does not survive a reload
//! and a conference outlives a deploy.
//!
//! Refusals leave the named call exactly as it was, and each is the status the
//! script reports on the REFER's NOTIFY: `481` (no confirmed dialog here
//! matches), `403` (the dialog is not the referrer's), `488` (the engine, or
//! the call's state, refused the seat), `501` (the media backend cannot seat a
//! call's leg). There is no fallback to a re-INVITE of the far party: that is a
//! change on the wire nobody asked for.

use crate::b2bua::actor::{same_party, AdoptRefusal, AdoptedSwap, DialogParty};
use crate::dispatcher::*;
use crate::rtpengine::backend::ConferenceRole;
use crate::rtpengine::error::RtpEngineError;

/// The `Reason` (RFC 3326) on the BYE that ends the dialog the `Replaces`
/// named: the dialog was not dropped, it was merged.
pub const MERGED_INTO_CONFERENCE_REASON: &str = "SIP;cause=200;text=\"Merged into conference\"";

/// The `Reason` on the BYE that ends an adopted call with its conference
/// dialog: normal call clearing (Q.850 cause 16).
pub const CONFERENCE_ENDED_REASON: &str = "Q.850;cause=16;text=\"Conference ended\"";

/// The `Reason` on the BYE that ends an adopted call whose seat went silent:
/// a local timer ended an established call, as for the session timer
/// (Q.850 cause 102, recovery on timer expiry).
pub const SEAT_MEDIA_TIMEOUT_REASON: &str = "Q.850;cause=102;text=\"Media timeout\"";

/// What `b2bua.adopt_replaced` is asked to do.
#[derive(Debug, Clone)]
pub struct AdoptRequest {
    /// Internal id of the call whose dialog the REFER arrived in: the
    /// conference dialog.
    pub owner_call_id: String,
    /// Whether the REFER arrived on that call's A-leg.
    pub referrer_on_a_leg: bool,
    /// The dialog the REFER's `Replaces` names.
    pub replaces: crate::sip::headers::refer::Replaces,
    /// The room to seat the far party in.
    pub conference_id: String,
    /// The far party's routing role in the room.
    pub role: ConferenceRole,
    /// Whether the adopted call ends with the conference dialog.
    pub ends_with_owner: bool,
}

/// Carry out `request` on the running dispatcher. Resolves to the status the
/// script reports with `b2bua.complete_refer`.
pub async fn b2bua_adopt_replaced(request: AdoptRequest) -> u16 {
    let Some(control) = B2BUA_CONTROL.get() else {
        warn!("b2bua.adopt_replaced: the B2BUA is not running");
        return 503;
    };
    let state = Arc::clone(&control.state);
    b2bua_adopt_replaced_with_state(&state, request).await
}

/// [`b2bua_adopt_replaced`] on a dispatcher in hand.
pub async fn b2bua_adopt_replaced_with_state(
    state: &DispatcherState,
    request: AdoptRequest,
) -> u16 {
    let owner = &request.owner_call_id;
    let replaces = &request.replaces;
    // 1. The named dialog: a confirmed leg of a call here, and not the
    //    conference dialog itself.
    let Some((named, answered)) = state.call_actors.replaced_dialog_party(
        &replaces.call_id,
        &replaces.from_tag,
        &replaces.to_tag,
    ) else {
        info!(call_id = %owner, replaces = %replaces.call_id, "b2bua.adopt_replaced: no dialog here matches the Replaces — 481");
        return 481;
    };
    if !answered || named.internal_call_id == *owner {
        info!(call_id = %owner, replaces = %replaces.call_id, answered, "b2bua.adopt_replaced: the named dialog is not a confirmed call that can be merged — 481");
        return 481;
    }
    // 2. Whose dialog it is (RFC 3891 §5).
    let Some(referrer) = state
        .call_actors
        .dialog_party(owner, request.referrer_on_a_leg)
    else {
        info!(call_id = %owner, "b2bua.adopt_replaced: the conference dialog is gone — 481");
        return 481;
    };
    if let Some(status) = refuse_another_partys_dialog(&referrer, &named) {
        return status;
    }
    // 3. A backend that can seat a call's leg at all.
    let (Some(backend), Some(sessions)) = (
        state.rtpengine_set.as_ref(),
        state.rtpengine_sessions.as_ref(),
    ) else {
        warn!(call_id = %owner, "b2bua.adopt_replaced: no media backend — 501");
        return 501;
    };
    if !matches!(**backend, crate::rtpengine::MediaBackend::SiphonRtp(_)) {
        warn!(call_id = %owner, backend = backend.kind().as_str(), "b2bua.adopt_replaced: only siphon-rtp seats a call's leg in a room — 501");
        return 501;
    }
    // 4. Claim the call, so nothing else merges or transfers it meanwhile.
    let adopted = named.internal_call_id.clone();
    let media_key = match state.call_actors.begin_adoption(
        &adopted,
        &request.conference_id,
        owner,
        request.ends_with_owner,
    ) {
        Ok(key) => key,
        Err(AdoptRefusal::NoDialog) => return 481,
        Err(AdoptRefusal::Busy) => {
            info!(call_id = %adopted, "b2bua.adopt_replaced: the call is being transferred, bridged or merged already — 488");
            return 488;
        }
    };
    // 5. The far party's engine leg, and the seat.
    let far_on_a_leg = !named.on_a_leg;
    let Some((engine_call_id, far_tag)) = sessions.get(&media_key).and_then(|session| {
        session
            .offer_tag(far_on_a_leg)
            .map(|tag| (session.rtpengine_id().to_string(), tag.to_string()))
    }) else {
        state.call_actors.abandon_adoption(&adopted);
        warn!(call_id = %adopted, "b2bua.adopt_replaced: the call has no media session naming the far party on this backend — 488");
        return 488;
    };
    if let Err(error) = backend
        .conference_seat_call(
            &engine_call_id,
            &far_tag,
            &request.conference_id,
            request.role.clone(),
        )
        .await
    {
        state.call_actors.abandon_adoption(&adopted);
        return match error {
            RtpEngineError::Unsupported { .. } => {
                warn!(call_id = %adopted, "b2bua.adopt_replaced: {error} — 501");
                501
            }
            other => {
                warn!(call_id = %adopted, conference_id = %request.conference_id, "b2bua.adopt_replaced: the engine refused the seat: {other} — 488");
                488
            }
        };
    }
    // 6. The seat is in: the call keeps the far party only, and the named leg
    //    ends (RFC 3891 §3).
    let Some(swap) = state
        .call_actors
        .complete_adoption(&adopted, named.on_a_leg)
    else {
        // Ended while the seat was asked for; its teardown deleted the call,
        // seat and all.
        info!(call_id = %adopted, "b2bua.adopt_replaced: the call ended while it was being seated — 481");
        return 481;
    };
    follow_the_far_party(state, &adopted, &swap, &far_tag);
    end_the_replaced_dialog(state, &adopted, &swap);
    info!(
        call_id = %adopted,
        conference_id = %request.conference_id,
        owner = %owner,
        replaced_on_a_leg = named.on_a_leg,
        ends_with_owner = request.ends_with_owner,
        "b2bua.adopt_replaced: the far party is seated in the room and the named dialog is ended"
    );
    // The conference dialog may have ended while the seat was asked for.
    state.call_actors.orphan_adoptions_of_ended_owners();
    end_orphaned_adoptions(state);
    200
}

/// `403` when `named` is not the referrer's own dialog, `None` when it is.
fn refuse_another_partys_dialog(referrer: &DialogParty, named: &DialogParty) -> Option<u16> {
    match same_party(referrer, named) {
        Ok(by) => {
            debug!(call_id = %referrer.internal_call_id, ?by, "b2bua.adopt_replaced: the named dialog is the referrer's");
            None
        }
        Err(why) => {
            warn!(
                call_id = %referrer.internal_call_id,
                named = %named.sip_call_id,
                "b2bua.adopt_replaced: {why} — 403"
            );
            Some(403)
        }
    }
}

/// The media session, a control channel and the event key follow the far
/// party into the A-leg slot when the named leg was the A-leg.
fn follow_the_far_party(state: &DispatcherState, call_id: &str, swap: &AdoptedSwap, far_tag: &str) {
    if swap.previous_a_call_id == swap.a_call_id {
        return;
    }
    if let Some(sessions) = state.rtpengine_sessions.as_ref() {
        if let Some(mut session) = sessions.get(&swap.previous_a_call_id) {
            let engine_call_id = session.rtpengine_id().to_string();
            sessions.remove(&swap.previous_a_call_id);
            session.rtpengine_call_id = engine_call_id.clone();
            session.call_id = swap.a_call_id.clone();
            // The far party is the A-party now, so its tag is the session's
            // `from_tag`; the departed party's stays recorded beside it.
            if session.to_tag.as_deref() == Some(far_tag) {
                let departed = std::mem::replace(&mut session.from_tag, far_tag.to_string());
                session.to_tag = Some(departed);
            }
            sessions.insert(session);
            sessions.record_parties(
                &swap.a_call_id,
                &engine_call_id,
                &[(&swap.a_call_id, Some(far_tag))],
            );
        }
    }
    control_channel_follows_a_leg(state, call_id, &swap.previous_a_call_id);
}

/// Send the named leg its BYE, after anything its dialog is still owed.
fn end_the_replaced_dialog(state: &DispatcherState, call_id: &str, swap: &AdoptedSwap) {
    // A REFER the departed party sent, still held, is answered first.
    pending_refer_leg_released(state, call_id, &swap.replaced);
    match build_b2bua_bye(&swap.replaced, state) {
        Some(mut bye) => {
            bye.headers
                .add("Reason", MERGED_INTO_CONFERENCE_REASON.to_string());
            send_or_hold_bye(call_id, &swap.replaced, bye, ByeSender::Dialog, state);
        }
        None => {
            warn!(call_id = %call_id, "b2bua.adopt_replaced: could not build the BYE for the named dialog")
        }
    }
}

/// Tear down every adopted call whose conference dialog has ended, through the
/// normal teardown: a BYE to the far party, Ro and Rf stop, the CDR, and the
/// engine delete that takes the seat out.
pub fn end_orphaned_adoptions(state: &DispatcherState) {
    for call_id in state.call_actors.take_orphaned_adoptions() {
        info!(call_id = %call_id, "b2bua.adopt_replaced: the conference dialog ended — ending the call it adopted");
        b2bua_terminate_call_inner(&call_id, Some(CONFERENCE_ENDED_REASON), "b2bua", state);
    }
}

/// The 500 ms sweep: a conference dialog taken out of the store by a path that
/// does not end its adopted calls itself.
pub fn check_orphaned_adoptions(state: &DispatcherState) {
    state.call_actors.orphan_adoptions_of_ended_owners();
    end_orphaned_adoptions(state);
}

/// The adopted call on engine call `engine_call_id`, if it is one.
pub fn adopted_call_on_engine_call(
    state: &DispatcherState,
    engine_call_id: &str,
) -> Option<String> {
    let key = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.session_key_for_engine_call(engine_call_id))
        .unwrap_or_else(|| engine_call_id.to_string());
    let call_id = state.call_actors.find_by_sip_call_id(&key)?;
    state
        .call_actors
        .get_call(&call_id)
        .is_some_and(|call| {
            call.adoption
                .as_ref()
                .is_some_and(|adoption| adoption.seated)
        })
        .then_some(call_id)
}

/// The engine reported the seat of an adopted call silent. The engine keeps the
/// leg allocated for a seated call, so the call is ended here through its
/// normal path, whose `delete` frees it. `true` when `engine_call_id` was one.
pub fn end_adopted_call_on_media_timeout(state: &DispatcherState, engine_call_id: &str) -> bool {
    let Some(call_id) = adopted_call_on_engine_call(state, engine_call_id) else {
        return false;
    };
    info!(call_id = %call_id, "b2bua.adopt_replaced: the seat went silent — ending the adopted call");
    b2bua_terminate_call_inner(&call_id, Some(SEAT_MEDIA_TIMEOUT_REASON), "timeout", state);
    true
}
