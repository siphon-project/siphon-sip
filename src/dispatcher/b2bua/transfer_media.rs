//! The media engine's half of a transfer: offering the surviving party onto a
//! fresh engine call and completing it with the new party's answer.
use crate::dispatcher::*;

/// rtpengine `offer` for a siphon-terminated transfer (Phase 1): anchor the
/// survivor's media (`survivor_sdp`, offered under `survivor_tag`) on the FRESH
/// rtpengine call-id `cid_new` using `profile_name`'s offer flags, and return
/// the SDP to place in the transfer target's INVITE. `None` if media control is
/// not configured or the offer failed (the caller then dials with the survivor's
/// raw SDP). Awaited with the same `block_in_place` idiom as the bridged
/// re-INVITE path. `offerer_sip_call_id` is the Call-ID of the dialog the
/// offered SDP belongs to.
pub fn b2bua_transfer_rtpengine_offer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    survivor_sdp: &[u8],
    offerer_sip_call_id: &str,
    profile_name: &str,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let profile = profiles.get(profile_name)?;
    let mut offer_flags = profile.offer.clone();
    offer_flags.stamp_sip_call_id(offerer_sip_call_id);
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.offer(
            cid_new,
            survivor_tag,
            survivor_sdp,
            &offer_flags,
        ))
    }) {
        Ok(rewritten) => Some(rewritten),
        Err(error) => {
            warn!(rtpengine_call_id = %cid_new, "REFER terminate: rtpengine offer failed: {error}");
            None
        }
    }
}

/// rtpengine `answer` for a siphon-terminated transfer (Phase 2): complete the
/// survivor↔target media on the fresh rtpengine call-id `cid_new` with the
/// target's answer SDP (`target_sdp`, under `target_tag`) against the offerer
/// (`survivor_tag`), and return the SDP to re-INVITE the survivor with. `None`
/// if media control is not configured or the answer failed.
///
/// It also completes an anchored delayed offer with the caller's answer
/// (`send_delayed_offer_ack`): the offerer is then the callee, and the answer the
/// caller's. `answerer_sip_call_id` is the Call-ID of the dialog the
/// answer SDP belongs to.
pub fn b2bua_transfer_rtpengine_answer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    target_tag: &str,
    target_sdp: &[u8],
    answerer_sip_call_id: &str,
    profile_name: &str,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let profile = profiles.get(profile_name)?;
    let mut answer_flags = profile.answer.clone();
    answer_flags.stamp_sip_call_id(answerer_sip_call_id);
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(backend.answer(
            cid_new,
            survivor_tag,
            target_tag,
            target_sdp,
            &answer_flags,
        ))
    }) {
        Ok(rewritten) => Some(rewritten),
        Err(error) => {
            warn!(rtpengine_call_id = %cid_new, "rtpengine answer failed: {error}");
            None
        }
    }
}
