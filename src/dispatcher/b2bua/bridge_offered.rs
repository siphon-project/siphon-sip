//! Bridging a caller to a phone that was offered early (`offer: "early"` on a
//! bridging `dial`, see [`super::leg_offer`]).
//!
//! The bridge's first half — offer the peer the anchor's media and take its
//! answer — already happened on the phone's own INVITE and 2xx: its
//! allocation is exactly the engine call the bridge would have offered it on,
//! and its 2xx carried the answer. What is left is the bridge's second half,
//! run through the bridge's own machinery: the attachments come off both legs
//! ([`bridge_media_plan`]), the phone's answer completes the allocation, and the
//! caller is re-INVITEd with the result ([`bridge_offer_anchor`]). From there
//! the anchor's answer forms the bridge ([`bridge_complete`]), which adopts the
//! allocation as the pair's session and deletes the caller's own; a refusal
//! fails it ([`bridge_fail`]), which deletes the allocation instead.
//!
//! The phone is never re-INVITEd: the offer/answer it made on its INVITE stands.

use super::bridge::{bridge_offer_anchor, bridge_peer_answer_flags};
use crate::dispatcher::*;

/// Bridge `peer_sip_call_id`, an answered leg whose INVITE carried the offer
/// `offered` was allocated for, to the caller `anchor_sip_call_id`. Returns
/// once the caller's re-INVITE is on the wire; the bridge settles as any other
/// does. A refusal here leaves both legs, and the allocation, as they were.
pub(crate) async fn bridge_offered_with_state(
    state: &DispatcherState,
    anchor_sip_call_id: &str,
    peer_sip_call_id: &str,
    offered: &crate::b2bua::actor::OriginateOffer,
) -> Result<BridgeAccepted, crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::{
        bridge_anchor_ingress, bridge_answer_profile, bridge_media_plan, bridge_peer_ingress,
        AnchorOffer, BridgeContext, BridgeError, BridgeRole, BridgeStage, MediaStep,
        PeerHangupPolicy,
    };

    let anchor = bridge_leg_snapshot(state, anchor_sip_call_id, "target")?;
    let peer = bridge_leg_snapshot(state, peer_sip_call_id, "with")?;
    bridge_leg_validate(&anchor)?;
    bridge_leg_validate(&peer)?;
    // The allocation was made from the caller's own session, on its tag; a
    // caller whose media moved since cannot be joined through it.
    let anchor_media = anchor
        .media
        .clone()
        .filter(|media| !media.relaying && media.from_tag == offered.offerer_tag)
        .ok_or_else(|| {
            BridgeError::Unsupported(
                "the caller's media changed since the phone was offered from it".to_string(),
            )
        })?;
    let peer_media = peer
        .media
        .clone()
        .filter(|media| media.media_call_id == offered.media_call_id)
        .ok_or_else(|| {
            BridgeError::Unavailable("the phone's offered media session is gone".to_string())
        })?;
    let backend = state.rtpengine_set.clone().ok_or_else(|| {
        BridgeError::Unavailable(
            "the legs are media-anchored but no media backend is configured".to_string(),
        )
    })?;
    let (peer_answer_tag, peer_answer, peer_offer) = state
        .call_actors
        .get_call(&peer.internal_call_id)
        .map(|call| {
            (
                call.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
                call.a_leg.last_sdp.clone().unwrap_or_default(),
                call.a_leg_invite
                    .as_ref()
                    .and_then(|invite| invite.lock().ok().map(|invite| invite.body.clone()))
                    .unwrap_or_default(),
            )
        })
        .ok_or_else(|| BridgeError::UnknownLeg {
            which: "with",
            id: peer_sip_call_id.to_string(),
        })?;

    // The anchor's re-INVITE slot is held until its answer settles the
    // bridge; the phone's is only checked, since nothing is sent to it
    // (RFC 3261 §14.1).
    if state
        .call_actors
        .set_pending_reinvite(&anchor.internal_call_id, true, true)
    {
        return Err(BridgeError::Glare {
            id: anchor.sip_call_id,
        });
    }
    let release_anchor = || {
        state
            .call_actors
            .set_pending_reinvite(&anchor.internal_call_id, true, false);
    };
    if state
        .call_actors
        .set_pending_reinvite(&peer.internal_call_id, true, true)
    {
        release_anchor();
        return Err(BridgeError::Glare {
            id: peer.sip_call_id,
        });
    }
    state
        .call_actors
        .set_pending_reinvite(&peer.internal_call_id, true, false);

    // Every attachment off both legs, as any bridge takes them: the plan's
    // negotiating step is the one the phone's INVITE already carried out.
    let teardown = bridge_media_plan(
        Some(&anchor_media),
        Some(&peer_media),
        AnchorOffer {
            sdp: &anchor.last_sdp,
            pair_profile: None,
            source: Some(anchor.source_ip),
            sip_call_id: &anchor.sip_call_id,
        },
        &offered.media_call_id,
    );
    for step in teardown
        .iter()
        .filter(|step| !matches!(step, MediaStep::Offer { .. } | MediaStep::Reoffer { .. }))
    {
        if let Err(error) =
            bridge_run_media_step(&backend, state.rtpengine_profiles.as_ref(), step).await
        {
            release_anchor();
            return Err(error);
        }
    }

    let half = |peer_call_id: &str, peer_sip_call_id: &str, role, last_local_offer| BridgeContext {
        peer_call_id: peer_call_id.to_string(),
        peer_sip_call_id: peer_sip_call_id.to_string(),
        role,
        stage: BridgeStage::OfferingPeer,
        on_peer_hangup: PeerHangupPolicy::default(),
        media_call_id: Some(offered.media_call_id.clone()),
        media_from_tag: Some(offered.offerer_tag.clone()),
        media_profile: Some(bridge_answer_profile(None, &anchor_media).to_string()),
        // What the phone's INVITE was offered under: its own profile.
        media_peer_profile: Some(peer_media.profile.clone()),
        media_anchor_ingress: Some(bridge_anchor_ingress(None, &anchor_media)),
        media_peer_ingress: Some(bridge_peer_ingress(None, &anchor_media, Some(&peer_media))),
        media_pending_adoption: true,
        last_local_offer,
        release_reason: None,
    };
    let anchor_half = half(
        &peer.internal_call_id,
        &peer.sip_call_id,
        BridgeRole::Anchor,
        Vec::new(),
    );

    // The phone's answer completes its allocation, under the flags the
    // bridge answers any peer with. Refused, nothing has moved: the caller
    // keeps its own session and the phone is released with its allocation.
    let flags = bridge_peer_answer_flags(
        &anchor_half,
        &peer.internal_call_id,
        &peer.sip_call_id,
        state,
    )
    .map_err(|_| {
        release_anchor();
        BridgeError::Unsupported("unknown media profile for the caller's answer".to_string())
    })?;
    let sdp_for_anchor = match backend
        .answer(
            &offered.media_call_id,
            &offered.offerer_tag,
            &peer_answer_tag,
            &peer_answer,
            &flags,
        )
        .await
    {
        Ok(sdp) => sdp,
        Err(error) => {
            release_anchor();
            return Err(BridgeError::Unsupported(format!(
                "the media engine refused the phone's answer: {error}"
            )));
        }
    };

    state
        .call_actors
        .set_bridge(&anchor.internal_call_id, anchor_half);
    state.call_actors.set_bridge(
        &peer.internal_call_id,
        half(
            &anchor.internal_call_id,
            &anchor.sip_call_id,
            BridgeRole::Peer,
            peer_offer,
        ),
    );
    if !bridge_offer_anchor(
        &peer.internal_call_id,
        &anchor.internal_call_id,
        sdp_for_anchor,
        state,
    ) {
        if let Some(context) = state.call_actors.take_bridge(&anchor.internal_call_id) {
            bridge_discard_pending_media(&context, state);
        }
        state.call_actors.take_bridge(&peer.internal_call_id);
        release_anchor();
        return Err(BridgeError::Unavailable(
            "the caller vanished before its bridge re-INVITE could be sent".to_string(),
        ));
    }
    info!(
        anchor_call_id = %anchor.internal_call_id,
        peer_call_id = %peer.internal_call_id,
        "B2BUA bridge: the early-offered phone's answer taken, re-INVITEing the caller"
    );
    Ok(BridgeAccepted {
        anchor_call_id: anchor.internal_call_id,
        anchor_sip_call_id: anchor.sip_call_id,
        peer_call_id: peer.internal_call_id,
        anchored: true,
    })
}
