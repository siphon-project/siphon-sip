//! Bridging two independent B2BUA calls into one (`b2bua.bridge()`), the
//! re-INVITE dance that re-anchors their media, and unbridging them again.
use crate::dispatcher::*;

// ---------------------------------------------------------------------------
// bridge — joining two answered legs siphon already owns
// ---------------------------------------------------------------------------

/// What a `bridge` needs. Both legs are named by their SIP Call-ID, the one id
/// the control rail, the script rail, the CDR and HEP all already share.
#[derive(Debug, Clone)]
pub struct BridgeParams {
    /// The leg the verb is addressed to. It keeps its media session — its
    /// ports and everything attached to them (see [`crate::b2bua::bridge`]).
    pub anchor_sip_call_id: String,
    /// The leg to join it to. Its own media session is deleted; it becomes the
    /// second party on the anchor's.
    pub peer_sip_call_id: String,
    /// What happens to the survivor when one of the two hangs up.
    pub on_peer_hangup: crate::b2bua::bridge::PeerHangupPolicy,
}

/// A bridge that has been accepted and put in motion: both call actors carry
/// their half and the first re-INVITE is on the wire. The media does **not**
/// meet yet — `ChannelBridged` says that, and it arrives once both legs have
/// answered their re-INVITE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeAccepted {
    /// Internal `CallActor` id of the anchor leg — the one that kept its media
    /// session. Normally the leg the verb was addressed to; the other one when
    /// only it had a session to keep.
    pub anchor_call_id: String,
    /// The anchor leg's SIP Call-ID, so a caller can tell which of the two legs
    /// it named ended up the anchor without a second lookup.
    pub anchor_sip_call_id: String,
    /// Internal `CallActor` id of the peer leg.
    pub peer_call_id: String,
    /// Whether the pair is anchored on the media backend (as opposed to a raw
    /// SDP crossing, where the two endpoints exchange RTP directly).
    pub anchored: bool,
}

/// Everything the bridge reads off one leg, snapshotted before anything is
/// mutated.
pub struct BridgeLegSnapshot {
    pub internal_call_id: String,
    pub sip_call_id: String,
    /// The call's lifecycle state — only `Answered` can be bridged.
    pub call_state: CallState,
    /// Whether the leg is already half of a bridge.
    pub already_bridged: bool,
    /// Whether siphon placed this call (it then never sees an inbound ACK).
    pub originated: bool,
    /// Whether the initial INVITE's ACK has arrived (RFC 3261 §14.1).
    pub initial_acked: bool,
    /// The endpoint's own current media description — what the engine is told
    /// the offerer looks like, and what a raw crossing hands the other leg.
    pub last_sdp: Vec<u8>,
    /// The leg's engine session, when it is anchored.
    pub media: Option<crate::b2bua::bridge::LegMedia>,
}

/// Resolve one side of a bridge: does this leg exist at all, and what does it
/// carry. Read-only, and deliberately state-blind — both legs are resolved
/// before either is validated, so naming a channel that does not exist always
/// reads `not_found` and never gets masked by the *other* leg happening to be
/// in the wrong state at that moment.
pub fn bridge_leg_snapshot(
    state: &DispatcherState,
    sip_call_id: &str,
    which: &'static str,
) -> Result<BridgeLegSnapshot, crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::BridgeError;

    let unknown = || BridgeError::UnknownLeg {
        which,
        id: sip_call_id.to_string(),
    };
    let internal_call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or_else(unknown)?;
    let call = state
        .call_actors
        .get_call(&internal_call_id)
        .ok_or_else(unknown)?;
    let call_state = call.state.clone();
    let already_bridged = call.bridge.is_some();
    let originated = call.originated;
    let initial_acked = call.a_leg.initial_acked;
    let last_sdp = call.a_leg.last_sdp.clone().unwrap_or_default();
    drop(call);

    let media = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|store| store.get(sip_call_id))
        .map(|session| crate::b2bua::bridge::LegMedia {
            media_call_id: session.rtpengine_id().to_string(),
            from_tag: session.from_tag.clone(),
            profile: session.profile.clone(),
            // A session with a second party is a relay and can be renegotiated
            // in place; one the engine answered itself has only the caller.
            relaying: session.to_tag.is_some(),
            // The *tee*, not the takeover: `ws_uri` is the profile-negotiated
            // bridge and reading it here sent `detach_ws_tee` at a leg holding
            // a takeover — which answers ok, because it is idempotent — while
            // the real tee on a leg that had one was never detached at all.
            has_tee: session.ws_tee.is_some(),
            has_ws_bridge: session.ws_bridge_attached,
            has_playback: crate::rtpengine::MediaBackend::playback_started(
                session.rtpengine_id(),
                &session.from_tag,
            ),
        });

    Ok(BridgeLegSnapshot {
        internal_call_id,
        sip_call_id: sip_call_id.to_string(),
        call_state,
        already_bridged,
        originated,
        initial_acked,
        last_sdp,
        media,
    })
}

/// Refuse everything about one leg that would make the bridge a half-formed
/// one. Runs after both legs have been resolved.
pub fn bridge_leg_validate(
    leg: &BridgeLegSnapshot,
) -> Result<(), crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::BridgeError;

    if leg.call_state != CallState::Answered {
        return Err(BridgeError::NotAnswered {
            id: leg.sip_call_id.clone(),
            state: format!("{:?}", leg.call_state).to_lowercase(),
        });
    }
    if leg.already_bridged {
        return Err(BridgeError::AlreadyBridged {
            id: leg.sip_call_id.clone(),
        });
    }
    // RFC 3261 §14.1: a re-INVITE may not start while the initial exchange's
    // offer/answer is still in flight. A leg siphon *placed* never sees an
    // inbound ACK (siphon sends it), so `initial_acked` only means anything on
    // a leg that answered an INVITE we received.
    if !leg.originated && !leg.initial_acked {
        return Err(BridgeError::Glare {
            id: leg.sip_call_id.clone(),
        });
    }
    if leg.last_sdp.is_empty() {
        return Err(BridgeError::NoMediaDescription {
            id: leg.sip_call_id.clone(),
        });
    }
    Ok(())
}

/// Run one media step of a bridge and wait for the engine to say it is done.
///
/// Every step is awaited and its reply checked — an attachment assumed gone is
/// an attachment that is still replacing a leg's audio when the bridge forms.
/// Returns the renegotiated SDP for the one step that produces one
/// ([`MediaStep::Reoffer`]).
pub async fn bridge_run_media_step(
    backend: &Arc<crate::rtpengine::MediaBackend>,
    profiles: Option<&Arc<crate::rtpengine::ProfileRegistry>>,
    step: &crate::b2bua::bridge::MediaStep,
) -> Result<Option<Vec<u8>>, crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::{classify_media_failure, BridgeError, MediaStep};

    let outcome: Result<Option<Vec<u8>>, crate::rtpengine::error::RtpEngineError> = match step {
        MediaStep::StopPlayback {
            media_call_id,
            from_tag,
        } => backend
            .stop_media(media_call_id, from_tag, None)
            .await
            .map(|()| None),
        MediaStep::DetachTee {
            media_call_id,
            from_tag,
        } => backend
            .detach_ws_tee(media_call_id, from_tag)
            .await
            .map(|()| None),
        MediaStep::DetachBridge {
            media_call_id,
            from_tag,
        } => backend
            .detach_ws_bridge(media_call_id, from_tag)
            .await
            .map(|()| None),
        MediaStep::DeleteSession {
            media_call_id,
            from_tag,
        } => backend.delete(media_call_id, from_tag).await.map(|()| None),
        MediaStep::Offer {
            media_call_id,
            from_tag,
            profile,
            sdp,
        }
        | MediaStep::Reoffer {
            media_call_id,
            from_tag,
            profile,
            sdp,
        } => {
            // A profile the registry no longer carries is a deployment this
            // build cannot serve, not a transport hiccup — refuse before the
            // engine is touched.
            let Some(flags) = profiles
                .and_then(|registry| registry.get(profile).map(|entry| entry.offer.clone()))
            else {
                return Err(BridgeError::Unsupported(format!(
                    "unknown media profile '{profile}' on the leg being bridged"
                )));
            };
            // `offer` on the fresh call-id the plan minted; `reoffer` on the
            // live relaying one. The plan decides which — never both, and never
            // an `offer` over something live.
            if matches!(step, MediaStep::Offer { .. }) {
                backend
                    .offer(media_call_id, from_tag, sdp, &flags)
                    .await
                    .map(Some)
            } else {
                backend
                    .reoffer(media_call_id, from_tag, sdp, &flags)
                    .await
                    .map(Some)
            }
        }
    };

    match outcome {
        Ok(sdp) => Ok(sdp),
        Err(error) => {
            let unsupported = matches!(
                error,
                crate::rtpengine::error::RtpEngineError::Unsupported { .. }
            );
            match classify_media_failure(
                step,
                error.is_call_not_found(),
                unsupported,
                &error.to_string(),
            ) {
                Some(refusal) => Err(refusal),
                None => {
                    debug!(?step, %error, "B2BUA bridge: tolerable media-step failure (nothing was attached)");
                    Ok(None)
                }
            }
        }
    }
}

/// Join two answered legs this process owns.
///
/// Returns as soon as the media has been re-pointed and the **first** re-INVITE
/// is on the wire. The bridge is not formed yet — that is a far-end outcome and
/// arrives as `ChannelBridged` (or `BridgeFailed`) once both legs have answered
/// their re-INVITE. Blocking here to "audio is flowing" would serialise the
/// caller's whole command stream behind two endpoints' re-INVITE round trips.
///
/// The media work, by contrast, **is** awaited before returning: an attachment
/// still live when the bridge forms is one-way audio, so the teardown is
/// confirmed rather than assumed (see [`crate::b2bua::bridge`]).
pub async fn b2bua_bridge_calls(
    params: BridgeParams,
) -> Result<BridgeAccepted, crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::{
        bridge_media_plan, set_media_direction, BridgeContext, BridgeError, BridgeRole,
        BridgeStage, MediaDirection,
    };

    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(BridgeError::Unavailable(
            "b2bua is not running — nothing to bridge".to_string(),
        ));
    };
    let state = &control.state;

    if params.anchor_sip_call_id == params.peer_sip_call_id {
        return Err(BridgeError::SameLeg(params.anchor_sip_call_id));
    }
    let anchor = bridge_leg_snapshot(state, &params.anchor_sip_call_id, "target")?;
    let peer = bridge_leg_snapshot(state, &params.peer_sip_call_id, "with")?;
    if anchor.internal_call_id == peer.internal_call_id {
        return Err(BridgeError::SameLeg(params.anchor_sip_call_id));
    }
    // The anchor is the leg that keeps its media session, and the target is it
    // — unless the target has no session and the other leg does. Anchoring on
    // the leg with nothing to keep would delete the only media session in the
    // bridge and quietly drop both parties out of the media path, which on a
    // deployment that anchors media (NAT, SRTP, recording, lawful intercept) is
    // a topology change nobody asked for. Swapping is deterministic and the
    // reply names which leg ended up the anchor.
    let (anchor, peer) = if anchor.media.is_none() && peer.media.is_some() {
        (peer, anchor)
    } else {
        (anchor, peer)
    };
    bridge_leg_validate(&anchor)?;
    bridge_leg_validate(&peer)?;

    // Claim both legs' re-INVITE slots before any media moves (RFC 3261 §14.1).
    // Take-and-set, so two `bridge` commands racing for the same leg cannot both
    // win — the loser gets a typed glare refusal, not a mangled media state.
    if state
        .call_actors
        .set_pending_reinvite(&anchor.internal_call_id, true, true)
    {
        return Err(BridgeError::Glare {
            id: anchor.sip_call_id,
        });
    }
    if state
        .call_actors
        .set_pending_reinvite(&peer.internal_call_id, true, true)
    {
        state
            .call_actors
            .set_pending_reinvite(&anchor.internal_call_id, true, false);
        return Err(BridgeError::Glare {
            id: peer.sip_call_id,
        });
    }

    let release_claims = || {
        state
            .call_actors
            .set_pending_reinvite(&anchor.internal_call_id, true, false);
        state
            .call_actors
            .set_pending_reinvite(&peer.internal_call_id, true, false);
    };

    // Media: every attachment off both legs, the sessions in the way deleted,
    // then the pair negotiated — on the anchor's live call-id when it already
    // relays, otherwise on this fresh one (see `bridge_media_plan`).
    let fresh_media_call_id = crate::b2bua::actor::generate_call_id();
    // The anchor endpoint's description, restated as siphon's own direction
    // (RFC 3264 §6.1). It matters on a re-bridge: after an unbridge the leg
    // answered our hold `recvonly`, and handing the engine that as the offerer's
    // current state would build a one-way relay out of a bridge.
    let anchor_sdp = set_media_direction(&anchor.last_sdp, MediaDirection::SendRecv);
    let plan = bridge_media_plan(
        anchor.media.as_ref(),
        peer.media.as_ref(),
        &anchor_sdp,
        &fresh_media_call_id,
    );
    let mut renegotiated: Option<Vec<u8>> = None;
    if !plan.is_empty() {
        let Some(backend) = state.rtpengine_set.clone() else {
            release_claims();
            return Err(BridgeError::Unavailable(
                "the legs are media-anchored but no media backend is configured".to_string(),
            ));
        };
        for step in &plan {
            match bridge_run_media_step(&backend, state.rtpengine_profiles.as_ref(), step).await {
                Ok(Some(sdp)) => renegotiated = Some(sdp),
                Ok(None) => {}
                Err(error) => {
                    release_claims();
                    return Err(error);
                }
            }
        }
    }

    if let Some(store) = state.rtpengine_sessions.as_ref() {
        // The peer's engine session is gone from the engine; drop the store
        // entry too, or a later media verb (or a re-INVITE response's answer
        // rewrite) would address a call-id the engine no longer has.
        if peer.media.is_some() {
            store.remove(&peer.sip_call_id);
        }
        // The anchor moved to a fresh engine call-id: re-key its entry to it.
        // The store key stays the leg's SIP Call-ID — that is what every media
        // verb and the teardown look up — and only the engine-facing id moves,
        // which is exactly what `rtpengine_call_id` is decoupled for. `ws_uri`
        // is deliberately not carried over: the tee died with the old call-id.
        let moved_to_fresh_id = anchor
            .media
            .as_ref()
            .is_some_and(|media| !media.relaying && renegotiated.is_some());
        if moved_to_fresh_id {
            if let Some(media) = anchor.media.as_ref() {
                store.insert(crate::rtpengine::session::MediaSession {
                    call_id: anchor.sip_call_id.clone(),
                    rtpengine_call_id: fresh_media_call_id.clone(),
                    from_tag: media.from_tag.clone(),
                    to_tag: None,
                    profile: media.profile.clone(),
                    ws_uri: None,
                    ws_tee: None,
                    ws_bridge_attached: false,
                    created_at: std::time::Instant::now(),
                });
            }
        }
    }

    // The offer that goes to the peer: the engine's own description when the
    // pair is anchored, otherwise the anchor endpoint's, restated as siphon's
    // own direction (RFC 3264 §6.1 — see `set_media_direction`).
    let anchored = anchor.media.is_some();
    let offer = renegotiated.unwrap_or(anchor_sdp);

    // Own the bridge before it is on the wire, the same two-phase rule
    // `originate` follows: a peer that answers instantly must not beat its own
    // bookkeeping, or its 200 arrives with no bridge to advance.
    let media_call_id = anchor.media.as_ref().map(|media| {
        if media.relaying {
            media.media_call_id.clone()
        } else {
            fresh_media_call_id.clone()
        }
    });
    state.call_actors.set_bridge(
        &anchor.internal_call_id,
        BridgeContext {
            peer_call_id: peer.internal_call_id.clone(),
            peer_sip_call_id: peer.sip_call_id.clone(),
            role: BridgeRole::Anchor,
            stage: BridgeStage::OfferingPeer,
            on_peer_hangup: params.on_peer_hangup,
            media_call_id: media_call_id.clone(),
            last_local_offer: Vec::new(),
            release_reason: None,
        },
    );
    state.call_actors.set_bridge(
        &peer.internal_call_id,
        BridgeContext {
            peer_call_id: anchor.internal_call_id.clone(),
            peer_sip_call_id: anchor.sip_call_id.clone(),
            role: BridgeRole::Peer,
            stage: BridgeStage::OfferingPeer,
            on_peer_hangup: params.on_peer_hangup,
            media_call_id,
            last_local_offer: offer.clone(),
            release_reason: None,
        },
    );

    if !b2bua_send_reinvite_on_leg(
        &peer.internal_call_id,
        true,
        offer,
        BRIDGE_TRACKING_OFFER,
        state,
    ) {
        state.call_actors.take_bridge(&anchor.internal_call_id);
        state.call_actors.take_bridge(&peer.internal_call_id);
        release_claims();
        return Err(BridgeError::Unavailable(
            "the leg vanished before its bridge re-INVITE could be sent".to_string(),
        ));
    }

    info!(
        anchor_call_id = %anchor.internal_call_id,
        peer_call_id = %peer.internal_call_id,
        anchored,
        "B2BUA bridge: media re-pointed, offering the peer leg"
    );
    Ok(BridgeAccepted {
        anchor_call_id: anchor.internal_call_id,
        anchor_sip_call_id: anchor.sip_call_id,
        peer_call_id: peer.internal_call_id,
        anchored,
    })
}

/// Tracking-leg target for the re-INVITE that offers the peer the anchor's
/// media. Distinct from the `reinvite:` prefix so a bridge step never runs
/// through the bridged-pair response arm, which assumes an originator leg to
/// forward the answer to — a bridged pair has none: both legs are A-legs of
/// their own call actor.
pub const BRIDGE_TRACKING_OFFER: &str = "bridge:offer";
/// Tracking-leg target for the re-INVITE that hands the anchor the peer's
/// answer.
pub const BRIDGE_TRACKING_ANSWER: &str = "bridge:answer";
/// Tracking-leg target for the hold re-INVITE an `unbridge` sends each leg.
pub const BRIDGE_TRACKING_RELEASE: &str = "bridge:release";

/// Break a bridge, leaving both legs answered and held.
///
/// Each leg falls back to exactly the state a freshly answered, unbridged leg
/// is in: up, owned by its controller, addressable, and held — siphon re-offers
/// it `a=sendonly` (RFC 3264 §8.4; RFC 6337 §3.1 prefers that over the
/// `c=0.0.0.0` of RFC 2543, and §5.1 warns against it), so the endpoint stops
/// sending and hears nothing. Neither leg is hung up: that would make
/// `unbridge` indistinguishable from two hangups and throw away the very state
/// the controller wanted to keep. A later `bridge` re-offers `sendrecv`.
pub async fn b2bua_unbridge_call(
    sip_call_id: &str,
    reason: &str,
) -> Result<(String, String), crate::b2bua::bridge::BridgeError> {
    use crate::b2bua::bridge::BridgeError;

    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(BridgeError::Unavailable(
            "b2bua is not running — nothing to unbridge".to_string(),
        ));
    };
    let state = &control.state;

    let internal_call_id = state
        .call_actors
        .find_by_sip_call_id(sip_call_id)
        .ok_or_else(|| BridgeError::UnknownLeg {
            which: "target",
            id: sip_call_id.to_string(),
        })?;
    let context =
        state
            .call_actors
            .bridge(&internal_call_id)
            .ok_or_else(|| BridgeError::NotBridged {
                id: sip_call_id.to_string(),
            })?;
    if context.stage.is_pending() {
        // The bridge is still forming — a re-INVITE is outstanding on both legs
        // and a hold offer now would collide with it (RFC 3261 §14.1).
        return Err(BridgeError::Glare {
            id: sip_call_id.to_string(),
        });
    }
    let peer_call_id = context.peer_call_id.clone();
    let peer_sip_call_id = context.peer_sip_call_id.clone();
    b2bua_bridge_release(&internal_call_id, &peer_call_id, reason, state);
    Ok((peer_call_id, peer_sip_call_id))
}

/// Hold both legs of a formed bridge and drop both halves of it.
///
/// Shared by the explicit `unbridge` and by the `hold` peer-hangup policy (which
/// calls it with only the survivor still present).
///
/// A leg with a hold to send keeps its half until the hold's own answer comes
/// back, so `ChannelUnbridged` means "parted **and** held" rather than "the hold
/// is on the wire". Without that a controller that re-bridges the moment it sees
/// the event races its own outstanding re-INVITE into an RFC 3261 §14.1 glare
/// refusal, with nothing on the rail to tell it when to try again.
pub fn b2bua_bridge_release(
    call_id: &str,
    peer_call_id: &str,
    reason: &str,
    state: &DispatcherState,
) {
    use crate::b2bua::bridge::{set_media_direction, BridgeStage, MediaDirection};

    for leg_call_id in [call_id, peer_call_id] {
        let Some(context) = state.call_actors.bridge(leg_call_id) else {
            continue;
        };
        let held_offer = (!context.last_local_offer.is_empty()
            && !state
                .call_actors
                .set_pending_reinvite(leg_call_id, true, true))
        .then(|| set_media_direction(&context.last_local_offer, MediaDirection::SendOnly));

        if let Some(held) = held_offer {
            if let Some(mut call) = state.call_actors.get_call_mut(leg_call_id) {
                if let Some(bridge) = call.bridge.as_mut() {
                    bridge.stage = BridgeStage::Releasing;
                    bridge.release_reason = Some(reason.to_string());
                }
            }
            if b2bua_send_reinvite_on_leg(leg_call_id, true, held, BRIDGE_TRACKING_RELEASE, state) {
                continue;
            }
            state
                .call_actors
                .set_pending_reinvite(leg_call_id, true, false);
        }
        // No hold went out (nothing to offer, a re-INVITE already outstanding,
        // or the send failed): the pairing is broken either way, so part it now
        // rather than leave a half nothing will ever clear.
        b2bua_bridge_finish_release(leg_call_id, reason, state);
    }
    info!(%call_id, %peer_call_id, %reason, "B2BUA bridge: releasing — both legs held");
}

/// Drop one leg's half of a bridge and tell its controller. Idempotent.
pub fn b2bua_bridge_finish_release(call_id: &str, reason: &str, state: &DispatcherState) {
    let Some(context) = state.call_actors.take_bridge(call_id) else {
        return;
    };
    let Some(sip_call_id) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())
    else {
        return;
    };
    control_notify_channel_event(
        &sip_call_id,
        "ChannelUnbridged",
        serde_json::json!({
            "peer_call_id": context.peer_call_id,
            "peer_sip_call_id": context.peer_sip_call_id,
            "reason": context.release_reason.as_deref().unwrap_or(reason),
        }),
    );
}

/// The bridge partner of a call that is going away.
///
/// Called from every teardown junction an *answered* call can reach. Clears
/// both halves before it acts, so terminating the survivor cannot bounce back
/// here and tear down the leg that started it.
pub fn b2bua_bridge_peer_left(sip_call_id: &str, state: &DispatcherState) {
    use crate::b2bua::bridge::PeerHangupPolicy;

    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return;
    };
    let Some(context) = state.call_actors.take_bridge(&internal_call_id) else {
        return;
    };
    let survivor = context.peer_call_id.clone();
    // The survivor's own half carries the policy that applies to *it*.
    let Some(survivor_context) = state.call_actors.take_bridge(&survivor) else {
        return;
    };
    match survivor_context.on_peer_hangup {
        PeerHangupPolicy::Hangup => {
            info!(
                %sip_call_id,
                survivor = %survivor,
                "B2BUA bridge: peer hung up — tearing the survivor down"
            );
            // Both halves are already taken, so the survivor's own teardown
            // re-enters this function and finds nothing — no bounce back to the
            // leg that started it.
            b2bua_terminate_call_inner(&survivor, None, "peer_hangup", state);
        }
        PeerHangupPolicy::Hold => {
            info!(
                %sip_call_id,
                survivor = %survivor,
                "B2BUA bridge: peer hung up — holding the survivor"
            );
            // Only the survivor is left to hold; its half was taken above, so
            // re-attach it for the release path to consume.
            state.call_actors.set_bridge(&survivor, survivor_context);
            b2bua_bridge_release(&survivor, &internal_call_id, "peer_hangup", state);
        }
    }
}

/// Handle a response to one of a bridge's own re-INVITEs.
///
/// The responder is always the call actor's A-leg — a bridged leg is the A-leg
/// of its own actor, whether it arrived as an INVITE or siphon placed it — so
/// there is no originator to forward the response to and no identity to rewrite.
/// The response is absorbed: it is ACKed (RFC 3261 §13.2.2.4 for a 2xx on a new
/// branch, §17.1.1.3 for a final non-2xx on the request's own branch) and drives
/// the bridge's next step.
pub fn handle_bridge_reinvite_response(
    call_id: &str,
    stage: &str,
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    a_leg: &Leg,
    b_leg_index: Option<usize>,
    state: &DispatcherState,
) {
    if status_code < 200 {
        return;
    }
    let success = (200..300).contains(&status_code);
    let ack_branch = if success {
        TransactionKey::generate_branch()
    } else {
        branch.to_string()
    };
    if let Some(ack) = build_ack_for_owned_leg(a_leg, message, &ack_branch, state) {
        let (destination, transport) = resolve_in_dialog_destination(
            &a_leg.dialog.route_set,
            state,
            a_leg.transport.remote_addr,
            a_leg.transport.transport,
        );
        send_message_from(
            ack,
            transport,
            destination,
            a_leg.transport.connection_id,
            a_leg.transport.local_addr,
            state,
        );
    }
    if let Some(index) = b_leg_index {
        if success {
            // Keep the entry so a retransmitted 200 is re-ACKed rather than
            // treated as a response to an unknown branch.
            state
                .call_actors
                .set_b_leg_target_uri(call_id, index, format!("bridge_done:{stage}"));
        } else {
            state.call_actors.remove_b_leg(call_id, index);
        }
    }
    state.call_actors.set_pending_reinvite(call_id, true, false);
    // A final response to a re-INVITE on the leg's dialog, which siphon sent: a
    // 2xx refreshes the session there when the dialog runs a session timer
    // (RFC 4028 §7.2).
    session_timer_on_response(
        call_id,
        true,
        branch,
        status_code,
        &message.headers,
        None,
        state,
    );

    match stage {
        // The hold offer an `unbridge` sent. The leg is only *parted* now that
        // its answer is in — that is what `ChannelUnbridged` reports, and it is
        // what makes an immediate re-bridge safe.
        "release" => b2bua_bridge_finish_release(call_id, "unbridged", state),
        "offer" => {
            if success {
                bridge_advance_to_anchor(call_id, message, state);
            } else {
                bridge_fail(call_id, "offering_peer", status_code, state);
            }
        }
        "answer" => {
            if success {
                bridge_complete(call_id, message, state);
            } else {
                bridge_fail(call_id, "offering_anchor", status_code, state);
            }
        }
        other => {
            warn!(%call_id, stage = %other, "B2BUA bridge: unknown re-INVITE stage");
        }
    }
}

/// The peer answered its bridge offer: fold that answer into the anchor's media
/// and re-INVITE the anchor with the result.
pub fn bridge_advance_to_anchor(
    peer_call_id: &str,
    response: &SipMessage,
    state: &DispatcherState,
) {
    use crate::b2bua::bridge::{set_media_direction, BridgeStage, MediaDirection};

    let Some(context) = state.call_actors.bridge(peer_call_id) else {
        return;
    };
    let anchor_call_id = context.peer_call_id.clone();
    if response.body.is_empty() {
        warn!(
            %peer_call_id,
            "B2BUA bridge: the peer answered its re-INVITE with no SDP — nothing to hand the anchor"
        );
        bridge_fail(peer_call_id, "offering_peer", 488, state);
        return;
    }
    let peer_answer_tag = crate::b2bua::actor::extract_to_tag(response)
        .or_else(|| {
            state
                .call_actors
                .get_call(peer_call_id)
                .and_then(|call| call.a_leg.dialog.remote_tag.clone())
        })
        .unwrap_or_default();
    state
        .call_actors
        .set_leg_last_sdp(peer_call_id, true, &response.body);

    // Anchored: complete the offer/answer on the anchor's live engine call, so
    // the pair now relays through the ports the anchor already held. Raw: cross
    // the peer's own description, restated as siphon's direction.
    let sdp_for_anchor = match (&context.media_call_id, state.rtpengine_set.as_ref()) {
        (Some(media_call_id), Some(backend)) => {
            let anchor_media = state
                .call_actors
                .get_call(&anchor_call_id)
                .map(|call| call.a_leg.dialog.call_id.clone())
                .and_then(|key| {
                    state
                        .rtpengine_sessions
                        .as_ref()
                        .and_then(|store| store.get(&key).map(|session| (key, session)))
                });
            let Some((anchor_key, session)) = anchor_media else {
                warn!(%anchor_call_id, "B2BUA bridge: the anchor's media session vanished mid-bridge");
                bridge_fail(peer_call_id, "offering_peer", 500, state);
                return;
            };
            let flags = state.rtpengine_profiles.as_ref().and_then(|registry| {
                registry
                    .get(&session.profile)
                    .map(|entry| entry.answer.clone())
            });
            let Some(flags) = flags else {
                warn!(profile = %session.profile, "B2BUA bridge: unknown media profile on the anchor");
                bridge_fail(peer_call_id, "offering_peer", 500, state);
                return;
            };
            // Address the engine by the session's own id, not the context's
            // copy: they agree, and the store is the one that stays right if a
            // re-anchor ever moves it again.
            debug_assert_eq!(session.rtpengine_id(), media_call_id);
            let answered = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(backend.answer(
                    session.rtpengine_id(),
                    &session.from_tag,
                    &peer_answer_tag,
                    &response.body,
                    &flags,
                ))
            });
            match answered {
                Ok(sdp) => {
                    // The pair is now two-sided on the engine; record the peer
                    // as the answerer so a later hold / re-INVITE addresses the
                    // right monologue.
                    if let Some(store) = state.rtpengine_sessions.as_ref() {
                        store.set_to_tag(&anchor_key, peer_answer_tag.clone());
                    }
                    sdp
                }
                Err(error) => {
                    warn!(%anchor_call_id, %error, "B2BUA bridge: the engine refused the peer's answer");
                    bridge_fail(peer_call_id, "offering_peer", 488, state);
                    return;
                }
            }
        }
        _ => set_media_direction(&response.body, MediaDirection::SendRecv),
    };

    state
        .call_actors
        .set_bridge_stage(peer_call_id, BridgeStage::OfferingAnchor);
    state
        .call_actors
        .set_bridge_stage(&anchor_call_id, BridgeStage::OfferingAnchor);
    if let Some(mut call) = state.call_actors.get_call_mut(&anchor_call_id) {
        if let Some(bridge) = call.bridge.as_mut() {
            bridge.last_local_offer = sdp_for_anchor.clone();
        }
    }

    if !b2bua_send_reinvite_on_leg(
        &anchor_call_id,
        true,
        sdp_for_anchor,
        BRIDGE_TRACKING_ANSWER,
        state,
    ) {
        bridge_fail(peer_call_id, "offering_anchor", 500, state);
    }
}

/// Both legs have renegotiated — the media meets.
pub fn bridge_complete(anchor_call_id: &str, response: &SipMessage, state: &DispatcherState) {
    use crate::b2bua::bridge::BridgeStage;

    if !response.body.is_empty() {
        state
            .call_actors
            .set_leg_last_sdp(anchor_call_id, true, &response.body);
    }
    let Some(context) = state.call_actors.bridge(anchor_call_id) else {
        return;
    };
    let peer_call_id = context.peer_call_id.clone();
    state
        .call_actors
        .set_bridge_stage(anchor_call_id, BridgeStage::Bridged);
    state
        .call_actors
        .set_bridge_stage(&peer_call_id, BridgeStage::Bridged);
    // The peer's slot was released when its own re-INVITE settled; the anchor's
    // is released by the caller of this function.
    let anchor_sip_call_id = state
        .call_actors
        .get_call(anchor_call_id)
        .map(|call| call.a_leg.dialog.call_id.clone());
    let anchored = context.media_call_id.is_some();
    if let Some(anchor_sip_call_id) = anchor_sip_call_id {
        control_notify_channel_event(
            &anchor_sip_call_id,
            "ChannelBridged",
            serde_json::json!({
                "peer_call_id": peer_call_id,
                "peer_sip_call_id": context.peer_sip_call_id,
                "role": "anchor",
                "anchored": anchored,
            }),
        );
        control_notify_channel_event(
            &context.peer_sip_call_id,
            "ChannelBridged",
            serde_json::json!({
                "peer_call_id": anchor_call_id,
                "peer_sip_call_id": anchor_sip_call_id,
                "role": "peer",
                "anchored": anchored,
            }),
        );
    }
    info!(%anchor_call_id, %peer_call_id, anchored, "B2BUA bridge: formed — media meets");
}

/// A bridge step was refused. Drop both halves, release both re-INVITE slots and
/// tell the controller which stage failed and with what — never a silent
/// half-bridge, and never a teardown of calls the controller still owns.
pub fn bridge_fail(call_id: &str, stage: &str, status_code: u16, state: &DispatcherState) {
    let Some(context) = state.call_actors.take_bridge(call_id) else {
        return;
    };
    let peer_call_id = context.peer_call_id.clone();
    state.call_actors.take_bridge(&peer_call_id);
    state
        .call_actors
        .set_pending_reinvite(&peer_call_id, true, false);
    let sip_call_id = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone());
    let payload = serde_json::json!({
        "stage": stage,
        "code": status_code,
        "peer_sip_call_id": context.peer_sip_call_id,
    });
    if let Some(sip_call_id) = sip_call_id.as_deref() {
        control_notify_channel_event(sip_call_id, "BridgeFailed", payload.clone());
    }
    control_notify_channel_event(&context.peer_sip_call_id, "BridgeFailed", payload);
    warn!(
        %call_id,
        %peer_call_id,
        %stage,
        status = status_code,
        "B2BUA bridge: failed — both legs left as they were"
    );
}
