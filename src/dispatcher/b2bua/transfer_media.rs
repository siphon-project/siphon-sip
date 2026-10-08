//! The media engine's half of a transfer: offering the surviving party onto a
//! fresh engine call and completing it with the new party's answer.
//!
//! ## Whose policy pins which party's media ingress
//!
//! The fresh engine call has no hint from before, so each command carries the
//! `received_from` hint of the party whose SDP it holds: where that party's
//! signalling comes from, which is where its media comes from when the
//! address in its SDP is not (a party behind NAT). Without it the engine
//! gates that party on the address in its SDP and the call is silent.
//!
//! Whether a party is pinned is its own policy's decision, not that of the
//! flags that shape the command, which are for the other party
//! ([`RepairedIngress`]):
//!
//! * A profile **named** for the transfer describes the pair it creates the
//!   way a dial's profile does: its `offer` half is the one the offered SDP is
//!   sent under, its `answer` half the answering party's.
//! * With none named the call's own profile is **inherited**, and it was
//!   written for the pair the call started as. The surviving party keeps what
//!   it was set up under (the caller the `offer` half, the callee the `answer`
//!   half), whichever command its SDP rides now, and the new party takes the
//!   place, and so the policy, of the party it replaces.
use crate::dispatcher::*;
use crate::rtpengine::session::{BridgeSides, MediaSession, ProfileHalf, SideFlags};

/// The party whose SDP an engine command carries: where it signals from, and
/// whose `received_from` policy decides whether its media ingress is pinned
/// there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyIngress {
    /// Where the party's signalling comes from.
    pub source: std::net::IpAddr,
    /// Whose policy asks for the pin. The party's own, never that of the
    /// profile half that shapes the command.
    pub policy: SideFlags,
}

/// Whose `received_from` policies pin the two parties a transfer pairs on a
/// fresh engine call. See the module docs for which is which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedIngress {
    /// The party that stays in the call.
    pub survivor: SideFlags,
    /// The party that joins it: a replacement's target, or the newcomer of a
    /// `Replaces` takeover.
    pub joining: SideFlags,
}

impl RepairedIngress {
    /// The policies for the pair re-anchored from `anchor`, the session the
    /// call was on, under the profile `named` for it when there is one.
    ///
    /// `survivor_tag` is the surviving party's engine tag on `anchor`, which
    /// is how its own policy is found there. `survivor_offers` says whose SDP
    /// the fresh call's `offer` carries: the survivor's on a leg replacement,
    /// the newcomer's on a takeover.
    pub fn of(
        named: Option<&str>,
        anchor: &MediaSession,
        survivor_tag: &str,
        survivor_offers: bool,
    ) -> Self {
        match named {
            Some(profile) => {
                let half = |half| SideFlags {
                    profile: profile.to_string(),
                    half,
                };
                let (survivor, joining) = if survivor_offers {
                    (ProfileHalf::Offer, ProfileHalf::Answer)
                } else {
                    (ProfileHalf::Answer, ProfileHalf::Offer)
                };
                RepairedIngress {
                    survivor: half(survivor),
                    joining: half(joining),
                }
            }
            None => {
                let survivor_on_from_tag = anchor.from_tag == survivor_tag;
                RepairedIngress {
                    survivor: anchor.party_ingress(survivor_on_from_tag),
                    joining: anchor.party_ingress(!survivor_on_from_tag),
                }
            }
        }
    }

    /// What the re-anchored pair's session records per party, so a later
    /// re-pairing of the same call still reads each party's own policy.
    ///
    /// That session names the party in the call's A-leg slot on its
    /// `from_tag` and the other on its `to_tag`: `joiner_on_from_tag` says the
    /// joining party is the one in the A-leg slot (it replaced the caller, or
    /// took over), otherwise the survivor is. `profile` is the one the pair
    /// was shaped with, and `joiner_offered` says whether the joining party's
    /// SDP was the fresh call's `offer`: the party whose SDP is offered is
    /// sent the `answer` half's result, the other one the `offer` half's.
    pub fn sides(
        &self,
        profile: &str,
        joiner_on_from_tag: bool,
        joiner_offered: bool,
    ) -> BridgeSides {
        let half = |half| SideFlags {
            profile: profile.to_string(),
            half,
        };
        let (joining, survivor) = if joiner_offered {
            (ProfileHalf::Answer, ProfileHalf::Offer)
        } else {
            (ProfileHalf::Offer, ProfileHalf::Answer)
        };
        if joiner_on_from_tag {
            BridgeSides {
                anchor: half(joining),
                peer: half(survivor),
                anchor_ingress: self.joining.clone(),
                peer_ingress: self.survivor.clone(),
            }
        } else {
            BridgeSides {
                anchor: half(survivor),
                peer: half(joining),
                anchor_ingress: self.survivor.clone(),
                peer_ingress: self.joining.clone(),
            }
        }
    }
}

/// The media session a `Replaces` takeover leaves the pair on, keyed on the
/// newcomer's Call-ID `cid_new`.
///
/// `own` is the session the script opened when it anchored the taking-over
/// INVITE, which now gains its other party and keeps everything else it was
/// opened with. With none, the takeover anchored the newcomer itself on a
/// fresh engine call named by `cid_new`, under `new_tag` and `profile`.
pub fn takeover_session(
    own: Option<MediaSession>,
    cid_new: &str,
    new_tag: &str,
    survivor_tag: &str,
    profile: &str,
    bridge_sides: Option<BridgeSides>,
) -> MediaSession {
    match own {
        Some(own) => MediaSession {
            to_tag: Some(survivor_tag.to_string()),
            bridge_sides,
            ..own
        },
        None => MediaSession {
            call_id: cid_new.to_string(),
            rtpengine_call_id: cid_new.to_string(),
            from_tag: new_tag.to_string(),
            to_tag: Some(survivor_tag.to_string()),
            profile: profile.to_string(),
            // A fresh engine call-id: any WebSocket bridge the old anchor
            // held belonged to the call-id that just went away.
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides,
            created_at: std::time::Instant::now(),
        },
    }
}

/// Pin the party `flags` carry the SDP of to its signalling source, where its
/// own policy asks for it. With no `ingress` the flags are left as they are.
fn stamp_party_ingress(
    flags: &mut crate::rtpengine::profile::NgFlags,
    profiles: &crate::rtpengine::ProfileRegistry,
    ingress: Option<&PartyIngress>,
) {
    if let Some(ingress) = ingress {
        flags.carry_received_from = ingress.policy.pins_ingress(profiles);
        flags.stamp_received_from(ingress.source);
    }
}

/// rtpengine `offer` for a siphon-terminated transfer (Phase 1): anchor the
/// survivor's media (`survivor_sdp`, offered under `survivor_tag`) on the FRESH
/// rtpengine call-id `cid_new` using `profile_name`'s offer flags, and return
/// the SDP to place in the transfer target's INVITE. `None` if media control is
/// not configured or the offer failed (the caller then dials with the survivor's
/// raw SDP). Awaited with the same `block_in_place` idiom as the bridged
/// re-INVITE path. `offerer_sip_call_id` is the Call-ID of the dialog the
/// offered SDP belongs to, and `ingress` the party it belongs to: the offer is
/// pinned to that party's signalling source where its own policy asks for it.
pub fn b2bua_transfer_rtpengine_offer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    survivor_sdp: &[u8],
    offerer_sip_call_id: &str,
    profile_name: &str,
    ingress: Option<&PartyIngress>,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let profile = profiles.get(profile_name)?;
    let mut offer_flags = profile.offer.clone();
    stamp_party_ingress(&mut offer_flags, profiles, ingress);
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
/// answer SDP belongs to, and `ingress` the party it belongs to: the answer is
/// pinned to that party's signalling source where its own policy asks for it.
///
/// `shape` is what shapes the result, which goes to the offerer: the `answer`
/// half of the pair's profile when the offerer is the party a dial's `answer`
/// half describes, and for a delayed offer, whose offerer is the callee, the
/// `offer` half.
#[allow(clippy::too_many_arguments)]
pub fn b2bua_transfer_rtpengine_answer(
    state: &DispatcherState,
    cid_new: &str,
    survivor_tag: &str,
    target_tag: &str,
    target_sdp: &[u8],
    answerer_sip_call_id: &str,
    shape: &SideFlags,
    ingress: Option<&PartyIngress>,
) -> Option<Vec<u8>> {
    let backend = state.rtpengine_set.as_ref()?;
    let profiles = state.rtpengine_profiles.as_ref()?;
    let mut answer_flags = shape.resolve(profiles)?;
    stamp_party_ingress(&mut answer_flags, profiles, ingress);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn side(profile: &str, half: ProfileHalf) -> SideFlags {
        SideFlags {
            profile: profile.to_string(),
            half,
        }
    }

    /// A relay one dial set up under `dialled`: the caller on `caller-tag`
    /// offered, the callee on `callee-tag` answered.
    fn dialled_pair() -> MediaSession {
        MediaSession {
            call_id: "caller-dialog@192.0.2.10".to_string(),
            rtpengine_call_id: String::new(),
            from_tag: "caller-tag".to_string(),
            to_tag: Some("callee-tag".to_string()),
            profile: "dialled".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: std::time::Instant::now(),
        }
    }

    #[test]
    fn an_inherited_profile_keeps_the_survivors_half_and_gives_the_joiner_the_replaced_partys() {
        // The callee is replaced: the caller keeps its `offer` half.
        let kept_caller = RepairedIngress::of(None, &dialled_pair(), "caller-tag", true);
        assert_eq!(kept_caller.survivor, side("dialled", ProfileHalf::Offer));
        assert_eq!(kept_caller.joining, side("dialled", ProfileHalf::Answer));
        // The caller is replaced: the callee keeps its `answer` half, though
        // its SDP is now the one offered.
        let kept_callee = RepairedIngress::of(None, &dialled_pair(), "callee-tag", true);
        assert_eq!(kept_callee.survivor, side("dialled", ProfileHalf::Answer));
        assert_eq!(kept_callee.joining, side("dialled", ProfileHalf::Offer));
        // Which command carries whose SDP does not change whose policy it is.
        assert_eq!(
            RepairedIngress::of(None, &dialled_pair(), "caller-tag", false),
            kept_caller
        );
    }

    #[test]
    fn a_named_profile_describes_the_pair_it_creates_as_a_dial_would() {
        let offered = RepairedIngress::of(Some("named"), &dialled_pair(), "callee-tag", true);
        assert_eq!(offered.survivor, side("named", ProfileHalf::Offer));
        assert_eq!(offered.joining, side("named", ProfileHalf::Answer));
        let answering = RepairedIngress::of(Some("named"), &dialled_pair(), "callee-tag", false);
        assert_eq!(answering.survivor, side("named", ProfileHalf::Answer));
        assert_eq!(answering.joining, side("named", ProfileHalf::Offer));
    }

    #[test]
    fn the_recorded_sides_name_each_partys_policy_by_the_tag_it_sits_on() {
        let ingress = RepairedIngress {
            survivor: side("dialled", ProfileHalf::Offer),
            joining: side("dialled", ProfileHalf::Answer),
        };
        // A replacement of the caller stores the target on `from_tag`, and
        // the target answered: it was sent the `offer` half's result.
        let replaced = ingress.sides("shaped", true, false);
        assert_eq!(replaced.anchor, side("shaped", ProfileHalf::Offer));
        assert_eq!(replaced.peer, side("shaped", ProfileHalf::Answer));
        assert_eq!(replaced.anchor_ingress, ingress.joining);
        assert_eq!(replaced.peer_ingress, ingress.survivor);
        // A replacement of the callee leaves the surviving caller on
        // `from_tag`: the same two parties, the other way round.
        let callee_replaced = ingress.sides("shaped", false, false);
        assert_eq!(callee_replaced.anchor, side("shaped", ProfileHalf::Answer));
        assert_eq!(callee_replaced.peer, side("shaped", ProfileHalf::Offer));
        assert_eq!(callee_replaced.anchor_ingress, ingress.survivor);
        assert_eq!(callee_replaced.peer_ingress, ingress.joining);
        // A takeover stores the newcomer on `from_tag`, and the newcomer
        // offered: it was sent the `answer` half's result.
        let taken_over = ingress.sides("shaped", true, true);
        assert_eq!(taken_over.anchor, side("shaped", ProfileHalf::Answer));
        assert_eq!(taken_over.peer, side("shaped", ProfileHalf::Offer));
        assert_eq!(taken_over.anchor_ingress, ingress.joining);
        assert_eq!(taken_over.peer_ingress, ingress.survivor);

        // Read back off a session, the next re-pairing finds each party's own.
        let session = MediaSession {
            from_tag: "target-tag".to_string(),
            to_tag: Some("caller-tag".to_string()),
            profile: "shaped".to_string(),
            bridge_sides: Some(replaced),
            ..dialled_pair()
        };
        let next = RepairedIngress::of(None, &session, "caller-tag", true);
        assert_eq!(next.survivor, ingress.survivor);
        assert_eq!(next.joining, ingress.joining);
    }
}
