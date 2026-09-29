//! Bridging two answered legs this process already owns.
//!
//! A *bridge* joins two confirmed dialogs — a parked inbound call and a call
//! siphon placed (`originate`), two originated calls, whatever the controller
//! owns — so the two parties hear each other. It is the primitive behind a
//! callback-and-connect, an attended hand-off, and a controller-driven
//! transfer.
//!
//! ## Why both legs get re-offered, and in that order
//!
//! siphon is a B2BUA: each leg is its own offer/answer context (RFC 3264 §8),
//! and siphon is the offerer on both. Neither party ever offers to the other —
//! the parties never share a dialog. So a bridge is two RFC 3261 §14 re-INVITEs
//! run back to back:
//!
//! 1. the **peer** leg is re-INVITEd with the anchor leg's current media
//!    description, and
//! 2. the **anchor** leg is re-INVITEd with the answer that came back.
//!
//! The peer goes first because that is the order in which a failure costs the
//! least: a peer that answers `488`/`491` leaves the anchor leg untouched and
//! the two calls exactly as they were. Doing it the other way round would
//! re-point a leg at media the second party then refused.
//!
//! The *anchor* is the leg the verb is addressed to (`bridge` target), and it
//! is the leg that keeps its media session — its ports, its recording fork,
//! anything still riding on it. The peer's own media session is deleted once
//! the bridge forms; the peer joins the anchor's as the second party.
//!
//! ## Re-negotiation, not replacement
//!
//! An anchor that is **already relaying between two parties** is renegotiated
//! with `reoffer` ([`MediaStep::Reoffer`]) on the call-id it already holds,
//! never a repeat `offer`. On the native backend a repeat offer on a live
//! call-id is a *replacement*: it frees the ports and drops everything attached
//! to them, and hands the peer an address it was never told about.
//! [`crate::rtpengine::MediaBackend::reoffer`] is the verb that keeps them. That
//! is the re-bridge path — a pair that was bridged, unbridged, and joined again.
//!
//! An anchor the engine answered **itself** is a different shape and cannot be
//! renegotiated into a relay: `answer_local` leaves the session with one party
//! and the engine as the far side, and the engine refuses an `answer` on it
//! ("no far leg to answer") rather than pointing the new party at the caller's
//! own endpoint. Every leg a controller owns starts that way — an answer-first
//! handover and an `originate(media=true)` both answer locally — so the bridge
//! `offer`s the pair onto a **fresh** engine call-id ([`MediaStep::Offer`]).
//! That is not the replacement bug above: nothing live is being offered over.
//!
//! ## Nothing is taken away until the peer has said yes
//!
//! The fresh session is built *beside* the two single-party sessions, not in
//! place of them. Both stay on the engine, and the anchor's store entry keeps
//! pointing at its own, until the bridge forms: only then are the two old
//! sessions deleted and the anchor's entry moved to the fresh call-id (the
//! store key stays the leg's SIP Call-ID, so every media verb still resolves).
//! A peer that answers the bridge offer `488` therefore leaves the caller
//! exactly as it was — its media, its prompts, its ringback all still work —
//! and the fresh session, which only ever had one party, is deleted.
//!
//! ## Which profile shapes which leg
//!
//! The engine's `offer` produces the SDP the **peer** is offered, and its
//! `answer` the SDP the **anchor** is re-INVITEd with, so the two halves of a
//! media profile land on different parties. A bridge given a *pair* profile
//! uses its `offer` half for the peer and its `answer` half for the anchor —
//! the way one profile describes both parties of an ordinary dial. With none,
//! each party is shaped by the profile it was anchored with: the peer's for
//! the offer (an SRTP phone rung with an SRTP profile is offered SRTP), the
//! anchor's for the answer (a caller answered with plain RTP is re-INVITEd with
//! plain RTP). See [`bridge_offer_profile`].
//!
//! ## Attachments come off first, and the teardown is confirmed
//!
//! An announcement still playing on a leg *replaces that leg's outgoing audio*,
//! and a WebSocket bridge makes the engine the far side of it. Either one still
//! live when the bridge forms is one-way audio. So every attachment is torn
//! down before the media is re-pointed, each step awaited and its reply
//! checked — [`bridge_media_plan`] fixes the order, and a step the backend
//! refuses fails the bridge rather than forming half of one.
//!
//! Each teardown runs only where there is something to tear down: the detach
//! where a tee is attached, the stop where siphon started a playback. Firing
//! them blind is not free — the engine answers a stop on an idle leg by
//! *rejecting* it, into the same counter that means "siphon sent something the
//! engine refused".

use std::fmt;
use std::net::IpAddr;

/// Which side of a bridge a leg is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeRole {
    /// The leg the `bridge` was addressed to. Keeps its media session — its
    /// ports and everything attached to them survive the bridge.
    Anchor,
    /// The leg named by `with`. It joins the anchor's media session as the
    /// second party, and its own session is deleted once the bridge forms.
    Peer,
}

impl BridgeRole {
    /// The wire/log token.
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeRole::Anchor => "anchor",
            BridgeRole::Peer => "peer",
        }
    }
}

/// How far a bridge has got. A bridge is two re-INVITEs, so it is not complete
/// until both have been answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeStage {
    /// The peer leg has been re-INVITEd with the anchor's media; waiting for
    /// its answer.
    OfferingPeer,
    /// The peer answered; the anchor leg has been re-INVITEd with that answer,
    /// waiting for its 2xx.
    OfferingAnchor,
    /// Both legs renegotiated — the media meets.
    Bridged,
    /// Being parted: the hold offer is out and its answer is outstanding. The
    /// half is kept until then so `ChannelUnbridged` can mean "this leg is
    /// parted **and** held" — which is what lets a controller bridge it again
    /// straight away instead of racing the hold's own re-INVITE into an
    /// RFC 3261 §14.1 glare refusal.
    Releasing,
}

impl BridgeStage {
    /// The wire/log token.
    pub fn as_str(&self) -> &'static str {
        match self {
            BridgeStage::OfferingPeer => "offering_peer",
            BridgeStage::OfferingAnchor => "offering_anchor",
            BridgeStage::Bridged => "bridged",
            BridgeStage::Releasing => "releasing",
        }
    }

    /// Whether the bridge is still forming (a re-INVITE is outstanding).
    pub fn is_pending(&self) -> bool {
        !matches!(self, BridgeStage::Bridged)
    }
}

/// What happens to the surviving leg when its bridge partner hangs up.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PeerHangupPolicy {
    /// Tear the survivor down too (the default): a bridged pair behaves like
    /// one call, so when one party leaves the other has nobody to talk to.
    #[default]
    Hangup,
    /// Keep the survivor up and held (RFC 3264 §8.4), still owned and still
    /// addressable, so the controller can bridge it to somebody else. The
    /// supervisor / attended-hand-off case.
    Hold,
}

impl PeerHangupPolicy {
    /// Parse the control-plane / script argument. `None` for an unrecognised
    /// value — guessing at a teardown policy is how calls get stranded.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "hangup" => Some(PeerHangupPolicy::Hangup),
            "hold" => Some(PeerHangupPolicy::Hold),
            _ => None,
        }
    }

    /// The wire token.
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerHangupPolicy::Hangup => "hangup",
            PeerHangupPolicy::Hold => "hold",
        }
    }
}

/// One half of a bridge, stored on each of the two call actors so either side's
/// teardown finds the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeContext {
    /// The internal `CallActor` id of the leg on the other side.
    pub peer_call_id: String,
    /// The peer leg's SIP Call-ID — the control-plane / CDR join key, kept here
    /// so a teardown can name the peer without a second store lookup.
    pub peer_sip_call_id: String,
    /// Which side this leg is.
    pub role: BridgeRole,
    /// How far the bridge has got.
    pub stage: BridgeStage,
    /// What happens to this leg when the peer hangs up.
    pub on_peer_hangup: PeerHangupPolicy,
    /// The media-engine call-id the bridged pair lives on (the anchor leg's),
    /// when the bridge is anchored. `None` for a raw SDP crossing.
    pub media_call_id: Option<String>,
    /// The anchor's engine tag on [`BridgeContext::media_call_id`], kept here
    /// because the session on a fresh call-id is in no store entry until the
    /// bridge forms, and a failure or a hangup before then has to delete it.
    pub media_from_tag: Option<String>,
    /// The profile whose `answer` half shapes the SDP the anchor is re-INVITEd
    /// with, and which the pair's session carries once formed: the bridge's
    /// pair profile when it was given one, the anchor's own otherwise.
    pub media_profile: Option<String>,
    /// The profile whose `offer` half shaped what the peer was offered
    /// ([`bridge_offer_profile`]). With [`BridgeContext::media_profile`] it is
    /// what the pair's session records per side once formed, so a re-offer
    /// relayed to either party later is shaped the way that party was bridged.
    pub media_peer_profile: Option<String>,
    /// Whether [`BridgeContext::media_call_id`] is a fresh session the anchor's
    /// store entry does not point at yet. It is adopted — the two single-party
    /// sessions deleted, the anchor's entry moved to it — when the bridge
    /// forms, and deleted when the bridge fails or a leg hangs up first.
    pub media_pending_adoption: bool,
    /// The SDP siphon last **offered this leg**, kept because an unbridge has to
    /// re-offer the same media held (RFC 3264 §8.4) and the leg's own
    /// description is the far party's, not siphon's — offering it back would
    /// point the endpoint's RTP at itself.
    pub last_local_offer: Vec<u8>,
    /// Why the pair is being parted, carried from the `unbridge` (or the
    /// peer-hangup policy) to the `ChannelUnbridged` the hold's answer emits.
    /// `None` until the half enters [`BridgeStage::Releasing`].
    pub release_reason: Option<String>,
}

/// Why a bridge (or unbridge) was refused. Each variant maps to its own
/// control-plane error code — a caller must be able to tell "no such leg" from
/// "that leg has not answered" from "you named the same leg twice" from "this
/// backend cannot do it".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// No such leg (unknown channel, or the call is already gone).
    UnknownLeg {
        /// Which side the caller named.
        which: &'static str,
        /// The identifier that resolved to nothing.
        id: String,
    },
    /// The same leg was named on both sides.
    SameLeg(String),
    /// The leg exists but has not answered. A bridge renegotiates two
    /// *confirmed* dialogs (RFC 3261 §14 defines the re-INVITE only inside
    /// one), so an unanswered leg is refused rather than waited on — the
    /// controller gets `answered` as an event and can bridge then.
    NotAnswered {
        /// The leg that is in the wrong state.
        id: String,
        /// Its current state.
        state: String,
    },
    /// The leg is already part of a bridge.
    AlreadyBridged {
        /// The leg that is already bridged.
        id: String,
    },
    /// The leg is not bridged (an `unbridge` of a leg that never was).
    NotBridged {
        /// The leg named.
        id: String,
    },
    /// A re-INVITE is already outstanding on that leg, so a second offer/answer
    /// exchange would leave the media state undefined (RFC 3261 §14.1). The
    /// caller retries; siphon does not guess when.
    Glare {
        /// The leg with the outstanding transaction.
        id: String,
    },
    /// The leg carries no media description to cross, so there is nothing to
    /// bridge it with.
    NoMediaDescription {
        /// The leg with no SDP.
        id: String,
    },
    /// The configured media backend refused one of the bridge's media steps.
    Unsupported(String),
    /// The dispatcher is not running, or the media backend failed.
    Unavailable(String),
}

impl BridgeError {
    /// The stable machine-readable token for this refusal.
    ///
    /// One token per cause, shared by both rails: the control adapter renders it
    /// as the reply's `error.code`, and the in-process primitive prefixes its
    /// `ValueError` with it — so "you named the same leg twice" never reads the
    /// same as "that leg has not answered" on either.
    pub fn code(&self) -> &'static str {
        match self {
            BridgeError::UnknownLeg { .. } => "not_found",
            BridgeError::SameLeg(_) => "bad_request",
            BridgeError::NotAnswered { .. }
            | BridgeError::AlreadyBridged { .. }
            | BridgeError::NotBridged { .. }
            | BridgeError::Glare { .. }
            | BridgeError::NoMediaDescription { .. } => "invalid_state",
            BridgeError::Unsupported(_) => "unsupported_verb",
            BridgeError::Unavailable(_) => "unavailable",
        }
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BridgeError::UnknownLeg { which, id } => {
                write!(formatter, "no such {which} leg '{id}' — it is unknown or already gone")
            }
            BridgeError::SameLeg(id) => write!(
                formatter,
                "cannot bridge leg '{id}' to itself — name two different legs"
            ),
            BridgeError::NotAnswered { id, state } => write!(
                formatter,
                "leg '{id}' is {state}, not answered — a bridge renegotiates two confirmed \
                 dialogs, so wait for its answered event and bridge then"
            ),
            BridgeError::AlreadyBridged { id } => {
                write!(formatter, "leg '{id}' is already bridged — unbridge it first")
            }
            BridgeError::NotBridged { id } => {
                write!(formatter, "leg '{id}' is not bridged")
            }
            BridgeError::Glare { id } => write!(
                formatter,
                "leg '{id}' already has a re-INVITE outstanding (RFC 3261 §14.1) — retry once it settles"
            ),
            BridgeError::NoMediaDescription { id } => write!(
                formatter,
                "leg '{id}' carries no media description to bridge"
            ),
            BridgeError::Unsupported(detail) => write!(formatter, "{detail}"),
            BridgeError::Unavailable(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// The media-engine facts about one leg that the bridge needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegMedia {
    /// The engine call-id this leg's media lives on.
    pub media_call_id: String,
    /// The endpoint's tag — the engine keys the leg's monologue on the offerer's
    /// tag, which for every anchor siphon creates is the far party's.
    pub from_tag: String,
    /// The media profile the session was established with.
    pub profile: String,
    /// Whether the session already relays between **two** parties. A session the
    /// engine answered itself (`answer_local`) has one, and cannot be
    /// renegotiated into a relay — see the module docs.
    pub relaying: bool,
    /// Whether a WebSocket **tee** is attached to this session. The detach only
    /// runs when there is one: a backend that cannot hold a tee, or a session
    /// that never had one, has nothing to confirm.
    pub has_tee: bool,
    /// Whether a WebSocket **takeover bridge** was attached to this session
    /// mid-call and is therefore detachable.
    ///
    /// Tracked apart from [`LegMedia::has_tee`] because the two need different
    /// verbs and the wrong one *succeeds*: `detach_ws_tee` on a leg holding a
    /// takeover answers ok (it is idempotent), so a conflated flag would let
    /// the plan renegotiate a media path the WebSocket server still owns.
    ///
    /// A bridge negotiated through the profile's `ws_uri` is not counted here:
    /// it cannot be detached, and it does not need to be — such a session is
    /// not `relaying`, so the plan already deletes it and offers the leg onto a
    /// fresh call-id, which ends the bridge with it.
    pub has_ws_bridge: bool,
    /// Whether siphon started a playback on this leg and has not stopped it.
    /// The stop only runs when it did: on an idle leg the engine answers
    /// "this call has no active media playback", and it counts that answer as a
    /// rejected command in the counter operators alert on.
    pub has_playback: bool,
}

/// One step of the media work a bridge performs, in the order
/// [`bridge_media_plan`] emits them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaStep {
    /// Stop whatever announcement is playing on this leg. A prompt *replaces*
    /// the leg's outgoing audio, so one still running when the bridge forms is
    /// audible to the other party instead of the caller.
    StopPlayback {
        /// Engine call-id.
        media_call_id: String,
        /// The leg's engine tag.
        from_tag: String,
    },
    /// Detach this leg's WebSocket tee. Ordered after the playback stop so the
    /// tee is not torn down mid-prompt.
    DetachTee {
        /// Engine call-id.
        media_call_id: String,
        /// The leg's engine tag.
        from_tag: String,
    },
    /// Detach this leg's WebSocket **takeover bridge**, handing its media path
    /// back to the relay. Ordered after the tee detach: the tee is a copy of
    /// the audio and comes off first, then the path itself is returned, and
    /// only then is the leg renegotiated into the new bridge.
    ///
    /// Without this the leg would be re-INVITEd while the WebSocket server is
    /// still its far side — the bridge would form on paper and neither party
    /// would hear the other.
    DetachBridge {
        /// Engine call-id.
        media_call_id: String,
        /// The leg's engine tag.
        from_tag: String,
    },
    /// Delete a media session the pair no longer needs: the two single-party
    /// sessions once the bridge has formed on a fresh call-id, or the fresh one
    /// when the bridge failed before it could be adopted.
    DeleteSession {
        /// Engine call-id.
        media_call_id: String,
        /// The leg's engine tag.
        from_tag: String,
    },
    /// Put the pair onto a **fresh** engine call-id, yielding the SDP to offer
    /// the peer. Used when the anchor's own session is one the engine answered
    /// itself (`answer_local`) and so cannot become a relay. The anchor's own
    /// session is left where it is until the bridge forms, and the call-id is
    /// one nothing else uses, so this never offers over a live call.
    Offer {
        /// The fresh engine call-id the bridged pair will live on.
        media_call_id: String,
        /// The anchor leg's engine tag.
        from_tag: String,
        /// The media profile whose offer flags to use ([`bridge_offer_profile`]).
        profile: String,
        /// The anchor endpoint's current media description.
        sdp: Vec<u8>,
        /// The anchor's signalling source, pinned as the media ingress when the
        /// profile's offer half carries `received_from`: the SDP in this offer
        /// is the anchor's.
        received_from: Option<IpAddr>,
        /// The anchor's SIP Call-ID: the SDP in this offer is the anchor's, so
        /// the engine files the offerer leg's captures under the anchor's dialog
        /// rather than the pair's engine call-id.
        sip_call_id: String,
    },
    /// Renegotiate the anchor leg's **live, relaying** session on the ports it
    /// already holds, yielding the SDP to offer the peer. Never a repeat
    /// `offer`: that is a replacement on the native backend and would free the
    /// ports and drop everything attached to them.
    Reoffer {
        /// Engine call-id.
        media_call_id: String,
        /// The anchor leg's engine tag.
        from_tag: String,
        /// The media profile whose offer flags to use ([`bridge_offer_profile`]).
        profile: String,
        /// The anchor endpoint's current media description.
        sdp: Vec<u8>,
        /// The anchor's signalling source, as for [`MediaStep::Offer`].
        received_from: Option<IpAddr>,
        /// The anchor's SIP Call-ID, as for [`MediaStep::Offer`].
        sip_call_id: String,
    },
}

/// The profile whose `offer` half shapes what the peer is offered.
///
/// A pair profile, when the bridge was given one, describes both parties: its
/// `offer` half is the peer's. Without one it is the profile the **peer** was
/// anchored with, because that profile was chosen for that party — an SRTP
/// phone rung with an SRTP profile has to be offered SRTP, whatever the caller
/// it is joined to was answered with. A peer with no session of its own has no
/// such choice to honour, so the anchor's profile shapes both sides.
pub fn bridge_offer_profile<'a>(
    pair_profile: Option<&'a str>,
    anchor: &'a LegMedia,
    peer: Option<&'a LegMedia>,
) -> &'a str {
    pair_profile
        .or_else(|| peer.map(|peer| peer.profile.as_str()))
        .unwrap_or(anchor.profile.as_str())
}

/// The profile whose `answer` half shapes what the anchor is re-INVITEd with:
/// the pair profile when there is one, the anchor's own otherwise — the party
/// being answered was anchored with it.
pub fn bridge_answer_profile<'a>(pair_profile: Option<&'a str>, anchor: &'a LegMedia) -> &'a str {
    pair_profile.unwrap_or(anchor.profile.as_str())
}

/// What the anchor side of a bridge brings to the engine's offer.
#[derive(Debug, Clone, Copy)]
pub struct AnchorOffer<'a> {
    /// The anchor endpoint's current media description — what the engine is
    /// told the offerer looks like now.
    pub sdp: &'a [u8],
    /// The pair profile the bridge was given, if any ([`bridge_offer_profile`]).
    pub pair_profile: Option<&'a str>,
    /// The anchor's signalling source address.
    pub source: Option<IpAddr>,
    /// The anchor's SIP Call-ID, the dialog the offered SDP belongs to.
    pub sip_call_id: &'a str,
}

/// The ordered media work a bridge performs before it puts anything on the SIP
/// wire.
///
/// Order is the whole point: every attachment on **both** legs comes off first
/// (an announcement or a WebSocket bridge still live when the media is
/// re-pointed is one-way audio), and only then is the pair's media negotiated.
/// No session is deleted here: the peer has not accepted anything yet, and a
/// bridge it refuses must leave both legs' media where it was (see the module
/// docs). The sessions the pair no longer needs go once it forms.
///
/// The last step is the one that yields the SDP to offer the peer, and which
/// verb it is depends on what the anchor's session already is:
///
/// * **already relaying** → [`MediaStep::Reoffer`] on the call-id it holds, so
///   the ports and everything on them survive;
/// * **answered by the engine itself** → the pair is [`MediaStep::Offer`]ed
///   onto `fresh_call_id`, beside the anchor's own session.
///
/// An unanchored anchor yields no negotiation: the bridge crosses the
/// endpoints' own descriptions instead.
pub fn bridge_media_plan(
    anchor: Option<&LegMedia>,
    peer: Option<&LegMedia>,
    anchor_offer: AnchorOffer<'_>,
    fresh_call_id: &str,
) -> Vec<MediaStep> {
    let mut steps = Vec::new();
    for leg in [anchor, peer].into_iter().flatten() {
        if leg.has_playback {
            steps.push(MediaStep::StopPlayback {
                media_call_id: leg.media_call_id.clone(),
                from_tag: leg.from_tag.clone(),
            });
        }
        if leg.has_tee {
            steps.push(MediaStep::DetachTee {
                media_call_id: leg.media_call_id.clone(),
                from_tag: leg.from_tag.clone(),
            });
        }
        if leg.has_ws_bridge {
            steps.push(MediaStep::DetachBridge {
                media_call_id: leg.media_call_id.clone(),
                from_tag: leg.from_tag.clone(),
            });
        }
    }
    if let Some(anchor) = anchor {
        let profile = bridge_offer_profile(anchor_offer.pair_profile, anchor, peer).to_string();
        let sdp = anchor_offer.sdp.to_vec();
        let received_from = anchor_offer.source;
        let sip_call_id = anchor_offer.sip_call_id.to_string();
        steps.push(if anchor.relaying {
            MediaStep::Reoffer {
                media_call_id: anchor.media_call_id.clone(),
                from_tag: anchor.from_tag.clone(),
                profile,
                sdp,
                received_from,
                sip_call_id,
            }
        } else {
            MediaStep::Offer {
                media_call_id: fresh_call_id.to_string(),
                from_tag: anchor.from_tag.clone(),
                profile,
                sdp,
                received_from,
                sip_call_id,
            }
        });
    }
    steps
}

/// Whether a media step's failure stops the bridge, and with which typed
/// refusal.
///
/// The two teardown steps tolerate both "the engine has no such call" and "this
/// backend has no such thing": there is then nothing attached to come off, which
/// is the state the bridge wanted. The two steps that *form* the bridge tolerate
/// neither — a refused `reoffer` or a session that could not be deleted is a
/// bridge that would carry audio one way or not at all, and it is surfaced as
/// the typed `unsupported` / `unavailable` refusal rather than formed anyway.
///
/// `None` means "carry on".
pub fn classify_media_failure(
    step: &MediaStep,
    call_not_found: bool,
    unsupported: bool,
    detail: &str,
) -> Option<BridgeError> {
    let teardown = matches!(
        step,
        MediaStep::StopPlayback { .. } | MediaStep::DetachTee { .. }
    );
    if teardown && (call_not_found || unsupported) {
        return None;
    }
    // "Nothing is playing" is the guarantee the stop was asking for, not a
    // failure — the engine says it plainly rather than answering ok, and the
    // bridge must read it as met (the same way `is_call_not_found` reads the
    // engine's own not-found wording).
    if matches!(step, MediaStep::StopPlayback { .. }) && is_nothing_playing(detail) {
        return None;
    }
    if unsupported {
        return Some(BridgeError::Unsupported(detail.to_string()));
    }
    if call_not_found && matches!(step, MediaStep::DeleteSession { .. }) {
        // The session the bridge wanted gone is already gone.
        return None;
    }
    Some(BridgeError::Unavailable(detail.to_string()))
}

/// Whether an engine's refusal of a playback stop means "there was nothing
/// playing".
///
/// The native engine answers a stop on a call with no playback with
/// `"call has no active media playback"` (and a targeted one with
/// `"no playback <id> is running on this call"`) rather than a hollow ok. For a
/// bridge that is the wanted state, so it is read as met — the same string-level
/// reading [`crate::rtpengine::error::RtpEngineError::is_call_not_found`] does
/// of the engines' not-found wording.
pub fn is_nothing_playing(detail: &str) -> bool {
    let lower = detail.to_ascii_lowercase();
    lower.contains("no active media playback") || lower.contains("no playback")
}

/// A media direction attribute (RFC 3264 §6.1 / RFC 4566 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDirection {
    /// Both ways — what a formed bridge offers.
    SendRecv,
    /// Offerer sends only: the RFC 6337 §3.1 way to put a stream on hold
    /// (preferred over `c=0.0.0.0`, which RFC 6337 §5.1 warns against).
    SendOnly,
}

impl MediaDirection {
    /// The attribute token.
    pub fn as_str(&self) -> &'static str {
        match self {
            MediaDirection::SendRecv => "sendrecv",
            MediaDirection::SendOnly => "sendonly",
        }
    }
}

/// Every direction attribute RFC 3264 §6.1 defines. Removed wholesale before
/// the wanted one is set, so a stream never carries two.
const DIRECTION_ATTRS: [&str; 4] = ["sendrecv", "sendonly", "recvonly", "inactive"];

/// Restate an SDP body's direction as siphon's own.
///
/// siphon is the offerer on each leg's dialog, so the direction attribute it
/// sends states *siphon's* intent for that stream, not the far party's
/// (RFC 3264 §6.1 — the attribute is a property of the offer, and the answerer
/// mirrors it). Crossing another leg's description verbatim would replay that
/// party's direction: a leg that was held `sendonly` answers `recvonly`, and
/// replaying *that* to the other side tells it not to send at all — the exact
/// one-way audio a re-bridge must not produce.
///
/// The attribute is removed at session level and re-set on every media section,
/// so the media-level value (which overrides the session-level one per
/// RFC 4566 §6) is unambiguous. A body that does not parse as SDP is returned
/// untouched rather than mangled.
pub fn set_media_direction(body: &[u8], direction: MediaDirection) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return body.to_vec();
    };
    let mut sdp = crate::media::sdp::SdpBody::parse(text);
    if sdp.media_sections.is_empty() {
        return body.to_vec();
    }
    for attribute in DIRECTION_ATTRS {
        sdp.session_remove_attr(attribute);
    }
    for media in &mut sdp.media_sections {
        for attribute in DIRECTION_ATTRS {
            media.remove_attr(attribute);
        }
        media.set_attr(direction.as_str(), "");
    }
    sdp.to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A single-party session the engine answered itself with no tee — what
    /// every leg a controller owns starts as.
    fn local_leg(call_id: &str, tag: &str) -> LegMedia {
        LegMedia {
            media_call_id: call_id.to_string(),
            from_tag: tag.to_string(),
            profile: "rtp_passthrough".to_string(),
            relaying: false,
            has_tee: false,
            has_ws_bridge: false,
            has_playback: false,
        }
    }

    /// A session already relaying between two parties — what a leg looks like
    /// after a bridge, i.e. on a re-bridge.
    fn relaying_leg(call_id: &str, tag: &str) -> LegMedia {
        LegMedia {
            relaying: true,
            ..local_leg(call_id, tag)
        }
    }

    /// A relaying session with a mid-call WebSocket takeover bridge attached —
    /// a leg whose far side is a media server rather than the other party.
    fn bridged_leg(call_id: &str, tag: &str) -> LegMedia {
        LegMedia {
            relaying: true,
            has_ws_bridge: true,
            ..local_leg(call_id, tag)
        }
    }

    fn kinds(steps: &[MediaStep]) -> Vec<&'static str> {
        steps
            .iter()
            .map(|step| match step {
                MediaStep::StopPlayback { .. } => "stop",
                MediaStep::DetachTee { .. } => "detach",
                MediaStep::DetachBridge { .. } => "detach_bridge",
                MediaStep::DeleteSession { .. } => "delete",
                MediaStep::Offer { .. } => "offer",
                MediaStep::Reoffer { .. } => "reoffer",
            })
            .collect()
    }

    // -----------------------------------------------------------------------
    // Media plan — the ordering is the contract
    // -----------------------------------------------------------------------

    /// What an anchor with this description, no pair profile and no known
    /// source offers.
    fn offer_of(sdp: &[u8]) -> AnchorOffer<'_> {
        AnchorOffer {
            sdp,
            pair_profile: None,
            source: None,
            sip_call_id: "anchor-dialog@192.0.2.10",
        }
    }

    /// Whether a step deletes a session.
    fn deletes(steps: &[MediaStep]) -> bool {
        steps
            .iter()
            .any(|step| matches!(step, MediaStep::DeleteSession { .. }))
    }

    #[test]
    fn plan_tears_every_attachment_down_before_it_re_points_the_media() {
        let anchor = LegMedia {
            has_tee: true,
            has_playback: true,
            ..relaying_leg("cid-a", "tag-a")
        };
        let peer = LegMedia {
            has_tee: true,
            has_playback: true,
            ..local_leg("cid-b", "tag-b")
        };
        let steps = bridge_media_plan(
            Some(&anchor),
            Some(&peer),
            offer_of(b"v=0\r\n"),
            "cid-fresh",
        );

        // Both legs' attachments first, then the anchor's renegotiation.
        // Anything else is one-way audio.
        assert_eq!(
            kinds(&steps),
            vec!["stop", "detach", "stop", "detach", "reoffer"]
        );
    }

    #[test]
    fn plan_only_tears_down_what_is_actually_attached() {
        // A detach on a session with no tee, or a stop on a leg with nothing
        // playing, draws a refusal from the engine that says nothing — and the
        // engine counts it as a command it rejected. Only run the step when
        // there is something to confirm.
        let anchor = relaying_leg("cid-a", "tag-a");
        let peer = local_leg("cid-b", "tag-b");
        let steps = bridge_media_plan(
            Some(&anchor),
            Some(&peer),
            offer_of(b"v=0\r\n"),
            "cid-fresh",
        );
        assert_eq!(kinds(&steps), vec!["reoffer"]);

        // …and it still runs where there is: a playback on the anchor only.
        let playing = LegMedia {
            has_playback: true,
            ..relaying_leg("cid-a", "tag-a")
        };
        let steps = bridge_media_plan(
            Some(&playing),
            Some(&peer),
            offer_of(b"v=0\r\n"),
            "cid-fresh",
        );
        assert_eq!(kinds(&steps), vec!["stop", "reoffer"]);
    }

    #[test]
    fn plan_renegotiates_a_relaying_anchor_and_never_replaces_it() {
        // The bug this guards: a plain repeat `offer` on a live call-id frees
        // its ports and drops the WebSocket bridge / tee / SIPREC subscription
        // riding on them. A relaying anchor gets `reoffer`, never `offer`, and
        // its own session is never deleted.
        let anchor = relaying_leg("cid-a", "tag-a");
        let steps = bridge_media_plan(
            Some(&anchor),
            None,
            offer_of(b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n"),
            "cid-fresh",
        );
        assert_eq!(kinds(&steps), vec!["reoffer"]);
        match &steps[0] {
            MediaStep::Reoffer {
                media_call_id,
                from_tag,
                profile,
                sdp,
                received_from,
                sip_call_id,
            } => {
                assert_eq!(media_call_id, "cid-a");
                assert_eq!(from_tag, "tag-a");
                assert_eq!(profile, "rtp_passthrough");
                assert_eq!(sdp, b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n");
                assert_eq!(*received_from, None);
                assert_eq!(sip_call_id, "anchor-dialog@192.0.2.10");
            }
            other => panic!("expected Reoffer, got {other:?}"),
        }
    }

    #[test]
    fn plan_offers_a_locally_answered_anchor_on_a_fresh_call_beside_its_own() {
        // The engine refuses an `answer` on a call it answered itself — there is
        // no far leg to answer — so a single-party anchor cannot become a relay
        // in place. The pair is offered onto a fresh id, and the anchor's own
        // session is left alone: the peer has accepted nothing yet.
        let anchor = local_leg("cid-a", "tag-a");
        let steps = bridge_media_plan(Some(&anchor), None, offer_of(b"v=0\r\n"), "cid-fresh");
        assert_eq!(kinds(&steps), vec!["offer"]);
        match &steps[0] {
            MediaStep::Offer {
                media_call_id,
                from_tag,
                sip_call_id,
                ..
            } => {
                assert_eq!(media_call_id, "cid-fresh");
                assert_eq!(
                    sip_call_id, "anchor-dialog@192.0.2.10",
                    "the pair's own call-id, the anchor's dialog"
                );
                assert_ne!(
                    media_call_id, "cid-a",
                    "the offer must not reuse the live id"
                );
                assert_eq!(from_tag, "tag-a");
            }
            other => panic!("expected an offer, got {other:?}"),
        }
    }

    #[test]
    fn plan_never_deletes_a_session_before_the_peer_has_accepted() {
        // A peer that refuses the bridge must find both legs' media where it
        // was: the caller's prompts, ringback and recording all still work.
        for anchor in [local_leg("cid-a", "tag-a"), relaying_leg("cid-a", "tag-a")] {
            let peer = LegMedia {
                has_playback: true,
                ..local_leg("cid-b", "tag-b")
            };
            let steps = bridge_media_plan(
                Some(&anchor),
                Some(&peer),
                offer_of(b"v=0\r\n"),
                "cid-fresh",
            );
            assert!(!deletes(&steps), "{:?}", kinds(&steps));
            // Positive control: the plan still negotiates and still clears
            // what is attached.
            assert!(kinds(&steps).contains(&"stop"));
            assert!(kinds(&steps)
                .iter()
                .any(|kind| *kind == "offer" || *kind == "reoffer"));
        }
    }

    #[test]
    fn plan_for_two_unanchored_legs_is_empty() {
        assert!(bridge_media_plan(None, None, offer_of(b"v=0\r\n"), "cid-fresh").is_empty());
    }

    #[test]
    fn plan_with_only_a_peer_anchor_clears_it_and_negotiates_nothing() {
        let peer = LegMedia {
            has_tee: true,
            has_playback: true,
            ..local_leg("cid-b", "tag-b")
        };
        let steps = bridge_media_plan(None, Some(&peer), offer_of(b"v=0\r\n"), "cid-fresh");
        assert_eq!(kinds(&steps), vec!["stop", "detach"]);
    }

    /// The profile named on a step, for either negotiation.
    fn offered_profile(steps: &[MediaStep]) -> Option<&str> {
        steps.iter().find_map(|step| match step {
            MediaStep::Offer { profile, .. } | MediaStep::Reoffer { profile, .. } => {
                Some(profile.as_str())
            }
            _ => None,
        })
    }

    #[test]
    fn the_peer_is_offered_media_shaped_by_its_own_profile() {
        // The bug: a plain-RTP caller bridged to an SRTP phone offered the
        // phone RTP/AVP, because the offer was built from the caller's
        // profile. The phone was anchored with its own; that is the one that
        // describes it.
        let anchor = local_leg("cid-a", "tag-a");
        let peer = LegMedia {
            profile: "srtp_phone".to_string(),
            ..local_leg("cid-b", "tag-b")
        };
        for anchor in [anchor.clone(), relaying_leg("cid-a", "tag-a")] {
            let steps = bridge_media_plan(
                Some(&anchor),
                Some(&peer),
                offer_of(b"v=0\r\n"),
                "cid-fresh",
            );
            assert_eq!(offered_profile(&steps), Some("srtp_phone"));
        }
        // A pair profile overrides both.
        let steps = bridge_media_plan(
            Some(&anchor),
            Some(&peer),
            AnchorOffer {
                pair_profile: Some("rtp_to_srtp"),
                ..offer_of(b"v=0\r\n")
            },
            "cid-fresh",
        );
        assert_eq!(offered_profile(&steps), Some("rtp_to_srtp"));
        // Positive control: a peer with no session of its own leaves the
        // anchor's profile in charge.
        let steps = bridge_media_plan(Some(&anchor), None, offer_of(b"v=0\r\n"), "cid-fresh");
        assert_eq!(offered_profile(&steps), Some("rtp_passthrough"));
    }

    #[test]
    fn the_anchor_is_answered_with_its_own_profile_unless_a_pair_names_one() {
        let anchor = local_leg("cid-a", "tag-a");
        assert_eq!(bridge_answer_profile(None, &anchor), "rtp_passthrough");
        assert_eq!(
            bridge_answer_profile(Some("rtp_to_srtp"), &anchor),
            "rtp_to_srtp"
        );
    }

    #[test]
    fn the_offer_carries_the_anchors_signalling_source() {
        // The SDP in the bridge's offer is the anchor's, so the anchor is the
        // party whose media ingress `received_from` pins.
        let source: IpAddr = "192.0.2.10".parse().expect("an address");
        for anchor in [local_leg("cid-a", "tag-a"), relaying_leg("cid-a", "tag-a")] {
            let steps = bridge_media_plan(
                Some(&anchor),
                None,
                AnchorOffer {
                    source: Some(source),
                    ..offer_of(b"v=0\r\n")
                },
                "cid-fresh",
            );
            let carried = steps.iter().find_map(|step| match step {
                MediaStep::Offer { received_from, .. }
                | MediaStep::Reoffer { received_from, .. } => Some(*received_from),
                _ => None,
            });
            assert_eq!(carried, Some(Some(source)));
        }
    }

    // -----------------------------------------------------------------------
    // Media-failure classification
    // -----------------------------------------------------------------------

    /// A takeover bridge must come off before the leg is renegotiated. Without
    /// the detach the re-INVITE forms a bridge on paper while the WebSocket
    /// server is still the leg's far side, and neither party hears the other.
    #[test]
    fn a_leg_holding_a_takeover_bridge_has_it_detached_before_renegotiation() {
        let anchor = bridged_leg("call-a", "tag-a");
        let peer = relaying_leg("call-b", "tag-b");
        let steps = bridge_media_plan(Some(&anchor), Some(&peer), offer_of(b"v=0\r\n"), "fresh");
        let kinds = kinds(&steps);

        let detach = kinds
            .iter()
            .position(|kind| *kind == "detach_bridge")
            .expect("a leg with a takeover bridge must have it detached");
        let renegotiate = kinds
            .iter()
            .position(|kind| *kind == "reoffer" || *kind == "offer")
            .expect("the bridge must renegotiate the anchor");
        assert!(
            detach < renegotiate,
            "the takeover must be handed back before the leg is renegotiated, got {kinds:?}"
        );
    }

    /// The bug this pair of flags exists to prevent: a leg holding a *takeover*
    /// used to be read as holding a *tee*, so the plan sent `detach_ws_tee` —
    /// which is idempotent and answers ok — and then renegotiated a media path
    /// the WebSocket server still owned. A takeover must produce the bridge
    /// detach and never the tee detach.
    #[test]
    fn a_takeover_bridge_is_never_mistaken_for_a_tee() {
        let anchor = bridged_leg("call-a", "tag-a");
        let steps = bridge_media_plan(Some(&anchor), None, offer_of(b"v=0\r\n"), "fresh");
        let kinds = kinds(&steps);
        assert!(
            kinds.contains(&"detach_bridge"),
            "a takeover must be detached as a bridge, got {kinds:?}"
        );
        assert!(
            !kinds.contains(&"detach"),
            "a takeover must not be detached as a tee, got {kinds:?}"
        );
    }

    /// The other half of the same bug: a leg with a real tee and no takeover
    /// must still get the tee detach.
    #[test]
    fn a_tee_is_still_detached_as_a_tee() {
        let anchor = LegMedia {
            relaying: true,
            has_tee: true,
            ..local_leg("call-a", "tag-a")
        };
        let steps = bridge_media_plan(Some(&anchor), None, offer_of(b"v=0\r\n"), "fresh");
        let kinds = kinds(&steps);
        assert!(
            kinds.contains(&"detach"),
            "a tee must be detached as a tee, got {kinds:?}"
        );
        assert!(
            !kinds.contains(&"detach_bridge"),
            "a tee must not be detached as a bridge, got {kinds:?}"
        );
    }

    /// A leg holding both a copy and a takeover peels the copy off first, then
    /// hands the path back — the tee is a consumer of the audio, so detaching
    /// it after the path has already moved would stream from a leg that is
    /// mid-renegotiation.
    #[test]
    fn a_tee_comes_off_before_the_takeover_it_sits_on() {
        let anchor = LegMedia {
            has_tee: true,
            ..bridged_leg("call-a", "tag-a")
        };
        let steps = bridge_media_plan(Some(&anchor), None, offer_of(b"v=0\r\n"), "fresh");
        let kinds = kinds(&steps);
        let tee = kinds
            .iter()
            .position(|k| *k == "detach")
            .expect("tee detach");
        let bridge = kinds
            .iter()
            .position(|k| *k == "detach_bridge")
            .expect("bridge detach");
        assert!(tee < bridge, "tee must come off first, got {kinds:?}");
    }

    #[test]
    fn a_backend_with_no_tee_is_a_leg_with_no_tee_not_a_failed_bridge() {
        // rtpengine and rtpproxy answer `detach_ws_tee` with Unsupported. That
        // means the leg cannot be holding a tee, which is what the step wanted.
        let step = MediaStep::DetachTee {
            media_call_id: "cid".to_string(),
            from_tag: "tag".to_string(),
        };
        assert_eq!(
            classify_media_failure(&step, false, true, "no tee here"),
            None
        );
        assert_eq!(
            classify_media_failure(&step, true, false, "unknown call"),
            None
        );
    }

    #[test]
    fn nothing_playing_is_not_a_failed_bridge() {
        let step = MediaStep::StopPlayback {
            media_call_id: "cid".to_string(),
            from_tag: "tag".to_string(),
        };
        assert_eq!(
            classify_media_failure(&step, true, false, "unknown call"),
            None
        );
        assert_eq!(
            classify_media_failure(&step, false, true, "no player"),
            None
        );
    }

    #[test]
    fn the_engines_own_nothing_playing_refusal_reads_as_the_stop_having_worked() {
        // The native engine refuses a stop on a call with no playback rather
        // than answering ok. That refusal IS the guarantee the step wanted, so
        // reading it as a failure would make every bridge on an idle leg fail.
        let step = MediaStep::StopPlayback {
            media_call_id: "cid".to_string(),
            from_tag: "tag".to_string(),
        };
        for detail in [
            "stop_media error: call has no active media playback",
            "no playback 7 is running on this call",
        ] {
            assert_eq!(
                classify_media_failure(&step, false, false, detail),
                None,
                "{detail}"
            );
            assert!(is_nothing_playing(detail));
        }
        // A real failure on the same step still stops the bridge.
        assert!(!is_nothing_playing(
            "media actor closed before the stop was applied"
        ));
        assert_eq!(
            classify_media_failure(
                &step,
                false,
                false,
                "media actor closed before the stop was applied"
            ),
            Some(BridgeError::Unavailable(
                "media actor closed before the stop was applied".to_string()
            ))
        );
    }

    #[test]
    fn a_refused_offer_or_reoffer_is_the_typed_unsupported_refusal_never_a_formed_bridge() {
        let step = MediaStep::Reoffer {
            media_call_id: "cid".to_string(),
            from_tag: "tag".to_string(),
            profile: "rtp_passthrough".to_string(),
            sdp: b"v=0\r\n".to_vec(),
            received_from: None,
            sip_call_id: "anchor-dialog@192.0.2.10".to_string(),
        };
        assert_eq!(
            classify_media_failure(&step, false, true, "backend cannot reoffer"),
            Some(BridgeError::Unsupported(
                "backend cannot reoffer".to_string()
            ))
        );
        // A vanished anchor session is not "nothing to do" — the bridge has no
        // media to renegotiate, so it is refused rather than formed blind.
        assert_eq!(
            classify_media_failure(&step, true, false, "unknown call"),
            Some(BridgeError::Unavailable("unknown call".to_string()))
        );
        // The fresh-call form is held to the same rule.
        let offer = MediaStep::Offer {
            media_call_id: "cid-fresh".to_string(),
            from_tag: "tag".to_string(),
            profile: "rtp_passthrough".to_string(),
            sdp: b"v=0\r\n".to_vec(),
            received_from: None,
            sip_call_id: "anchor-dialog@192.0.2.10".to_string(),
        };
        assert_eq!(
            classify_media_failure(&offer, false, true, "backend cannot offer"),
            Some(BridgeError::Unsupported("backend cannot offer".to_string()))
        );
    }

    #[test]
    fn an_already_deleted_peer_session_is_tolerated_but_a_refused_delete_is_not() {
        let step = MediaStep::DeleteSession {
            media_call_id: "cid".to_string(),
            from_tag: "tag".to_string(),
        };
        assert_eq!(
            classify_media_failure(&step, true, false, "unknown call"),
            None
        );
        assert_eq!(
            classify_media_failure(&step, false, false, "engine timeout"),
            Some(BridgeError::Unavailable("engine timeout".to_string()))
        );
        assert_eq!(
            classify_media_failure(&step, false, true, "no delete"),
            Some(BridgeError::Unsupported("no delete".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // Direction rewrite
    // -----------------------------------------------------------------------

    const HELD_ANSWER: &str = concat!(
        "v=0\r\n",
        "o=alice 1 1 IN IP4 192.0.2.1\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.1\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=recvonly\r\n",
    );

    #[test]
    fn direction_rewrite_restores_sendrecv_on_a_held_description() {
        let rewritten = set_media_direction(HELD_ANSWER.as_bytes(), MediaDirection::SendRecv);
        let text = String::from_utf8(rewritten).expect("utf-8");
        assert!(text.contains("a=sendrecv"), "{text}");
        assert!(!text.contains("a=recvonly"), "{text}");
        // Everything else survives — the rewrite is a direction change, not a
        // re-authoring of the media.
        assert!(text.contains("m=audio 40000 RTP/AVP 0"), "{text}");
        assert!(text.contains("a=rtpmap:0 PCMU/8000"), "{text}");
        assert!(text.contains("c=IN IP4 192.0.2.1"), "{text}");
    }

    #[test]
    fn direction_rewrite_holds_with_sendonly_not_a_null_connection() {
        // RFC 6337 §3.1 prefers a=sendonly; §5.1 warns against c=0.0.0.0.
        let rewritten = set_media_direction(HELD_ANSWER.as_bytes(), MediaDirection::SendOnly);
        let text = String::from_utf8(rewritten).expect("utf-8");
        assert!(text.contains("a=sendonly"), "{text}");
        assert!(!text.contains("0.0.0.0"), "{text}");
    }

    #[test]
    fn direction_rewrite_never_leaves_two_direction_attributes() {
        let both = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.1\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "t=0 0\r\n",
            "a=inactive\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=sendonly\r\n",
        );
        let text = String::from_utf8(set_media_direction(
            both.as_bytes(),
            MediaDirection::SendRecv,
        ))
        .expect("utf-8");
        for attribute in ["sendonly", "recvonly", "inactive"] {
            assert!(
                !text.contains(&format!("a={attribute}")),
                "left a={attribute} behind: {text}"
            );
        }
        assert_eq!(text.matches("a=sendrecv").count(), 1, "{text}");
    }

    #[test]
    fn direction_rewrite_sets_every_media_section() {
        let two_streams = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.1\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
            "m=video 40002 RTP/AVP 96\r\n",
            "a=recvonly\r\n",
        );
        let text = String::from_utf8(set_media_direction(
            two_streams.as_bytes(),
            MediaDirection::SendRecv,
        ))
        .expect("utf-8");
        assert_eq!(text.matches("a=sendrecv").count(), 2, "{text}");
    }

    #[test]
    fn direction_rewrite_keeps_formats_that_are_not_payload_types() {
        // A re-bridge re-serializes the whole body, so a T.38 or data channel
        // section has to come back out with its token format (RFC 8866 §5.14),
        // not as an m= line with no format.
        let mixed = concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 192.0.2.1\r\n",
            "s=-\r\n",
            "c=IN IP4 192.0.2.1\r\n",
            "t=0 0\r\n",
            "m=audio 0 RTP/AVP 0\r\n",
            "a=recvonly\r\n",
            "m=image 40002 udptl t38\r\n",
            "a=T38FaxVersion:0\r\n",
            "a=recvonly\r\n",
            "m=application 40004 UDP/DTLS/SCTP webrtc-datachannel\r\n",
            "a=sctp-port:5000\r\n",
        );
        let text = String::from_utf8(set_media_direction(
            mixed.as_bytes(),
            MediaDirection::SendRecv,
        ))
        .expect("utf-8");
        assert_eq!(
            text,
            concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 192.0.2.1\r\n",
                "s=-\r\n",
                "c=IN IP4 192.0.2.1\r\n",
                "t=0 0\r\n",
                "m=audio 0 RTP/AVP 0\r\n",
                "a=sendrecv\r\n",
                "m=image 40002 udptl t38\r\n",
                "a=T38FaxVersion:0\r\n",
                "a=sendrecv\r\n",
                "m=application 40004 UDP/DTLS/SCTP webrtc-datachannel\r\n",
                "a=sctp-port:5000\r\n",
                "a=sendrecv\r\n",
            )
        );
    }

    #[test]
    fn direction_rewrite_leaves_a_non_sdp_body_untouched() {
        assert_eq!(
            set_media_direction(b"not sdp at all", MediaDirection::SendRecv),
            b"not sdp at all".to_vec()
        );
        assert_eq!(
            set_media_direction(&[0xff, 0xfe], MediaDirection::SendRecv),
            vec![0xff, 0xfe]
        );
        // No m= line: nothing to set a direction on.
        assert_eq!(
            set_media_direction(
                b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n",
                MediaDirection::SendRecv
            ),
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\n".to_vec()
        );
    }

    // -----------------------------------------------------------------------
    // Typed errors + policy parsing
    // -----------------------------------------------------------------------

    #[test]
    fn every_refusal_renders_a_distinct_actionable_message() {
        let rendered: Vec<String> = [
            BridgeError::UnknownLeg {
                which: "with",
                id: "ch-2".to_string(),
            },
            BridgeError::SameLeg("ch-1".to_string()),
            BridgeError::NotAnswered {
                id: "ch-1".to_string(),
                state: "ringing".to_string(),
            },
            BridgeError::AlreadyBridged {
                id: "ch-1".to_string(),
            },
            BridgeError::NotBridged {
                id: "ch-1".to_string(),
            },
            BridgeError::Glare {
                id: "ch-1".to_string(),
            },
            BridgeError::NoMediaDescription {
                id: "ch-1".to_string(),
            },
            BridgeError::Unsupported("backend cannot".to_string()),
            BridgeError::Unavailable("no dispatcher".to_string()),
        ]
        .iter()
        .map(|error| error.to_string())
        .collect();
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            rendered.len(),
            "messages collide: {rendered:?}"
        );
        assert!(rendered.iter().all(|message| !message.is_empty()));
    }

    #[test]
    fn each_refusal_carries_its_own_stable_code() {
        // The four causes the rails must keep apart: no such leg, wrong state,
        // the same leg twice, a backend that cannot express it.
        assert_eq!(
            BridgeError::UnknownLeg {
                which: "with",
                id: "ch".to_string()
            }
            .code(),
            "not_found"
        );
        assert_eq!(BridgeError::SameLeg("ch".to_string()).code(), "bad_request");
        assert_eq!(
            BridgeError::NotAnswered {
                id: "ch".to_string(),
                state: "ringing".to_string()
            }
            .code(),
            "invalid_state"
        );
        assert_eq!(
            BridgeError::AlreadyBridged {
                id: "ch".to_string()
            }
            .code(),
            "invalid_state"
        );
        assert_eq!(
            BridgeError::Unsupported("no".to_string()).code(),
            "unsupported_verb"
        );
        assert_eq!(
            BridgeError::Unavailable("gone".to_string()).code(),
            "unavailable"
        );
    }

    #[test]
    fn peer_hangup_policy_refuses_anything_it_does_not_implement() {
        assert_eq!(
            PeerHangupPolicy::parse("hangup"),
            Some(PeerHangupPolicy::Hangup)
        );
        assert_eq!(
            PeerHangupPolicy::parse("hold"),
            Some(PeerHangupPolicy::Hold)
        );
        assert_eq!(PeerHangupPolicy::parse("continue"), None);
        assert_eq!(PeerHangupPolicy::parse(""), None);
        assert_eq!(PeerHangupPolicy::default(), PeerHangupPolicy::Hangup);
        assert_eq!(PeerHangupPolicy::Hold.as_str(), "hold");
    }

    #[test]
    fn stage_is_pending_until_both_legs_have_renegotiated() {
        assert!(BridgeStage::OfferingPeer.is_pending());
        assert!(BridgeStage::OfferingAnchor.is_pending());
        assert!(!BridgeStage::Bridged.is_pending());
        // A leg whose hold offer is still outstanding is pending too: bridging
        // it again would collide with that very re-INVITE (RFC 3261 §14.1).
        assert!(BridgeStage::Releasing.is_pending());
        assert_eq!(BridgeStage::Releasing.as_str(), "releasing");
        assert_eq!(BridgeStage::OfferingPeer.as_str(), "offering_peer");
        assert_eq!(BridgeRole::Anchor.as_str(), "anchor");
        assert_eq!(BridgeRole::Peer.as_str(), "peer");
    }
}
