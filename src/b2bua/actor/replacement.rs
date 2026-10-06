//! The targets a leg replacement rings, and how it settles between them.
//!
//! A replacement (a siphon-terminated REFER transfer, or `replace_peer`) dials
//! a new party for one side of an answered call. Named by an address-of-record
//! with several registered contacts it rings them all, and the call's
//! [`ReferSubscription`] keeps one [`ReplacementTarget`] per INVITE on the wire.
//!
//! They are told apart by **Via branch**: unique per INVITE (RFC 3261 §8.1.1.7)
//! and carried back by every response to it, where a Call-ID need not be unique
//! to a leg and a position in the call's leg list moves whenever another leg is
//! removed.
//!
//! The first 2xx keeps its target and ends the others, as a forking proxy does
//! (RFC 3261 §16.7 step 10); the replacement fails only once no target is left
//! that could still answer, on the best of their responses (§16.7 step 6).

use super::*;

/// How one target of a replacement ended, or that it has not yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementOutcome {
    /// Its INVITE is out and no final response is in.
    Pending,
    /// It answered first and is the party the replacement brings in.
    Answered,
    /// It answered with this final non-2xx.
    Failed(u16),
    /// siphon CANCELled it: another target answered, the replacement ran out of
    /// time, or the call ended under it.
    Cancelled,
}

/// The media engine call a target's INVITE was offered from.
///
/// Each target is offered the surviving party's media on an engine call of its
/// own, so the one that answers completes its own and the others are released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementMedia {
    /// The engine's call-id for this target.
    pub call_id: String,
    /// The tag the surviving party was offered under, which the engine's
    /// `delete` names.
    pub from_tag: String,
}

/// One target a replacement rang.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplacementTarget {
    /// Via branch of the INVITE siphon sent it: the key.
    pub branch: String,
    /// SIP Call-ID of the leg dialled to it.
    pub leg_call_id: String,
    /// The engine call its INVITE was offered from, until that is completed by
    /// its answer or released. `None` on a call that is not media-anchored.
    pub media: Option<ReplacementMedia>,
    /// How it ended.
    pub outcome: ReplacementOutcome,
}

impl ReplacementTarget {
    /// A target whose INVITE just went out.
    pub fn ringing(branch: String, leg_call_id: String, media: Option<ReplacementMedia>) -> Self {
        Self {
            branch,
            leg_call_id,
            media,
            outcome: ReplacementOutcome::Pending,
        }
    }
}

/// What the target that answered first is handed, read under the same lock that
/// made it the winner.
#[derive(Debug, Clone)]
pub struct ReplacementWin {
    /// Which leg of the call is being replaced.
    pub replaced_on_a_leg: bool,
    /// Whether that leg already ended its dialog.
    pub referrer_gone: bool,
    /// What asked for the replacement.
    pub origin: crate::b2bua::transfer::ReplacementOrigin,
    /// The REFER subscription's `id` (RFC 3515 §2.4.4).
    pub event_id: u32,
    /// The media profile named for the pairing the replacement creates.
    pub media_profile: Option<String>,
    /// The winner's own record, with the engine call its answer completes.
    pub target: ReplacementTarget,
    /// The winner's leg as it stood when it answered.
    pub target_leg: Leg,
    /// The targets that were still ringing, for the caller to CANCEL. Each is
    /// already kept answerable.
    pub cancelled: Vec<Leg>,
    /// The engine calls of every other target, for the caller to release.
    pub released_media: Vec<ReplacementMedia>,
}

/// What a 2xx from a replacement target turned out to be.
#[derive(Debug, Clone)]
pub enum ReplacementClaim {
    /// The first answer: this target is the one the replacement brings in.
    Won(Box<ReplacementWin>),
    /// Another target answered first, or the replacement was given up on. The
    /// dialog this 2xx established is owed an ACK and a BYE (RFC 3261
    /// §13.2.2.4, §15) and nothing else.
    Lost,
    /// A retransmission of the winner's own 2xx, while it is being brought in.
    Duplicate,
    /// The branch belongs to no replacement on this call.
    NotATarget,
}

/// What the leg behind a Via branch is to the replacements on its call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplacementBranch {
    /// A target of a replacement still on the call: its responses are the
    /// replacement's to decide on.
    Target,
    /// A leg siphon cancelled and is keeping answerable, whose replacement is
    /// no longer there to say so: the loser of one that has since completed.
    /// Its responses are a cancelled branch's.
    Settled,
    /// Neither.
    Other,
}

/// A replacement that ended with no target answering.
#[derive(Debug, Clone)]
pub struct FailedReplacement {
    /// Which leg of the call was to be replaced.
    pub replaced_on_a_leg: bool,
    /// Whether that leg already ended its dialog.
    pub referrer_gone: bool,
    /// What asked for the replacement.
    pub origin: crate::b2bua::transfer::ReplacementOrigin,
    /// The REFER subscription's `id` (RFC 3515 §2.4.4).
    pub event_id: u32,
    /// The response the replacement failed on: the best of its targets' (RFC
    /// 3261 §16.7 step 6), a target that never answered counting as a 408
    /// (§16.8).
    pub status_code: u16,
    /// Every target's Via branch, for the caller to take their legs off the
    /// call.
    pub branches: Vec<String>,
    /// The targets that were still ringing, for the caller to CANCEL. Each is
    /// already kept answerable.
    pub cancelled: Vec<Leg>,
    /// The engine calls still held for the targets, for the caller to release.
    pub released_media: Vec<ReplacementMedia>,
}

/// What recording one target's final non-2xx came to.
#[derive(Debug, Clone, Default)]
pub struct ReplacementTargetFailure {
    /// The engine call that target was offered from, for the caller to
    /// release.
    pub released_media: Option<ReplacementMedia>,
    /// The replacement's failure, when this was the last target that could
    /// still answer. `None` while another rings.
    pub settled: Option<FailedReplacement>,
}

/// The pending targets a teardown ended, with what they held.
#[derive(Debug, Clone, Default)]
pub struct AbandonedReplacements {
    /// The targets that were still ringing, for the caller to CANCEL. Each is
    /// already kept answerable.
    pub cancelled: Vec<Leg>,
    /// The engine calls held for the targets, for the caller to release.
    pub released_media: Vec<ReplacementMedia>,
}

impl AbandonedReplacements {
    /// Whether the teardown found nothing to end.
    pub fn is_empty(&self) -> bool {
        self.cancelled.is_empty() && self.released_media.is_empty()
    }
}

impl CallActor {
    /// Whether a leg replacement is being carried out on this call: a
    /// siphon-terminated transfer or a `replace_peer`, from the moment it is
    /// accepted until it succeeds, fails or runs out of time.
    ///
    /// A call is re-paired once at a time. A second replacement would race the
    /// first for the same promotion: its target's 2xx would promote against a
    /// pair the first had already changed.
    pub fn replacement_in_flight(&self) -> bool {
        self.refer_subscriptions
            .iter()
            .any(|subscription| subscription.siphon_notifies)
    }
}

impl ReferSubscription {
    /// Whether this is a replacement still waiting on its targets: siphon
    /// dialled them, and neither an answer nor a failure has settled it.
    pub fn is_open_replacement(&self) -> bool {
        self.siphon_notifies
            && !self.targets.is_empty()
            && self.state == crate::b2bua::transfer::TransferState::Trying
    }

    /// The target whose INVITE rides Via `branch`.
    pub fn target(&self, branch: &str) -> Option<&ReplacementTarget> {
        self.targets.iter().find(|target| target.branch == branch)
    }

    /// The best of the responses the targets failed with (RFC 3261 §16.7 step
    /// 6), `also` standing in for one that never answered.
    pub fn best_failure(&self, also: Option<u16>) -> Option<u16> {
        crate::sip::best_response::best_status(
            self.targets
                .iter()
                .filter_map(|target| match target.outcome {
                    ReplacementOutcome::Failed(code) => Some(code),
                    _ => None,
                })
                .chain(also),
        )
    }
}
