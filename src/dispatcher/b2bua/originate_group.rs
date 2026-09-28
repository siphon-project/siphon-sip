//! Ringing several contacts as calls siphon places itself, and keeping the one
//! that answers first.
//!
//! An originate group rings each target — in practice each contact a registered
//! AoR resolved to ([`dial_targets_for_aor`]) — as its own originated call: its
//! own `CallActor`, its own INVITE over that contact's flow or Path, and every
//! response handled by [`handle_originated_call_response`] like any originate.
//! The group only decides which leg the call becomes:
//!
//! * the first leg to answer wins, and every other leg still ringing is
//!   CANCELled (RFC 3261 §9.1). A leg that answers after another won has its
//!   dialog released, ACK then BYE (§13.2.2.4, §15);
//! * `parallel` rings every target at once; `sequential` rings them one at a
//!   time in the order given, moving on when a leg fails or its own ring
//!   timeout ends it;
//! * the group as a whole has a deadline, and when it passes every leg still
//!   ringing is CANCELled.
//!
//! What the group reports goes to an [`OriginateGroupSink`] its creator
//! supplies. The `originate` control verb's sink publishes to the controller's
//! channel and binds that channel to the winner; a caller that rings phones for
//! a caller already on the line supplies its own.
//!
//! Every entry the store holds is removed on every way a group ends: a winner,
//! every leg failing, the deadline, and a cancel from the controller. A leg's
//! own index entry goes when that leg ends.

use std::time::Instant;

use crate::b2bua::actor::{DialBranch, DialBranchCause, DialBranchOutcome};
use crate::dispatcher::*;

/// How an originate group rings its targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginateGroupStrategy {
    /// Every target at once; the first to answer wins.
    Parallel,
    /// One target at a time, in order, moving on when a leg ends unanswered.
    Sequential,
}

impl OriginateGroupStrategy {
    /// The strategy named `text` (`parallel` / `sequential`, any case).
    pub fn parse(text: &str) -> Option<Self> {
        if text.eq_ignore_ascii_case("parallel") {
            Some(Self::Parallel)
        } else if text.eq_ignore_ascii_case("sequential") {
            Some(Self::Sequential)
        } else {
            None
        }
    }

    /// The name the control plane uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
            Self::Sequential => "sequential",
        }
    }
}

/// What an originate group rings, and how.
#[derive(Debug, Clone)]
pub struct OriginateGroupSpec {
    /// What every leg's INVITE carries. `to` is each leg's To — the AoR the
    /// contacts are registered at — while each leg's Request-URI is its own
    /// target; left empty, a leg's To is its target's AoR or, failing that,
    /// its URI. `timeout_secs` is each leg's own ring timeout (`0`: none).
    pub params: OriginateParams,
    /// One per leg, in the order a sequential group tries them. A target's
    /// `uri`, `next_hop`, `flow`, `route`, `headers` and `aor` apply to its
    /// leg, and so do the calling identity fields it names
    /// (`from`, `from_display`, `p_asserted_identity`, `privacy`).
    pub targets: Vec<DialTarget>,
    /// Parallel or sequential.
    pub strategy: OriginateGroupStrategy,
    /// The deadline of the group as a whole, in seconds from its start. `0`
    /// sets none, leaving each leg's own ring timeout as the only bound.
    pub total_timeout_secs: u32,
    /// Whether the first answer is final.
    pub answers: OriginateGroupAnswers,
}

/// When an answer settles a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginateGroupAnswers {
    /// The first leg to answer wins: every other leg is CANCELled at once and
    /// the sink's `answered` is its last call. What `originate {aor}` does.
    First,
    /// Each answer is provisional. Every answered leg is ACKed and reported to
    /// the sink's `answered`, while the legs still ringing keep ringing; the
    /// creator then either confirms one ([`confirm_originate_group_answer`]),
    /// which CANCELs the rest and releases every other answered leg, or rejects
    /// it ([`reject_originate_group_answer`]), and the group carries on as if
    /// that leg had failed. For a creator that has to do something with an
    /// answer before it can keep it — bridging it to a caller already on the
    /// line — and must fall back to the other legs when that fails.
    Confirmed,
}

/// A provisional response one leg of a group received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateLegProgress {
    /// The status, `180` or `183` in practice (`100` never reaches a group).
    pub code: u16,
    /// Whether it carried a session description (RFC 3960 early media).
    pub early_media: bool,
    /// That description, when it is text.
    pub sdp: Option<String>,
}

/// The leg that answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateGroupWinner {
    /// The group it won.
    pub group_id: String,
    /// Its `CallActor` id. From here on it is an ordinary originated call.
    pub internal_call_id: String,
    /// The SIP Call-ID of its dialog.
    pub sip_call_id: String,
    /// The branch as the group reported it, with its `answered` outcome.
    pub branch: DialBranch,
}

/// How a group ended without an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginateGroupFailure {
    /// The group.
    pub group_id: String,
    /// Why, in the vocabulary a plain originate's `StasisEnd` uses:
    /// `rejected`, `ring timeout`, `unsent`, `media_failed`, or the reason a
    /// cancel gave (`cancelled` by default).
    pub reason: String,
    /// The status that ended it: the best of the legs' own (RFC 3261 §16.7
    /// step 6) when every leg failed, `408` when the group timed out, `487`
    /// when it was cancelled, the answer's status when the winner could not
    /// be anchored.
    pub code: u16,
    /// The reason phrase that goes with `code`.
    pub response: String,
    /// Every leg the group placed, each with its outcome.
    pub branches: Vec<DialBranch>,
}

/// Where an originate group reports what happens to it.
///
/// Called outside every lock the group store holds, in the order things
/// happen, from whichever thread handled the response that moved the group.
/// For a group whose first answer is final, `answered` or `failed` is called
/// exactly once and last; the branch calls before it name the legs in the order
/// they were placed. For a group whose answers are confirmed, `answered` is
/// called once per leg that answers, and `failed` — only once no leg is ringing
/// or answered and awaiting its creator — is the last call when nothing is
/// confirmed; a confirmed group reports the legs it releases, and no more.
pub trait OriginateGroupSink: Send + Sync {
    /// A leg's INVITE was built and is about to go out.
    fn branch_created(&self, group_id: &str, branch: &DialBranch);
    /// A leg is ringing, or sent early media.
    fn branch_progress(&self, group_id: &str, branch: &DialBranch, progress: &OriginateLegProgress);
    /// A leg ended without winning; `branch.outcome` says how.
    fn branch_ended(&self, group_id: &str, branch: &DialBranch);
    /// A leg answered first and its media is set up. It is ACKed, and from
    /// here on an ordinary originated call: its later events are published
    /// under its own SIP Call-ID, and a hangup of it is a hangup of that call.
    /// Called before its `answered` state change is published, so a sink that
    /// binds a channel to it here gets that event.
    fn answered(&self, winner: &OriginateGroupWinner);
    /// The group ended with nobody answering.
    fn failed(&self, failure: &OriginateGroupFailure);
}

/// How a group is ended from outside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OriginateGroupEnd {
    /// Its creator gave up on it (a controller's hangup, its connection lost).
    Cancelled {
        /// Reported as the failure's `reason`.
        reason: String,
    },
    /// The group's own deadline passed.
    TimedOut,
}

impl OriginateGroupEnd {
    /// What each leg still ringing ends on.
    fn leg_outcome(&self) -> DialBranchOutcome {
        match self {
            Self::Cancelled { .. } => {
                DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled)
            }
            Self::TimedOut => {
                DialBranchOutcome::new(408, "Request Timeout", DialBranchCause::Timeout)
            }
        }
    }

    /// The failure's `reason`.
    fn reason(&self) -> String {
        match self {
            Self::Cancelled { reason } => reason.clone(),
            Self::TimedOut => "ring timeout".to_string(),
        }
    }
}

/// One leg a group placed.
#[derive(Debug, Clone)]
struct GroupLeg {
    internal_call_id: String,
    branch: DialBranch,
    /// Answered, and awaiting its creator's confirmation (a group whose
    /// answers are confirmed).
    answered: bool,
}

impl GroupLeg {
    /// Still ringing.
    fn is_live(&self) -> bool {
        self.branch.outcome.is_none() && !self.answered
    }

    /// Answered, not yet confirmed or rejected.
    fn is_pending(&self) -> bool {
        self.branch.outcome.is_none() && self.answered
    }
}

/// A group in the store.
struct OriginateGroup {
    params: OriginateParams,
    targets: Vec<DialTarget>,
    strategy: OriginateGroupStrategy,
    total_timeout_secs: u32,
    sink: Arc<dyn OriginateGroupSink>,
    /// The next target not yet placed.
    next_target: usize,
    legs: Vec<GroupLeg>,
    /// Legs are being placed right now. While they are, a leg ending does not
    /// move the group on: the placement does, once it is done, so a leg that
    /// fails in the middle of a parallel placement cannot fail the group
    /// before its siblings are out.
    placing: bool,
    /// Won, failed, timed out or cancelled. Nothing moves a concluded group.
    concluded: bool,
    deadline: Option<Instant>,
    /// Why the last target that could not be placed was refused.
    last_refusal: Option<OriginateError>,
    answers: OriginateGroupAnswers,
    /// The deadline passed while an answer awaited confirmation: the ringing
    /// legs were CANCELled and nothing more is placed, but the answers already
    /// in are still the creator's to confirm or reject.
    expired: bool,
}

impl OriginateGroup {
    /// What the group does now that nothing is being placed.
    fn next_step(&mut self, group_id: &str) -> Next {
        if self.concluded {
            return Next::Nothing;
        }
        if self
            .legs
            .iter()
            .any(|leg| leg.is_live() || leg.is_pending())
        {
            return Next::Continue;
        }
        if self.strategy == OriginateGroupStrategy::Sequential
            && self.next_target < self.targets.len()
            && !self.expired
        {
            self.placing = true;
            return Next::Place;
        }
        self.concluded = true;
        if self.legs.is_empty() {
            return Next::NothingPlaced(self.last_refusal.clone().unwrap_or_else(|| {
                OriginateError::Unroutable("no target could be dialled".to_string())
            }));
        }
        Next::Failed(
            Arc::clone(&self.sink),
            failure_from_branches(group_id, self.branches()),
        )
    }

    fn branches(&self) -> Vec<DialBranch> {
        self.legs.iter().map(|leg| leg.branch.clone()).collect()
    }
}

/// The failure a group whose every leg ended reports: the leg whose status
/// ranks best (RFC 3261 §16.7 step 6), with its own reason phrase.
fn failure_from_branches(group_id: &str, branches: Vec<DialBranch>) -> OriginateGroupFailure {
    let best = crate::sip::best_response::best_status(
        branches
            .iter()
            .filter_map(|branch| branch.outcome.as_ref().map(|outcome| outcome.code)),
    );
    let chosen = best.and_then(|code| {
        branches
            .iter()
            .filter_map(|branch| branch.outcome.as_ref())
            .find(|outcome| outcome.code == code)
            .cloned()
    });
    let (reason, code, response) = match chosen {
        Some(outcome) => (
            match outcome.cause {
                DialBranchCause::Rejected | DialBranchCause::Answered => "rejected",
                DialBranchCause::Timeout => "ring timeout",
                DialBranchCause::Cancelled => "cancelled",
                DialBranchCause::Unsent => "unsent",
                DialBranchCause::BridgeFailed => "bridge_failed",
            }
            .to_string(),
            outcome.code,
            outcome.reason,
        ),
        None => ("unsent".to_string(), 503, "Service Unavailable".to_string()),
    };
    OriginateGroupFailure {
        group_id: group_id.to_string(),
        reason,
        code,
        response,
        branches,
    }
}

/// What the group does next, decided under its lock and carried out outside it.
enum Next {
    /// Nothing: the group is concluded, or gone.
    Nothing,
    /// Legs are still ringing.
    Continue,
    /// Place the next target(s). The group is marked as placing.
    Place,
    /// Every leg ended unanswered: report the failure.
    Failed(Arc<dyn OriginateGroupSink>, OriginateGroupFailure),
    /// No target could even be dialled: nothing went on the wire, and the
    /// refusal is the caller's to report.
    NothingPlaced(OriginateError),
}

/// A leg that ended, and what its group does about it.
struct EndedLeg {
    group_id: String,
    sink: Arc<dyn OriginateGroupSink>,
    branch: DialBranch,
    next: Next,
}

/// What a leg is to its group, in the leg index.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LegRole {
    /// Ringing for the group named.
    Member(String),
    /// Answered, for a group whose answers are confirmed: awaiting its
    /// creator's confirmation or rejection.
    Answered(String),
    /// Answered first; its 2xx is being carried out.
    Winner,
    /// Being released: CANCELled when another leg won or the group ended, or
    /// answered after that.
    Loser,
}

/// What a 2xx means for the leg that got it, decided under the group's lock.
enum Claim {
    /// Not a group's leg.
    Ungrouped,
    /// The first to answer.
    Won(GroupClaimed),
    /// This leg already won, and the first copy of its 2xx is being carried
    /// out.
    Duplicate,
    /// Too late: another leg won, or the group ended.
    Lost,
}

/// A group whose leg answered first: what the winner's 2xx handling needs.
struct GroupClaimed {
    group_id: String,
    sink: Arc<dyn OriginateGroupSink>,
    winner: DialBranch,
    losers: Vec<GroupLeg>,
    /// The group's answers are confirmed: this one is provisional, nothing was
    /// released and the group stays in the store.
    provisional: bool,
}

/// A group ended from outside: what the ending has to CANCEL, release and
/// report.
struct GroupEnded {
    sink: Arc<dyn OriginateGroupSink>,
    /// Ringing legs, to CANCEL.
    live: Vec<GroupLeg>,
    /// Answered legs awaiting confirmation, to release (a cancelled group).
    answered: Vec<GroupLeg>,
    /// The group's failure; `None` when it timed out with answers still
    /// awaiting confirmation, and so carries on without its ringing legs.
    failure: Option<OriginateGroupFailure>,
}

/// An answer a group's creator confirmed: what the confirmation CANCELs and
/// releases.
struct GroupConfirmed {
    sink: Arc<dyn OriginateGroupSink>,
    live: Vec<GroupLeg>,
    answered: Vec<GroupLeg>,
}

/// Every originate group siphon is ringing, and the index from each leg's
/// `CallActor` id to its group.
#[derive(Default)]
pub struct OriginateGroupStore {
    groups: DashMap<String, OriginateGroup>,
    legs: DashMap<String, LegRole>,
}

impl std::fmt::Debug for OriginateGroupStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OriginateGroupStore")
            .field("groups", &self.groups.len())
            .field("legs", &self.legs.len())
            .finish()
    }
}

impl OriginateGroupStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether `group_id` names a group that is still ringing.
    pub fn contains(&self, group_id: &str) -> bool {
        self.groups
            .get(group_id)
            .is_some_and(|group| !group.concluded)
    }

    /// Groups held. Drains to zero when every group has ended — the leak gate.
    #[cfg(test)]
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Legs indexed. Drains to zero with the groups.
    #[cfg(test)]
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    /// The ids of the groups whose deadline has passed at `now`.
    pub fn take_timed_out(&self, now: Instant) -> Vec<String> {
        self.groups
            .iter()
            .filter(|group| {
                !group.concluded
                    && !group.expired
                    && group.deadline.is_some_and(|deadline| deadline <= now)
            })
            .map(|group| group.key().clone())
            .collect()
    }

    fn insert(&self, group_id: String, group: OriginateGroup) {
        self.groups.insert(group_id, group);
    }

    /// Drop a group. The index entries of legs it still had are the caller's
    /// to forget once each is released ([`Self::forget_leg`]): until then a
    /// 2xx on one has to find it and be told it lost.
    fn remove(&self, group_id: &str) {
        self.groups.remove(group_id);
    }

    /// Drop a released leg's index entry.
    fn forget_leg(&self, internal_call_id: &str) {
        self.legs.remove(internal_call_id);
    }

    /// The group a leg is ringing for, while it is.
    fn member_group(&self, internal_call_id: &str) -> Option<String> {
        match self.legs.get(internal_call_id)?.value() {
            LegRole::Member(group_id) => Some(group_id.clone()),
            LegRole::Answered(_) | LegRole::Winner | LegRole::Loser => None,
        }
    }

    /// Mark a group as placing its first legs and arm its deadline. `false`
    /// when it is gone, concluded or already started.
    fn start(&self, group_id: &str, now: Instant) -> bool {
        let Some(mut group) = self.groups.get_mut(group_id) else {
            return false;
        };
        if group.concluded || group.placing || group.next_target > 0 {
            return false;
        }
        group.placing = true;
        if group.total_timeout_secs > 0 {
            group.deadline =
                Some(now + std::time::Duration::from_secs(u64::from(group.total_timeout_secs)));
        }
        true
    }

    /// The targets to place now, with what their INVITEs carry: every target
    /// left for a parallel group, the next one for a sequential group. `None`
    /// for a group that is gone or concluded.
    fn targets_to_place(
        &self,
        group_id: &str,
    ) -> Option<(
        Vec<DialTarget>,
        OriginateParams,
        Arc<dyn OriginateGroupSink>,
    )> {
        let mut group = self.groups.get_mut(group_id)?;
        if group.concluded {
            group.placing = false;
            return None;
        }
        let end = match group.strategy {
            OriginateGroupStrategy::Parallel => group.targets.len(),
            OriginateGroupStrategy::Sequential => (group.next_target + 1).min(group.targets.len()),
        };
        let targets = group.targets[group.next_target..end].to_vec();
        group.next_target = end;
        Some((targets, group.params.clone(), Arc::clone(&group.sink)))
    }

    /// Record why a target could not be placed.
    fn record_refusal(&self, group_id: &str, refusal: OriginateError) {
        if let Some(mut group) = self.groups.get_mut(group_id) {
            group.last_refusal = Some(refusal);
        }
    }

    /// Add a placed leg to its group and index it. `false` when the group
    /// ended while the leg was being staged, so its INVITE must not go out.
    fn attach_leg(&self, group_id: &str, internal_call_id: &str, branch: DialBranch) -> bool {
        let Some(mut group) = self.groups.get_mut(group_id) else {
            return false;
        };
        if group.concluded {
            return false;
        }
        group.legs.push(GroupLeg {
            internal_call_id: internal_call_id.to_string(),
            branch,
            answered: false,
        });
        self.legs.insert(
            internal_call_id.to_string(),
            LegRole::Member(group_id.to_string()),
        );
        true
    }

    /// The placement is done: what the group does now.
    fn finish_placement(&self, group_id: &str) -> Next {
        let Some(mut group) = self.groups.get_mut(group_id) else {
            return Next::Nothing;
        };
        group.placing = false;
        group.next_step(group_id)
    }

    /// The live branch of a leg and its group's sink, for a progress report.
    fn live_branch(
        &self,
        internal_call_id: &str,
    ) -> Option<(String, Arc<dyn OriginateGroupSink>, DialBranch)> {
        let group_id = self.member_group(internal_call_id)?;
        let group = self.groups.get(&group_id)?;
        if group.concluded {
            return None;
        }
        let leg = group
            .legs
            .iter()
            .find(|leg| leg.internal_call_id == internal_call_id && leg.is_live())?;
        Some((
            group_id.clone(),
            Arc::clone(&group.sink),
            leg.branch.clone(),
        ))
    }

    /// A leg ended on `outcome`. `None` when it is no group's live leg: an
    /// ordinary originate, or a leg its group already settled (a loser the
    /// win CANCELled, a leg a cancel ended).
    fn leg_ended(&self, internal_call_id: &str, outcome: DialBranchOutcome) -> Option<EndedLeg> {
        let (_, role) = self.legs.remove_if(internal_call_id, |_, role| {
            matches!(role, LegRole::Member(_))
        })?;
        let LegRole::Member(group_id) = role else {
            return None;
        };
        let mut group = self.groups.get_mut(&group_id)?;
        if group.concluded {
            return None;
        }
        let leg = group
            .legs
            .iter_mut()
            .find(|leg| leg.internal_call_id == internal_call_id && leg.is_live())?;
        leg.branch.outcome = Some(outcome);
        let branch = leg.branch.clone();
        let next = if group.placing {
            Next::Continue
        } else {
            group.next_step(&group_id)
        };
        Some(EndedLeg {
            sink: Arc::clone(&group.sink),
            group_id,
            branch,
            next,
        })
    }

    /// A leg received a 2xx. The first leg to claim its group wins it: the
    /// group concludes, the winner's branch is marked answered, every other
    /// live leg is settled as cancelled, and the index records each role so a
    /// 2xx on any of them in the meantime is told where it stands.
    fn claim_answer(&self, internal_call_id: &str, code: u16) -> Claim {
        let Some(role) = self
            .legs
            .get(internal_call_id)
            .map(|entry| entry.value().clone())
        else {
            return Claim::Ungrouped;
        };
        let group_id = match role {
            LegRole::Member(group_id) => group_id,
            LegRole::Answered(_) | LegRole::Winner => return Claim::Duplicate,
            LegRole::Loser => return Claim::Lost,
        };
        let Some(mut group) = self.groups.get_mut(&group_id) else {
            // Removed by an ending that is releasing its legs right now.
            self.legs
                .insert(internal_call_id.to_string(), LegRole::Loser);
            return Claim::Lost;
        };
        if group.concluded {
            self.legs
                .insert(internal_call_id.to_string(), LegRole::Loser);
            return Claim::Lost;
        }
        let provisional = group.answers == OriginateGroupAnswers::Confirmed;
        let Some(winner) = group
            .legs
            .iter_mut()
            .find(|leg| leg.internal_call_id == internal_call_id && leg.is_live())
        else {
            self.legs
                .insert(internal_call_id.to_string(), LegRole::Loser);
            return Claim::Lost;
        };
        let answered = DialBranchOutcome::new(code, "OK", DialBranchCause::Answered);
        if provisional {
            // Provisional: the leg is answered but not the group's until its
            // creator says so, and every other leg keeps ringing meanwhile.
            winner.answered = true;
            let mut reported = winner.branch.clone();
            reported.outcome = Some(answered);
            self.legs.insert(
                internal_call_id.to_string(),
                LegRole::Answered(group_id.clone()),
            );
            return Claim::Won(GroupClaimed {
                sink: Arc::clone(&group.sink),
                group_id,
                winner: reported,
                losers: Vec::new(),
                provisional: true,
            });
        }
        winner.branch.outcome = Some(answered);
        let winner = winner.branch.clone();
        self.legs
            .insert(internal_call_id.to_string(), LegRole::Winner);
        let cancelled =
            DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled);
        let mut losers = Vec::new();
        for leg in group.legs.iter_mut().filter(|leg| leg.is_live()) {
            leg.branch.outcome = Some(cancelled.clone());
            self.legs
                .insert(leg.internal_call_id.clone(), LegRole::Loser);
            losers.push(leg.clone());
        }
        group.concluded = true;
        Claim::Won(GroupClaimed {
            sink: Arc::clone(&group.sink),
            group_id,
            winner,
            losers,
            provisional: false,
        })
    }

    /// End a group from outside: settle every live leg on `end`'s outcome.
    /// The group concludes, except when it times out with answers still
    /// awaiting their creator: those stay the creator's to confirm or reject,
    /// and only its ringing legs end (the group is marked expired so nothing
    /// more is placed). A cancel also settles the answers awaiting
    /// confirmation, to be released. `None` for a group that is gone or
    /// already concluded.
    fn end(&self, group_id: &str, end: &OriginateGroupEnd) -> Option<GroupEnded> {
        let mut group = self.groups.get_mut(group_id)?;
        if group.concluded || (group.expired && *end == OriginateGroupEnd::TimedOut) {
            return None;
        }
        let outcome = end.leg_outcome();
        let mut live = Vec::new();
        for leg in group.legs.iter_mut().filter(|leg| leg.is_live()) {
            leg.branch.outcome = Some(outcome.clone());
            self.legs
                .insert(leg.internal_call_id.clone(), LegRole::Loser);
            live.push(leg.clone());
        }
        let awaiting = group.legs.iter().any(GroupLeg::is_pending);
        if awaiting && *end == OriginateGroupEnd::TimedOut {
            group.expired = true;
            return Some(GroupEnded {
                sink: Arc::clone(&group.sink),
                live,
                answered: Vec::new(),
                failure: None,
            });
        }
        let released =
            DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled);
        let mut answered = Vec::new();
        for leg in group.legs.iter_mut().filter(|leg| leg.is_pending()) {
            leg.branch.outcome = Some(released.clone());
            self.legs
                .insert(leg.internal_call_id.clone(), LegRole::Loser);
            answered.push(leg.clone());
        }
        group.concluded = true;
        Some(GroupEnded {
            sink: Arc::clone(&group.sink),
            failure: Some(OriginateGroupFailure {
                group_id: group_id.to_string(),
                reason: end.reason(),
                code: outcome.code,
                response: outcome.reason.clone(),
                branches: group.branches(),
            }),
            live,
            answered,
        })
    }

    /// Confirm `internal_call_id`'s answer: the group concludes, won by it,
    /// and every other leg — ringing, or answered and awaiting confirmation —
    /// is settled as cancelled, for the caller to CANCEL or release. `None`
    /// unless that leg's answer is awaiting confirmation.
    fn confirm(&self, group_id: &str, internal_call_id: &str) -> Option<GroupConfirmed> {
        let mut group = self.groups.get_mut(group_id)?;
        if group.concluded {
            return None;
        }
        let winner = group
            .legs
            .iter_mut()
            .find(|leg| leg.internal_call_id == internal_call_id && leg.is_pending())?;
        winner.branch.outcome = Some(DialBranchOutcome::new(200, "OK", DialBranchCause::Answered));
        self.legs.remove(internal_call_id);
        let cancelled =
            DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled);
        let (mut live, mut answered) = (Vec::new(), Vec::new());
        for leg in group
            .legs
            .iter_mut()
            .filter(|leg| leg.is_live() || leg.is_pending())
        {
            let pending = leg.is_pending();
            leg.branch.outcome = Some(cancelled.clone());
            self.legs
                .insert(leg.internal_call_id.clone(), LegRole::Loser);
            if pending {
                answered.push(leg.clone());
            } else {
                live.push(leg.clone());
            }
        }
        group.concluded = true;
        Some(GroupConfirmed {
            sink: Arc::clone(&group.sink),
            live,
            answered,
        })
    }

    /// Reject `internal_call_id`'s answer: the leg ends on `outcome` and the
    /// group moves on as if it had failed. `None` unless that leg's answer is
    /// awaiting confirmation.
    fn reject(
        &self,
        group_id: &str,
        internal_call_id: &str,
        outcome: DialBranchOutcome,
    ) -> Option<EndedLeg> {
        let mut group = self.groups.get_mut(group_id)?;
        if group.concluded {
            return None;
        }
        let leg = group
            .legs
            .iter_mut()
            .find(|leg| leg.internal_call_id == internal_call_id && leg.is_pending())?;
        leg.branch.outcome = Some(outcome);
        let branch = leg.branch.clone();
        self.legs.remove(internal_call_id);
        let next = if group.placing {
            Next::Continue
        } else {
            group.next_step(group_id)
        };
        Some(EndedLeg {
            sink: Arc::clone(&group.sink),
            group_id: group_id.to_string(),
            branch,
            next,
        })
    }
}

/// Create an originate group ringing nothing yet, and return its id.
///
/// Two steps so the creator can make the group addressable — bind a channel
/// to its id — before any INVITE is on the wire and a fast phone's response
/// has nowhere to be reported. [`start_originate_group`] places the legs.
pub fn create_originate_group(
    state: &DispatcherState,
    spec: OriginateGroupSpec,
    sink: Arc<dyn OriginateGroupSink>,
) -> Result<String, OriginateError> {
    if spec.targets.is_empty() {
        return Err(OriginateError::Unroutable(
            "an originate group needs at least one target".to_string(),
        ));
    }
    // The shared shape of every leg is checked once here, not per leg: a
    // media plan this deployment cannot serve fails the command, never a call.
    if let OriginateMedia::Anchor { profile, .. } = &spec.params.media {
        originate_validate_anchor(profile, state)?;
    }
    let group_id = format!("originate-group-{}", uuid::Uuid::new_v4().simple());
    state.originate_groups.insert(
        group_id.clone(),
        OriginateGroup {
            params: spec.params,
            targets: spec.targets,
            strategy: spec.strategy,
            total_timeout_secs: spec.total_timeout_secs,
            sink,
            next_target: 0,
            legs: Vec::new(),
            placing: false,
            concluded: false,
            deadline: None,
            last_refusal: None,
            answers: spec.answers,
            expired: false,
        },
    );
    Ok(group_id)
}

/// Place a group's first legs — every target for a parallel group, the first
/// that can be dialled for a sequential one — and arm its deadline.
///
/// Returns the branches placed. When no target could be dialled at all,
/// nothing is on the wire, the group is gone, its sink is not told, and the
/// last refusal is returned for the caller to report as the command's.
pub fn start_originate_group(
    state: &DispatcherState,
    group_id: &str,
) -> Result<Vec<DialBranch>, OriginateError> {
    if !state.originate_groups.start(group_id, Instant::now()) {
        return Err(OriginateError::Unavailable(format!(
            "originate group '{group_id}' is not waiting to start"
        )));
    }
    let placed = drive(state, group_id, Next::Place)?;
    info!(
        group_id,
        legs = placed.len(),
        "B2BUA: originate group ringing"
    );
    Ok(placed)
}

/// End a group from outside it: CANCEL every leg still ringing (RFC 3261 §9.1),
/// release every answer awaiting confirmation (BYE, §15) and report the
/// failure. A group whose deadline passes while an answer awaits confirmation
/// only loses its ringing legs; it fails once no answer is left. `false` for a
/// group that is gone or already ended.
pub fn cancel_originate_group(
    state: &DispatcherState,
    group_id: &str,
    end: OriginateGroupEnd,
) -> bool {
    let Some(ended) = state.originate_groups.end(group_id, &end) else {
        return false;
    };
    let reason = end.reason();
    if ended.failure.is_some() {
        // Gone from the store before its legs are CANCELled, so each leg
        // ending below finds no group to move.
        state.originate_groups.remove(group_id);
    }
    info!(
        group_id,
        %reason,
        legs = ended.live.len(),
        answered = ended.answered.len(),
        concluded = ended.failure.is_some(),
        "B2BUA: originate group ended before an answer was kept"
    );
    for leg in &ended.live {
        abandon_leg(state, leg, &reason);
        state.originate_groups.forget_leg(&leg.internal_call_id);
        ended.sink.branch_ended(group_id, &leg.branch);
    }
    for leg in &ended.answered {
        release_answered_leg(state, leg);
        ended.sink.branch_ended(group_id, &leg.branch);
    }
    if let Some(failure) = &ended.failure {
        ended.sink.failed(failure);
    }
    true
}

/// The `Reason` an answered leg is released with when its group keeps another
/// answer, or is abandoned (RFC 3326; Q.850 16, normal clearing).
const RELEASED_REASON: &str = q850_reason!(16, "answered elsewhere");

/// BYE an answered leg the group will not keep, and forget it.
fn release_answered_leg(state: &DispatcherState, leg: &GroupLeg) {
    b2bua_terminate_call_inner(&leg.internal_call_id, Some(RELEASED_REASON), "b2bua", state);
    state.originate_groups.forget_leg(&leg.internal_call_id);
}

/// Keep `internal_call_id`'s answer, for a group whose answers are confirmed:
/// the group is won by it, every leg still ringing is CANCELled (RFC 3261
/// §9.1) and every other answered leg is released (BYE, §15), each reported as
/// cancelled. The sink gets no further call. `false` unless that leg's answer
/// is awaiting confirmation.
pub fn confirm_originate_group_answer(
    state: &DispatcherState,
    group_id: &str,
    internal_call_id: &str,
) -> bool {
    let Some(confirmed) = state.originate_groups.confirm(group_id, internal_call_id) else {
        return false;
    };
    state.originate_groups.remove(group_id);
    info!(
        group_id,
        call_id = %internal_call_id,
        cancelled = confirmed.live.len(),
        released = confirmed.answered.len(),
        "B2BUA: originate group answer kept"
    );
    for leg in &confirmed.live {
        abandon_leg(state, leg, "answered elsewhere");
        state.originate_groups.forget_leg(&leg.internal_call_id);
        confirmed.sink.branch_ended(group_id, &leg.branch);
    }
    for leg in &confirmed.answered {
        release_answered_leg(state, leg);
        confirmed.sink.branch_ended(group_id, &leg.branch);
    }
    true
}

/// Refuse `internal_call_id`'s answer, for a group whose answers are
/// confirmed: the leg ends on `outcome`, reported to the sink, and the group
/// carries on as if it had failed — the next target of a sequential group, or
/// its failure once no leg is ringing or answered. Releasing the answered call
/// itself is the caller's. `false` unless that leg's answer is awaiting
/// confirmation.
pub fn reject_originate_group_answer(
    state: &DispatcherState,
    group_id: &str,
    internal_call_id: &str,
    outcome: DialBranchOutcome,
) -> bool {
    let Some(ended) = state
        .originate_groups
        .reject(group_id, internal_call_id, outcome)
    else {
        return false;
    };
    ended.sink.branch_ended(&ended.group_id, &ended.branch);
    if let Err(refusal) = drive(state, &ended.group_id, ended.next) {
        error!(
            group_id = %ended.group_id,
            "B2BUA: originate group reported placing nothing after an answer was refused: {refusal}"
        );
    }
    true
}

/// CANCEL one leg of a group, keeping it answerable for a 2xx that races the
/// CANCEL.
fn abandon_leg(state: &DispatcherState, leg: &GroupLeg, reason: &str) {
    if let Some(outcome) = leg.branch.outcome.clone() {
        abandon_originated_call(
            state,
            &leg.internal_call_id,
            &leg.branch.leg_sip_call_id,
            Some(reason),
            outcome,
        );
    }
}

/// Carry out `next` and whatever it leads to, placing legs until the group is
/// ringing, concluded, or out of targets. Returns every branch it placed, or
/// the refusal when a group placed nothing at all.
fn drive(
    state: &DispatcherState,
    group_id: &str,
    mut next: Next,
) -> Result<Vec<DialBranch>, OriginateError> {
    let mut placed = Vec::new();
    loop {
        match next {
            Next::Nothing | Next::Continue => return Ok(placed),
            Next::Place => {
                let Some((targets, params, sink)) =
                    state.originate_groups.targets_to_place(group_id)
                else {
                    return Ok(placed);
                };
                for target in targets {
                    if let Some(branch) = place_leg(state, group_id, &target, &params, &sink) {
                        placed.push(branch);
                    }
                }
                next = state.originate_groups.finish_placement(group_id);
            }
            Next::Failed(sink, failure) => {
                state.originate_groups.remove(group_id);
                info!(
                    group_id,
                    reason = %failure.reason,
                    code = failure.code,
                    "B2BUA: originate group failed — no leg answered"
                );
                sink.failed(&failure);
                return Ok(placed);
            }
            Next::NothingPlaced(refusal) => {
                state.originate_groups.remove(group_id);
                return Err(refusal);
            }
        }
    }
}

/// What one leg's INVITE carries: the group's, with the target's own over it.
///
/// * The To is the AoR the target is a contact of, when it names one; the
///   group's `to` otherwise, and the target's own URI when the group names
///   none either (a group of URIs dialled as written, each its own callee).
/// * A target's `next_hop` and headers (in a stable order) replace the
///   group's.
/// * A target that names a calling identity presents it: `from` and
///   `from_display` together (an empty display name presents none), and its
///   `p_asserted_identity` and `privacy` where it names them. A contact an AoR
///   resolved to names none, so every leg of an `originate {aor}` presents the
///   group's.
fn leg_params(template: &OriginateParams, target: &DialTarget) -> OriginateParams {
    let mut params = template.clone();
    if let Some(aor) = &target.aor {
        params.to = aor.clone();
    } else if params.to.is_empty() {
        params.to = target.uri.clone();
    }
    if target.next_hop.is_some() {
        params.next_hop = target.next_hop.clone();
    }
    if target.from.is_some() || target.from_display.is_some() {
        if target.from.is_some() {
            params.from = target.from.clone();
        }
        params.from_display = target.from_display.clone();
    }
    if target.p_asserted_identity.is_some() {
        params.p_asserted_identity = target.p_asserted_identity.clone();
    }
    if target.privacy.is_some() {
        params.privacy = target.privacy;
    }
    let mut headers: Vec<(&String, &String)> = target.headers.iter().collect();
    headers.sort();
    for (name, value) in headers {
        params
            .headers
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        params.headers.push((name.clone(), value.clone()));
    }
    params
}

/// Stage one leg, attach it to its group, and send its INVITE. `None` when
/// the target could not be staged (the refusal is recorded on the group) or
/// the group ended meanwhile.
fn place_leg(
    state: &DispatcherState,
    group_id: &str,
    target: &DialTarget,
    template: &OriginateParams,
    sink: &Arc<dyn OriginateGroupSink>,
) -> Option<DialBranch> {
    let params = leg_params(template, target);
    let route = OriginateRoute {
        request_uri: Some(target.uri.clone()),
        flow: target.flow.clone(),
        route: target.route.clone(),
    };
    let prepared = match prepare_originate_routed(state, params, &route) {
        Ok(prepared) => prepared,
        Err(refusal) => {
            warn!(
                group_id,
                target = %target.uri,
                "B2BUA: originate group cannot dial a target: {refusal}"
            );
            state.originate_groups.record_refusal(group_id, refusal);
            return None;
        }
    };
    let branch = state
        .call_actors
        .get_call(&prepared.internal_call_id)
        .map(|call| DialBranch::of_leg(&call.a_leg, &target.uri, target.aor.clone()))?;
    if !state
        .originate_groups
        .attach_leg(group_id, &prepared.internal_call_id, branch.clone())
    {
        // The group ended while this leg was staged: its INVITE never goes.
        state.call_actors.remove_call(&prepared.internal_call_id);
        state
            .call_event_receivers
            .remove(&prepared.internal_call_id);
        return None;
    }
    sink.branch_created(group_id, &branch);
    if !dial_originate(state, &prepared) {
        // Staged and attached, but the transport would not take its INVITE.
        originate_group_leg_ended(
            state,
            &prepared.internal_call_id,
            DialBranchOutcome::new(503, "Service Unavailable", DialBranchCause::Unsent),
        );
    }
    Some(branch)
}

/// A provisional on an originated call: reported to its group's sink when it
/// is one's live leg.
pub fn originate_group_leg_progress(
    state: &DispatcherState,
    internal_call_id: &str,
    progress: OriginateLegProgress,
) {
    if let Some((group_id, sink, branch)) = state.originate_groups.live_branch(internal_call_id) {
        sink.branch_progress(&group_id, &branch, &progress);
    }
}

/// An originated call ended unanswered on `outcome`: when it was a group's
/// live leg, reported, and the group moves on — the next target of a
/// sequential group, or the group's failure once no leg is left.
pub fn originate_group_leg_ended(
    state: &DispatcherState,
    internal_call_id: &str,
    outcome: DialBranchOutcome,
) {
    let Some(ended) = state.originate_groups.leg_ended(internal_call_id, outcome) else {
        return;
    };
    ended.sink.branch_ended(&ended.group_id, &ended.branch);
    if let Err(refusal) = drive(state, &ended.group_id, ended.next) {
        // Only a group that never placed a leg can end this way, and this
        // group had one — the leg that just ended.
        error!(
            group_id = %ended.group_id,
            "B2BUA: originate group reported placing nothing after a leg ended: {refusal}"
        );
    }
}

/// What a 2xx on an originated call means for its group.
pub enum OriginateGroupClaim {
    /// Not a group's leg: an ordinary originate.
    Ungrouped,
    /// The first leg to answer. Its losers are already CANCELled.
    Won(Box<OriginateGroupWin>),
    /// A copy of the winning 2xx, arriving while the first is still being
    /// carried out. The first one ACKs; this one does nothing.
    Duplicate,
    /// Another leg won, or the group ended: release this dialog, then
    /// [`originate_group_leg_released`].
    Lost,
}

/// The winning leg of a group, between its 2xx and its answer being carried
/// out. The group is already gone from the store; this is what reports the
/// outcome.
pub struct OriginateGroupWin {
    group_id: String,
    internal_call_id: String,
    sink: Arc<dyn OriginateGroupSink>,
    winner: DialBranch,
    losers: Vec<DialBranch>,
    store: Arc<OriginateGroupStore>,
    /// The group's answers are confirmed: this one is provisional and the
    /// group is still in the store.
    provisional: bool,
}

impl OriginateGroupWin {
    /// The winner's media is set up and its 2xx ACKed: hand it over.
    pub fn answered(self, sip_call_id: &str) {
        self.sink.answered(&OriginateGroupWinner {
            group_id: self.group_id.clone(),
            internal_call_id: self.internal_call_id.clone(),
            sip_call_id: sip_call_id.to_string(),
            branch: self.winner.clone(),
        });
    }

    /// The winner answered but its media could not be anchored: the call it
    /// would have become has already been released. With the other legs
    /// CANCELled when it won, the group fails; a provisional answer is refused
    /// instead, and the group carries on with its other legs.
    pub fn media_failed(self, state: &DispatcherState, code: u16, reason: &str) {
        if self.provisional {
            reject_originate_group_answer(
                state,
                &self.group_id,
                &self.internal_call_id,
                DialBranchOutcome::new(code, reason, DialBranchCause::Rejected),
            );
            return;
        }
        let mut branches = self.losers.clone();
        branches.push(self.winner.clone());
        self.sink.failed(&OriginateGroupFailure {
            group_id: self.group_id.clone(),
            reason: "media_failed".to_string(),
            code,
            response: reason.to_string(),
            branches,
        });
    }
}

impl Drop for OriginateGroupWin {
    /// However the winner's 2xx handling ends, the leg's index entry goes
    /// with it: past this point a retransmitted 2xx is an answered call's.
    fn drop(&mut self) {
        self.store.forget_leg(&self.internal_call_id);
    }
}

/// A 2xx arrived on an originated call: claim its group's win for it, when it
/// is a group's leg. The losers are CANCELled here, before the winner's media
/// is anchored, so none keeps ringing while the engine answers.
pub fn originate_group_claim_answer(
    state: &DispatcherState,
    internal_call_id: &str,
    code: u16,
) -> OriginateGroupClaim {
    let claimed = match state.originate_groups.claim_answer(internal_call_id, code) {
        Claim::Won(claimed) => claimed,
        Claim::Ungrouped => return OriginateGroupClaim::Ungrouped,
        Claim::Duplicate => return OriginateGroupClaim::Duplicate,
        Claim::Lost => return OriginateGroupClaim::Lost,
    };
    // A provisional answer leaves the group ringing, in the store.
    if !claimed.provisional {
        state.originate_groups.remove(&claimed.group_id);
    }
    info!(
        group_id = %claimed.group_id,
        call_id = %internal_call_id,
        target = %claimed.winner.target,
        losers = claimed.losers.len(),
        provisional = claimed.provisional,
        "B2BUA: originate group answered"
    );
    for loser in &claimed.losers {
        abandon_leg(state, loser, "answered elsewhere");
        state.originate_groups.forget_leg(&loser.internal_call_id);
        claimed.sink.branch_ended(&claimed.group_id, &loser.branch);
    }
    OriginateGroupClaim::Won(Box::new(OriginateGroupWin {
        group_id: claimed.group_id,
        internal_call_id: internal_call_id.to_string(),
        sink: claimed.sink,
        winner: claimed.winner,
        losers: claimed.losers.into_iter().map(|leg| leg.branch).collect(),
        store: Arc::clone(&state.originate_groups),
        provisional: claimed.provisional,
    }))
}

/// A leg that lost its group's race has been released: forget it.
pub fn originate_group_leg_released(state: &DispatcherState, internal_call_id: &str) {
    state.originate_groups.forget_leg(internal_call_id);
}

/// [`create_originate_group`] on the running B2BUA.
pub fn b2bua_originate_group_create(
    spec: OriginateGroupSpec,
    sink: Arc<dyn OriginateGroupSink>,
) -> Result<String, OriginateError> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(OriginateError::Unavailable(
            "b2bua is not running — nothing to originate from".to_string(),
        ));
    };
    create_originate_group(&control.state, spec, sink)
}

/// [`start_originate_group`] on the running B2BUA.
pub fn b2bua_originate_group_start(group_id: &str) -> Result<Vec<DialBranch>, OriginateError> {
    let Some(control) = B2BUA_CONTROL.get() else {
        return Err(OriginateError::Unavailable(
            "b2bua is not running — nothing to originate from".to_string(),
        ));
    };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread (the control command consumer).
    let _enter = control.runtime.enter();
    start_originate_group(&control.state, group_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branch(target: &str, outcome: Option<DialBranchOutcome>) -> DialBranch {
        DialBranch {
            leg_id: format!("leg-{target}"),
            leg_sip_call_id: format!("{target}@siphon"),
            target: target.to_string(),
            aor: Some("sip:201@example.com".to_string()),
            outcome,
        }
    }

    struct Silent;

    impl OriginateGroupSink for Silent {
        fn branch_created(&self, _: &str, _: &DialBranch) {}
        fn branch_progress(&self, _: &str, _: &DialBranch, _: &OriginateLegProgress) {}
        fn branch_ended(&self, _: &str, _: &DialBranch) {}
        fn answered(&self, _: &OriginateGroupWinner) {}
        fn failed(&self, _: &OriginateGroupFailure) {}
    }

    fn group(strategy: OriginateGroupStrategy, targets: usize) -> OriginateGroup {
        OriginateGroup {
            params: OriginateParams {
                to: "sip:201@example.com".to_string(),
                to_display: None,
                from: None,
                from_display: None,
                next_hop: None,
                p_asserted_identity: None,
                privacy: None,
                headers: Vec::new(),
                timeout_secs: 30,
                media: OriginateMedia::Offer {
                    body: b"v=0\r\n".to_vec(),
                    content_type: "application/sdp".to_string(),
                },
                session_timer: None,
            },
            targets: (0..targets)
                .map(|index| DialTarget {
                    uri: format!("sip:201@198.51.100.{index}"),
                    ..Default::default()
                })
                .collect(),
            strategy,
            total_timeout_secs: 60,
            sink: Arc::new(Silent),
            next_target: 0,
            legs: Vec::new(),
            placing: false,
            concluded: false,
            deadline: None,
            last_refusal: None,
            answers: OriginateGroupAnswers::First,
            expired: false,
        }
    }

    /// A store holding one group with `legs` placed legs, `leg-0`...
    fn store_with(strategy: OriginateGroupStrategy, legs: usize) -> OriginateGroupStore {
        let store = OriginateGroupStore::new();
        store.insert("group".to_string(), group(strategy, legs));
        assert!(store.start("group", Instant::now()));
        let _ = store.targets_to_place("group");
        for index in 0..legs {
            assert!(store.attach_leg(
                "group",
                &format!("leg-{index}"),
                branch(&format!("sip:201@198.51.100.{index}"), None),
            ));
        }
        store
    }

    /// [`store_with`] for a group whose answers are confirmed.
    fn confirmed_store(strategy: OriginateGroupStrategy, legs: usize) -> OriginateGroupStore {
        let store = store_with(strategy, legs);
        if let Some(mut group) = store.groups.get_mut("group") {
            group.answers = OriginateGroupAnswers::Confirmed;
        }
        assert!(matches!(store.finish_placement("group"), Next::Continue));
        store
    }

    fn bridge_failed() -> DialBranchOutcome {
        DialBranchOutcome::new(488, "Bridge Failed", DialBranchCause::BridgeFailed)
    }

    #[test]
    fn a_provisional_answer_leaves_every_other_leg_ringing() {
        let store = confirmed_store(OriginateGroupStrategy::Parallel, 3);
        let Claim::Won(first) = store.claim_answer("leg-0", 200) else {
            panic!("an answer is claimed");
        };
        assert!(first.provisional);
        assert!(first.losers.is_empty(), "nobody is CANCELled yet");
        assert!(store.contains("group"), "the group rings on");
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Duplicate));
        // A second answer is claimed too: a standby.
        let Claim::Won(second) = store.claim_answer("leg-1", 200) else {
            panic!("a second answer is claimed");
        };
        assert!(second.provisional);
        // Positive control: the group whose first answer is final releases.
        let final_store = store_with(OriginateGroupStrategy::Parallel, 3);
        let Claim::Won(won) = final_store.claim_answer("leg-0", 200) else {
            panic!("the first claim wins");
        };
        assert_eq!(won.losers.len(), 2);
        assert!(!won.provisional);
    }

    #[test]
    fn confirming_an_answer_releases_the_ringing_and_the_standbys() {
        let store = confirmed_store(OriginateGroupStrategy::Parallel, 3);
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Won(_)));
        assert!(matches!(store.claim_answer("leg-1", 200), Claim::Won(_)));
        assert!(store.confirm("group", "leg-2").is_none(), "not answered");
        let confirmed = store.confirm("group", "leg-0").expect("an answer to keep");
        assert_eq!(confirmed.live.len(), 1, "leg-2 is CANCELled");
        assert_eq!(confirmed.answered.len(), 1, "leg-1 is released");
        assert!(!store.contains("group"));
        assert!(store.confirm("group", "leg-1").is_none(), "once");
    }

    #[test]
    fn a_refused_answer_moves_the_group_on_and_fails_it_only_when_nothing_is_left() {
        let store = confirmed_store(OriginateGroupStrategy::Parallel, 2);
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Won(_)));
        let refused = store
            .reject("group", "leg-0", bridge_failed())
            .expect("an answer to refuse");
        assert!(matches!(refused.next, Next::Continue), "leg-1 still rings");
        assert_eq!(
            refused.branch.outcome.map(|outcome| outcome.cause),
            Some(DialBranchCause::BridgeFailed)
        );
        assert!(matches!(store.claim_answer("leg-1", 200), Claim::Won(_)));
        let last = store
            .reject("group", "leg-1", bridge_failed())
            .expect("an answer to refuse");
        assert!(matches!(last.next, Next::Failed(_, _)), "nothing is left");
        assert!(store.reject("group", "leg-1", bridge_failed()).is_none());
    }

    #[test]
    fn a_sequential_group_places_the_next_target_after_a_refused_answer() {
        let store = OriginateGroupStore::new();
        store.insert(
            "group".to_string(),
            group(OriginateGroupStrategy::Sequential, 2),
        );
        if let Some(mut group) = store.groups.get_mut("group") {
            group.answers = OriginateGroupAnswers::Confirmed;
        }
        assert!(store.start("group", Instant::now()));
        let _ = store.targets_to_place("group");
        assert!(store.attach_leg("group", "leg-0", branch("a", None)));
        assert!(matches!(store.finish_placement("group"), Next::Continue));
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Won(_)));
        let refused = store
            .reject("group", "leg-0", bridge_failed())
            .expect("an answer to refuse");
        assert!(matches!(refused.next, Next::Place), "the next target");
    }

    #[test]
    fn a_deadline_keeps_the_answers_awaiting_confirmation() {
        let store = confirmed_store(OriginateGroupStrategy::Parallel, 2);
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Won(_)));
        let ended = store
            .end("group", &OriginateGroupEnd::TimedOut)
            .expect("the deadline ends the ringing");
        assert_eq!(ended.live.len(), 1, "leg-1 stops ringing");
        assert!(ended.failure.is_none(), "leg-0 is still to be decided");
        assert!(store.take_timed_out(Instant::now()).is_empty(), "once");
        // Refused, the answer leaves nothing: the group fails.
        let refused = store
            .reject("group", "leg-0", bridge_failed())
            .expect("an answer to refuse");
        assert!(matches!(refused.next, Next::Failed(_, _)));
        // A cancel still releases an answer awaiting confirmation.
        let store = confirmed_store(OriginateGroupStrategy::Parallel, 1);
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Won(_)));
        let cancelled = store
            .end(
                "group",
                &OriginateGroupEnd::Cancelled {
                    reason: "gone".to_string(),
                },
            )
            .expect("a cancel ends the group");
        assert_eq!(cancelled.answered.len(), 1);
        assert!(cancelled.failure.is_some());
    }

    #[test]
    fn a_strategy_parses_from_its_name() {
        assert_eq!(
            OriginateGroupStrategy::parse("PARALLEL"),
            Some(OriginateGroupStrategy::Parallel)
        );
        assert_eq!(
            OriginateGroupStrategy::parse("sequential"),
            Some(OriginateGroupStrategy::Sequential)
        );
        assert_eq!(OriginateGroupStrategy::parse("hunt"), None);
        assert_eq!(OriginateGroupStrategy::Sequential.as_str(), "sequential");
        assert_eq!(OriginateGroupStrategy::Parallel.as_str(), "parallel");
    }

    #[test]
    fn a_failure_reports_the_best_status_with_its_own_reason() {
        let failure = failure_from_branches(
            "group",
            vec![
                branch(
                    "a",
                    Some(DialBranchOutcome::new(
                        408,
                        "Request Timeout",
                        DialBranchCause::Timeout,
                    )),
                ),
                branch(
                    "b",
                    Some(DialBranchOutcome::new(
                        486,
                        "Busy Here",
                        DialBranchCause::Rejected,
                    )),
                ),
            ],
        );
        // RFC 3261 §16.7 step 6 ranks 486 (a resubmission hint) over the 408
        // a silent phone ends on.
        assert_eq!(
            (
                failure.reason.as_str(),
                failure.code,
                failure.response.as_str()
            ),
            ("rejected", 486, "Busy Here")
        );
        assert_eq!(failure.branches.len(), 2);

        let timed_out = failure_from_branches(
            "group",
            vec![branch(
                "a",
                Some(DialBranchOutcome::new(
                    408,
                    "Request Timeout",
                    DialBranchCause::Timeout,
                )),
            )],
        );
        assert_eq!(
            (timed_out.reason.as_str(), timed_out.code),
            ("ring timeout", 408)
        );

        let unsent = failure_from_branches(
            "group",
            vec![branch(
                "a",
                Some(DialBranchOutcome::new(
                    503,
                    "Service Unavailable",
                    DialBranchCause::Unsent,
                )),
            )],
        );
        assert_eq!((unsent.reason.as_str(), unsent.code), ("unsent", 503));
    }

    #[test]
    fn an_ending_settles_each_leg_by_how_the_group_ended() {
        let cancelled = OriginateGroupEnd::Cancelled {
            reason: "caller gave up".to_string(),
        };
        assert_eq!(cancelled.leg_outcome().code, 487);
        assert_eq!(cancelled.reason(), "caller gave up");
        assert_eq!(OriginateGroupEnd::TimedOut.leg_outcome().code, 408);
        assert_eq!(OriginateGroupEnd::TimedOut.reason(), "ring timeout");
    }

    #[test]
    fn the_first_leg_to_claim_wins_and_every_other_loses() {
        let store = store_with(OriginateGroupStrategy::Parallel, 3);
        let Claim::Won(claimed) = store.claim_answer("leg-1", 200) else {
            panic!("the first claim wins");
        };
        assert_eq!(claimed.losers.len(), 2);
        assert_eq!(
            claimed.winner.outcome.map(|outcome| outcome.cause),
            Some(DialBranchCause::Answered)
        );
        assert!(matches!(store.claim_answer("leg-1", 200), Claim::Duplicate));
        assert!(matches!(store.claim_answer("leg-0", 200), Claim::Lost));
        assert!(matches!(store.claim_answer("leg-9", 200), Claim::Ungrouped));
        // A loser ending is not the group's to move: it is concluded.
        assert!(store
            .leg_ended(
                "leg-2",
                DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled)
            )
            .is_none());
        assert!(!store.contains("group"));
        store.remove("group");
        for leg in ["leg-0", "leg-1", "leg-2"] {
            store.forget_leg(leg);
        }
        assert_eq!((store.group_count(), store.leg_count()), (0, 0));
    }

    #[test]
    fn a_parallel_group_fails_only_once_its_last_leg_ends() {
        let store = store_with(OriginateGroupStrategy::Parallel, 2);
        assert!(matches!(store.finish_placement("group"), Next::Continue));
        let rejected = DialBranchOutcome::new(486, "Busy Here", DialBranchCause::Rejected);
        let first = store
            .leg_ended("leg-0", rejected.clone())
            .expect("a live leg");
        assert!(matches!(first.next, Next::Continue));
        let last = store.leg_ended("leg-1", rejected).expect("a live leg");
        assert!(matches!(last.next, Next::Failed(_, _)));
        // Each leg's index entry went as it ended.
        assert_eq!(store.leg_count(), 0);
        store.remove("group");
        assert_eq!(store.group_count(), 0);
    }

    #[test]
    fn a_leg_ending_while_legs_are_placed_waits_for_the_placement() {
        let store = OriginateGroupStore::new();
        store.insert(
            "group".to_string(),
            group(OriginateGroupStrategy::Parallel, 2),
        );
        assert!(store.start("group", Instant::now()));
        let _ = store.targets_to_place("group");
        assert!(store.attach_leg("group", "leg-0", branch("a", None)));
        let ended = store
            .leg_ended(
                "leg-0",
                DialBranchOutcome::new(503, "Service Unavailable", DialBranchCause::Unsent),
            )
            .expect("a live leg");
        assert!(
            matches!(ended.next, Next::Continue),
            "the sibling is not out yet"
        );
        assert!(store.attach_leg("group", "leg-1", branch("b", None)));
        assert!(matches!(store.finish_placement("group"), Next::Continue));
    }

    #[test]
    fn a_sequential_group_places_one_target_at_a_time() {
        let store = OriginateGroupStore::new();
        store.insert(
            "group".to_string(),
            group(OriginateGroupStrategy::Sequential, 2),
        );
        assert!(store.start("group", Instant::now()));
        assert!(!store.start("group", Instant::now()), "a group starts once");
        let (first, _, _) = store.targets_to_place("group").expect("a target");
        assert_eq!(first.len(), 1);
        assert!(store.attach_leg("group", "leg-0", branch("a", None)));
        assert!(matches!(store.finish_placement("group"), Next::Continue));
        let ended = store
            .leg_ended(
                "leg-0",
                DialBranchOutcome::new(486, "Busy Here", DialBranchCause::Rejected),
            )
            .expect("a live leg");
        assert!(matches!(ended.next, Next::Place));
        let (second, _, _) = store.targets_to_place("group").expect("a target");
        assert_eq!(second[0].uri, "sip:201@198.51.100.1");
        assert!(store
            .targets_to_place("group")
            .is_some_and(|(rest, _, _)| rest.is_empty()));
    }

    #[test]
    fn a_group_that_placed_nothing_hands_back_the_refusal() {
        let store = OriginateGroupStore::new();
        store.insert(
            "group".to_string(),
            group(OriginateGroupStrategy::Parallel, 1),
        );
        assert!(store.start("group", Instant::now()));
        let _ = store.targets_to_place("group");
        store.record_refusal("group", OriginateError::Unroutable("nowhere".to_string()));
        assert!(matches!(
            store.finish_placement("group"),
            Next::NothingPlaced(OriginateError::Unroutable(_))
        ));
    }

    #[test]
    fn only_a_group_past_its_deadline_times_out() {
        let store = OriginateGroupStore::new();
        store.insert(
            "group".to_string(),
            group(OriginateGroupStrategy::Parallel, 1),
        );
        let now = Instant::now();
        assert!(store.start("group", now));
        assert!(store
            .take_timed_out(now + std::time::Duration::from_secs(59))
            .is_empty());
        assert_eq!(
            store.take_timed_out(now + std::time::Duration::from_secs(61)),
            vec!["group".to_string()]
        );
        // An ended group does not time out again.
        assert!(store.end("group", &OriginateGroupEnd::TimedOut).is_some());
        assert!(store.end("group", &OriginateGroupEnd::TimedOut).is_none());
        assert!(store
            .take_timed_out(now + std::time::Duration::from_secs(61))
            .is_empty());
    }

    #[test]
    fn a_contact_of_an_aor_is_called_as_the_aor_with_the_groups_identity() {
        let template = group(OriginateGroupStrategy::Parallel, 0).params;
        let contact = DialTarget {
            uri: "sip:201@198.51.100.7:5070".to_string(),
            aor: Some("sip:201@siphon.example.com".to_string()),
            ..Default::default()
        };
        let params = leg_params(&template, &contact);
        assert_eq!(params.to, "sip:201@siphon.example.com");
        // Nothing of its own: the group's identity stands.
        assert_eq!(params.from, template.from);
        assert_eq!(params.from_display, template.from_display);
        assert_eq!(params.privacy, None);
    }

    #[test]
    fn a_uri_target_in_a_group_with_no_callee_is_its_own_callee() {
        let mut template = group(OriginateGroupStrategy::Parallel, 0).params;
        template.to = String::new();
        let target = DialTarget {
            uri: "sip:3000@198.51.100.8".to_string(),
            ..Default::default()
        };
        assert_eq!(leg_params(&template, &target).to, "sip:3000@198.51.100.8");
        // Positive control: a group that names its callee keeps it.
        let named = group(OriginateGroupStrategy::Parallel, 0).params;
        assert_eq!(leg_params(&named, &target).to, "sip:201@example.com");
    }

    #[test]
    fn a_target_that_names_an_identity_presents_it_over_the_groups() {
        let mut template = group(OriginateGroupStrategy::Parallel, 0).params;
        template.from = Some("sip:1000@siphon.example.com".to_string());
        template.from_display = Some("Reception".to_string());
        template.headers = vec![("X-Queue".to_string(), "sales".to_string())];
        let target = DialTarget {
            uri: "sip:3000@198.51.100.8".to_string(),
            next_hop: Some("sip:198.51.100.9:5070".to_string()),
            from: Some("sip:5550100@siphon.example.com".to_string()),
            // Empty: present no display name at all.
            from_display: Some(String::new()),
            p_asserted_identity: Some("sip:5550100@siphon.example.com".to_string()),
            privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
            headers: [("x-queue".to_string(), "support".to_string())].into(),
            ..Default::default()
        };
        let params = leg_params(&template, &target);
        assert_eq!(
            params.from.as_deref(),
            Some("sip:5550100@siphon.example.com")
        );
        assert_eq!(params.from_display.as_deref(), Some(""));
        assert_eq!(
            params.p_asserted_identity.as_deref(),
            Some("sip:5550100@siphon.example.com")
        );
        assert_eq!(
            params.privacy,
            Some(crate::sip::privacy::CallerIdPresentation::Restricted)
        );
        assert_eq!(params.next_hop.as_deref(), Some("sip:198.51.100.9:5070"));
        assert_eq!(
            params.headers,
            vec![("x-queue".to_string(), "support".to_string())],
            "the target's header replaces the group's of the same name"
        );
    }
}
