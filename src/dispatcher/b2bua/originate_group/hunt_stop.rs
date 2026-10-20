//! When an originate group stops: a sequential group's hunt ending on the leg
//! that just failed, and a 6xx ending any group
//! ([`crate::b2bua::actor::hunt_stops_at`]).
//!
//! Split from the group store to keep that file inside its size budget.

use super::*;
use crate::sip::message::SipMessage;

impl OriginateGroup {
    /// The outcome of the leg that stopped the hunt, when one did.
    pub(super) fn stopped_leg(&self) -> Option<DialBranchOutcome> {
        let stopper = self.stopped_by.as_deref()?;
        self.legs
            .iter()
            .find(|leg| leg.internal_call_id == stopper)
            .and_then(|leg| leg.branch.outcome.clone())
    }

    /// A leg that ended on `outcome`, the leg at `index`: whether it stops the
    /// hunt, and if so the legs still ringing that now have to be CANCELled,
    /// each settled as cancelled.
    ///
    /// The progress rule is a hunt's alone: a parallel group has no next
    /// target, so a phone that rang and was busy says nothing about the
    /// others. A 6xx stops either kind (RFC 3261 §16.7 step 5).
    pub(super) fn stop_on(
        &mut self,
        index: usize,
        outcome: &DialBranchOutcome,
        retry_elsewhere: bool,
    ) -> Vec<GroupLeg> {
        let Some(leg) = self.legs.get(index) else {
            return Vec::new();
        };
        let sequential = self.strategy == OriginateGroupStrategy::Sequential;
        if self.stopped_by.is_some()
            || !crate::b2bua::actor::hunt_stops_at(
                outcome.code,
                sequential && leg.progressed,
                leg.reroute_after_progress,
                retry_elsewhere,
            )
        {
            return Vec::new();
        }
        self.stopped_by = Some(leg.internal_call_id.clone());
        let cancelled =
            DialBranchOutcome::new(487, "Request Terminated", DialBranchCause::Cancelled);
        let mut ringing = Vec::new();
        for leg in self.legs.iter_mut().filter(|leg| leg.is_live()) {
            leg.branch.outcome = Some(cancelled.clone());
            ringing.push(leg.clone());
        }
        ringing
    }
}

/// The failure a group whose hunt `stopper` ended reports: that leg's own
/// outcome, which is the callee's answer, rather than the best of every leg.
pub(super) fn failure_from_outcome(
    group_id: &str,
    stopper: DialBranchOutcome,
    branches: Vec<DialBranch>,
) -> OriginateGroupFailure {
    failure_of(group_id, Some(stopper), branches)
}

/// An originated leg the far end failed with the final `message` (its
/// `status_code` and `reason_phrase`): ended as rejected, a `503` carrying
/// `Retry-After` noted as such.
pub fn originate_group_leg_rejected(
    state: &DispatcherState,
    internal_call_id: &str,
    status_code: u16,
    reason_phrase: &str,
    message: &SipMessage,
) {
    originate_group_leg_failed(
        state,
        internal_call_id,
        DialBranchOutcome::new(status_code, reason_phrase, DialBranchCause::Rejected),
        crate::b2bua::actor::is_retry_elsewhere(status_code, message),
    );
}

/// [`originate_group_leg_ended`] for a leg the far end failed with a final
/// response: `retry_elsewhere` says it was a `503` carrying `Retry-After`
/// ([`crate::b2bua::actor::is_retry_elsewhere`]), which moves a hunt on even
/// from a leg that rang.
pub fn originate_group_leg_failed(
    state: &DispatcherState,
    internal_call_id: &str,
    outcome: DialBranchOutcome,
    retry_elsewhere: bool,
) {
    let Some(ended) = state
        .originate_groups
        .leg_ended(internal_call_id, outcome, retry_elsewhere)
    else {
        return;
    };
    ended.sink.branch_ended(&ended.group_id, &ended.branch);
    // A 6xx stopped the legs still ringing: CANCELled (RFC 3261 §16.7 step 5)
    // and reported before the group's failure is.
    for leg in &ended.stopped {
        abandon_leg(state, leg, "declined elsewhere");
        state.originate_groups.forget_leg(&leg.internal_call_id);
        ended.sink.branch_ended(&ended.group_id, &leg.branch);
    }
    if let Err(refusal) = drive(state, &ended.group_id, ended.next) {
        // Only a group that never placed a leg can end this way, and this
        // group had one — the leg that just ended.
        error!(
            group_id = %ended.group_id,
            "B2BUA: originate group reported placing nothing after a leg ended: {refusal}"
        );
    }
}
