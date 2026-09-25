use super::*;

/// The A-leg's SIP Call-ID, which the control plane keys the call's channel on,
/// with the branches an operation settled.
pub type SettledDialBranches = (String, Vec<DialBranch>);

impl CallActorStore {
    /// Enter `leg` as a branch of a controller-issued `dial`. See
    /// [`CallActor::record_dial_branch`]. Returns the A-leg's SIP Call-ID with
    /// the branch, `None` when the call is gone or no controller dial is
    /// awaiting its outcome.
    pub fn record_dial_branch(
        &self,
        call_id: &str,
        leg: &Leg,
        target: &str,
    ) -> Option<(String, DialBranch)> {
        let mut call = self.calls.get_mut(call_id)?;
        let branch = call.record_dial_branch(leg, target)?;
        Some((call.a_leg.dialog.call_id.clone(), branch))
    }

    /// Settle the branch whose INVITE rides Via `via_branch`. See
    /// [`CallActor::settle_dial_branch_by_via`].
    pub fn settle_dial_branch_by_via(
        &self,
        call_id: &str,
        via_branch: &str,
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Option<SettledDialBranches> {
        let mut call = self.calls.get_mut(call_id)?;
        let settled = call.settle_dial_branch_by_via(via_branch, code, reason, cause)?;
        Some((call.a_leg.dialog.call_id.clone(), vec![settled]))
    }

    /// Settle the branches for `legs` that have no outcome yet. `None` when the
    /// call is gone or none of them was open.
    pub fn settle_dial_branch_legs(
        &self,
        call_id: &str,
        legs: &[Leg],
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Option<SettledDialBranches> {
        let mut call = self.calls.get_mut(call_id)?;
        if call.dial_branches.is_empty() {
            return None;
        }
        let settled: Vec<DialBranch> = legs
            .iter()
            .filter_map(|leg| call.settle_dial_branch(&leg.id.0, code, reason, cause))
            .collect();
        (!settled.is_empty()).then(|| (call.a_leg.dialog.call_id.clone(), settled))
    }

    /// Settle every branch that has no outcome yet. See
    /// [`CallActor::settle_open_dial_branches`].
    pub fn settle_open_dial_branches(
        &self,
        call_id: &str,
        code: u16,
        reason: &str,
        cause: DialBranchCause,
    ) -> Option<SettledDialBranches> {
        let mut call = self.calls.get_mut(call_id)?;
        let settled = call.settle_open_dial_branches(code, reason, cause);
        (!settled.is_empty()).then(|| (call.a_leg.dialog.call_id.clone(), settled))
    }

    /// Hand back every branch of the call's dial and forget them. Empty when the
    /// call is gone.
    pub fn take_dial_branches(&self, call_id: &str) -> Vec<DialBranch> {
        self.calls
            .get_mut(call_id)
            .map(|mut call| call.take_dial_branches())
            .unwrap_or_default()
    }

    /// Drop every B-leg of a call, leaving the A-leg and its dialog intact.
    ///
    /// A controller-owned dial that failed is done with the legs it rang, but
    /// not with the caller: the controller may dial somewhere else on the same
    /// channel, and a stale B-leg would make the next attempt look like glare
    /// and confuse the winner bookkeeping.
    pub fn clear_b_legs(&self, call_id: &str) {
        let mut ended = Vec::new();
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.b_legs.clear();
            call.b_leg_status.clear();
            call.b_leg_handles.clear();
            call.winner = None;
            ended = call.end_orphaned_dialogs();
        }
        publish_dialog_states(ended);
    }

    /// Whether a controller-issued `dial` is still awaiting its outcome.
    pub fn is_control_dial(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .map(|call| call.control_dial)
            .unwrap_or(false)
    }
}
