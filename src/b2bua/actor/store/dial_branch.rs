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

    /// A controller gave up on its dial: drop the targets a sequential hunt had
    /// left and the dial's ring deadline, so no later attempt is placed and the
    /// deadline cannot fail a caller that is parked again.
    pub fn abandon_dial_hunt(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.route_sequence = None;
            call.answer_deadline = None;
        }
    }

    /// Name the media profile the next B-leg INVITE of the call's dial is
    /// offered. See [`DialMedia::sending_profile`].
    pub fn set_dial_sending_profile(&self, call_id: &str, profile: Option<String>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.dial_media.sending_profile = profile;
        }
    }

    /// Keep the anchored offer made for `profile`, for the branches of the
    /// call's dial that name it.
    pub fn add_dial_branch_offer(&self, call_id: &str, profile: String, offer: Vec<u8>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.dial_media.branch_offers.push((profile, offer));
        }
    }

    /// The anchored offer made for `profile`, when it has an allocation of its
    /// own rather than being the call's media session's.
    pub fn dial_branch_offer(&self, call_id: &str, profile: &str) -> Option<Vec<u8>> {
        let call = self.calls.get(call_id)?;
        call.dial_media.branch_offer(profile).map(<[u8]>::to_vec)
    }

    /// The media profile the B-leg on Via `via_branch` was offered. See
    /// [`CallActor::dial_branch_media_profile`].
    pub fn dial_branch_media_profile(&self, call_id: &str, via_branch: &str) -> Option<String> {
        self.calls
            .get(call_id)?
            .dial_branch_media_profile(via_branch)
    }

    /// Forget the dial's per-branch media: its allocations are settled or
    /// released, so no later attempt may be built from them.
    pub fn clear_dial_media(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.dial_media = DialMedia::default();
        }
    }

    /// Whether a controller-issued `dial` is still awaiting its outcome.
    pub fn is_control_dial(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .map(|call| call.control_dial)
            .unwrap_or(false)
    }
}

impl CallActorStore {
    /// Record the allocation an originated leg's INVITE offered.
    pub fn set_originate_offer(&self, call_id: &str, offer: OriginateOffer) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.originate_offer = Some(offer);
        }
    }

    /// The allocation an originated leg's INVITE offered, when it carried one.
    pub fn originate_offer(&self, call_id: &str) -> Option<OriginateOffer> {
        self.calls
            .get(call_id)
            .and_then(|call| call.originate_offer.clone())
    }
}
