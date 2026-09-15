//! The store side of a parallel fork's settlement: each wrapper takes the call
//! under its shard lock, lets [`CallActor`] decide, and keeps whatever branches
//! that decision cancelled answerable for the final response their CANCEL draws.
//!
//! Split from `store.rs` because it is one concern with its own vocabulary
//! (branch failures, the dispatch window, the ring timeout), not another thin
//! accessor on the call map.

use super::*;

impl CallActorStore {
    /// Record a B-leg's final failure and settle its fork, keeping any branch
    /// that settlement cancels answerable. See
    /// [`CallActor::record_branch_failure`]. `None` when the call is gone.
    pub fn record_branch_failure(
        &self,
        call_id: &str,
        index: usize,
        status_code: u16,
        response: &SipMessage,
    ) -> Option<BranchSettlement> {
        let mut call = self.calls.get_mut(call_id)?;
        let settlement = call.record_branch_failure(index, status_code, response);
        self.keep_answerable(&settlement.cancelled);
        Some(settlement)
    }

    /// Whether the B-leg at `index` is a branch still waiting for its final
    /// response. See [`CallActor::is_pending_branch`]. `false` when the call is
    /// gone.
    pub fn is_pending_branch(&self, call_id: &str, index: usize) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.is_pending_branch(index))
    }

    /// Whether the B-leg at `index` is a branch that has ended. See
    /// [`CallActor::is_ended_branch`]. `true` when the call is gone, which ended
    /// every branch it had.
    pub fn is_ended_branch(&self, call_id: &str, index: usize) -> bool {
        // `map_or(true, …)` not `is_none_or`: MSRV 1.80, and that is 1.82.
        self.calls
            .get(call_id)
            .map_or(true, |call| call.is_ended_branch(index))
    }

    /// Open a fork's dispatch window. See [`CallActor::fork_dispatching`].
    pub fn start_fork_dispatch(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.fork_dispatching = true;
        }
    }

    /// Close a fork's dispatch window and settle it. See
    /// [`CallActor::finish_fork_dispatch`]. `None` when the call is gone.
    pub fn finish_fork_dispatch(&self, call_id: &str) -> Option<BranchSettlement> {
        let mut call = self.calls.get_mut(call_id)?;
        let settlement = call.finish_fork_dispatch();
        self.keep_answerable(&settlement.cancelled);
        Some(settlement)
    }

    /// On the ring timeout, hand back a fork's held failure when it beats 408,
    /// with the branches still ringing cancelled and kept answerable. See
    /// [`CallActor::settle_fork_on_timeout`]. `None` when the call is gone or the
    /// timeout's own 408 stands.
    pub fn settle_fork_on_timeout(&self, call_id: &str) -> Option<BranchSettlement> {
        let mut call = self.calls.get_mut(call_id)?;
        let settlement = call.settle_fork_on_timeout()?;
        self.keep_answerable(&settlement.cancelled);
        Some(settlement)
    }

    /// Cancel every branch still ringing without ending the call, keeping each
    /// answerable apart from it, and hand back the ones to CANCEL. See
    /// [`CallActor::cancel_pending_branches`].
    ///
    /// For a call that goes on after its ring timeout, to the next LCR carrier:
    /// that carrier can fail, and end the call, before the timed-out one's 487
    /// arrives, and the 487 is owed its ACK (RFC 3261 §17.1.1.3) either way.
    pub fn cancel_ringing_branches(&self, call_id: &str) -> Vec<Leg> {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return Vec::new();
        };
        let cancelled = call.cancel_pending_branches(None);
        self.keep_answerable(&cancelled);
        cancelled
    }
}
