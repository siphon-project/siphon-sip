//! The store side of an LCR attempt in flight: whether its carrier has sent a
//! 101-199, which decides what its ring timeout does, and settling its leg when
//! the carrier fails.

use super::*;

impl CallActorStore {
    /// Settle a sequential failover call's B-leg on its final failure. See
    /// [`CallActor::settle_route_branch`]. `false` when the call is gone.
    pub fn settle_route_branch(&self, call_id: &str, index: usize, status_code: u16) -> bool {
        self.calls
            .get_mut(call_id)
            .is_some_and(|mut call| call.settle_route_branch(index, status_code))
    }

    /// Note a B-leg provisional against a call's sequential-failover attempt.
    /// See [`CallActor::record_route_progress`]. `false` when the call is gone.
    pub fn record_route_progress(&self, call_id: &str, branch: &str, status_code: u16) -> bool {
        self.calls
            .get_mut(call_id)
            .is_some_and(|mut call| call.record_route_progress(branch, status_code))
    }

    /// Whether a call's carrier in flight keeps the call past its ring timeout.
    /// See [`CallActor::route_kept_by_progress`]. `false` when the call is gone.
    pub fn route_kept_by_progress(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.route_kept_by_progress())
    }
}
