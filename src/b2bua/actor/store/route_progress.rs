//! The store side of an LCR attempt's progress: whether the carrier in flight
//! has sent a 101-199, which decides what its ring timeout does.

use super::*;

impl CallActorStore {
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
