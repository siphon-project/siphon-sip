//! The store side of a call that `@b2bua.on_failure` keeps alive: routed again
//! after it failed, or taken back from an answer that failed before its caller
//! was connected.

use super::*;

/// Whether a failure may conclude a call: run `@b2bua.on_failure` and act on
/// what it decides. See [`CallActorStore::claim_failure_conclusion`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureConclusion {
    /// This failure concludes the call. `reroutes` is how many times
    /// `@b2bua.on_failure` has already routed it again.
    Claimed { reroutes: u32 },
    /// Another failure is concluding the call right now; this one must not.
    AlreadyConcluding,
    /// The call is gone.
    Gone,
}

impl CallActorStore {
    /// Claim the conclusion of a failed call, under the per-call lock.
    ///
    /// `@b2bua.on_failure` runs once per failure of a call. Two paths can reach
    /// the same failure at once (the last branch failing while the ring timeout
    /// fires, or two copies of one final response on different workers), and a
    /// check-then-act split across the handler, which runs without the lock,
    /// let both conclude it: the handler ran twice, and a call it routed again
    /// was dialled twice. The first claim wins; the flag clears only when the
    /// call is routed again ([`CallActor::begin_failure_reroute`]) or lives on
    /// ([`release_failure_conclusion`](Self::release_failure_conclusion)).
    pub fn claim_failure_conclusion(&self, call_id: &str) -> FailureConclusion {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return FailureConclusion::Gone;
        };
        if call.failure_concluding {
            return FailureConclusion::AlreadyConcluding;
        }
        call.failure_concluding = true;
        FailureConclusion::Claimed {
            reroutes: call.failure_reroutes,
        }
    }

    /// The call lives on after its failure was concluded (handed to a control
    /// app, or answered by `@b2bua.on_failure`): a later failure concludes it
    /// afresh.
    pub fn release_failure_conclusion(&self, call_id: &str) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.failure_concluding = false;
        }
    }

    /// Whether a failure is concluding the call right now.
    pub fn is_failure_concluding(&self, call_id: &str) -> bool {
        self.calls
            .get(call_id)
            .is_some_and(|call| call.failure_concluding)
    }

    /// Ready a failed call to be routed again. See
    /// [`CallActor::begin_failure_reroute`].
    pub fn begin_failure_reroute(&self, call_id: &str, replaces_route_sequence: bool) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.begin_failure_reroute(replaces_route_sequence);
        }
    }

    /// Take back an answer the call failed on. See
    /// [`CallActor::rewind_failed_answer`].
    pub fn rewind_failed_answer(
        &self,
        call_id: &str,
        b_leg_index: Option<usize>,
        status_code: u16,
    ) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            call.rewind_failed_answer(b_leg_index, status_code);
        }
    }
}
