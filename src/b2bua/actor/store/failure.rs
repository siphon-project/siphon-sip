//! The store side of a call that `@b2bua.on_failure` keeps alive: routed again
//! after it failed, or taken back from an answer that failed before its caller
//! was connected.

use super::*;

impl CallActorStore {
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
