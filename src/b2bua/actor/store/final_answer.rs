//! The claim on a call's final response to its INVITE.

use super::*;

impl CallActorStore {
    /// Claim the 2xx that answers the caller's INVITE: moves the call to
    /// answered unless a CANCEL has claimed it first, in one step under the
    /// call's lock. A CANCEL claims under the same lock after reading the state,
    /// so of the two exactly one wins: a 2xx can never follow the 487, and a
    /// CANCEL that comes after finds an answered call. `false` when the call is
    /// being cancelled (or is gone).
    pub fn claim_final_answer(&self, call_id: &str) -> bool {
        let Some(mut call) = self.get_call_mut(call_id) else {
            return false;
        };
        if call.cancel_claimed {
            return false;
        }
        call.transition_to(CallState::Answered);
        true
    }
}
