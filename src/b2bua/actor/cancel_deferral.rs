//! Deferring `@b2bua.on_cancel` while `@b2bua.on_invite` is running for a call.
//!
//! The handler may await, and the caller may CANCEL while it does. Firing
//! `@b2bua.on_cancel` at that moment runs it beside the handler it is meant to
//! clean up after: a media offer still in flight is released before it exists
//! and then outlives the call. The CANCEL path raises the call's
//! `invite_handler_cancelled` flag instead, and the INVITE path runs
//! `on_cancel` once the handler is done.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use super::CallActorStore;
use crate::sip::SipMessage;

impl CallActorStore {
    /// Mark `@b2bua.on_invite` as running for `call_id` and return the flag a
    /// CANCEL raises while it does (see `CallActor::invite_handler_cancelled`).
    /// `None` when the call does not exist.
    pub fn begin_invite_handler(&self, call_id: &str) -> Option<Arc<AtomicBool>> {
        let mut call = self.get_call_mut(call_id)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        call.invite_handler_cancelled = Some(Arc::clone(&cancelled));
        Some(cancelled)
    }

    /// `@b2bua.on_invite` has returned: stop deferring `on_cancel` and store
    /// the A-leg INVITE, in one step under the call's lock so a CANCEL sees
    /// either a handler in flight or a call it can run `on_cancel` for itself,
    /// never the gap between. Returns whether the call still exists.
    pub fn finish_invite_handler(&self, call_id: &str, message: Arc<Mutex<SipMessage>>) -> bool {
        match self.get_call_mut(call_id) {
            Some(mut call) => {
                call.invite_handler_cancelled = None;
                call.set_a_leg_invite(message);
                true
            }
            None => false,
        }
    }
}
