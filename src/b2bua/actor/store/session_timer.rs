//! The store side of RFC 4028 session timers: the timer each dialog of a call
//! keeps, whether its peer allows UPDATE, the early media answer a B-leg's caller
//! was sent, and which dialogs the sweep has to act on.

use std::time::{Duration, Instant};

use crate::b2bua::session_timer::SessionTimerDue;

use super::*;

/// The A-leg of `call`, or its winning B-leg.
fn dialog_leg(call: &mut CallActor, on_a_leg: bool) -> Option<&mut Leg> {
    if on_a_leg {
        Some(&mut call.a_leg)
    } else {
        let winner = call.winner?;
        call.b_legs.get_mut(winner)
    }
}

impl CallActorStore {
    /// Set, or clear, the session timer of one leg's dialog: the A-leg, or the
    /// winning B-leg. A no-op when the call or the leg is absent.
    pub fn set_leg_session_timer(
        &self,
        call_id: &str,
        on_a_leg: bool,
        timer: Option<SessionTimerState>,
    ) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(leg) = dialog_leg(&mut call, on_a_leg) {
                leg.dialog.session_timer = timer;
            }
        }
    }

    /// The session timer of one leg's dialog, when it has one.
    pub fn leg_session_timer(&self, call_id: &str, on_a_leg: bool) -> Option<SessionTimerState> {
        let call = self.calls.get(call_id)?;
        let leg = if on_a_leg {
            Some(&call.a_leg)
        } else {
            call.winner.and_then(|index| call.b_legs.get(index))
        };
        leg.and_then(|leg| leg.dialog.session_timer.clone())
    }

    /// Change the session timer of one leg's dialog in place. `false` when the
    /// call, the leg or its timer is absent.
    pub fn update_leg_session_timer(
        &self,
        call_id: &str,
        on_a_leg: bool,
        change: impl FnOnce(&mut SessionTimerState),
    ) -> bool {
        let Some(mut call) = self.calls.get_mut(call_id) else {
            return false;
        };
        match dialog_leg(&mut call, on_a_leg).and_then(|leg| leg.dialog.session_timer.as_mut()) {
            Some(timer) => {
                change(timer);
                true
            }
            None => false,
        }
    }

    /// Record whether the peer on one leg's dialog allows UPDATE, which decides
    /// what a session refresh without an offer can be (RFC 4028 §7.4).
    pub fn set_leg_peer_allows_update(&self, call_id: &str, on_a_leg: bool, allows: bool) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(leg) = dialog_leg(&mut call, on_a_leg) {
                leg.dialog.peer_allows_update = allows;
            }
        }
    }

    /// Record the SDP siphon relayed to the caller in the early media of the
    /// B-leg at `index`, as it went on the wire.
    pub fn set_b_leg_early_answer(&self, call_id: &str, index: usize, sdp: Vec<u8>) {
        if let Some(mut call) = self.calls.get_mut(call_id) {
            if let Some(leg) = call.b_legs.get_mut(index) {
                leg.early_answer_sent = Some(sdp);
            }
        }
    }

    /// The SDP siphon last relayed to the caller in the early media of the B-leg
    /// at `index`.
    pub fn b_leg_early_answer(&self, call_id: &str, index: usize) -> Option<Vec<u8>> {
        self.calls.get(call_id).and_then(|call| {
            call.b_legs
                .get(index)
                .and_then(|leg| leg.early_answer_sent.clone())
        })
    }

    /// Every dialog of an answered call whose session timer asks for something at
    /// `now`: the call, whether the dialog is the A-leg's, and what is due.
    /// Expirations come first, so a call being ended is not refreshed as well.
    pub fn session_timers_due(
        &self,
        now: Instant,
        transaction_timeout: Duration,
    ) -> Vec<(String, bool, SessionTimerDue)> {
        let mut due = Vec::new();
        for entry in self.calls.iter() {
            let call = entry.value();
            // A call another teardown has already claimed is being ended: its
            // BYEs are that teardown's, sent or held until an ACK (RFC 3261 §15).
            if call.state != CallState::Answered || call.teardown_claimed {
                continue;
            }
            let legs = [
                (true, Some(&call.a_leg)),
                (false, call.winner.and_then(|index| call.b_legs.get(index))),
            ];
            for (on_a_leg, leg) in legs {
                let Some(timer) = leg.and_then(|leg| leg.dialog.session_timer.as_ref()) else {
                    continue;
                };
                match timer.due(now, transaction_timeout) {
                    SessionTimerDue::Nothing => {}
                    what => due.push((call.id.clone(), on_a_leg, what)),
                }
            }
        }
        due.sort_by_key(|(_, _, what)| *what != SessionTimerDue::Expire);
        due
    }
}
