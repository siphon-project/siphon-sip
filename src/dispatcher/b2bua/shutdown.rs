//! Ending the calls a drain deadline is still holding.
//!
//! The drain loop used to log `"drain timeout — exiting with in-flight work
//! still active"` and exit. Nothing was torn down on that path: no BYE on either
//! leg, no Ro `CCR-TERMINATION`, no Rf stop, no media delete, no CDR. A call
//! lasts minutes and `drain_secs` is seconds, so **every** restart taken with
//! traffic up ended there — the far side left holding a channel until someone
//! hung it up by hand, anchors held to media timeout, and charging sessions the
//! OCS had authorised never closed.
//!
//! This is the pass that ends them, at the deadline and only there. It reuses
//! the funnels the ordinary teardowns already go through rather than emitting
//! anything of its own, so a shutdown BYE is the same BYE a `b2bua.terminate`
//! sends, with the same Rf/Ro/CDR/media consequences.
//!
//! **Two things it deliberately does not do.** It never re-routes: the
//! `@b2bua.on_failure` path that a ring timeout runs would have a node that is
//! exiting start dialling carriers. And it cannot touch proxy-mode calls at all
//! — `ProxySession` is transaction state, not dialog state (no callee To-tag, no
//! remote target, no route set, no CSeq), so there is nothing an in-dialog BYE
//! could be built from. That is a property of the proxy, not a gap here, and it
//! is stated in `docs/deployment.md` where an operator reads it.

use std::time::Duration;

use tracing::{info, warn};

use super::terminate::{
    b2bua_reject_call_in, b2bua_terminate_call_inner, q850_reason, B2BUA_CONTROL,
};
use crate::b2bua::actor::CallState;
use crate::dispatcher::DispatcherState;

/// RFC 3326 `Reason:` on a shutdown BYE. Q.850 cause 16 is normal call
/// clearing: an orderly hangup the network chose, which is what an SBC taken out
/// of service emits, not a fault the far side should alarm on.
const SHUTDOWN_REASON: &str = q850_reason!(16, "Server shutting down");

/// What the pass did, for the one log line the sequence emits.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TeardownReport {
    /// Answered calls put through the full teardown (BYE both legs, Rf/Ro stop,
    /// CDR, media delete).
    pub calls_ended: usize,
    /// Unanswered calls: every pending B-leg CANCELled and the caller given a
    /// final response.
    pub rejected: usize,
    /// Calls already being torn down by something else when the pass reached
    /// them — an inbound BYE that won the race. Not a failure.
    pub already_ending: usize,
}

impl TeardownReport {
    fn total(&self) -> usize {
        self.calls_ended + self.rejected + self.already_ending
    }
}

/// End every call the store still holds.
///
/// Enumerates ids first and then acts on them: each teardown mutates the store,
/// so holding an iterator across the pass would be a deadlock rather than a
/// race. A call that changes state in between is handled by the funnels'
/// own guards — `claim_teardown` for an answered one, `get_call` returning
/// `None` for one already gone — so nothing here needs a second lock.
pub fn tear_down_surviving_calls() -> TeardownReport {
    let Some(control) = B2BUA_CONTROL.get() else {
        // No dispatcher — a proxy-only node, or a shutdown before start-up
        // finished. Nothing to end.
        return TeardownReport::default();
    };
    tear_down_calls_in(&control.state)
}

/// The pass itself, against an explicit dispatcher state.
///
/// Separate from [`tear_down_surviving_calls`] because that one reads the
/// process-global `B2BUA_CONTROL`, a `OnceLock` only one state can ever occupy —
/// so a test that drove it could only ever be the first test in the binary.
pub(crate) fn tear_down_calls_in(state: &DispatcherState) -> TeardownReport {
    let mut report = TeardownReport::default();

    let calls: Vec<(String, CallState)> = state
        .call_actors
        .iter_calls()
        .map(|entry| (entry.key().clone(), entry.value().state.clone()))
        .collect();

    for (call_id, call_state) in calls {
        match call_state {
            CallState::Answered => {
                // One funnel, everything the spec asks for: BYE on both legs
                // carrying the Reason, Rf ACR-STOP, Ro CCR-TERMINATION, the CDR,
                // the media delete, SIPREC stop, StasisEnd, actor removal.
                if b2bua_terminate_call_inner(&call_id, Some(SHUTDOWN_REASON), "shutdown", state) {
                    report.calls_ended += 1;
                } else {
                    report.already_ending += 1;
                }
            }
            CallState::Calling | CallState::Ringing => {
                cancel_pending_branches(&call_id, state);
                // 503 is what the drain already answers a new INVITE with, so a
                // caller that dialled during the drain and one whose ring the
                // deadline cut short hear the same story.
                if b2bua_reject_call_in(state, &call_id, 503, "Service Unavailable") {
                    report.rejected += 1;
                } else {
                    report.already_ending += 1;
                }
            }
            CallState::Terminated => report.already_ending += 1,
        }
    }

    if report.total() > 0 {
        info!(
            calls_ended = report.calls_ended,
            rejected = report.rejected,
            already_ending = report.already_ending,
            "shutdown: ended the calls the drain deadline was still holding"
        );
    }
    report
}

/// CANCEL every B-leg still outstanding on an unanswered call (RFC 3261 §9.1).
///
/// Issued explicitly rather than left to the store: removing a call sends its
/// legs `LegMessage::Shutdown`, which stops the actor and emits nothing on the
/// wire, so a callee that was ringing would keep ringing at a node that had
/// already exited.
fn cancel_pending_branches(call_id: &str, state: &DispatcherState) {
    let handle_txs: Vec<_> = match state.call_actors.get_call(call_id) {
        Some(call) => call
            .b_leg_handles
            .iter()
            .flatten()
            .map(|handle| handle.tx.clone())
            .collect(),
        None => return,
    };
    for tx in &handle_txs {
        let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }
    let cancelled = state.call_actors.cancel_ringing_branches(call_id);
    super::response::cancel_settled_branches(&cancelled, state);
}

/// Wait for the in-flight work a teardown pass leaves behind.
///
/// `spawn_rf_b2bua_stop`, `spawn_ro_b2bua_stop` and the media delete are all
/// `tokio::spawn`ed and awaited nowhere, so exiting straight after issuing the
/// teardowns would kill the Diameter round trips mid-flight and leave exactly
/// the sessions this pass exists to close. Bounded, because a peer that never
/// answers must not hold the shutdown open.
///
/// Returns whether everything drained before `grace` ran out.
pub async fn await_teardown(drain: &crate::dispatcher::DrainState, grace: Duration) -> bool {
    if grace.is_zero() {
        return drain.active_counts() == (0, 0);
    }
    let deadline = tokio::time::Instant::now() + grace;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.tick().await; // burn the immediate first tick
    loop {
        let (transactions, calls) = drain.active_counts();
        if transactions == 0 && calls == 0 {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            warn!(
                active_transactions = transactions,
                active_calls = calls,
                grace_secs = grace.as_secs(),
                "shutdown: teardown grace ran out with work still in flight — exiting anyway"
            );
            return false;
        }
        tick.tick().await;
    }
}
