//! `@b2bua.on_failure` and `@b2bua.on_cancel` run once per call outcome, even
//! when two messages about that outcome are handled at the same time.
//!
//! Dispatcher workers run concurrently, and each hook runs with the per-call
//! lock released. So the interleaving that matters is a second message arriving
//! *while the first one's handler is running*. These tests force exactly that:
//! the script's handler stops at a [`HandlerGate`] the first time it runs, the
//! test puts the second message through on its own thread, then lets the first
//! handler finish.

use super::lcr_ring_timeout_tests::{
    carrier_response, summaries, Sent, Sequence, CALLER, FIRST_CARRIER, SECOND_CARRIER,
};
use super::lcr_route_bookkeeping_tests::caller_cancels;
use super::*;
use std::time::Duration;

/// Seconds a gate waits before giving up, so a broken test fails rather than
/// hangs.
const GATE_TIMEOUT_SECS: f64 = 10.0;

/// A point a script handler stops at the first time it runs, until the test
/// releases it. Lives on `sys` under a name of its own, where both the script
/// and the test can reach it.
struct HandlerGate {
    name: &'static str,
}

impl HandlerGate {
    fn install(name: &'static str) -> HandlerGate {
        Python::attach(|python| {
            let code = format!(
                "import sys, threading, types\n\
                 setattr(sys, {name:?}, types.SimpleNamespace(\
                 entered=threading.Event(), release=threading.Event(), held=False))\n"
            );
            python
                .run(
                    &std::ffi::CString::new(code).expect("no NUL in the gate code"),
                    None,
                    None,
                )
                .expect("the gate installs");
        });
        HandlerGate { name }
    }

    /// Block until the handler has stopped at the gate.
    fn wait_until_held(&self) {
        let entered = Python::attach(|python| {
            python
                .import("sys")
                .and_then(|sys| sys.getattr(self.name))
                .and_then(|gate| gate.getattr("entered"))
                .and_then(|entered| entered.call_method1("wait", (GATE_TIMEOUT_SECS,)))
                .and_then(|entered| entered.extract::<bool>())
                .expect("the gate waits")
        });
        assert!(entered, "the handler never reached the gate");
    }

    fn release(&self) {
        Python::attach(|python| {
            python
                .import("sys")
                .and_then(|sys| sys.getattr(self.name))
                .and_then(|gate| gate.getattr("release"))
                .and_then(|release| release.call_method0("set"))
                .expect("the gate releases");
        });
    }
}

/// `hook` records every run as `<label>;` on the A-leg INVITE, and stops at the
/// gate named `gate` the first time.
fn gated_script(hook: &str, signature: &str, label: &str, gate: &str) -> String {
    format!(
        r#"
import sys
from siphon import b2bua

@b2bua.{hook}
def gated({signature}):
    seen = call.get_header("X-Test-Runs") or ""
    call.set_header("X-Test-Runs", seen + {label} + ";")
    gate = getattr(sys, "{gate}", None)
    if gate is not None and not gate.held:
        gate.held = True
        gate.entered.set()
        gate.release.wait({GATE_TIMEOUT_SECS})
"#
    )
}

fn on_failure_script(gate: &str) -> String {
    gated_script("on_failure", "call, code, reason", "str(code)", gate)
}

/// The INVITE among `sent` that went to `address`.
fn invite_in(sent: &[Sent], address: &str) -> SipMessage {
    sent.iter()
        .find(|sent| {
            sent.destination.to_string() == address
                && matches!(sent.message.start_line, StartLine::Request(_))
        })
        .map(|sent| sent.message.clone())
        .unwrap_or_else(|| panic!("no INVITE to {address}"))
}

/// What the gated hook recorded, `None` if it never ran.
fn runs(sequence: &Sequence) -> Option<String> {
    sequence
        .invite
        .lock()
        .expect("the A-leg INVITE lock")
        .headers
        .get("X-Test-Runs")
        .map(|value| value.to_string())
}

/// What went to the caller, in order.
fn to_caller(summaries: &[String]) -> Vec<String> {
    summaries
        .iter()
        .filter(|summary| summary.ends_with(&format!(" to {CALLER}")))
        .cloned()
        .collect()
}

/// Run `first` on a thread of its own until its handler is held at `gate`, then
/// `second` on this one, then let `first` finish.
fn interleave(gate: &HandlerGate, first: impl FnOnce() + Send, second: impl FnOnce()) {
    let runtime = tokio::runtime::Handle::current();
    tokio::task::block_in_place(|| {
        std::thread::scope(|scope| {
            let held = scope.spawn(move || {
                let _entered = runtime.enter();
                first();
            });
            gate.wait_until_held();
            second();
            gate.release();
            held.join().expect("the first message's thread");
        });
    });
}

/// The failure this exists for. A parallel fork's last branch answers 302, and
/// the callee's retransmission of it is handled on another worker while the
/// first copy's `@b2bua.on_failure` runs. The copy found its branch failed,
/// recorded it again as the fork's best failure, and concluded the call a
/// second time: the handler ran twice and the caller got the 302 twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_final_response_does_not_run_on_failure_again() {
    let name = "_siphon_test_gate_retransmit";
    let sequence = Sequence::start_fork_with_script(
        &[FIRST_CARRIER, SECOND_CARRIER],
        &on_failure_script(name),
    );
    let gate = HandlerGate::install(name);
    let sent = sequence.wire();
    let busy = invite_in(&sent, FIRST_CARRIER);
    let moved = invite_in(&sent, SECOND_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &busy, 486, "Busy Here");

    interleave(
        &gate,
        || sequence.carrier_answers(SECOND_CARRIER, &moved, 302, "Moved Temporarily"),
        || sequence.carrier_answers(SECOND_CARRIER, &moved, 302, "Moved Temporarily"),
    );

    assert_eq!(
        runs(&sequence).as_deref(),
        Some("302;"),
        "@b2bua.on_failure runs once"
    );
    let wire = summaries(&sequence.wire());
    assert_eq!(
        to_caller(&wire),
        [format!("302 to {CALLER}")],
        "the caller gets one final response, all sent: {wire:?}"
    );
    assert_eq!(
        wire.iter()
            .filter(|summary| **summary == format!("ACK to {SECOND_CARRIER}"))
            .count(),
        2,
        "each copy of the 302 is ACKed (RFC 3261 §17.1.1.2), all sent: {wire:?}"
    );
    assert!(sequence.call_is_gone());
}

/// The ring timeout firing while the last branch's failure is concluding the
/// call. The timeout saw a call still ringing (the failure had not ended it yet)
/// and concluded it too, with a 408: two runs of `@b2bua.on_failure` and two
/// final responses.
#[tokio::test(flavor = "multi_thread")]
async fn the_ring_timeout_does_not_conclude_a_call_a_failure_is_concluding() {
    let name = "_siphon_test_gate_timeout";
    let sequence = Sequence::start_fork_with_script(
        &[FIRST_CARRIER, SECOND_CARRIER],
        &on_failure_script(name),
    );
    let gate = HandlerGate::install(name);
    set_b2bua_answer_deadline(&sequence.call_id, 15, &sequence.dispatcher.state);
    let sent = sequence.wire();
    let busy = invite_in(&sent, FIRST_CARRIER);
    let away = invite_in(&sent, SECOND_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &busy, 486, "Busy Here");

    interleave(
        &gate,
        || sequence.carrier_answers(SECOND_CARRIER, &away, 480, "Temporarily Unavailable"),
        || sequence.ring_for(Duration::from_secs(16)),
    );

    assert_eq!(
        runs(&sequence).as_deref(),
        Some("486;"),
        "@b2bua.on_failure runs once, with the fork's best failure"
    );
    let wire = summaries(&sequence.wire());
    assert_eq!(
        to_caller(&wire),
        [format!("486 to {CALLER}")],
        "the caller gets one final response, all sent: {wire:?}"
    );
    assert!(sequence.call_is_gone());
}

/// The caller's CANCEL retransmitted while the first copy's `@b2bua.on_cancel`
/// runs. The unanswered-call check passed again (the call is only marked
/// terminated after the hook), so the hook ran twice and the caller got a
/// second 487.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_cancel_does_not_run_on_cancel_again() {
    let name = "_siphon_test_gate_cancel";
    let sequence = Sequence::start_fork_with_script(
        &[FIRST_CARRIER],
        &gated_script("on_cancel", "call", "'cancel'", name),
    );
    let gate = HandlerGate::install(name);
    sequence.wire();

    interleave(
        &gate,
        || caller_cancels(&sequence),
        || caller_cancels(&sequence),
    );

    assert_eq!(
        runs(&sequence).as_deref(),
        Some("cancel;"),
        "@b2bua.on_cancel runs once"
    );
    let wire = summaries(&sequence.wire());
    assert_eq!(
        to_caller(&wire),
        [
            format!("200 to {CALLER}"),
            format!("487 to {CALLER}"),
            format!("200 to {CALLER}"),
        ],
        "each CANCEL is answered 200 (RFC 3261 §9.2), the INVITE 487 once, all sent: {wire:?}"
    );
    assert!(sequence.call_is_gone());
}

/// A call siphon placed, rejected by the callee, whose rejection arrives twice
/// while the first copy's `@b2bua.on_failure` runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_rejection_of_an_originated_call_runs_on_failure_once() {
    let name = "_siphon_test_gate_originate";
    let sequence = Sequence::new_call(&on_failure_script(name));
    let gate = HandlerGate::install(name);
    let state = &sequence.dispatcher.state;
    if let Some(mut call) = state.call_actors.get_call_mut(&sequence.call_id) {
        call.originated = true;
    }
    let invite = sequence
        .invite
        .lock()
        .expect("the A-leg INVITE lock")
        .clone();
    let rejection = carrier_response(&invite, 486, "Busy Here");
    let reject = || handle_originated_call_response(&sequence.call_id, &rejection, 486, state);

    interleave(&gate, reject, reject);

    assert_eq!(
        runs(&sequence).as_deref(),
        Some("486;"),
        "@b2bua.on_failure runs once"
    );
    assert!(sequence.call_is_gone());
}
