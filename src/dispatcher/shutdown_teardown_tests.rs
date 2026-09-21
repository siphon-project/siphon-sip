//! A drain deadline ends the calls it is still holding, instead of exiting on
//! top of them.
//!
//! Before this, every restart taken with traffic up ended at
//! `"drain timeout — exiting with in-flight work still active"`: no BYE on
//! either leg, no charging stop, no media release, no CDR. A call lasts minutes
//! and `drain_secs` is seconds, so the deadline is the normal path, not the
//! exceptional one.

use super::b2bua::shutdown::tear_down_calls_in;
use super::b_leg_2xx_ack_tests::{callee, caller, Call, Sent};
use super::*;

const SHUTDOWN_REASON: &str = "Q.850;cause=16;text=\"Server shutting down\"";

fn sent_to(sent: &[Sent], destination: SocketAddr, method: Method) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.destination == destination && sent.message.method() == Some(&method))
        .collect()
}

fn responses_to(sent: &[Sent], destination: SocketAddr, status: u16) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination && sent.message.status_code() == Some(status)
        })
        .collect()
}

fn reason(sent: &Sent) -> Option<&str> {
    sent.message.headers.get("Reason").map(String::as_str)
}

/// The headline: an answered call gets a BYE on both legs, carrying a Reason
/// that says the network chose this.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_call_is_byed_on_both_legs() {
    let call = Call::bridged();
    call.callee_answers("");
    // The caller ACKs siphon's 2xx: an un-ACKed dialog's BYE is *held* (RFC 3261
    // §15), which is the documented limit of this pass, not what it is for.
    let relayed_200 = call
        .wire()
        .into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("siphon relayed the callee's 200 to the caller")
        .message;
    call.caller_acks(&relayed_200);
    call.wire();

    let report = tear_down_calls_in(&call.state);

    assert_eq!(report.calls_ended, 1);
    assert_eq!(report.rejected, 0);
    let sent = call.wire();
    let to_caller = sent_to(&sent, caller(), Method::Bye);
    let to_callee = sent_to(&sent, callee(), Method::Bye);
    assert_eq!(to_caller.len(), 1, "one BYE to the caller");
    assert_eq!(to_callee.len(), 1, "one BYE to the callee");
    // Q.850 cause 16 is normal clearing: an orderly hangup, not a fault for the
    // far side to alarm on.
    assert_eq!(reason(to_caller[0]), Some(SHUTDOWN_REASON));
    assert_eq!(reason(to_callee[0]), Some(SHUTDOWN_REASON));
    assert!(
        call.state.call_actors.get_call(&call.call_id).is_none(),
        "the call is removed, not left behind for the exit to drop"
    );
}

/// A call still ringing when the deadline lands: the callee is CANCELled and the
/// caller gets the same 503 the drain already answers a new INVITE with.
#[tokio::test(flavor = "multi_thread")]
async fn a_ringing_call_is_cancelled_and_the_caller_told() {
    // `bridged_without_an_offer` is the shape that stashes the B-leg INVITE the
    // way the dial does, which is what a CANCEL is built from (RFC 3261 §9.1
    // requires it to match the INVITE it cancels).
    let call = Call::bridged_without_an_offer();
    call.callee_sends(&call.callee_response("180 Ringing", "", ""));
    call.wire();

    let report = tear_down_calls_in(&call.state);

    assert_eq!(report.rejected, 1);
    assert_eq!(report.calls_ended, 0);
    let sent = call.wire();
    assert_eq!(
        sent_to(&sent, callee(), Method::Cancel).len(),
        1,
        "the ringing callee is CANCELled (RFC 3261 §9.1), not left ringing at a node that exited"
    );
    assert_eq!(
        responses_to(&sent, caller(), 503).len(),
        1,
        "the caller hears the same 503 the drain gives a new INVITE"
    );
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
}

/// A call an inbound BYE is already tearing down is counted, not torn down
/// twice: `claim_teardown` is what makes the pass safe to run against live
/// traffic.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_already_ending_is_left_alone() {
    let call = Call::bridged();
    call.callee_answers("");
    call.wire();
    assert!(
        call.state.call_actors.claim_teardown(&call.call_id),
        "something else takes the call first"
    );

    let report = tear_down_calls_in(&call.state);

    assert_eq!(report.calls_ended, 0);
    assert_eq!(report.already_ending, 1);
    let sent = call.wire();
    assert!(
        sent_to(&sent, caller(), Method::Bye).is_empty()
            && sent_to(&sent, callee(), Method::Bye).is_empty(),
        "no second BYE on a call another teardown owns"
    );
}

/// Nothing up, nothing sent. The common case on a node drained cleanly.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_store_sends_nothing() {
    let call = Call::bridged();
    call.state.call_actors.remove_call(&call.call_id);
    call.wire();

    let report = tear_down_calls_in(&call.state);

    assert_eq!(
        report,
        crate::dispatcher::b2bua::shutdown::TeardownReport::default()
    );
    assert!(
        call.wire().is_empty(),
        "an empty store puts nothing on the wire"
    );
}
