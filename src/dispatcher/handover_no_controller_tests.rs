//! A call handed to a control application with no controller connected.
//!
//! The control handover runs with the INVITE locked, and that lock is the call's
//! stored A-leg INVITE. The default for a call nobody can take is a 503, and it
//! used to be sent through the ordinary rejection, which looks the INVITE up
//! and locks it again: `std::sync::Mutex` is not re-entrant, so the thread never
//! came back, the caller was never answered, and the worker was lost. These
//! drive the rejection with the INVITE held, the way the handover holds it.

use super::control_dial_identity_tests::{park, wire, CALLER, SIP_CALL_ID};
use super::lcr_ring_timeout_tests::summaries;
use super::test_dispatcher::test_dispatcher;
use super::*;

/// With the A-leg INVITE locked by the caller, the 503 still goes out and the
/// call is released. Run on a thread of its own with a deadline, so a return of
/// the re-lock fails this test instead of hanging the suite.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_nobody_can_take_is_answered_503_while_its_invite_is_held() {
    let dispatcher = std::sync::Arc::new(test_dispatcher());
    let call_id = park(&dispatcher);
    let (done, finished) = std::sync::mpsc::channel();
    let held = std::sync::Arc::clone(&dispatcher);
    let handle = tokio::runtime::Handle::current();
    let held_call = call_id.clone();
    std::thread::spawn(move || {
        let _enter = handle.enter();
        let invite_arc = held
            .state
            .call_actors
            .get_call(&held_call)
            .and_then(|call| call.a_leg_invite.clone())
            .expect("the parked call stores its A-leg INVITE");
        let invite = invite_arc.lock().expect("the invite lock");
        let rejected = b2bua_reject_call_holding_invite(
            &held.state,
            &held_call,
            503,
            "No Controller Available",
            &invite,
        );
        let _ = done.send(rejected);
    });
    let rejected = finished
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the rejection never returned: it took the INVITE's lock a second time");
    assert!(rejected, "the call was not rejected");
    assert_eq!(summaries(&wire(&dispatcher)), [format!("503 to {CALLER}")]);
    assert!(
        dispatcher.state.call_actors.get_call(&call_id).is_none(),
        "the call was not released"
    );
    assert!(dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(SIP_CALL_ID)
        .is_none());
}

/// The positive control for the shape of the answer: rejecting through the
/// lookup, with nothing held, sends the same 503.
#[tokio::test(flavor = "multi_thread")]
async fn the_rejection_through_the_lookup_sends_the_same_answer() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(b2bua_reject_call_in(
        &dispatcher.state,
        &call_id,
        503,
        "No Controller Available",
        &[]
    ));
    assert_eq!(summaries(&wire(&dispatcher)), [format!("503 to {CALLER}")]);
}
