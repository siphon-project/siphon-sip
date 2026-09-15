//! Two teardowns of one call that run at the same moment send each leg one BYE,
//! not two.
//!
//! The 64*T1 sweep ends a call whose caller never ACKed (RFC 3261 §13.3.1.4), and
//! a BYE, a timer or a script can end the same call on another thread at that
//! instant. Each teardown read the call, sent its BYEs and only then removed it, so
//! both could read it before either removed it, and each leg was sent a BYE twice.
//!
//! The interleaving is forced, not hoped for: `teardown_race` runs a hook inside
//! the first teardown at the point where it has taken the call over, and the hook
//! starts the second one there. Tokio's clock is paused so the 64*T1 deadline has
//! passed when the test needs it to.

use super::b2bua::teardown_race;
use super::b_leg_2xx_ack_tests::{callee, caller, caller_leg, Call, Sent};
use super::*;
use std::time::Duration;

const NORMAL_CLEARING: &str = "Q.850;cause=16;text=\"Normal Clearing\"";
const NO_ACK_REASON: &str = "Q.850;cause=102;text=\"No ACK received\"";

fn byes_to(sent: &[Sent], destination: SocketAddr) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination && sent.message.method() == Some(&Method::Bye)
        })
        .collect()
}

fn reason(sent: &Sent) -> Option<&str> {
    sent.message.headers.get("Reason").map(String::as_str)
}

/// A call whose 2xx to the caller is past its 64*T1 deadline, with the sweep not
/// yet run.
async fn a_call_past_its_ack_deadline() -> Call {
    let call = Call::bridged();
    call.callee_answers("");
    tokio::time::sleep(Duration::from_secs(33)).await;
    call.wire();
    call
}

fn assert_the_call_is_gone(call: &Call) {
    assert!(call.state.call_actors.get_call(&call.call_id).is_none());
    assert!(call.state.uas_2xx_retransmits.is_empty());
    assert!(call.state.held_byes.is_empty());
}

/// A script's teardown has taken the call when the sweep's deadline fires: the
/// teardown sends the BYEs, the sweep sends none.
#[tokio::test(start_paused = true)]
async fn the_sweep_firing_inside_a_teardown_sends_no_second_bye() {
    let call = a_call_past_its_ack_deadline().await;
    let state = Arc::clone(&call.state);
    teardown_race::run_inside_next_teardown(move || sweep_unacked_uas_2xx(&state));

    b2bua_terminate_call_inner(&call.call_id, Some(NORMAL_CLEARING), "b2bua", &call.state);

    let sent = call.wire();
    let to_caller = byes_to(&sent, caller());
    let to_callee = byes_to(&sent, callee());
    assert_eq!(to_caller.len(), 1, "one BYE to the caller");
    assert_eq!(to_callee.len(), 1, "one BYE to the callee");
    assert_eq!(reason(to_caller[0]), Some(NORMAL_CLEARING));
    assert_eq!(reason(to_callee[0]), Some(NORMAL_CLEARING));
    assert_the_call_is_gone(&call);
}

/// The other order: the sweep's teardown has taken the call when a script ends it.
/// The sweep sends the BYEs, with its Reason, and the script's teardown sends none.
#[tokio::test(start_paused = true)]
async fn a_teardown_starting_inside_the_sweep_sends_no_second_bye() {
    let call = a_call_past_its_ack_deadline().await;
    let state = Arc::clone(&call.state);
    let call_id = call.call_id.clone();
    teardown_race::run_inside_next_teardown(move || {
        b2bua_terminate_call_inner(&call_id, Some(NORMAL_CLEARING), "b2bua", &state);
    });

    sweep_unacked_uas_2xx(&call.state);

    let sent = call.wire();
    let to_caller = byes_to(&sent, caller());
    let to_callee = byes_to(&sent, callee());
    assert_eq!(to_caller.len(), 1, "one BYE to the caller");
    assert_eq!(to_callee.len(), 1, "one BYE to the callee");
    assert_eq!(reason(to_caller[0]), Some(NO_ACK_REASON));
    assert_eq!(reason(to_callee[0]), Some(NO_ACK_REASON));
    assert_the_call_is_gone(&call);
}

/// The claim itself, raced for real: many threads ask to tear one call down at
/// once, and exactly one of them gets it.
#[tokio::test(flavor = "multi_thread")]
async fn exactly_one_of_many_racing_teardowns_claims_the_call() {
    for _ in 0..200 {
        let store = Arc::new(CallActorStore::new());
        let call_id = store.create_call(caller_leg());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let racers: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let call_id = call_id.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.claim_teardown(&call_id)
                })
            })
            .collect();
        let winners = racers
            .into_iter()
            .map(|racer| racer.join().expect("a claiming thread"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1, "exactly one teardown claims the call");
    }
}

/// The callee hangs up as the sweep's deadline fires. The callee's BYE is
/// answered and nothing more goes to the callee; the caller gets one BYE.
#[tokio::test(start_paused = true)]
async fn the_sweep_firing_inside_a_callee_hangup_sends_no_second_bye() {
    let call = a_call_past_its_ack_deadline().await;
    let state = Arc::clone(&call.state);
    teardown_race::run_inside_next_teardown(move || sweep_unacked_uas_2xx(&state));

    call.callee_hangs_up();

    let sent = call.wire();
    assert_eq!(
        sent.iter()
            .filter(|sent| sent.destination == callee() && sent.message.status_code() == Some(200))
            .count(),
        1,
        "the callee's BYE is answered"
    );
    assert!(
        byes_to(&sent, callee()).is_empty(),
        "the callee hung up and is sent no BYE"
    );
    assert_eq!(byes_to(&sent, caller()).len(), 1, "one BYE to the caller");
    assert_the_call_is_gone(&call);
}
