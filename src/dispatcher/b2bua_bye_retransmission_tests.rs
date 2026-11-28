//! A resent BYE on a B2BUA call is answered with the 200 the original got
//! (RFC 3261 §17.2.2), not 481.
//!
//! Over UDP the 200 siphon answers a BYE with can be lost. The peer then
//! retransmits the BYE on Timer E, with the same branch. By then the call is
//! torn down, so a BYE handled as a new request finds no call and is answered
//! 481, and the peer reports a failed hangup for a call that ended cleanly. The
//! answer is kept for Timer J (64*T1 on UDP) and every resend gets it, without
//! the teardown running again.
//!
//! Driven through [`handle_request`], on the harness `b_leg_2xx_ack_tests`
//! shares.

use super::b_leg_2xx_ack_tests::{callee, caller, caller_hangs_up, Call, Sent};
use super::*;
use std::time::{Duration, Instant};

/// A script with a B2BUA handler, so an in-dialog BYE takes the B2BUA path.
const B2BUA_SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def invite(call):\n",
    "    pass\n",
);

/// The status codes of every BYE response sent to `destination`, in order.
fn bye_answers_to(sent: &[Sent], destination: SocketAddr) -> Vec<u16> {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination
                && sent
                    .message
                    .headers
                    .cseq()
                    .is_some_and(|cseq| cseq.ends_with("BYE"))
        })
        .filter_map(|sent| sent.message.status_code())
        .collect()
}

fn byes_to(sent: &[Sent], destination: SocketAddr) -> usize {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination && sent.message.method() == Some(&Method::Bye)
        })
        .count()
}

fn relayed_answer(call: &Call) -> SipMessage {
    call.wire()
        .into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("the answer was relayed to the caller")
        .message
}

/// A confirmed call: the callee answered and the caller ACKed.
fn confirmed_call() -> (Call, SipMessage) {
    let call = Call::bridged_with_script(B2BUA_SCRIPT);
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    call.caller_acks(&relayed);
    call.wire();
    (call, relayed)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resent_caller_bye_is_answered_with_the_200_not_481() {
    let (call, relayed) = confirmed_call();

    caller_hangs_up(&call.state, &relayed);
    let first = call.wire();
    assert_eq!(bye_answers_to(&first, caller()), vec![200]);
    assert_eq!(byes_to(&first, callee()), 1, "the callee is sent its BYE");

    // The 200 is lost on the way; the caller resends its BYE on Timer E.
    caller_hangs_up(&call.state, &relayed);
    let resent = call.wire();
    assert_eq!(
        bye_answers_to(&resent, caller()),
        vec![200],
        "a resent BYE is answered from its server transaction (RFC 3261 §17.2.2)"
    );
    assert_eq!(
        byes_to(&resent, callee()),
        0,
        "the teardown does not run a second time"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_resent_callee_bye_is_answered_with_the_200_not_481() {
    let (call, _relayed) = confirmed_call();

    call.callee_hangs_up_through_the_dispatcher();
    let first = call.wire();
    assert_eq!(bye_answers_to(&first, callee()), vec![200]);
    assert_eq!(byes_to(&first, caller()), 1, "the caller is sent its BYE");

    call.callee_hangs_up_through_the_dispatcher();
    let resent = call.wire();
    assert_eq!(bye_answers_to(&resent, callee()), vec![200]);
    assert_eq!(byes_to(&resent, caller()), 0);
}

/// Leak gate: the kept answers go once Timer J has passed.
#[tokio::test(flavor = "multi_thread")]
async fn answered_byes_drain_with_timer_j() {
    let (call, relayed) = confirmed_call();
    assert!(call.state.answered_byes.is_empty());

    caller_hangs_up(&call.state, &relayed);
    caller_hangs_up(&call.state, &relayed);
    call.wire();
    assert_eq!(call.state.answered_byes.len(), 1, "one BYE, kept once");

    let timer_j = call.state.transaction_manager.timers().timer_j_udp();
    call.state
        .answered_byes
        .expire(Instant::now() + timer_j + Duration::from_millis(1));
    assert!(call.state.answered_byes.is_empty());

    // Past Timer J a resend is a new request again.
    caller_hangs_up(&call.state, &relayed);
    assert_eq!(bye_answers_to(&call.wire(), caller()), vec![481]);
}

/// A BYE that matches no call is answered 481 and not remembered: the store
/// grows with hangups, not with whatever a peer sends.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_for_no_call_is_not_remembered() {
    let (call, relayed) = confirmed_call();
    caller_hangs_up(&call.state, &relayed);
    call.wire();
    let timer_j = call.state.transaction_manager.timers().timer_j_udp();
    call.state
        .answered_byes
        .expire(Instant::now() + timer_j + Duration::from_millis(1));

    caller_hangs_up(&call.state, &relayed);
    caller_hangs_up(&call.state, &relayed);
    assert_eq!(bye_answers_to(&call.wire(), caller()), vec![481, 481]);
    assert!(call.state.answered_byes.is_empty());
}
