//! RFC 3261 §9.1 for a caller's own CANCEL: it ends the call at once, and
//! reaches a callee that has not answered anything only on that callee's
//! first provisional.
//!
//! With the fixtures of [`super::cancel_awaits_provisional_tests`] on the call
//! harness of [`super::lcr_ring_timeout_tests`].

use super::cancel_awaits_provisional_tests::{
    assert_branch_released, assert_no_cancel, branch_of, invite_among, phone_answers, the_cancel,
    until_invite_retransmitted, wire_until,
};
use super::lcr_ring_timeout_tests::{carrier, Sequence, CALLER, FIRST_CARRIER, SECOND_CARRIER};
use super::lcr_route_bookkeeping_tests::caller_cancels;
use super::originate_test_harness::{drain, requests_to, socket};
use super::*;

/// A caller's call to one callee that has sent nothing, abandoned by the
/// caller. Returns the call and the callee's INVITE.
fn caller_gave_up_on_a_silent_callee() -> (Sequence, SipMessage) {
    let sequence = Sequence::start_with_script(vec![carrier("callee", FIRST_CARRIER, 30)], 30, "");
    let silent = invite_among(&drain(&sequence.dispatcher.udp), FIRST_CARRIER);
    caller_cancels(&sequence);
    let sent = drain(&sequence.dispatcher.udp);
    let to_caller: Vec<_> = sent
        .iter()
        .filter(|frame| frame.destination == socket(CALLER))
        .filter_map(|frame| frame.message.status_code())
        .collect();
    assert_eq!(
        to_caller,
        [200, 487],
        "the caller's CANCEL is answered and its INVITE ended at once"
    );
    assert_no_cancel(&sent, FIRST_CARRIER);
    assert!(sequence.call_is_gone());
    assert_eq!(
        sequence
            .dispatcher
            .state
            .call_actors
            .deferred_cancel_count(),
        1
    );
    (sequence, silent)
}

/// The caller's CANCEL is not relayed to a callee that has sent nothing. The
/// call is gone at once all the same; the callee's INVITE retransmits, its
/// first provisional draws the CANCEL, and its 487 is ACKed.
#[tokio::test(flavor = "multi_thread")]
async fn a_callers_cancel_reaches_a_silent_callee_on_its_first_provisional() {
    let (sequence, silent) = caller_gave_up_on_a_silent_callee();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    let sent = until_invite_retransmitted(dispatcher, FIRST_CARRIER, &branch).await;
    assert_no_cancel(&sent, FIRST_CARRIER);

    phone_answers(state, FIRST_CARRIER, &silent, 180, "Ringing", None);
    let sent = drain(&dispatcher.udp);
    let cancel = the_cancel(&sent, FIRST_CARRIER, &silent);
    assert_eq!(sent.len(), 1, "the CANCEL and nothing to the caller");

    phone_answers(state, FIRST_CARRIER, &cancel, 200, "OK", None);
    phone_answers(
        state,
        FIRST_CARRIER,
        &silent,
        487,
        "Request Terminated",
        None,
    );
    let sent = wire_until(dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK of the 487 and nothing else");
    assert!(sent[0].is(Method::Ack));
    assert_branch_released(state, &branch);
}

/// The callee answers 200 after the caller gave up, never having sent a
/// provisional: ACK and BYE, no CANCEL, and nothing more to the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_callee_answering_after_the_caller_gave_up_is_acked_and_released() {
    let (sequence, silent) = caller_gave_up_on_a_silent_callee();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    phone_answers(state, FIRST_CARRIER, &silent, 200, "OK", None);
    let sent = drain(&dispatcher.udp);
    assert_no_cancel(&sent, FIRST_CARRIER);
    assert_eq!(
        requests_to(&sent, socket(FIRST_CARRIER), Method::Ack).len(),
        1
    );
    assert_eq!(
        requests_to(&sent, socket(FIRST_CARRIER), Method::Bye).len(),
        1
    );
    assert_eq!(sent.len(), 2, "nothing reaches the caller: {sent:?}");
    assert_branch_released(state, &branch);
}

/// The callee fails, or never responds at all, after the caller gave up.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_callee_failing_or_timing_out_after_the_caller_gave_up_draws_no_cancel() {
    let (sequence, silent) = caller_gave_up_on_a_silent_callee();
    let state = &sequence.dispatcher.state;
    let branch = branch_of(&silent);
    phone_answers(
        state,
        FIRST_CARRIER,
        &silent,
        503,
        "Service Unavailable",
        None,
    );
    let sent = wire_until(&sequence.dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK and nothing else: {sent:?}");
    assert!(sent[0].is(Method::Ack));
    assert_branch_released(state, &branch);

    let (sequence, silent) = caller_gave_up_on_a_silent_callee();
    let state = &sequence.dispatcher.state;
    super::timers::sweep_b2bua_retransmits_at(
        state,
        std::time::Instant::now() + state.b2bua_retransmits.transaction_timeout(),
    );
    assert_no_cancel(&drain(&sequence.dispatcher.udp), FIRST_CARRIER);
    assert_eq!(state.call_actors.cancelled_branch_count(), 0);
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);
    assert!(state.b2bua_retransmits.is_empty());
    let _ = silent;
}

/// The other half of RFC 3261 §9.1: a callee that has already sent its final
/// response is not CANCELled when the call is given up on afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_already_failed_is_not_cancelled_when_the_caller_gives_up() {
    let sequence = Sequence::start_fork(&[FIRST_CARRIER, SECOND_CARRIER]);
    let state = &sequence.dispatcher.state;
    let sent = drain(&sequence.dispatcher.udp);
    let (busy, ringing) = (
        invite_among(&sent, FIRST_CARRIER),
        invite_among(&sent, SECOND_CARRIER),
    );
    phone_answers(state, FIRST_CARRIER, &busy, 486, "Busy Here", None);
    phone_answers(state, SECOND_CARRIER, &ringing, 180, "Ringing", None);
    let _ = drain(&sequence.dispatcher.udp);

    caller_cancels(&sequence);
    let sent = drain(&sequence.dispatcher.udp);
    assert_no_cancel(&sent, FIRST_CARRIER);
    the_cancel(&sent, SECOND_CARRIER, &ringing);
    assert_eq!(
        state.call_actors.deferred_cancel_count(),
        0,
        "the branch that rang is CANCELled at once"
    );
}
