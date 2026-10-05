//! RFC 3261 §16.6 step 11 and §16.8: Timer C, the proxy's bound on an INVITE
//! that has drawn a provisional response and never a final one.
//!
//! "In order to handle the case where an INVITE request never generates a
//! final response, the TU uses a timer which is called timer C. Timer C MUST
//! be set for each client transaction when an INVITE request is proxied. The
//! timer MUST be larger than 3 minutes." A 101-199 provisional resets it
//! (§16.7 step 2). When it fires, a transaction that has had a provisional is
//! sent a CANCEL, and one that has had none is treated as having received a
//! `408` (§16.8).
//!
//! On the proxy harness of [`super::proxy_cancel_awaits_provisional_tests`],
//! read off the UDP egress, with the transaction's clock moved by the test.

use std::time::Duration;

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, cancels_to, fire, forking_proxy, relaying_proxy, requests_to,
    responses_to_caller, the_cancel, waiting_cancels, CALLER, FAILED, RINGING,
};
use super::proxy_dialog_state_tests::{find, header, headers, in_dialog, Proxy};
use super::*;

/// The INVITE on this branch has rung for longer than Timer C allows: Timer B
/// has passed (which starts Timer C for a transaction with a provisional), and
/// the time Timer C counts from is that long ago.
fn ring_past_timer_c(proxy: &Proxy, branch_invite: &SipMessage) {
    let client_key = TransactionManager::key_from_message(branch_invite).expect("a key");
    fire(proxy, branch_invite, TimerName::B);
    assert!(
        proxy
            .state
            .timer_wheel
            .contains_key(&format!("{}:{:?}", client_key, TimerName::C)),
        "Timer C runs once Timer B has passed"
    );
    proxy
        .state
        .transaction_manager
        .age_invite_client(&client_key, crate::transaction::timer::DEFAULT_TIMER_C);
}

/// Nothing is left of the branch or of its call.
fn assert_ended(proxy: &Proxy, branch_invite: &SipMessage) {
    let client_key = TransactionManager::key_from_message(branch_invite).expect("a key");
    let state = &proxy.state;
    assert!(!state
        .transaction_manager
        .invite_client_is_pending(&client_key));
    assert!(
        !state
            .timer_wheel
            .iter()
            .any(|entry| entry.key == client_key && entry.name != TimerName::D),
        "no timer of the INVITE is left running"
    );
    assert_eq!(state.session_store.session_count(), 0);
    assert_eq!(state.session_store.client_key_count(), 0);
    assert_eq!(waiting_cancels(proxy), 0);
}

/// A call may ring for longer than a transaction lasts. The session of an
/// INVITE whose branch is still owed a final response is not the periodic
/// sweep's to take: the answer, when it comes, still reaches the caller, and
/// the caller's ACK still reaches the callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_answered_after_ringing_past_the_transaction_timeout_still_connects() {
    let proxy = relaying_proxy(RINGING, "");
    let call_id = "long-ringing@example.com";
    let (_, invites) = call(&proxy, call_id);
    let to_ringing = find(&invites, RINGING).clone();
    let client_key = TransactionManager::key_from_message(&to_ringing).expect("a key");
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    let _ = proxy.wire();

    // It has been ringing for two minutes, and the sweep comes round.
    let state = &proxy.state;
    let session = state
        .session_store
        .get_by_client_key(&client_key)
        .expect("the call's session");
    session.write().expect("the session").created_at =
        std::time::Instant::now() - Duration::from_secs(120);
    drop(session);
    sweep_stale_entries(state).await;
    assert_eq!(
        state.session_store.session_count(),
        1,
        "a ringing call is not stale"
    );

    answers(&proxy, RINGING, &to_ringing, 200, "OK");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200]);
    let answer = sent
        .iter()
        .find(|sent| sent.destination == CALLER && sent.message.status_code() == Some(200))
        .map(|sent| sent.message.clone())
        .expect("the 200");

    // The sweep comes round again before the caller's ACK does.
    sweep_stale_entries(state).await;
    let route_set: Vec<String> = headers(&answer, "Record-Route").into_iter().rev().collect();
    proxy.request(
        CALLER,
        &in_dialog(
            "ACK",
            &format!("sip:callee@{RINGING}"),
            CALLER,
            &header(&answer, "From"),
            &header(&answer, "To"),
            call_id,
            &route_set,
            5,
        ),
    );
    assert_eq!(
        requests_to(&proxy.wire(), RINGING, Method::Ack).len(),
        1,
        "the caller's ACK reaches the callee"
    );
}

/// A callee that rings and never answers: when Timer C runs out the proxy
/// CANCELs the branch (RFC 3261 §16.8), and the `487` it answers is the
/// branch's final response, forwarded to the caller and ACKed.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_that_rings_past_timer_c_is_cancelled() {
    let proxy = relaying_proxy(RINGING, "");
    let (_, invites) = call(&proxy, "timer-c-cancel@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    let _ = proxy.wire();

    ring_past_timer_c(&proxy, &to_ringing);
    fire(&proxy, &to_ringing, TimerName::C);
    let sent = proxy.wire();
    the_cancel(&sent, RINGING, &to_ringing);
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the caller hears the branch's own final response, when it comes"
    );

    answers(&proxy, RINGING, &to_ringing, 487, "Request Terminated");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [487]);
    assert_eq!(requests_to(&sent, RINGING, Method::Ack).len(), 1);
    assert_ended(&proxy, &to_ringing);
}

/// A 101-199 resets Timer C (RFC 3261 §16.7 step 2): a callee that keeps
/// reporting progress is not CANCELled when the timer comes due.
#[tokio::test(flavor = "multi_thread")]
async fn progress_resets_timer_c() {
    let proxy = relaying_proxy(RINGING, "");
    let (_, invites) = call(&proxy, "timer-c-reset@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    let client_key = TransactionManager::key_from_message(&to_ringing).expect("a key");
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    ring_past_timer_c(&proxy, &to_ringing);
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    let _ = proxy.wire();

    fire(&proxy, &to_ringing, TimerName::C);
    assert!(cancels_to(&proxy.wire(), RINGING).is_empty());
    assert!(
        proxy
            .state
            .timer_wheel
            .contains_key(&format!("{}:{:?}", client_key, TimerName::C)),
        "set again, from the 183"
    );
    assert_eq!(proxy.state.session_store.session_count(), 1);
}

/// The callee, CANCELled by Timer C, never answers the INVITE: after 64*T1
/// the branch is given up as a `408` (RFC 3261 §9.1, §16.7 step 2), sent no
/// ACK for it, and nothing of it is left.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_cancelled_by_timer_c_that_stays_silent_is_answered_408() {
    let proxy = relaying_proxy(RINGING, "");
    let (_, invites) = call(&proxy, "timer-c-silent@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    ring_past_timer_c(&proxy, &to_ringing);
    fire(&proxy, &to_ringing, TimerName::C);
    the_cancel(&proxy.wire(), RINGING, &to_ringing);

    fire(&proxy, &to_ringing, TimerName::C);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [408]);
    assert!(cancels_to(&sent, RINGING).is_empty());
    assert!(requests_to(&sent, RINGING, Method::Ack).is_empty());
    assert_ended(&proxy, &to_ringing);
}

/// In a fork, the branch Timer C ends is one more branch that failed: its
/// `487`, or the `408` it is given when it stays silent, is that branch's
/// final response to the aggregator, and the fork settles on the best of them
/// with one response to the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_branch_ended_by_timer_c_counts_as_that_branchs_final_response() {
    for answers_its_cancel in [true, false] {
        let proxy = forking_proxy(&[RINGING, FAILED], "parallel", "");
        let call_id = format!("timer-c-fork-{answers_its_cancel}@example.com");
        let (_, invites) = call(&proxy, &call_id);
        let (to_ringing, to_failed) = (
            find(&invites, RINGING).clone(),
            find(&invites, FAILED).clone(),
        );
        answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
        answers(&proxy, FAILED, &to_failed, 404, "Not Found");
        let sent = proxy.wire();
        assert!(
            !responses_to_caller(&sent).contains(&404),
            "the fork waits for the branch still ringing"
        );

        ring_past_timer_c(&proxy, &to_ringing);
        fire(&proxy, &to_ringing, TimerName::C);
        the_cancel(&proxy.wire(), RINGING, &to_ringing);
        if answers_its_cancel {
            answers(&proxy, RINGING, &to_ringing, 487, "Request Terminated");
        } else {
            fire(&proxy, &to_ringing, TimerName::C);
        }
        let finals: Vec<u16> = responses_to_caller(&proxy.wire())
            .into_iter()
            .filter(|status_code| *status_code >= 200)
            .collect();
        // Which of the two the fork prefers is the aggregator's ranking; that
        // it now has both, and settles, is what Timer C owes it.
        let ended_with = if answers_its_cancel { 487 } else { 408 };
        assert_eq!(finals.len(), 1, "{call_id}: one final response: {finals:?}");
        assert!(
            finals[0] == 404 || finals[0] == ended_with,
            "{call_id}: the best of the two branches': {finals:?}"
        );
        assert_ended(&proxy, &to_ringing);
    }
}
