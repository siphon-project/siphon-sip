//! What a proxied INVITE's branch is sent when it ends: the ACK of its final
//! response, and nothing for a response it never sent.
//!
//! RFC 3261 §17.1.1.3 makes the ACK of a 300-699 final response the INVITE
//! client transaction's: one per response received, to the address, port and
//! transport the INVITE went to. On the proxy harness of
//! [`super::proxy_cancel_awaits_provisional_tests`], read off the UDP egress.

use super::proxy_cancel_awaits_provisional_tests::{
    answers, branch_of, call, fire, forking_proxy, relaying_proxy, requests_to,
    responses_to_caller, the_cancel, DECIDING, FAILED, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{find, header, response_to};
use super::*;

/// A branch that fails is ACKed once, by its client transaction, and a
/// retransmission of the failure once more.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_branch_is_acked_once_per_response_it_sent() {
    let proxy = relaying_proxy(FAILED, "");
    let (_, invites) = call(&proxy, "one-ack@example.com");
    let to_failed = find(&invites, FAILED).clone();

    answers(&proxy, FAILED, &to_failed, 486, "Busy Here");
    let sent = proxy.wire();
    let acks = requests_to(&sent, FAILED, Method::Ack);
    assert_eq!(acks.len(), 1, "one ACK for one 486");
    assert_eq!(branch_of(&acks[0]), branch_of(&to_failed));
    assert_eq!(header(&acks[0], "CSeq"), "5 ACK");
    assert!(header(&acks[0], "To").contains(";tag="));
    assert_eq!(responses_to_caller(&sent), [486]);

    answers(&proxy, FAILED, &to_failed, 486, "Busy Here");
    let sent = proxy.wire();
    assert_eq!(
        requests_to(&sent, FAILED, Method::Ack).len(),
        1,
        "the retransmitted 486 is ACKed again"
    );
    assert!(
        responses_to_caller(&sent).is_empty(),
        "and not forwarded again"
    );
}

/// The ACK goes where the INVITE went, also when the failure arrives from
/// another port of the same host.
#[tokio::test(flavor = "multi_thread")]
async fn the_ack_of_a_failure_goes_where_the_invite_went() {
    let proxy = relaying_proxy(FAILED, "");
    let (_, invites) = call(&proxy, "ack-destination@example.com");
    let to_failed = find(&invites, FAILED).clone();
    let elsewhere = "198.51.100.13:6000";
    proxy.response(
        elsewhere,
        response_to(
            &to_failed,
            486,
            "Busy Here",
            "busy-tag",
            &format!("sip:callee@{FAILED}"),
            "",
        ),
    );
    let sent = proxy.wire();
    assert_eq!(requests_to(&sent, FAILED, Method::Ack).len(), 1);
    assert!(requests_to(&sent, elsewhere, Method::Ack).is_empty());
}

/// A branch that never responds is answered for by the proxy (a 408 to the
/// caller, RFC 3261 §16.7 step 2), and is sent no ACK: it sent no response to
/// acknowledge.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_that_timed_out_is_sent_no_ack() {
    let proxy = relaying_proxy(SILENT, "");
    let (_, invites) = call(&proxy, "no-ack-for-a-timeout@example.com");
    let to_silent = find(&invites, SILENT).clone();
    fire(&proxy, &to_silent, TimerName::B);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [408]);
    assert!(
        requests_to(&sent, SILENT, Method::Ack).is_empty(),
        "no ACK for a response the branch never sent"
    );
}

/// Once a fork has settled, each branch that lost is released from the session
/// store as it ends: by the `487` of its CANCEL, by a failure of its own, by
/// its INVITE timing out. With the last one the session is gone, and nothing
/// is left for the periodic sweep to find.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_forks_losing_branches_are_released_as_they_end() {
    for deciding in [(200, "OK"), (603, "Decline")] {
        let proxy = forking_proxy(&[DECIDING, RINGING, FAILED, SILENT], "parallel", "");
        let call_id = format!("losers-released-{}@example.com", deciding.0);
        let (_, invites) = call(&proxy, &call_id);
        let (to_deciding, to_ringing, to_failed, to_silent) = (
            find(&invites, DECIDING).clone(),
            find(&invites, RINGING).clone(),
            find(&invites, FAILED).clone(),
            find(&invites, SILENT).clone(),
        );
        let store = &proxy.state.session_store;
        answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
        answers(&proxy, FAILED, &to_failed, 486, "Busy Here");
        assert_eq!(
            store.client_key_count(),
            4,
            "an unsettled fork keeps a branch that failed: its response may be the best"
        );
        let _ = proxy.wire();

        answers(&proxy, DECIDING, &to_deciding, deciding.0, deciding.1);
        let sent = proxy.wire();
        the_cancel(&sent, RINGING, &to_ringing);
        assert_eq!(
            store.client_key_count(),
            2,
            "the branches still to end; the one that had failed went with the settling"
        );

        // A failure of its own, crossing the CANCEL.
        answers(&proxy, RINGING, &to_ringing, 486, "Busy Here");
        assert_eq!(store.client_key_count(), 1, "released by its failure");
        // A provisional is not an end.
        answers(&proxy, SILENT, &to_silent, 100, "Trying");
        assert_eq!(store.client_key_count(), 1);
        fire(&proxy, &to_silent, TimerName::B);
        assert_eq!(
            store.client_key_count(),
            1,
            "Timer B is over once it has a 1xx"
        );
        answers(&proxy, SILENT, &to_silent, 487, "Request Terminated");
        assert_eq!(store.client_key_count(), 0, "released by its 487");
        assert_eq!(store.session_count(), 0, "and the session with the last");

        let sent = proxy.wire();
        assert!(
            responses_to_caller(&sent).is_empty(),
            "none of it reaches the caller: {:?}",
            responses_to_caller(&sent)
        );
    }
}

/// A branch of a settled fork that never responds is released when its INVITE
/// times out.
#[tokio::test(flavor = "multi_thread")]
async fn a_settled_forks_silent_branch_is_released_by_its_timeout() {
    let proxy = forking_proxy(&[DECIDING, SILENT], "parallel", "");
    let (_, invites) = call(&proxy, "loser-timeout@example.com");
    let (to_deciding, to_silent) = (
        find(&invites, DECIDING).clone(),
        find(&invites, SILENT).clone(),
    );
    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    let store = &proxy.state.session_store;
    assert_eq!(store.client_key_count(), 1);
    fire(&proxy, &to_silent, TimerName::B);
    assert_eq!(store.client_key_count(), 0);
    assert_eq!(store.session_count(), 0);
}
