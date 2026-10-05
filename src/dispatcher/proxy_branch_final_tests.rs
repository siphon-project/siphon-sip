//! What a proxied INVITE's branch is sent when it ends: the ACK of its final
//! response, and nothing for a response it never sent.
//!
//! RFC 3261 §17.1.1.3 makes the ACK of a 300-699 final response the INVITE
//! client transaction's: one per response received, to the address, port and
//! transport the INVITE went to. On the proxy harness of
//! [`super::proxy_cancel_awaits_provisional_tests`], read off the UDP egress.

use super::proxy_cancel_awaits_provisional_tests::{
    answers, branch_of, call, relaying_proxy, requests_to, responses_to_caller, FAILED,
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
