//! What the caller is sent when it CANCELs a proxied INVITE.
//!
//! RFC 3261 §9.2 answers the CANCEL `200` whatever became of the INVITE, and
//! has the INVITE answered `487 Request Terminated`. That `487` is the final
//! response of the INVITE's server transaction (§17.2.1): retransmitted on
//! Timer G over an unreliable transport until the caller's ACK, which the
//! transaction absorbs. And it is the *one* final response of that
//! transaction: an INVITE that already has one gets no second.
//!
//! On the proxy harness of [`super::proxy_cancel_awaits_provisional_tests`],
//! read off the UDP egress.

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, caller_cancels, cancels_to, fire, forking_proxy, relaying_proxy, requests_to,
    responses_to_caller, the_cancel, CALLER, DECIDING, REJECT_ON_183, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{find, header};
use super::*;

/// The caller's ACK for the final response `status_code` it was sent for the
/// INVITE `raw`: on the INVITE's own branch (RFC 3261 §17.1.1.3).
fn caller_acks(raw: &str, to: &str) -> String {
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    format!(
        concat!(
            "ACK sip:callee@example.com SIP/2.0\r\n",
            "Via: {via}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 5 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        via = header(&invite, "Via"),
        from = header(&invite, "From"),
        to = to,
        call_id = header(&invite, "Call-ID"),
    )
}

/// The `487` to a cancelled INVITE is its server transaction's final
/// response: retransmitted until ACKed, sent again for a retransmitted
/// INVITE, and its ACK absorbed and the transaction ended.
#[tokio::test(flavor = "multi_thread")]
async fn the_487_of_a_cancelled_invite_is_the_server_transactions_final_response() {
    let proxy = relaying_proxy(RINGING, "");
    let (raw, invites) = call(&proxy, "cancelled-487@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    let caller_invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let server_key = TransactionManager::key_from_message(&caller_invite).expect("a key");
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    let _ = proxy.wire();

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200, 487]);
    let terminated = sent
        .iter()
        .find(|sent| sent.message.status_code() == Some(487))
        .map(|sent| sent.message.clone())
        .expect("the 487");

    // Unacknowledged, it is sent again on Timer G (RFC 3261 §17.2.1)...
    fire(&proxy, &caller_invite, TimerName::G);
    assert_eq!(responses_to_caller(&proxy.wire()), [487]);
    // ...and again for a retransmission of the INVITE, which is not relayed.
    proxy.request(CALLER, &raw);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [487]);
    assert!(requests_to(&sent, RINGING, Method::Invite).is_empty());

    // The caller's ACK ends the retransmissions and goes no further.
    proxy.request(CALLER, &caller_acks(&raw, &header(&terminated, "To")));
    let sent = proxy.wire();
    assert!(sent.is_empty(), "the ACK is absorbed");
    for name in [TimerName::G, TimerName::H] {
        assert!(
            !proxy
                .state
                .timer_wheel
                .contains_key(&format!("{}:{:?}", server_key, name)),
            "{name:?} stopped by the ACK"
        );
    }
    fire(&proxy, &caller_invite, TimerName::I);
    assert!(
        !proxy.state.transaction_manager.contains(&server_key),
        "the INVITE's server transaction is over"
    );
}

/// RFC 3261 §9.2: a CANCEL for an INVITE that already has its final response
/// "has no effect on the processing of the original request". It is answered
/// `200`, and the INVITE, which has had its one final response, gets no `487`
/// after it. Whether that final response was the script's own
/// (`reply.reject()`) or a fork branch's answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_after_the_final_response_is_answered_and_changes_nothing() {
    // Rejected from the reply path.
    let proxy = forking_proxy(&[RINGING, SILENT], "parallel", REJECT_ON_183);
    let (raw, invites) = call(&proxy, "cancel-after-reject@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [503]);
    the_cancel(&sent, RINGING, &to_ringing);

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(
        responses_to_caller(&sent),
        [200],
        "the CANCEL's 200, and no 487 behind the 503"
    );
    assert!(cancels_to(&sent, RINGING).is_empty());
    assert!(cancels_to(&sent, SILENT).is_empty());

    // Answered by a fork branch, with another branch still to end.
    let proxy = forking_proxy(&[DECIDING, RINGING], "parallel", "");
    let (raw, invites) = call(&proxy, "cancel-after-answer@example.com");
    let (to_deciding, to_ringing) = (
        find(&invites, DECIDING).clone(),
        find(&invites, RINGING).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    let sent = proxy.wire();
    assert!(responses_to_caller(&sent).contains(&200));
    the_cancel(&sent, RINGING, &to_ringing);
    let sessions = proxy.state.session_store.client_key_count();

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(
        responses_to_caller(&sent),
        [200],
        "the CANCEL's 200, and no 487 behind the answer"
    );
    assert!(cancels_to(&sent, RINGING).is_empty());
    assert_eq!(
        proxy.state.session_store.client_key_count(),
        sessions,
        "and the call is as it was"
    );
}
