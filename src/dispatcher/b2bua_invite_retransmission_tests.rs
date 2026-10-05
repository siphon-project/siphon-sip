//! A retransmitted INVITE on a B2BUA call that already has its final non-2xx
//! (RFC 3261 §17.2.1, Completed).
//!
//! The B2BUA removes a failed call once it has answered the caller. A caller
//! that did not get that answer retransmits its INVITE, and the retransmission
//! then found no call and was taken for a new one: the script ran again and the
//! caller got a second, different final response. It is owed the first one.
//!
//! Driven through `handle_request` on a test dispatcher and read back off the
//! UDP egress.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "198.51.100.10:5060";

const REJECTING_B2BUA: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.reject(486, \"Busy Here\")\n",
);

const REJECTING_PROXY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"INVITE\")\n",
    "def on_invite(request):\n",
    "    request.reply(486, \"Busy Here\")\n",
);

fn invite(branch: &str) -> String {
    format!(
        concat!(
            "INVITE sip:+15550100@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:+15550111@peer.example.com>;tag=caller-tag\r\n",
            "To: <sip:+15550100@siphon.example.com>\r\n",
            "Call-ID: retransmitted@peer.example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:+15550111@{caller}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
        branch = branch,
    )
}

fn dispatcher(script: &str) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    (Arc::new(state), udp)
}

/// Feed `raw` in from the caller and return the bytes of every final response
/// sent for it.
fn final_responses_to(
    (state, udp): &(Arc<DispatcherState>, flume::Receiver<OutboundMessage>),
    raw: String,
) -> Vec<Bytes> {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        "INVITE".to_string(),
        state,
    );
    udp.try_iter()
        .map(|sent| sent.data)
        .filter(|data| {
            parse_sip_message_bytes(data)
                .ok()
                .and_then(|sent| sent.status_code())
                .is_some_and(|code| code >= 200)
        })
        .collect()
}

/// The caller's ACK for the final response to `invite("z9hG4bK-first")`: the
/// INVITE's own branch and CSeq number (RFC 3261 §17.1.1.3).
fn ack_arrives(
    (state, _udp): &(Arc<DispatcherState>, flume::Receiver<OutboundMessage>),
    transport: Transport,
) {
    let raw = invite("z9hG4bK-first")
        .replace("INVITE sip:", "ACK sip:")
        .replace("CSeq: 1 INVITE", "CSeq: 1 ACK");
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the ACK parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport,
            local_addr: state.local_addr,
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        "ACK".to_string(),
        state,
    );
}

/// Over UDP the ACK leaves the response owed for Timer I, so a retransmission
/// already in flight is still answered with it.
#[tokio::test(flavor = "multi_thread")]
async fn an_acked_final_response_is_still_owed_over_udp() {
    let dispatcher = dispatcher(REJECTING_B2BUA);
    let first = final_responses_to(&dispatcher, invite("z9hG4bK-first"));

    ack_arrives(&dispatcher, Transport::Udp);
    assert_eq!(dispatcher.0.completed_invites.len(), 1);
    let again = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert_eq!(again, first);
}

/// Over a reliable transport the ACK ends the transaction (Timer I is zero):
/// nothing is kept, and the same identifiers afterwards are a new call.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_over_a_reliable_transport_releases_the_response() {
    let dispatcher = dispatcher(REJECTING_B2BUA);
    let first = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert_eq!(dispatcher.0.completed_invites.len(), 1);

    ack_arrives(&dispatcher, Transport::Tcp);
    assert!(dispatcher.0.completed_invites.is_empty());
    let again = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert_eq!(again.len(), 1);
    assert_ne!(again, first, "a new call builds its own response");
}

/// The retransmission gets the first final response again, byte for byte. A
/// second run of the script would have built a new one with a new To-tag.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_invite_gets_the_same_final_response() {
    let dispatcher = dispatcher(REJECTING_B2BUA);

    let first = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert_eq!(first.len(), 1, "one final response to the INVITE");
    let status = parse_sip_message_bytes(&first[0]).unwrap().status_code();
    assert_eq!(status, Some(486));
    assert_eq!(dispatcher.0.call_actors.count(), 0, "the call is over");
    assert_eq!(dispatcher.0.completed_invites.len(), 1);

    let again = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert_eq!(again, first, "the retransmission is owed the same response");
    assert_eq!(dispatcher.0.call_actors.count(), 0, "and it starts no call");
    assert_eq!(dispatcher.0.completed_invites.len(), 1);
}

/// An INVITE on another Via branch is a new transaction (a retry after a
/// challenge, a new attempt): it is a call of its own.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_on_another_branch_is_a_new_call() {
    let dispatcher = dispatcher(REJECTING_B2BUA);

    let first = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    let second = final_responses_to(&dispatcher, invite("z9hG4bK-second"));
    assert_eq!(second.len(), 1);
    assert_ne!(second, first, "a new transaction gets its own response");
    assert_eq!(dispatcher.0.completed_invites.len(), 2);
}

/// A proxy has its own INVITE server transaction, so nothing is recorded for a
/// deployment with no B2BUA handler.
#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_only_deployment_records_nothing() {
    let dispatcher = dispatcher(REJECTING_PROXY);
    let first = final_responses_to(&dispatcher, invite("z9hG4bK-first"));
    assert!(!first.is_empty());
    assert!(dispatcher.0.completed_invites.is_empty());
}
