//! A retransmission of a 2xx the proxy forwarded goes to the caller as the
//! first copy went: the message the script's `@proxy.on_reply` produced, from
//! the local socket the INVITE came in on.
//!
//! A UAS retransmits its 2xx until the ACK arrives (RFC 3261 §13.3.1.4). The
//! proxy forwards each copy (§16.7 step 5, RFC 6026 §8.4), and a copy is the
//! same response, so it carries what the proxy did to the first: a P-CSCF that
//! anchors the media rewrites the SDP of the first and must send the same SDP
//! again. The caller may take either copy. A copy that leaves from another
//! socket also misses the IPsec SA the first went over (3GPP TS 33.203 §7.4).

use super::proxy_cancel_awaits_provisional_tests::{call, CALLER, DECIDING, SILENT};
use super::proxy_dialog_state_tests::{find, header, knows_itself, response_to, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// The protected port the caller's INVITE arrives on, as on a P-CSCF.
const PROTECTED: &str = "192.0.2.1:5064";

/// A proxy that forks every INVITE to `targets` and rewrites every response
/// its `@proxy.on_reply` handler sees, as a media anchor rewrites the SDP.
fn rewriting_proxy(targets: &[&str]) -> Proxy {
    let uris: Vec<String> = targets
        .iter()
        .map(|target| format!("\"sip:callee@{target}\""))
        .collect();
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    if request.in_dialog:\n",
            "        request.loose_route()\n",
            "        request.relay()\n",
            "        return\n",
            "    request.record_route()\n",
            "    request.fork([{uris}])\n",
            "\n",
            "@proxy.on_reply\n",
            "def answered(request, reply):\n",
            "    reply.set_header(\"X-Anchored\", \"192.0.2.99\")\n",
            "    reply.relay()\n",
        ),
        uris = uris.join(", "),
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    knows_itself(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// `target`'s 200 to `invite`, the same octets every time it is sent.
fn answer(invite: &SipMessage, target: &str) -> SipMessage {
    response_to(
        invite,
        200,
        "OK",
        &format!("tag-{}", target.replace(['.', ':'], "-")),
        &format!("sip:callee@{target}"),
        "",
    )
}

/// The 200s to the INVITE that left for the caller: (octets, local socket).
fn answers_to_caller(proxy: &Proxy) -> Vec<(SipMessage, Option<SocketAddr>)> {
    let mut answers = Vec::new();
    while let Ok(outbound) = proxy.udp.try_recv() {
        if outbound.destination.to_string() != CALLER {
            continue;
        }
        for frame in outbound.frames() {
            let message =
                parse_sip_message_bytes(frame).expect("siphon sent a message that parses");
            if message.status_code() == Some(200) && header(&message, "CSeq").ends_with("INVITE") {
                answers.push((message, outbound.source_local_addr));
            }
        }
    }
    answers
}

fn assert_retransmission_is_the_forwarded_answer(proxy: &Proxy, target: &str, invite: &SipMessage) {
    let answer = answer(invite, target);
    proxy.response(target, answer.clone());
    let first = answers_to_caller(proxy);
    assert_eq!(first.len(), 1, "the answer reaches the caller");
    assert_eq!(header(&first[0].0, "X-Anchored"), "192.0.2.99");

    // No ACK yet: the UAS sends the same 200 at T1 and 2*T1.
    for _ in 0..2 {
        proxy.response(target, answer.clone());
        let again = answers_to_caller(proxy);
        assert_eq!(again.len(), 1, "each retransmission reaches the caller");
        assert_eq!(
            again[0].0.to_bytes(),
            first[0].0.to_bytes(),
            "a retransmission carries what the reply handler made of the first"
        );
        assert_eq!(
            again[0].1, first[0].1,
            "and leaves from the socket the first left from"
        );
    }
}

/// The caller's INVITE arrives on `local` (a P-CSCF's protected port).
fn call_on(proxy: &Proxy, call_id: &str, local: &str) -> Vec<(String, SipMessage)> {
    let raw = super::proxy_cancel_awaits_provisional_tests::caller_invite(call_id);
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: local.parse().expect("a literal address"),
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.clone()),
    };
    tokio::task::block_in_place(|| {
        handle_request(inbound, message, "INVITE".to_string(), &proxy.state)
    });
    super::proxy_dialog_state_tests::invites_by_destination(&proxy.wire())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_answer_is_sent_as_the_reply_handler_made_it() {
    let proxy = rewriting_proxy(&[DECIDING]);
    let (_, invites) = call(&proxy, "retransmitted-2xx@example.com");
    let invite = find(&invites, DECIDING).clone();

    assert_retransmission_is_the_forwarded_answer(&proxy, DECIDING, &invite);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_answer_of_a_fork_is_sent_as_the_reply_handler_made_it() {
    let proxy = rewriting_proxy(&[DECIDING, SILENT]);
    let (_, invites) = call(&proxy, "retransmitted-2xx-fork@example.com");
    let invite = find(&invites, DECIDING).clone();

    assert_retransmission_is_the_forwarded_answer(&proxy, DECIDING, &invite);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_answer_leaves_from_the_socket_the_invite_came_in_on() {
    let proxy = rewriting_proxy(&[DECIDING]);
    let invites = call_on(&proxy, "retransmitted-2xx-protected@example.com", PROTECTED);
    let invite = find(&invites, DECIDING).clone();
    let answer = answer(&invite, DECIDING);

    proxy.response(DECIDING, answer.clone());
    let first = answers_to_caller(&proxy);
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].1,
        Some(PROTECTED.parse().expect("a literal address"))
    );

    proxy.response(DECIDING, answer);
    let again = answers_to_caller(&proxy);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].1, first[0].1, "over the same SA's local endpoint");
    assert_eq!(header(&again[0].0, "X-Anchored"), "192.0.2.99");
}

/// What is kept for the retransmissions goes with the ACK, or after 64*T1.
#[tokio::test(flavor = "multi_thread")]
async fn a_forwarded_answer_is_kept_until_its_ack_or_its_lifetime() {
    use crate::proxy::session::FORWARDED_ANSWER_LIFETIME;
    let proxy = rewriting_proxy(&[DECIDING]);
    let (_, invites) = call(&proxy, "forwarded-2xx-lifetime@example.com");
    let invite = find(&invites, DECIDING).clone();
    let answer = answer(&invite, DECIDING);
    proxy.response(DECIDING, answer.clone());
    let store = &proxy.state.session_store;
    assert_eq!(store.forwarded_answer_count(), 1);

    store.sweep_forwarded_answers(std::time::Instant::now(), FORWARDED_ANSWER_LIFETIME);
    assert_eq!(store.forwarded_answer_count(), 1, "within 64*T1 it stays");
    store.sweep_forwarded_answers(
        std::time::Instant::now() + FORWARDED_ANSWER_LIFETIME + std::time::Duration::from_secs(1),
        FORWARDED_ANSWER_LIFETIME,
    );
    assert_eq!(store.forwarded_answer_count(), 0, "past 64*T1 it goes");

    proxy.response(DECIDING, answer.clone());
    let raw_ack = String::from_utf8(answer.to_bytes())
        .expect("UTF-8")
        .replacen(
            "SIP/2.0 200 OK",
            "ACK sip:callee@198.51.100.14:5060 SIP/2.0",
            1,
        )
        .replace("CSeq: 5 INVITE", "CSeq: 5 ACK");
    let ack = parse_sip_message_bytes(raw_ack.as_bytes()).expect("the ACK parses");
    store.note_forwarded_answer(crate::proxy::session::ForwardedAnswer {
        branch: "z9hG4bK-test".to_string(),
        message: answer,
        destination: CALLER.parse().expect("a literal address"),
        transport: Transport::Udp,
        connection_id: ConnectionId::default(),
        source_local_addr: None,
        forwarded_at: std::time::Instant::now(),
    });
    assert_eq!(store.forwarded_answer_count(), 1);
    store.forget_forwarded_answer(&ack);
    assert_eq!(store.forwarded_answer_count(), 0, "its ACK ends it");
}
