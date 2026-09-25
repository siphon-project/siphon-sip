//! The initial NOTIFY a SUBSCRIBE handler sends must leave behind the 200 that
//! accepted the subscription (RFC 6665 §4.1.2.3).
//!
//! `subscribe_state.accept()` stages the 200, which the dispatcher sends once
//! the handler returns, while `await handle.notify()` sends inside the handler.
//! The handler is `async def`, so the NOTIFY is built on a tokio worker and the
//! coroutine runs on an asyncio driver: neither is the dispatcher thread whose
//! deferred-send queue orders messages behind the reply. Only a test that runs
//! a real async script through `handle_request` sees that; a unit test on the
//! queue or on `accept()` alone stays green while the wire order is reversed.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

const NOTIFIER: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"SUBSCRIBE\")\n",
    "async def subscribe(request):\n",
    "    handle = proxy.subscribe_state.accept(request, expires=60)\n",
    "    await handle.notify(\n",
    "        body=\"Messages-Waiting: no\\r\\n\",\n",
    "        content_type=\"application/simple-message-summary\",\n",
    "    )\n",
);

const SUBSCRIBER: &str = "192.0.2.20:5070";

fn subscribe() -> String {
    concat!(
        "SUBSCRIBE sip:201@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-order\r\n",
        "From: <sip:201@siphon.example.com>;tag=watcher\r\n",
        "To: <sip:201@siphon.example.com>\r\n",
        "Call-ID: reply-order@example.com\r\n",
        "CSeq: 1 SUBSCRIBE\r\n",
        "Contact: <sip:201@192.0.2.20:5070>\r\n",
        "Event: message-summary\r\n",
        "Expires: 60\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
    .to_string()
}

/// The frames a peer receives, in egress order: each outbound message's own
/// data, then the followups the transport writes behind it.
fn frames(udp: &flume::Receiver<OutboundMessage>) -> Vec<(SocketAddr, Bytes)> {
    let mut frames = Vec::new();
    while let Ok(message) = udp.try_recv() {
        let destination = message.destination;
        for frame in message.frames() {
            frames.push((destination, frame.clone()));
        }
    }
    frames
}

#[test]
fn the_initial_notify_leaves_after_the_200_that_accepted_the_subscription() {
    Python::initialize();
    // The singleton goes in before the script engine is built, so the script's
    // `proxy.subscribe_state` is the Rust namespace rather than the stub.
    Python::attach(|python| {
        let namespace = crate::script::api::subscribe_state::PySubscribeState::new(Arc::new(
            crate::subscribe_state::SubscribeStore::new(),
        ));
        let _ = crate::script::api::set_subscribe_state_singleton(python, namespace);
    });
    let TestDispatcher { state, udp } = test_dispatcher_with_script(NOTIFIER);
    crate::script::api::subscribe_state::set_uac_sender(Arc::clone(&state.uac_sender));
    crate::script::api::subscribe_state::set_resolver(Arc::clone(&state.dns_resolver));
    let state = Arc::new(state);
    let raw = subscribe();
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the SUBSCRIBE parses");

    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: SUBSCRIBER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        "SUBSCRIBE".to_string(),
        &state,
    );

    let sent = frames(&udp);
    let starts: Vec<String> = sent
        .iter()
        .map(|(_, frame)| {
            String::from_utf8_lossy(frame)
                .lines()
                .next()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(
        starts.len(),
        2,
        "exactly the 200 and the initial NOTIFY, got {starts:?}"
    );
    assert!(
        starts[0].starts_with("SIP/2.0 200"),
        "the 200 accepting the subscription goes first, got {starts:?}"
    );
    assert!(
        starts[1].starts_with("NOTIFY "),
        "the initial NOTIFY follows it, got {starts:?}"
    );
    assert!(
        sent.iter()
            .all(|(destination, _)| destination.to_string() == SUBSCRIBER),
        "both go to the subscriber"
    );
}
