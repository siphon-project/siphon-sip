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

use super::subscribe_test_harness::subscribe_harness;

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

#[test]
fn the_initial_notify_leaves_after_the_200_that_accepted_the_subscription() {
    // The script is the harness's: its SUBSCRIBE handler accepts the
    // subscription and awaits the initial NOTIFY.
    let (_turn, harness) = subscribe_harness();

    harness.receive_request(&subscribe(), SUBSCRIBER);

    let sent = harness.frames();
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
