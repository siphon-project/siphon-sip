//! A notifier reads the final response to the NOTIFY it sent (RFC 6665
//! §4.2.2), through the dispatcher: the script accepts a SUBSCRIBE and awaits
//! its initial NOTIFY, the subscriber's answer comes in as any response does,
//! and a 481 removes the subscription the script holds a handle to.
//!
//! The NOTIFY here is the one held behind the 200 that accepted the
//! subscription, so this is also the check that a held NOTIFY is watched.

use std::time::{Duration, Instant};

use super::subscribe_test_harness::{header_value, subscribe_harness, SubscribeHarness};

const SUBSCRIBER: &str = "192.0.2.20:5070";

fn subscribe(case: &str) -> String {
    format!(
        concat!(
            "SUBSCRIBE sip:201@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-{case}\r\n",
            "From: <sip:201@siphon.example.com>;tag=watcher\r\n",
            "To: <sip:201@siphon.example.com>\r\n",
            "Call-ID: {case}@example.com\r\n",
            "CSeq: 1 SUBSCRIBE\r\n",
            "Contact: <sip:201@192.0.2.20:5070>\r\n",
            "Event: message-summary\r\n",
            "Expires: 60\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        case = case
    )
}

/// Subscribe, and return the initial NOTIFY the notifier sent behind its 200.
fn subscribed(harness: &SubscribeHarness, case: &str) -> String {
    harness.receive_request(&subscribe(case), SUBSCRIBER);
    let frames = harness.frames_awaiting(2, Duration::from_secs(10));
    let texts: Vec<String> = frames
        .iter()
        .map(|(_, frame)| String::from_utf8_lossy(frame).to_string())
        .collect();
    assert_eq!(texts.len(), 2, "the 200 and the initial NOTIFY: {texts:?}");
    assert!(texts[0].starts_with("SIP/2.0 200"), "{texts:?}");
    assert!(texts[1].starts_with("NOTIFY "), "{texts:?}");
    texts[1].clone()
}

/// The subscriber's answer to `notify`.
fn answer(notify: &str, status: u16) -> String {
    let header = |name: &str| header_value(notify, name).expect(name);
    format!(
        "SIP/2.0 {status} Reason\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\n\
         CSeq: {}\r\nContent-Length: 0\r\n\r\n",
        header("Via"),
        header("From"),
        header("To"),
        header("Call-ID"),
        header("CSeq"),
    )
}

/// The notifier's tag: the From tag of its NOTIFY.
fn notifier_tag(notify: &str) -> String {
    let from = header_value(notify, "From").expect("From");
    from.split(";tag=")
        .nth(1)
        .expect("the NOTIFY's From is tagged")
        .to_string()
}

fn held(harness: &SubscribeHarness, case: &str, notify: &str) -> bool {
    harness
        .store
        .find_by_tags(
            &format!("{case}@example.com"),
            &notifier_tag(notify),
            "watcher",
        )
        .is_some()
}

#[test]
fn a_481_to_the_notify_removes_the_subscription() {
    let (_turn, harness) = subscribe_harness();
    let case = "notify-answered-481";
    let notify = subscribed(harness, case);
    assert!(held(harness, case, &notify));
    let pending = harness.state.uac_sender.pending_count();

    harness.receive_response(&answer(&notify, 481), SUBSCRIBER);

    let deadline = Instant::now() + Duration::from_secs(10);
    while held(harness, case, &notify) {
        assert!(
            Instant::now() < deadline,
            "the 481 did not remove the subscription"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        harness.state.uac_sender.pending_count(),
        pending - 1,
        "the NOTIFY's transaction is over"
    );
    assert!(
        harness.frames().is_empty(),
        "the response is the notifier's own: nothing is relayed or answered"
    );
}

#[test]
fn a_200_to_the_notify_keeps_the_subscription() {
    let (_turn, harness) = subscribe_harness();
    let case = "notify-answered-200";
    let notify = subscribed(harness, case);
    let pending = harness.state.uac_sender.pending_count();

    harness.receive_response(&answer(&notify, 200), SUBSCRIBER);

    assert_eq!(
        harness.state.uac_sender.pending_count(),
        pending - 1,
        "the NOTIFY's transaction is over"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(held(harness, case, &notify));
    harness
        .store
        .remove(&harness_id(harness, case, &notify).expect("the subscription"));
}

/// The id of the subscription, to clear it from the shared store.
fn harness_id(harness: &SubscribeHarness, case: &str, notify: &str) -> Option<String> {
    harness
        .store
        .find_by_tags(
            &format!("{case}@example.com"),
            &notifier_tag(notify),
            "watcher",
        )
        .map(|dialog| dialog.id)
}
