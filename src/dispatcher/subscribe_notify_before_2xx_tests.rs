//! A NOTIFY that arrives before the 2xx to the SUBSCRIBE it answers belongs to
//! that subscription (RFC 6665 §4.1.2.4, §4.4.1).
//!
//! `await proxy.subscribe_state.send()` suspends a coroutine on the 2xx, while
//! the NOTIFY is a request of its own that runs the script's NOTIFY handler on
//! another thread. Which of the two the subscriber processes first is not the
//! notifier's to decide, so the tests here deliver them in a chosen order
//! through `handle_request` / `handle_response` and read what the script did
//! off the wire.

use super::subscribe_test_harness::{header_value, subscribe_harness, SubscribeHarness};

const TRIGGER_SOURCE: &str = "192.0.2.20:5070";
const NOTIFIER: &str = "192.0.2.30:5060";
const NOTIFIER_TAG: &str = "notifier-tag";

/// The MESSAGE that makes the script subscribe, waiting `timeout_ms` for the
/// 2xx. Each call is a transaction of its own.
fn trigger(sequence: u32, timeout_ms: u64) -> String {
    format!(
        concat!(
            "MESSAGE sip:watch@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-trigger-{sequence}\r\n",
            "From: <sip:operator@example.com>;tag=trigger-{sequence}\r\n",
            "To: <sip:watch@siphon.example.com>\r\n",
            "Call-ID: trigger-{sequence}@example.com\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "X-Timeout-Ms: {timeout_ms}\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        sequence = sequence,
        timeout_ms = timeout_ms,
    )
}

/// A subscription attempt in flight: the SUBSCRIBE is on the wire and the
/// script's `send()` is suspended on its response.
struct Attempt {
    harness: &'static SubscribeHarness,
    subscribe: String,
    handler: Option<std::thread::JoinHandle<()>>,
    notifies: u32,
}

impl Attempt {
    fn start(harness: &'static SubscribeHarness, sequence: u32, timeout_ms: u64) -> Self {
        let raw = trigger(sequence, timeout_ms);
        let handler = std::thread::spawn(move || harness.receive_request(&raw, TRIGGER_SOURCE));
        let subscribe = harness.next_sent("SUBSCRIBE ");
        Self {
            harness,
            subscribe,
            handler: Some(handler),
            notifies: 0,
        }
    }

    fn subscribe_header(&self, name: &str) -> String {
        header_value(&self.subscribe, name)
            .unwrap_or_else(|| panic!("the SUBSCRIBE carries {name}"))
    }

    /// The notifier's NOTIFY for this subscription, from `tag`, and the start
    /// line and headers of what the script answered it with.
    fn notify(&mut self, tag: &str, event: &str, subscription_state: &str) -> String {
        self.notifies += 1;
        let raw = format!(
            concat!(
                "NOTIFY sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-notify-{branch}\r\n",
                "From: <sip:001010123456789@example.com>;tag={tag}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} NOTIFY\r\n",
                "Contact: <sip:notifier@192.0.2.30:5060>\r\n",
                "Event: {event}\r\n",
                "Subscription-State: {subscription_state}\r\n",
                "Max-Forwards: 70\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            branch = uuid::Uuid::new_v4(),
            tag = tag,
            to = self.subscribe_header("From"),
            call_id = self.subscribe_header("Call-ID"),
            cseq = self.notifies,
            event = event,
            subscription_state = subscription_state,
        );
        self.harness.receive_request(&raw, NOTIFIER);
        self.harness.next_sent("SIP/2.0 ")
    }

    /// The notifier's final response to the SUBSCRIBE, with `to_tag` as its
    /// dialog tag when it has one.
    fn answer(&self, status_line: &str, to_tag: Option<&str>) {
        let to = match to_tag {
            Some(tag) => format!("{};tag={tag}", self.subscribe_header("To")),
            None => self.subscribe_header("To"),
        };
        let raw = format!(
            concat!(
                "SIP/2.0 {status_line}\r\n",
                "Via: {via}\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq}\r\n",
                "Contact: <sip:notifier@192.0.2.30:5060>\r\n",
                "Expires: 600\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            status_line = status_line,
            via = self.subscribe_header("Via"),
            from = self.subscribe_header("From"),
            to = to,
            call_id = self.subscribe_header("Call-ID"),
            cseq = self.subscribe_header("CSeq"),
        );
        self.harness.receive_response(&raw, NOTIFIER);
    }

    /// Wait for the script's `send()` to return or raise, and give back what
    /// the handler answered the MESSAGE with.
    fn outcome(&mut self) -> String {
        let reply = self.harness.next_sent("SIP/2.0 ");
        if let Some(handler) = self.handler.take() {
            handler.join().expect("the handler thread finishes");
        }
        reply
    }
}

#[test]
fn a_notify_ahead_of_the_2xx_reaches_the_subscription_send_returns() {
    let (_turn, harness) = subscribe_harness();
    let mut attempt = Attempt::start(harness, 1, 5000);

    // The notifier's first NOTIFY overtakes its own 200 to the SUBSCRIBE.
    let early = attempt.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(
        early.starts_with("SIP/2.0 200"),
        "the script finds the subscription for a NOTIFY ahead of the 2xx, got {early:?}"
    );
    let early_id = header_value(&early, "X-Subscription").expect("the handle the script found");
    assert_eq!(header_value(&early, "X-Event").as_deref(), Some("reg"));

    attempt.answer("200 OK", Some(NOTIFIER_TAG));
    let reply = attempt.outcome();
    assert!(
        reply.starts_with("SIP/2.0 200"),
        "send() returns: {reply:?}"
    );
    assert_eq!(
        header_value(&reply, "X-Subscription").as_deref(),
        Some(early_id.as_str()),
        "send() returns the subscription the early NOTIFY was matched to"
    );

    // A NOTIFY after the 2xx finds that same subscription.
    let later = attempt.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(later.starts_with("SIP/2.0 200"), "got {later:?}");
    assert_eq!(
        header_value(&later, "X-Subscription").as_deref(),
        Some(early_id.as_str())
    );
}

#[test]
fn a_notify_after_the_2xx_finds_the_subscription_as_before() {
    let (_turn, harness) = subscribe_harness();
    let mut attempt = Attempt::start(harness, 2, 5000);

    attempt.answer("200 OK", Some(NOTIFIER_TAG));
    let reply = attempt.outcome();
    assert!(
        reply.starts_with("SIP/2.0 200"),
        "send() returns: {reply:?}"
    );
    let id = header_value(&reply, "X-Subscription").expect("the handle send() returned");

    let notified = attempt.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(notified.starts_with("SIP/2.0 200"), "got {notified:?}");
    assert_eq!(
        header_value(&notified, "X-Subscription").as_deref(),
        Some(id.as_str())
    );
    assert_eq!(harness.store.pending_count(), 0);
}

#[test]
fn a_rejected_subscribe_leaves_nothing_behind_even_after_an_early_notify() {
    let (_turn, harness) = subscribe_harness();
    let dialogs_before = harness.store.local_count();
    let mut attempt = Attempt::start(harness, 3, 5000);
    assert_eq!(harness.store.pending_count(), 1);

    let early = attempt.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(early.starts_with("SIP/2.0 200"), "got {early:?}");

    attempt.answer("403 Forbidden", None);
    let reply = attempt.outcome();
    assert!(reply.starts_with("SIP/2.0 500"), "send() raises: {reply:?}");
    assert!(
        header_value(&reply, "X-Failure").is_some_and(|failure| failure.contains("403")),
        "the script is told why, got {reply:?}"
    );

    assert_eq!(harness.store.pending_count(), 0);
    assert_eq!(harness.store.local_count(), dialogs_before);
    // RFC 6665 §4.1.2.1: a non-2xx created no subscription, so a NOTIFY for
    // it now matches none.
    let late = attempt.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(late.starts_with("SIP/2.0 481"), "got {late:?}");
}

#[test]
fn a_subscribe_that_times_out_leaves_nothing_behind() {
    let (_turn, harness) = subscribe_harness();
    let dialogs_before = harness.store.local_count();

    // Unanswered, and never notified.
    let mut silent = Attempt::start(harness, 4, 100);
    assert_eq!(harness.store.pending_count(), 1);
    let reply = silent.outcome();
    assert!(reply.starts_with("SIP/2.0 500"), "send() raises: {reply:?}");
    assert!(
        header_value(&reply, "X-Failure").is_some_and(|failure| failure.contains("timed out")),
        "got {reply:?}"
    );
    assert_eq!(harness.store.pending_count(), 0);
    assert_eq!(harness.store.local_count(), dialogs_before);

    // Notified, but the 2xx never comes.
    let mut notified = Attempt::start(harness, 5, 400);
    let early = notified.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(early.starts_with("SIP/2.0 200"), "got {early:?}");
    let reply = notified.outcome();
    assert!(reply.starts_with("SIP/2.0 500"), "send() raises: {reply:?}");
    assert_eq!(harness.store.pending_count(), 0);
    assert_eq!(harness.store.local_count(), dialogs_before);
    let late = notified.notify(NOTIFIER_TAG, "reg", "active;expires=600");
    assert!(late.starts_with("SIP/2.0 481"), "got {late:?}");
}

#[test]
fn a_terminated_notify_ahead_of_the_2xx_is_the_subscriptions_too() {
    let (_turn, harness) = subscribe_harness();
    let mut attempt = Attempt::start(harness, 6, 5000);

    let early = attempt.notify(NOTIFIER_TAG, "reg", "terminated;reason=rejected");
    assert!(
        early.starts_with("SIP/2.0 200"),
        "the script learns its subscription ended, got {early:?}"
    );
    let id = header_value(&early, "X-Subscription").expect("the handle the script found");

    attempt.answer("200 OK", Some(NOTIFIER_TAG));
    let reply = attempt.outcome();
    assert_eq!(
        header_value(&reply, "X-Subscription").as_deref(),
        Some(id.as_str()),
        "the same subscription as with the 2xx first"
    );
    assert_eq!(harness.store.pending_count(), 0);
}

#[test]
fn a_notify_for_another_event_package_does_not_take_the_pending_subscription() {
    let (_turn, harness) = subscribe_harness();
    let mut attempt = Attempt::start(harness, 7, 5000);

    let other = attempt.notify(NOTIFIER_TAG, "presence", "active;expires=600");
    assert!(other.starts_with("SIP/2.0 481"), "got {other:?}");
    assert_eq!(harness.store.pending_count(), 1);

    attempt.answer("200 OK", Some(NOTIFIER_TAG));
    let reply = attempt.outcome();
    assert!(
        reply.starts_with("SIP/2.0 200"),
        "send() returns: {reply:?}"
    );
    assert_eq!(harness.store.pending_count(), 0);
}
