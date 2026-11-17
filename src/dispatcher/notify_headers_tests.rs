//! `handle.notify(headers=…)` and `handle.terminate(headers=…)`: the headers a
//! script adds reach the wire on the NOTIFY, and a header siphon owns on a
//! NOTIFY inside a subscription (RFC 3261 §12.2.1.1, RFC 6665 §4.2.1.2) is
//! refused before anything is sent.
//!
//! Run through `handle_request` with a real script: the refusal has to reach
//! the script as an exception, and the header has to be on the bytes that
//! leave, neither of which a test on the argument check alone would show.

use super::subscribe_test_harness::{header_value, subscribe_harness, SubscribeHarness};

const SUBSCRIBER: &str = "192.0.2.20:5070";

/// Subscribe as `call_id`; returns the notifier's tag off the 200.
fn subscribed(harness: &SubscribeHarness, call_id: &str) -> String {
    let subscribe = format!(
        concat!(
            "SUBSCRIBE sip:group@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-{call_id}\r\n",
            "From: <sip:201@siphon.example.com>;tag=watcher\r\n",
            "To: <sip:group@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 SUBSCRIBE\r\n",
            "Contact: <sip:201@192.0.2.20:5070>\r\n",
            "Event: conference\r\n",
            "Expires: 60\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = call_id,
    );
    harness.receive_request(&subscribe, SUBSCRIBER);
    let frames = texts(harness);
    assert_eq!(
        frames.len(),
        2,
        "the 200 and the initial NOTIFY: {frames:?}"
    );
    let to = header_value(&frames[0], "To").expect("the 200 has a To");
    let (_, tag) = to.split_once(";tag=").expect("the 200 carries the To tag");
    tag.to_string()
}

fn texts(harness: &SubscribeHarness) -> Vec<String> {
    harness
        .frames()
        .iter()
        .map(|(_, frame)| String::from_utf8_lossy(frame).to_string())
        .collect()
}

/// Have the script notify (or terminate) in the subscription, with `extra`
/// request headers steering what it passes as `headers=`. Returns what left.
fn asked(
    harness: &SubscribeHarness,
    call_id: &str,
    local_tag: &str,
    sequence: u32,
    extra: &str,
) -> Vec<String> {
    let publish = format!(
        concat!(
            "PUBLISH sip:group@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.40:5070;branch=z9hG4bK-{call_id}-{sequence}\r\n",
            "From: <sip:focus@siphon.example.com>;tag=focus\r\n",
            "To: <sip:group@siphon.example.com>\r\n",
            "Call-ID: ask-{call_id}-{sequence}\r\n",
            "CSeq: {sequence} PUBLISH\r\n",
            "X-Dialog-Call-ID: {call_id}\r\n",
            "X-Local-Tag: {local_tag}\r\n",
            "X-Remote-Tag: watcher\r\n",
            "{extra}",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = call_id,
        local_tag = local_tag,
        sequence = sequence,
        extra = extra,
    );
    harness.receive_request(&publish, "192.0.2.40:5070");
    texts(harness)
}

fn the_notify(frames: &[String]) -> &String {
    let notifies: Vec<&String> = frames
        .iter()
        .filter(|frame| frame.starts_with("NOTIFY "))
        .collect();
    assert_eq!(notifies.len(), 1, "exactly one NOTIFY: {frames:?}");
    notifies[0]
}

fn sequence_number(notify: &str) -> u32 {
    header_value(notify, "CSeq")
        .and_then(|value| value.split(' ').next()?.parse().ok())
        .expect("a NOTIFY has a CSeq")
}

fn assert_asserted_headers(notify: &str) {
    assert_eq!(
        header_value(notify, "P-Asserted-Identity").as_deref(),
        Some("<sip:group@example.com>"),
        "{notify}"
    );
    assert_eq!(
        header_value(notify, "P-Asserted-Service").as_deref(),
        Some("urn:urn-7:3gpp-service.ims.icsi.mcptt"),
        "{notify}"
    );
    // In the order the mapping gave them.
    let identity = notify.find("P-Asserted-Identity:").expect("present");
    let service = notify.find("P-Asserted-Service:").expect("present");
    assert!(identity < service, "{notify}");
}

fn subscription_stands(harness: &SubscribeHarness, call_id: &str, local_tag: &str) -> bool {
    harness
        .store
        .find_by_tags(call_id, local_tag, "watcher")
        .is_some()
}

#[test]
fn headers_a_script_adds_reach_the_wire_on_notify_and_on_terminate() {
    let (_turn, harness) = subscribe_harness();
    let call_id = "notify-headers@example.com";
    let local_tag = subscribed(harness, call_id);

    let frames = asked(harness, call_id, &local_tag, 1, "");
    let notify = the_notify(&frames);
    assert_asserted_headers(notify);
    // Still the subscription's own NOTIFY around them.
    assert_eq!(header_value(notify, "Event").as_deref(), Some("conference"));
    assert!(header_value(notify, "Subscription-State")
        .is_some_and(|state| state.starts_with("active;expires=")));
    assert_eq!(header_value(notify, "Call-ID").as_deref(), Some(call_id));
    assert!(frames.iter().any(|frame| frame.starts_with("SIP/2.0 200")));

    let frames = asked(harness, call_id, &local_tag, 2, "X-Terminate: yes\r\n");
    let last = the_notify(&frames);
    assert_asserted_headers(last);
    assert_eq!(
        header_value(last, "Subscription-State").as_deref(),
        Some("terminated;reason=deactivated")
    );
    assert_eq!(sequence_number(last), sequence_number(notify) + 1);
    assert!(
        !subscription_stands(harness, call_id, &local_tag),
        "the terminated subscription is gone"
    );
}

#[test]
fn a_header_siphon_owns_is_refused_and_nothing_is_sent() {
    let (_turn, harness) = subscribe_harness();
    let call_id = "notify-owned-headers@example.com";
    let local_tag = subscribed(harness, call_id);
    let before = sequence_number(the_notify(&asked(harness, call_id, &local_tag, 1, "")));

    let owned = [
        "Via",
        "From",
        "To",
        "Call-ID",
        "CSeq",
        "Contact",
        "Route",
        "Max-Forwards",
        "Content-Length",
        "Content-Type",
        "Event",
        "Subscription-State",
    ];
    let mut sequence = 2;
    for terminate in ["", "X-Terminate: yes\r\n"] {
        for name in owned {
            let extra = format!("X-Owned: {name}\r\n{terminate}");
            let frames = asked(harness, call_id, &local_tag, sequence, &extra);
            sequence += 1;
            assert_eq!(frames.len(), 1, "only the answer to the ask: {frames:?}");
            assert!(frames[0].starts_with("SIP/2.0 400"), "{frames:?}");
            let failure = header_value(&frames[0], "X-Failure").expect("the refusal");
            assert!(
                failure.starts_with("ValueError: ") && failure.contains(&format!("{name} cannot")),
                "a ValueError naming {name}, got {failure:?}"
            );
        }
    }

    // A refusal used nothing up: the next NOTIFY is the next CSeq, in a
    // subscription that is still there (a refused terminate() ended nothing).
    assert!(subscription_stands(harness, call_id, &local_tag));
    let frames = asked(harness, call_id, &local_tag, sequence, "");
    assert_eq!(sequence_number(the_notify(&frames)), before + 1);
}

#[test]
fn a_header_value_that_is_not_a_str_raises_type_error_and_nothing_is_sent() {
    let (_turn, harness) = subscribe_harness();
    let call_id = "notify-header-types@example.com";
    let local_tag = subscribed(harness, call_id);

    for (sequence, terminate) in [(1, ""), (2, "X-Terminate: yes\r\n")] {
        let extra = format!("X-Not-A-Str: yes\r\n{terminate}");
        let frames = asked(harness, call_id, &local_tag, sequence, &extra);
        assert_eq!(frames.len(), 1, "only the answer to the ask: {frames:?}");
        let failure = header_value(&frames[0], "X-Failure").expect("the refusal");
        assert!(
            failure.starts_with("TypeError: ") && failure.contains("str header names"),
            "got {failure:?}"
        );
    }
    assert!(
        subscription_stands(harness, call_id, &local_tag),
        "the subscription stands"
    );
}
