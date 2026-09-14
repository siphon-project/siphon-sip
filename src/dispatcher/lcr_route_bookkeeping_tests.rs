//! What an LCR sequence keeps about the carriers it has been through: a carrier
//! that failed is settled, and is never CANCELled after its final response.
//!
//! Driven through the dispatcher with the harness of
//! [`super::lcr_ring_timeout_tests`]: carriers answer through
//! [`handle_b2bua_response`] and ring out through
//! [`check_b2bua_answer_timeouts_at`], and every message siphon sends is read
//! back off the UDP egress channel.

use super::lcr_ring_timeout_tests::{
    carrier, invite_to, summaries, Sequence, CALLER, FIRST_CARRIER, SECOND_CARRIER, THIRD_CARRIER,
};
use super::*;
use std::time::Duration;

/// Where `@b2bua.on_failure` sends the call again in the re-route test.
const BACKUP_TARGET: &str = "198.51.100.20:5060";

/// Logs every `@b2bua.on_route_failure` and `@b2bua.on_failure` onto the A-leg
/// INVITE, in the order they ran, with the attempt list `on_failure` was
/// handed. Kept on the call rather than in the script, so the script holds no
/// state of its own.
const RECORD_EVENTS: &str = r#"
from siphon import b2bua

def mark(call, entry):
    seen = call.get_header("X-Test-Events") or ""
    call.set_header("X-Test-Events", seen + entry + ";")

@b2bua.on_route_failure
def route_failed(call, route, code):
    mark(call, "route:" + route.carrier_id + ":" + str(code))

@b2bua.on_failure
def failed(call, code, reason):
    attempts = ",".join(
        attempt["carrier_id"] + "=" + str(attempt["status"])
        for attempt in call.route_attempts
    )
    mark(call, "failure:" + str(code) + ":" + attempts)
"#;

/// Routes the call once more from `@b2bua.on_failure`, to [`BACKUP_TARGET`],
/// and lets the second failure end it.
const REDIAL_ON_FAILURE: &str = r#"
from siphon import b2bua

@b2bua.on_failure
def failed(call, code, reason):
    seen = call.get_header("X-Test-Failures") or ""
    call.set_header("X-Test-Failures", seen + str(code) + ";")
    if not seen:
        call.dial("sip:15550100042@198.51.100.20:5060", timeout=4)
"#;

/// The hooks [`RECORD_EVENTS`] saw, in order.
fn events(sequence: &Sequence) -> String {
    sequence
        .invite
        .lock()
        .expect("the A-leg INVITE lock")
        .headers
        .get("X-Test-Events")
        .map(|value| value.to_string())
        .unwrap_or_default()
}

/// The call's attempt list as `carrier=status`, oldest first.
fn attempts(sequence: &Sequence) -> Vec<String> {
    sequence
        .dispatcher
        .state
        .call_actors
        .route_attempts(&sequence.call_id)
        .iter()
        .map(|attempt| format!("{}={}", attempt.carrier_id, attempt.status))
        .collect()
}

/// The caller abandons the call it placed with [`Sequence::start`].
fn caller_cancels(sequence: &Sequence) {
    let raw = concat!(
        "CANCEL sip:15550100042@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-lcr-policy\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>\r\n",
        "Call-ID: lcr-policy@192.0.2.10\r\n",
        "CSeq: 1 CANCEL\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let cancel = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's CANCEL parses");
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: sequence.dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(raw.as_bytes()),
    };
    handle_b2bua_cancel(inbound, cancel, &sequence.dispatcher.state);
}

/// Start `routes` and fail the first carrier with a 503, which dials the
/// second.
fn first_carrier_fails(routes: Vec<crate::lcr::Route>, script: &str) -> (Sequence, SipMessage) {
    let mut sequence = Sequence::start_with_script(routes, 5, script);
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence.redialled();
    let second = invite_to(sent, SECOND_CARRIER);
    (sequence, second)
}

/// The failure this exists for. The first carrier's 503 was ACKed and the
/// second carrier dialled, but the first carrier's leg stayed pending, so when
/// the second one rang out siphon CANCELled both. A CANCEL after a final
/// response is one RFC 3261 §9.1 says a client SHOULD NOT send.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_failed_is_not_cancelled_when_the_next_one_rings_out() {
    let (sequence, _) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        "",
    );

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("408 to {CALLER}")
        ],
        "only the carrier still ringing is CANCELled"
    );
}

/// The same for a carrier that showed progress and then rang out, which fails
/// the call without dialling the carrier after it.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_failed_is_not_cancelled_when_a_ringing_carrier_rings_out() {
    let (sequence, second) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
            carrier("carrier-c", THIRD_CARRIER, 2),
        ],
        "",
    );
    sequence.carrier_answers(SECOND_CARRIER, &second, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(5));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("408 to {CALLER}")
        ]
    );
}

/// A caller that hangs up while the second carrier rings CANCELs that carrier
/// only.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_cancel_after_a_carrier_failed_cancels_only_the_carrier_ringing() {
    let (sequence, _) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        "",
    );

    caller_cancels(&sequence);
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("200 to {CALLER}"),
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("487 to {CALLER}")
        ]
    );
    assert!(sequence.call_is_gone());
}

/// The second carrier answering cancels the branches still ringing, and the
/// first carrier is not one of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_failed_is_not_cancelled_when_the_next_one_answers() {
    let (sequence, second) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        "",
    );

    sequence.carrier_answers(SECOND_CARRIER, &second, 200, "OK");
    assert_eq!(summaries(&sequence.wire()), [format!("200 to {CALLER}")]);
}

/// `@b2bua.on_failure` routes the call again after the sequence ran out, and
/// when that dial rings out only its own leg is CANCELled: the carrier that
/// failed stays settled under the new routing.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_failed_is_not_cancelled_when_on_failure_routes_the_call_again() {
    let mut sequence = Sequence::start_with_script(
        vec![carrier("carrier-a", FIRST_CARRIER, 2)],
        5,
        REDIAL_ON_FAILURE,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {BACKUP_TARGET}")
        ]
    );
    sequence.redialled();

    sequence.ring_for(Duration::from_secs(4));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {BACKUP_TARGET}"),
            format!("408 to {CALLER}")
        ]
    );
    assert_eq!(sequence.failures_seen().as_deref(), Some("500;408;"));
}

/// A carrier whose ACK was lost retransmits its 503. That is re-ACKed and does
/// nothing else: it is not recorded against the carrier now in flight, and it
/// does not move the sequence past that carrier.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_failure_from_a_carrier_that_failed_is_absorbed() {
    let mut sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
            carrier("carrier-c", THIRD_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence.redialled();

    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("ACK to {FIRST_CARRIER}")],
        "the retransmission is ACKed again and nothing else goes out"
    );
    assert_eq!(attempts(&sequence), ["carrier-a=503"]);
    assert_eq!(events(&sequence), "route:carrier-a:503;");

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("INVITE to {THIRD_CARRIER}")
        ],
        "the second carrier was still the one in flight"
    );
}
