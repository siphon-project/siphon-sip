//! What an LCR sequence keeps about the carriers it has been through: a carrier
//! that failed is settled, and is never CANCELled after its final response,
//! every failed attempt, a ring timeout included, is recorded once, and a ring
//! timeout that ends the sequence tells the caller whether any carrier got as
//! far as the callee.
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
            format!("503 to {CALLER}")
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

/// The last carrier ringing out is a failed attempt like the one before it:
/// recorded as 408 and reported to `@b2bua.on_route_failure` once, before
/// `@b2bua.on_failure` runs, once, with it on the attempt list. It showed no
/// progress, so no carrier could take the call, and the call fails 503.
#[tokio::test(flavor = "multi_thread")]
async fn the_last_carrier_ringing_out_is_recorded_as_a_failed_attempt() {
    let (sequence, _) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        RECORD_EVENTS,
    );

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:503;route:carrier-b:408;failure:503:carrier-a=503,carrier-b=408;"
    );
    assert!(sequence.call_is_gone());
}

/// A carrier kept past its ring timeout by progress, which then rings out and
/// fails the call with carriers still left, is recorded the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_ringing_carrier_that_rings_out_is_recorded_as_a_failed_attempt() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        events(&sequence),
        "",
        "nothing is recorded while progress keeps the carrier"
    );

    sequence.ring_for(Duration::from_secs(5));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("408 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;failure:408:carrier-a=408;"
    );
}

/// A carrier whose route does not reroute on 408 ends the call when it rings
/// out, with carriers still left, and is recorded like any other. It showed no
/// progress, so the call fails 503.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rings_out_without_rerouting_is_recorded_as_a_failed_attempt() {
    let sequence = Sequence::start_with_script(
        vec![
            crate::lcr::Route {
                reroute_causes: vec![503],
                ..carrier("carrier-a", FIRST_CARRIER, 2)
            },
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;failure:503:carrier-a=408;"
    );
}

/// A carrier that rings out while the sequence moves on is recorded once, not
/// once for the ring timeout and again for the advance.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rings_out_and_is_failed_over_is_recorded_once() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    assert_eq!(attempts(&sequence), ["carrier-a=408"]);
    assert_eq!(events(&sequence), "route:carrier-a:408;");
}

/// A ring timeout whose advance finds no routable carrier left records the
/// carrier that rang out once, then each carrier burned once, and then fails
/// 503: every carrier left could not be dialled.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rings_out_onto_unroutable_carriers_is_recorded_once() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            crate::lcr::Route {
                carrier_id: "carrier-b".to_string(),
                ..Default::default()
            },
        ],
        5,
        RECORD_EVENTS,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;route:carrier-b:503;failure:503:carrier-a=408,carrier-b=503;"
    );
}

/// A 100 is hop by hop, so a last carrier that sent nothing more reached no
/// callee: the call fails 503, and the carrier's own attempt is still a 408.
#[tokio::test(flavor = "multi_thread")]
async fn a_last_carrier_that_only_sent_100_fails_the_call_503() {
    let (sequence, second) = first_carrier_fails(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        RECORD_EVENTS,
    );
    sequence.carrier_answers(SECOND_CARRIER, &second, 100, "Trying");
    assert_eq!(summaries(&sequence.wire()), Vec::<String>::new());

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:503;route:carrier-b:408;failure:503:carrier-a=503,carrier-b=408;"
    );
}

/// Progress belongs to the carrier that rang out, not to one before it: a
/// carrier that sent 183 and then failed with a reroute cause leaves the next
/// carrier to show its own, and a silent last carrier still fails the call 503.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rang_before_failing_is_not_progress_for_the_last_carrier() {
    let mut sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence.redialled();

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:503;route:carrier-b:408;failure:503:carrier-a=503,carrier-b=408;"
    );
}

/// A hunt (a sequential fork, or a sequential control-plane `dial`) moves on
/// from a target that rang, so every target has `reroute_after_progress`. Its
/// last target rang the callee all the same, so the call fails 408 when it
/// rings out, not 503.
#[tokio::test(flavor = "multi_thread")]
async fn a_hunt_whose_last_target_rang_fails_the_call_408() {
    let hunted = |carrier_id: &str, address: &str| crate::lcr::Route {
        reroute_after_progress: true,
        ..carrier(carrier_id, address, 2)
    };
    let mut sequence = Sequence::start_with_script(
        vec![
            hunted("phone-a", FIRST_CARRIER),
            hunted("phone-b", SECOND_CARRIER),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 180, "Ringing");
    assert_eq!(summaries(&sequence.wire()), [format!("180 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    let second = invite_to(sequence.wire(), SECOND_CARRIER);
    sequence.redialled();
    sequence.carrier_answers(SECOND_CARRIER, &second, 180, "Ringing");
    assert_eq!(summaries(&sequence.wire()), [format!("180 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("408 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:phone-a:408;route:phone-b:408;failure:408:phone-a=408,phone-b=408;"
    );
}

/// A carrier siphon cannot put an INVITE on the wire for: a next-hop that is
/// neither a socket address nor a SIP URI, so it fails before any DNS lookup.
fn unsendable(carrier_id: &str) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: carrier_id.to_string(),
        next_hop: Some("not a uri".to_string()),
        timeout_secs: Some(2),
        ..Default::default()
    }
}

/// A carrier with nothing to route it by: no gateway group, next-hop or R-URI.
fn unroutable(carrier_id: &str) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: carrier_id.to_string(),
        ..Default::default()
    }
}

/// A silent carrier rings out and the only carrier left cannot be sent to. The
/// carrier that rang out is one 408 attempt, the one that could not be dialled
/// is one 503 attempt, `@b2bua.on_route_failure` fires for each in sequence
/// order, and the caller and `@b2bua.on_failure` get 503, once.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_carrier_ringing_out_onto_an_undialable_carrier_fails_503() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            unsendable("carrier-b"),
        ],
        5,
        RECORD_EVENTS,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;route:carrier-b:503;failure:503:carrier-a=408,carrier-b=503;"
    );
    assert!(sequence.call_is_gone());
}

/// A carrier that rang and moves on anyway (`reroute_after_progress`) rings out
/// onto carriers none of which can be dialled. It reached a callee, but the
/// sequence ended on the carriers it could not reach, so the call fails 503 and
/// not the 408 a ringing carrier's own ring-out would give.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rang_and_moves_on_onto_undialable_carriers_fails_503() {
    let sequence = Sequence::start_with_script(
        vec![
            crate::lcr::Route {
                reroute_after_progress: true,
                ..carrier("carrier-a", FIRST_CARRIER, 2)
            },
            unroutable("carrier-b"),
            unsendable("carrier-c"),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 180, "Ringing");
    assert_eq!(summaries(&sequence.wire()), [format!("180 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        concat!(
            "route:carrier-a:408;route:carrier-b:503;route:carrier-c:503;",
            "failure:503:carrier-a=408,carrier-b=503,carrier-c=503;"
        )
    );
    assert!(sequence.call_is_gone());
}

/// A carrier fails with a reroute cause and every carrier left is undialable.
/// The §16.7 best of `[503, 503]` would reach the caller as a 500; the sequence
/// ended on carriers siphon could not reach, so it is siphon's own 503.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_failing_onto_undialable_carriers_fails_503() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            unroutable("carrier-b"),
            unsendable("carrier-c"),
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
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        concat!(
            "route:carrier-a:503;route:carrier-b:503;route:carrier-c:503;",
            "failure:503:carrier-a=503,carrier-b=503,carrier-c=503;"
        )
    );
    assert!(sequence.call_is_gone());
}

/// The same after the carrier rang: a 183 and then a 408 of its own, which
/// would otherwise outrank the undialable carriers' 503s.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_that_rang_and_failed_onto_an_undialable_carrier_fails_503() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            unsendable("carrier-b"),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);
    sequence.carrier_answers(FIRST_CARRIER, &first, 408, "Request Timeout");
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("ACK to {FIRST_CARRIER}"),
            format!("503 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;route:carrier-b:503;failure:503:carrier-a=408,carrier-b=503;"
    );
}

/// Unchanged: a carrier kept by progress never advances, so its ring-out fails
/// 408 and the undialable carrier behind it is never reached or recorded.
#[tokio::test(flavor = "multi_thread")]
async fn a_carrier_kept_by_progress_rings_out_without_reaching_undialable_carriers() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            unroutable("carrier-b"),
        ],
        5,
        RECORD_EVENTS,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(summaries(&sequence.wire()), [format!("183 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(summaries(&sequence.wire()), Vec::<String>::new());

    sequence.ring_for(Duration::from_secs(5));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("408 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:408;failure:408:carrier-a=408;"
    );
}

/// Unchanged: a carrier that could not be dialled before the last dialled one
/// does not end the sequence. The last dialled carrier's own failure does, and
/// the caller gets the §16.7 best of the attempts, a 503 going upstream as 500.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequence_ending_on_its_last_dialled_carrier_keeps_the_best_failure() {
    let sequence = Sequence::start_with_script(
        vec![
            unroutable("carrier-a"),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        RECORD_EVENTS,
    );
    let second = invite_to(sequence.wire(), SECOND_CARRIER);
    sequence.carrier_answers(SECOND_CARRIER, &second, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("ACK to {SECOND_CARRIER}"),
            format!("500 to {CALLER}")
        ]
    );
    assert_eq!(
        events(&sequence),
        "route:carrier-a:503;route:carrier-b:503;failure:500:carrier-a=503,carrier-b=503;"
    );
}

/// Hand the call's outcome to a controller, as a sequential control-plane
/// `dial` does, whose targets all move on after progress.
fn owned_by_controller(sequence: &Sequence) {
    sequence
        .dispatcher
        .state
        .call_actors
        .set_control_dial(&sequence.call_id, true);
}

/// A sequential control-plane `dial` whose phone rang and rang out onto targets
/// it cannot dial reports the failure to its controller, the code chosen by the
/// same rule as a route sequence: the caller is left unanswered and parked,
/// `@b2bua.on_failure` does not run, and both targets are on the attempt list.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_dial_ringing_out_onto_undialable_targets_leaves_the_caller_parked() {
    let hunted = |carrier_id: &str, address: &str| crate::lcr::Route {
        reroute_after_progress: true,
        ..carrier(carrier_id, address, 2)
    };
    let sequence = Sequence::start_with_script(
        vec![
            hunted("phone-a", FIRST_CARRIER),
            crate::lcr::Route {
                reroute_after_progress: true,
                ..unsendable("phone-b")
            },
        ],
        5,
        RECORD_EVENTS,
    );
    owned_by_controller(&sequence);
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 180, "Ringing");
    assert_eq!(summaries(&sequence.wire()), [format!("180 to {CALLER}")]);

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("CANCEL to {FIRST_CARRIER}")],
        "nothing goes to the caller"
    );
    assert_eq!(events(&sequence), "route:phone-a:408;route:phone-b:503;");
    assert_eq!(attempts(&sequence), ["phone-a=408", "phone-b=503"]);
    assert!(!sequence.call_is_gone());
    assert!(!sequence
        .dispatcher
        .state
        .call_actors
        .is_control_dial(&sequence.call_id));
}

/// The same for a target that fails with a reroute cause onto targets that
/// cannot be dialled.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_dial_failing_onto_undialable_targets_leaves_the_caller_parked() {
    let sequence = Sequence::start_with_script(
        vec![
            crate::lcr::Route {
                reroute_after_progress: true,
                ..carrier("phone-a", FIRST_CARRIER, 2)
            },
            crate::lcr::Route {
                reroute_after_progress: true,
                ..unroutable("phone-b")
            },
        ],
        5,
        RECORD_EVENTS,
    );
    owned_by_controller(&sequence);
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 503, "Service Unavailable");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("ACK to {FIRST_CARRIER}")],
        "nothing goes to the caller"
    );
    assert_eq!(events(&sequence), "route:phone-a:503;route:phone-b:503;");
    assert!(!sequence.call_is_gone());
    assert!(!sequence
        .dispatcher
        .state
        .call_actors
        .is_control_dial(&sequence.call_id));
}
