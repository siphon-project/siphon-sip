//! A provisional response on a B-leg that has already ended is dropped. It
//! reaches neither the caller nor the progress of the carrier in flight, and a
//! reliable one (RFC 3262) draws no PRACK.
//!
//! Driven through the dispatcher with the harness of
//! [`super::lcr_ring_timeout_tests`], for an LCR sequence and for a parallel
//! fork alike: branches answer through `handle_b2bua_response`, and every
//! message siphon sends is read back off the UDP egress channel.

use super::lcr_ring_timeout_tests::{
    carrier, invite_to, summaries, top_via_branch, Sequence, CALLER, FIRST_CARRIER, SECOND_CARRIER,
    THIRD_CARRIER,
};
use super::{SipMessage, StartLine};
use std::time::Duration;

/// The carrier at `address` sends `status_code` reliably (RFC 3262 §3):
/// `Require: 100rel`, `RSeq: 1`, and a Contact naming the early dialog's remote
/// target, which is where its PRACK goes (§4, RFC 3261 §12.1.2).
fn carrier_answers_reliably(
    sequence: &Sequence,
    address: &str,
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
) {
    let contact = format!("<sip:carrier@{address}>");
    sequence.carrier_answers_with(
        address,
        invite,
        status_code,
        reason,
        &[("Require", "100rel"), ("RSeq", "1"), ("Contact", &contact)],
    );
}

/// A carrier that answered 503 can still have a 183 arrive after it, reordered
/// on the way or sent by a carrier that gets its own transaction wrong. The
/// caller must not hear it, and it is no progress for the carrier now in
/// flight, which rings out on its own timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_provisional_from_a_carrier_that_failed_is_dropped() {
    let mut sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        "",
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

    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "the failed carrier's 183 is not relayed"
    );
    assert!(!sequence
        .dispatcher
        .state
        .call_actors
        .route_attempt_progressed(&sequence.call_id));

    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {SECOND_CARRIER}"),
            format!("503 to {CALLER}")
        ],
        "the carrier in flight showed nothing, so it is not kept past its timeout"
    );
}

/// A carrier CANCELled on its ring timeout is kept answerable apart from the
/// call only until Timer H. A 183 it sends after that, while the call is still
/// ringing the next carrier, is dropped too, and the next carrier's own 183
/// still reaches the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_provisional_from_a_cancelled_carrier_is_dropped() {
    let mut sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
            carrier("carrier-c", THIRD_CARRIER, 2),
        ],
        5,
        "",
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.ring_for(Duration::from_secs(2));
    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    let second = invite_to(sent, SECOND_CARRIER);
    sequence.redialled();

    // Timer H for the CANCELled INVITE: siphon no longer keeps the carrier
    // answerable apart from the call.
    sequence
        .dispatcher
        .state
        .call_actors
        .zombie_cancelled
        .remove(&top_via_branch(&first));

    sequence.carrier_answers(FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "the cancelled carrier's 183 is not relayed"
    );

    sequence.carrier_answers(SECOND_CARRIER, &second, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("183 to {CALLER}")],
        "the carrier in flight still reaches the caller"
    );
}

/// One branch of a parallel fork answers 486 while the other still rings. A
/// 180 from the branch that failed is dropped, and one from the branch still
/// ringing is relayed.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_provisional_from_a_failed_fork_branch_is_dropped() {
    let sequence = Sequence::start_fork(&[FIRST_CARRIER, SECOND_CARRIER]);
    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("INVITE to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    let mut invites = sent.into_iter().map(|sent| sent.message);
    let first = invites.next().expect("the first branch's INVITE");
    let second = invites.next().expect("the second branch's INVITE");

    sequence.carrier_answers(FIRST_CARRIER, &first, 486, "Busy Here");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("ACK to {FIRST_CARRIER}")],
        "the other branch can still answer, so the call goes on"
    );

    sequence.carrier_answers(FIRST_CARRIER, &first, 180, "Ringing");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "the failed branch's 180 is not relayed"
    );

    sequence.carrier_answers(SECOND_CARRIER, &second, 180, "Ringing");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("180 to {CALLER}")],
        "the branch still ringing reaches the caller"
    );
}

/// A reliable 183 from the carrier in flight is PRACKed at its early dialog's
/// Contact (RFC 3262 §4) and relayed to the caller. Its retransmission, sent
/// while the PRACK was on the way, draws no second PRACK.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_from_the_carrier_in_flight_is_pracked_once() {
    let sequence = Sequence::start_with_script(vec![carrier("carrier-a", FIRST_CARRIER, 2)], 5, "");
    let first = invite_to(sequence.wire(), FIRST_CARRIER);

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 183, "Session Progress");
    let sent = sequence.wire();
    assert_eq!(
        summaries(&sent),
        [
            format!("PRACK to {FIRST_CARRIER}"),
            format!("183 to {CALLER}")
        ]
    );
    let StartLine::Request(prack_line) = &sent[0].message.start_line else {
        panic!("the PRACK is a request");
    };
    assert_eq!(
        prack_line.request_uri.to_string(),
        format!("sip:carrier@{FIRST_CARRIER}"),
        "the PRACK goes to the early dialog's remote target"
    );
    let invite_cseq = first.headers.cseq().expect("the carrier INVITE's CSeq");
    assert_eq!(
        sent[0]
            .message
            .headers
            .get("RAck")
            .map(|value| value.to_string()),
        Some(format!("1 {invite_cseq}"))
    );

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("183 to {CALLER}")],
        "the retransmitted 183 is not PRACKed again"
    );
}

/// A carrier that answered 503 has no INVITE transaction left, so no early
/// dialog to PRACK. A reliable 183 it sends after that draws no PRACK, which the
/// carrier could only answer 481 (RFC 3262 §3), and reaches no one.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_from_a_carrier_that_failed_draws_no_prack() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        "",
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

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "no PRACK to the failed carrier and no 183 to the caller"
    );
}

/// A fork branch that answered 486 while its sibling still rings: its reliable
/// 180 draws no PRACK and is not relayed.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_from_a_failed_fork_branch_draws_no_prack() {
    let sequence = Sequence::start_fork(&[FIRST_CARRIER, SECOND_CARRIER]);
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &first, 486, "Busy Here");
    assert_eq!(
        summaries(&sequence.wire()),
        [format!("ACK to {FIRST_CARRIER}")]
    );

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 180, "Ringing");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "no PRACK to the failed branch and no 180 to the caller"
    );
}

/// A carrier CANCELled on its ring timeout whose 487 has not come back yet. Its
/// INVITE transaction is still alive, but siphon does not PRACK the reliable 183
/// that crossed the CANCEL: the carrier answers the CANCEL with a 487 at once
/// (RFC 3261 §9.2), and that ends its retransmissions sooner than a PRACK
/// trailing the CANCEL could, which would only meet a 481.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_from_a_carrier_awaiting_its_487_draws_no_prack() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        "",
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "no PRACK to the CANCELled carrier and no 183 to the caller"
    );
}

/// A CANCELled carrier past Timer H, no longer kept answerable apart from the
/// call: its reliable 183 draws no PRACK either, and is not relayed.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_provisional_from_a_cancelled_carrier_past_timer_h_draws_no_prack() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 2),
            carrier("carrier-b", SECOND_CARRIER, 2),
        ],
        5,
        "",
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.ring_for(Duration::from_secs(2));
    assert_eq!(
        summaries(&sequence.wire()),
        [
            format!("CANCEL to {FIRST_CARRIER}"),
            format!("INVITE to {SECOND_CARRIER}")
        ]
    );
    sequence
        .dispatcher
        .state
        .call_actors
        .zombie_cancelled
        .remove(&top_via_branch(&first));

    carrier_answers_reliably(&sequence, FIRST_CARRIER, &first, 183, "Session Progress");
    assert_eq!(
        summaries(&sequence.wire()),
        Vec::<String>::new(),
        "no PRACK to the CANCELled carrier and no 183 to the caller"
    );
}
