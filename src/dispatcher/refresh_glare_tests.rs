//! While the `200` to an offerless re-INVITE waits for the ACK that answers
//! it, and until that answer has reached the engine, the dialog has an offer
//! outstanding (RFC 3261 §14.1, §14.2): a further re-INVITE is answered 491
//! and an offer of siphon's own toward the caller is held off, through the
//! same pending-re-INVITE guard the ordinary path reads.
//!
//! A retransmission of the INVITE replays the stored 200 and arms nothing; a
//! request with an older CSeq never replaces the newer exchange.

use super::control_dial_delayed_offer_tests::{refreshed_dial, to_caller, to_phone, CALLER_ANSWER};
use super::*;

fn statuses(sent: &[&super::control_dial_delayed_offer_tests::Sent]) -> Vec<u16> {
    sent.iter()
        .filter_map(|sent| sent.message.status_code())
        .collect()
}

/// Another re-INVITE from the caller while its refresh is unanswered is 491.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_reinvite_from_the_caller_during_a_refresh_is_491() {
    let (dial, caller_200, _refreshed) = refreshed_dial("2 INVITE").await;
    let (arrived, reinvite) = dial.caller_request("INVITE", "3 INVITE", &caller_200, None);
    handle_b2bua_reinvite(arrived, reinvite, &dial.state);
    let sent = dial.wire();
    assert_eq!(statuses(&to_caller(&sent)), vec![491]);
    assert!(to_phone(&sent).is_empty());
}

/// The exchange occupies the caller's dialog on the guard the callee's
/// re-INVITE and siphon's own offers read, so they find it pending.
#[tokio::test(flavor = "multi_thread")]
async fn the_refresh_holds_the_pending_reinvite_guard_toward_the_caller_until_its_answer_is_applied(
) {
    let (dial, _caller_200, refreshed) = refreshed_dial("2 INVITE").await;
    // A take-and-set from the other side's re-INVITE finds it already pending.
    assert!(dial
        .state
        .call_actors
        .set_pending_reinvite(&dial.call_id, true, true));

    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, Some(CALLER_ANSWER));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);
    // The answer has been applied: the guard is free again (the flag set
    // above is the test's own, so clear it first).
    dial.state
        .call_actors
        .set_pending_reinvite(&dial.call_id, true, false);
    assert!(!dial
        .state
        .call_actors
        .set_pending_reinvite(&dial.call_id, true, true));
}

/// A request with an older CSeq never replaces the newer exchange, whose ACK
/// still reaches the engine.
#[tokio::test(flavor = "multi_thread")]
async fn an_older_cseq_does_not_overwrite_a_newer_pending_refresh() {
    let (dial, caller_200, refreshed) = refreshed_dial("3 INVITE").await;
    let (arrived, stale) = dial.caller_request("INVITE", "2 INVITE", &caller_200, None);
    handle_b2bua_reinvite(arrived, stale, &dial.state);
    let sent = dial.wire();
    assert!(
        !statuses(&to_caller(&sent)).contains(&200),
        "no second answer for an old request"
    );
    let offers = dial.engine.commands("offer").len();
    let moved = CALLER_ANSWER.replace("m=audio 40000", "m=audio 41000");
    let (inbound, ack) = dial.caller_request("ACK", "3 ACK", &refreshed, Some(&moved));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);
    let after = dial.engine.commands("offer");
    assert_eq!(
        after.len(),
        offers + 1,
        "the newer exchange's ACK still lands"
    );
    assert_eq!(after[offers].sdp.as_deref(), Some(moved.as_str()));
}
