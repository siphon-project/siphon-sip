//! `call.failure_response` in `@b2bua.on_failure`: the dialled leg's own final
//! response the failure `code` was derived from, as that leg sent it.
//!
//! The caller-facing `code` is not that response's status in general: a 503
//! reaches the caller as a 500 (RFC 3261 §16.7 step 6), and an exhausted
//! route sequence ends on the best failure of all its carriers. A script that
//! acts on what the far end actually said (TS 24.292 §10.4.7: CS breakout on a
//! 488 whose SDP offers no audio, or a 500 whose Reason carries a failure
//! cause) needs the response itself. When siphon concluded the leg on its own
//! (a ring timeout, a carrier it could not dial) there is none.
//!
//! Driven through [`Sequence`], with the script's view of the response left as
//! a header on the A-leg INVITE.

use super::lcr_ring_timeout_tests::{
    carrier, carrier_response, invite_to, summaries, top_via_branch, Sequence, CALLER,
    FIRST_CARRIER, SECOND_CARRIER,
};
use super::*;
use std::time::Duration;

/// Writes `code:` and what `call.failure_response` shows (or `none`) onto the
/// A-leg INVITE as `X-Test-Seen`.
const SHOW_FAILURE_RESPONSE: &str = r#"
from siphon import b2bua

@b2bua.on_failure
def failed(call, code, reason):
    response = call.failure_response
    if response is None:
        seen = "none"
    else:
        seen = "|".join([
            str(response.status_code),
            response.reason,
            str(response.get_header("Reason")),
            ",".join(response.get_headers("X-Carrier")),
            str(response.content_type),
            (response.body or b"").decode(),
        ])
    call.set_header("X-Test-Seen", str(code) + ":" + seen)
"#;

/// An SDP answer that offers no audio, only a video stream.
const VIDEO_ONLY: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=video 0 RTP/AVP 96\r\n",
);

/// What `@b2bua.on_failure` saw, or `None` if it never ran.
fn seen(sequence: &Sequence) -> Option<String> {
    sequence
        .invite
        .lock()
        .expect("the A-leg INVITE lock")
        .headers
        .get("X-Test-Seen")
        .cloned()
}

/// The carrier at `address` answers `invite` with `status_code`, carrying
/// `headers` and, when given, an SDP `body`.
fn carrier_fails(
    sequence: &Sequence,
    address: &str,
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
    headers: &[(&str, &str)],
    body: Option<&str>,
) {
    let mut response = carrier_response(invite, status_code, reason);
    for (name, value) in headers {
        response.headers.add(name, value.to_string());
    }
    if let Some(body) = body {
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", body.len().to_string());
        response.body = body.as_bytes().to_vec();
    }
    let handled = handle_b2bua_response(
        &sequence.call_id,
        &top_via_branch(invite),
        &mut response,
        status_code,
        address.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    );
    assert!(handled, "the call was gone when the {status_code} arrived");
}

/// TS 24.292 §10.4.7: a 503 whose Reason names a failure cause. The caller and
/// `code` get the 500 it becomes upstream; the response is the carrier's 503,
/// its Reason intact.
#[tokio::test(flavor = "multi_thread")]
async fn a_503_reaches_on_failure_as_500_with_the_carriers_own_503_beside_it() {
    let sequence = Sequence::start_with_script(
        vec![carrier("carrier-a", FIRST_CARRIER, 5)],
        5,
        SHOW_FAILURE_RESPONSE,
    );
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    carrier_fails(
        &sequence,
        FIRST_CARRIER,
        &invite,
        503,
        "Service Unavailable",
        &[
            ("Reason", "FAILURE_CAUSE;cause=2"),
            ("X-Carrier", "one"),
            ("X-Carrier", "two"),
        ],
        None,
    );
    assert!(summaries(&sequence.wire()).contains(&format!("500 to {CALLER}")));
    assert_eq!(
        seen(&sequence).as_deref(),
        Some("500:503|Service Unavailable|FAILURE_CAUSE;cause=2|one,two|None|")
    );
}

/// A 488 carries the carrier's SDP: the script reads that it offers no audio.
#[tokio::test(flavor = "multi_thread")]
async fn a_488_shows_its_sdp_to_on_failure() {
    let sequence = Sequence::start_with_script(
        vec![carrier("carrier-a", FIRST_CARRIER, 5)],
        5,
        SHOW_FAILURE_RESPONSE,
    );
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    carrier_fails(
        &sequence,
        FIRST_CARRIER,
        &invite,
        488,
        "Not Acceptable Here",
        &[],
        Some(VIDEO_ONLY),
    );
    assert_eq!(
        seen(&sequence),
        Some(format!(
            "488:488|Not Acceptable Here|None||application/sdp|{VIDEO_ONLY}"
        ))
    );
}

/// The carrier never answered: siphon ended the leg itself, so there is no
/// response to show.
#[tokio::test(flavor = "multi_thread")]
async fn a_ring_timeout_has_no_failure_response() {
    let sequence = Sequence::start_with_script(
        vec![carrier("carrier-a", FIRST_CARRIER, 2)],
        5,
        SHOW_FAILURE_RESPONSE,
    );
    invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.ring_for(Duration::from_secs(2));
    // A route sequence whose last carrier timed out ends 503 (no carrier left).
    assert_eq!(seen(&sequence).as_deref(), Some("503:none"));
}

/// An exhausted route sequence ends on the best failure of all its carriers
/// (RFC 3261 §16.7 step 6), here the first carrier's 480 over the second's
/// 503. The response shown is the one that code came from, not the last.
#[tokio::test(flavor = "multi_thread")]
async fn an_exhausted_sequence_shows_the_response_its_best_failure_came_from() {
    let sequence = Sequence::start_with_script(
        vec![
            crate::lcr::Route {
                reroute_causes: vec![480],
                ..carrier("carrier-a", FIRST_CARRIER, 5)
            },
            carrier("carrier-b", SECOND_CARRIER, 5),
        ],
        5,
        SHOW_FAILURE_RESPONSE,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    carrier_fails(
        &sequence,
        FIRST_CARRIER,
        &first,
        480,
        "Temporarily Unavailable",
        &[("X-Carrier", "a")],
        None,
    );
    let second = invite_to(sequence.wire(), SECOND_CARRIER);
    carrier_fails(
        &sequence,
        SECOND_CARRIER,
        &second,
        503,
        "Service Unavailable",
        &[("X-Carrier", "b")],
        None,
    );
    assert_eq!(
        seen(&sequence).as_deref(),
        Some("480:480|Temporarily Unavailable|None|a|None|")
    );
}

/// A sequence that ends on carriers siphon could not dial fails with siphon's
/// own 503, whatever the carrier before them answered: no response of a leg
/// is behind that code.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequence_ending_on_an_undialable_carrier_has_no_failure_response() {
    let sequence = Sequence::start_with_script(
        vec![
            carrier("carrier-a", FIRST_CARRIER, 5),
            crate::lcr::Route {
                carrier_id: "carrier-b".to_string(),
                ..Default::default()
            },
        ],
        5,
        SHOW_FAILURE_RESPONSE,
    );
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    carrier_fails(
        &sequence,
        FIRST_CARRIER,
        &first,
        503,
        "Service Unavailable",
        &[],
        None,
    );
    assert_eq!(seen(&sequence).as_deref(), Some("503:none"));
}

/// A parallel fork fails on its best branch failure: that branch's response.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_fork_shows_its_best_branchs_response() {
    let sequence =
        Sequence::start_fork_with_script(&[FIRST_CARRIER, SECOND_CARRIER], SHOW_FAILURE_RESPONSE);
    let sent = sequence.wire();
    let listed = summaries(&sent);
    let mut invites = sent
        .into_iter()
        .filter(|sent| matches!(sent.message.start_line, StartLine::Request(_)));
    let first = invites
        .next()
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("two INVITEs, sent: {listed:?}"));
    let second = invites
        .next()
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("two INVITEs, sent: {listed:?}"));
    carrier_fails(
        &sequence,
        FIRST_CARRIER,
        &first,
        486,
        "Busy Here",
        &[("X-Carrier", "busy")],
        None,
    );
    carrier_fails(
        &sequence,
        SECOND_CARRIER,
        &second,
        503,
        "Service Unavailable",
        &[("X-Carrier", "down")],
        None,
    );
    assert_eq!(
        seen(&sequence).as_deref(),
        Some("486:486|Busy Here|None|busy|None|")
    );
}
