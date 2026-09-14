//! Unit tests for proxy fork aggregation — RFC 3261 §16.7.

use super::*;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::uri::{Scheme, SipUri};

/// Helper: build a `SipUri` from a user@host string.
fn uri(user: &str, host: &str) -> SipUri {
    SipUri {
        scheme: Scheme::Sip,
        user: Some(user.to_string()),
        host: host.to_string(),
        port: None,
        params: Vec::new(),
        extras: None,
    }
}

/// Helper: build an aggregator with N branches.
fn make_aggregator(count: usize, strategy: ForkStrategy) -> ForkAggregator {
    let targets: Vec<SipUri> = (0..count)
        .map(|index| uri(&format!("user{}", index), "example.com"))
        .collect();
    ForkAggregator::new(targets, strategy)
}

// -----------------------------------------------------------------------
// Parallel forking
// -----------------------------------------------------------------------

#[test]
fn test_parallel_first_2xx_wins() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 180 Ringing
    let action = aggregator.on_branch_response(0, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));

    // Branch 1: 200 OK — immediate win
    let action = aggregator.on_branch_response(1, 200);
    assert_eq!(action, ForkAction::Forward2xx);

    // Branch 2 still pending — would be cancelled by the proxy core.
    assert!(!aggregator.is_complete());
}

/// Regression: parallel fork where two branches both return 200 OK
/// (CANCEL races with branch B's already-in-flight 200 on TCP).  The
/// aggregator must Forward2xx for the first 200 and `ContinueWaiting`
/// for the second, otherwise the proxy emits two copies of the 200 to
/// the UAC and sipp's UAC scenario classifies the late ACK as
/// `FailedUnexpectedMessage` (the documented Proxy/TCP ~0.025 % rate).
#[test]
fn test_parallel_late_2xx_from_cancelled_branch_is_dropped() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // First 200 — wins, gets forwarded.
    let action = aggregator.on_branch_response(1, 200);
    assert_eq!(action, ForkAction::Forward2xx);

    // Second 200 — branch 2's in-flight 200 racing with the CANCEL.
    // Must NOT be Forward2xx; must be silently absorbed.
    let action = aggregator.on_branch_response(2, 200);
    assert_eq!(action, ForkAction::ContinueWaiting);

    // And a third — defensive, e.g. branch 0 also raced.
    let action = aggregator.on_branch_response(0, 200);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

/// Regression: a late error after a 2xx already won must not be
/// upgraded to ForwardBestError — the UAC has already been told the
/// call succeeded.
#[test]
fn test_parallel_late_error_after_2xx_won_is_dropped() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    let action = aggregator.on_branch_response(1, 200);
    assert_eq!(action, ForkAction::Forward2xx);

    // Other branches complete with errors after the CANCEL — must be absorbed.
    let action = aggregator.on_branch_response(0, 487);
    assert_eq!(action, ForkAction::ContinueWaiting);
    let action = aggregator.on_branch_response(2, 503);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

#[test]
fn test_parallel_6xx_terminates_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 603 Decline → immediate termination
    let action = aggregator.on_branch_response(0, 603);
    assert_eq!(action, ForkAction::Forward6xx);
}

#[test]
fn test_parallel_all_fail_selects_best_error() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // Branch 0: 404
    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::ContinueWaiting);

    // Branch 1: 486 Busy
    let action = aggregator.on_branch_response(1, 486);
    assert_eq!(action, ForkAction::ContinueWaiting);

    // Branch 2: 503
    let action = aggregator.on_branch_response(2, 503);
    // All branches done.  RFC 3261 §16.7 step 6 chooses the lowest class
    // present, so a 4xx beats the 503, and 486 beats 404 on the higher code.
    // This expected 503 under the old 5xx-over-4xx ranking.
    assert_eq!(action, ForkAction::ForwardBestError(486));
}

#[test]
fn test_parallel_best_error_priority() {
    // RFC 3261 §16.7 step 6: the lowest class present wins; within a class,
    // the highest code (with 503 below every other 5xx).
    let mut aggregator = make_aggregator(4, ForkStrategy::Parallel);
    for index in 0..4 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 404);
    aggregator.on_branch_response(1, 486);
    aggregator.on_branch_response(2, 500);

    let action = aggregator.on_branch_response(3, 503);
    // The 4xx class beats both 5xx.  This expected 503 under the old ranking,
    // which put 5xx above 4xx and the higher 503 above 500.
    assert_eq!(action, ForkAction::ForwardBestError(486));
}

#[test]
fn test_parallel_4xx_beats_5xx_in_best_error() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    for index in 0..2 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 500);
    // Note: 6xx in on_branch_response returns Forward6xx immediately,
    // so test the best-failure fallback with only 4xx/5xx branches.
    // RFC 3261 §16.7 step 6 chooses the lowest class, so the 404 goes
    // upstream.  This expected the 500 under the old 5xx-over-4xx ranking.
    let action = aggregator.on_branch_response(1, 404);
    assert_eq!(action, ForkAction::ForwardBestError(404));
}

#[test]
fn test_parallel_100_forwarded_only_once() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // First 100 → forwarded
    let action = aggregator.on_branch_response(0, 100);
    assert_eq!(action, ForkAction::ForwardProvisional(100));

    // Second 100 → suppressed
    let action = aggregator.on_branch_response(1, 100);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

#[test]
fn test_parallel_180_forwarded_from_any_branch() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        aggregator.mark_trying(index);
    }

    // 180 from branch 0
    let action = aggregator.on_branch_response(0, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));

    // 180 from branch 2 — also forwarded (unlike 100)
    let action = aggregator.on_branch_response(2, 180);
    assert_eq!(action, ForkAction::ForwardProvisional(180));
}

#[test]
fn test_parallel_183_forwarded_from_any_branch() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    for index in 0..2 {
        aggregator.mark_trying(index);
    }

    let action = aggregator.on_branch_response(0, 183);
    assert_eq!(action, ForkAction::ForwardProvisional(183));

    let action = aggregator.on_branch_response(1, 183);
    assert_eq!(action, ForkAction::ForwardProvisional(183));
}

// -----------------------------------------------------------------------
// Sequential forking
// -----------------------------------------------------------------------

#[test]
fn test_sequential_tries_next_on_failure() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 486 Busy → try next
    let action = aggregator.on_branch_response(0, 486);
    assert_eq!(action, ForkAction::TryNext(1));
}

#[test]
fn test_sequential_2xx_stops_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 200 OK — done
    let action = aggregator.on_branch_response(0, 200);
    assert_eq!(action, ForkAction::Forward2xx);
}

#[test]
fn test_sequential_6xx_stops_immediately() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    // Branch 0: 603 Decline — done
    let action = aggregator.on_branch_response(0, 603);
    assert_eq!(action, ForkAction::Forward6xx);
}

#[test]
fn test_sequential_all_fail_returns_best_error() {
    let mut aggregator = make_aggregator(3, ForkStrategy::Sequential);

    // Branch 0: 404
    aggregator.mark_trying(0);
    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::TryNext(1));

    // Branch 1: 486
    aggregator.mark_trying(1);
    let action = aggregator.on_branch_response(1, 486);
    assert_eq!(action, ForkAction::TryNext(2));

    // Branch 2: 503 — all exhausted.  RFC 3261 §16.7 step 6: the 4xx class
    // beats the 503.  This expected 503 under the old 5xx-over-4xx ranking.
    aggregator.mark_trying(2);
    let action = aggregator.on_branch_response(2, 503);
    assert_eq!(action, ForkAction::ForwardBestError(486));
}

// -----------------------------------------------------------------------
// Edge cases
// -----------------------------------------------------------------------

#[test]
fn test_single_branch_parallel_is_relay() {
    let mut aggregator = make_aggregator(1, ForkStrategy::Parallel);
    aggregator.mark_trying(0);

    let action = aggregator.on_branch_response(0, 200);
    assert_eq!(action, ForkAction::Forward2xx);
}

#[test]
fn test_single_branch_failure() {
    let mut aggregator = make_aggregator(1, ForkStrategy::Parallel);
    aggregator.mark_trying(0);

    let action = aggregator.on_branch_response(0, 404);
    assert_eq!(action, ForkAction::ForwardBestError(404));
}

#[test]
fn test_out_of_bounds_branch_index() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    let action = aggregator.on_branch_response(99, 200);
    assert_eq!(action, ForkAction::ContinueWaiting);
}

#[test]
fn test_is_complete() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    assert!(!aggregator.is_complete());

    aggregator.mark_trying(0);
    aggregator.mark_trying(1);
    assert!(!aggregator.is_complete());

    aggregator.on_branch_response(0, 200);
    assert!(!aggregator.is_complete());

    aggregator.mark_cancelled(1);
    assert!(aggregator.is_complete());
}

#[test]
fn test_branch_count() {
    let aggregator = make_aggregator(5, ForkStrategy::Parallel);
    assert_eq!(aggregator.branch_count(), 5);
}

#[test]
fn test_default_strategy_is_parallel() {
    assert_eq!(ForkStrategy::default(), ForkStrategy::Parallel);
}
#[test]
fn a_real_answer_beats_a_transport_error_the_proxy_invented() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.mark_local_failure(0);
    assert_eq!(
        aggregator.on_branch_response(0, 503),
        ForkAction::ContinueWaiting,
        "the live branch has not answered yet"
    );

    assert_eq!(
        aggregator.on_branch_response(1, 486),
        ForkAction::ForwardBestError(486),
        "the callee's own answer is what the caller needs to hear"
    );
}

#[test]
fn a_real_answer_beats_a_timeout_the_proxy_invented() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.mark_local_failure(0);
    aggregator.on_branch_response(0, 408);

    assert_eq!(
        aggregator.on_branch_response(1, 404),
        ForkAction::ForwardBestError(404)
    );
}

#[test]
fn local_failures_are_still_forwarded_when_they_are_all_there_is() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.mark_local_failure(0);
    aggregator.on_branch_response(0, 503);
    aggregator.mark_local_failure(1);

    // RFC 3261 §16.7 step 6 (and §16.8, a timeout is a 408 in the response
    // context): the 4xx beats the 503.  This expected 503 under the old
    // 5xx-over-4xx ranking.
    assert_eq!(
        aggregator.on_branch_response(1, 408),
        ForkAction::ForwardBestError(408),
        "with nothing real to prefer, the lowest class wins"
    );
}

#[test]
fn peer_responses_keep_their_class_ordering_among_themselves() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.on_branch_response(0, 486);
    // RFC 3261 §16.7 step 6: the lowest class present wins, so the 486 goes
    // upstream.  This expected 503 under the old 5xx-over-4xx ranking.
    assert_eq!(
        aggregator.on_branch_response(1, 503),
        ForkAction::ForwardBestError(486)
    );
}

#[test]
fn a_sequential_fork_advances_past_a_branch_the_proxy_failed() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Sequential);
    aggregator.mark_trying(0);

    aggregator.mark_local_failure(0);
    assert_eq!(
        aggregator.on_branch_response(0, 503),
        ForkAction::TryNext(1)
    );

    aggregator.mark_trying(1);
    assert_eq!(
        aggregator.on_branch_response(1, 404),
        ForkAction::ForwardBestError(404)
    );
}

#[test]
fn branches_start_out_attributed_to_the_peer() {
    let aggregator = make_aggregator(3, ForkStrategy::Parallel);
    assert!(aggregator
        .branches
        .iter()
        .all(|branch| branch.origin == ResponseOrigin::Peer));
}

// -----------------------------------------------------------------------
// RFC 3261 §16.7 steps 6 and 7 — the response that goes upstream
// -----------------------------------------------------------------------

/// Helper: a branch's final response, To-tagged so a test can tell whose
/// response was chosen.
fn branch_response(status_code: u16, to_tag: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, "Failed".to_string())
        .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-uac".to_string())
        .from("<sip:alice@example.com>;tag=uac".to_string())
        .to(format!("<sip:bob@example.com>;tag={to_tag}"))
        .call_id("fork-best@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap()
}

/// Helper: the To-tag of a response.
fn to_tag(response: &SipMessage) -> Option<String> {
    response
        .headers
        .to()
        .and_then(|to| to.split("tag=").nth(1))
        .map(str::to_string)
}

/// Helper: every value of a header, in order.
fn header_values(response: &SipMessage, name: &str) -> Vec<String> {
    response.headers.get_all(name).cloned().unwrap_or_default()
}

#[test]
fn a_redirect_beats_a_client_error() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.on_branch_response(0, 486);
    assert_eq!(
        aggregator.on_branch_response(1, 302),
        ForkAction::ForwardBestError(302),
        "3xx is a lower class than 4xx"
    );
}

#[test]
fn a_resubmission_hint_beats_a_higher_4xx() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.on_branch_response(0, 486);
    assert_eq!(
        aggregator.on_branch_response(1, 407),
        ForkAction::ForwardBestError(407),
        "a 407 tells the caller how to resubmit"
    );
}

/// RFC 3261 §16.8: a timed-out branch is a 408 in the response context, so it
/// competes as a 4xx.  The preference for a peer's answer only breaks ties
/// within a class and cannot lift a peer's 5xx over it.
#[test]
fn a_timeout_the_proxy_invented_still_beats_a_server_error() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.mark_local_failure(0);
    aggregator.on_branch_response(0, 408);
    assert_eq!(
        aggregator.on_branch_response(1, 500),
        ForkAction::ForwardBestError(408)
    );
}

#[test]
fn the_chosen_branch_response_goes_upstream_with_its_own_headers() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    let mut redirect = branch_response(302, "moved");
    redirect
        .headers
        .set("Contact", "<sip:bob@198.51.100.7>".to_string());

    assert_eq!(
        aggregator.on_response(0, 486, &branch_response(486, "busy")),
        ForkAction::ContinueWaiting
    );
    assert_eq!(
        aggregator.on_response(1, 302, &redirect),
        ForkAction::ForwardBestError(302)
    );

    let chosen = aggregator
        .take_best_response()
        .expect("the chosen branch's response was fed");
    assert_eq!(chosen.status_code(), Some(302));
    assert_eq!(to_tag(&chosen).as_deref(), Some("moved"));
    assert_eq!(
        chosen.headers.get("Contact").map(String::as_str),
        Some("<sip:bob@198.51.100.7>"),
        "a redirect is useless without its Contact"
    );
    assert!(
        aggregator.take_best_response().is_none(),
        "the chosen response is handed over once"
    );
}

#[test]
fn a_sequential_fork_forwards_the_best_attempt_not_the_last() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Sequential);
    aggregator.mark_trying(0);
    assert_eq!(
        aggregator.on_response(0, 404, &branch_response(404, "gone")),
        ForkAction::TryNext(1)
    );

    aggregator.mark_trying(1);
    assert_eq!(
        aggregator.on_response(1, 503, &branch_response(503, "down")),
        ForkAction::ForwardBestError(404)
    );
    let chosen = aggregator.take_best_response().expect("404 was fed");
    assert_eq!(to_tag(&chosen).as_deref(), Some("gone"));
}

/// A fork of nothing but 503s settles on the 503.  It is the proxy core, not
/// the aggregator, that sends a generated 500 in its place (§16.7 step 6).
#[test]
fn a_fork_of_only_503s_settles_on_503() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.on_response(0, 503, &branch_response(503, "down-a"));
    assert_eq!(
        aggregator.on_response(1, 503, &branch_response(503, "down-b")),
        ForkAction::ForwardBestError(503)
    );
    assert_eq!(crate::sip::best_response::upstream_status(503), 500);
}

/// RFC 3261 §16.7 step 7: the forwarded 401/407 carries the challenges of
/// every other 401/407 branch, values unmodified.
#[test]
fn a_forwarded_challenge_carries_every_other_branch_challenge() {
    let mut aggregator = make_aggregator(4, ForkStrategy::Parallel);
    for index in 0..4 {
        aggregator.mark_trying(index);
    }

    let www_a = r#"Digest realm="a.example.com", nonce="n1", qop="auth""#;
    let www_c = r#"Digest realm="c.example.com", nonce="n3", algorithm=SHA-256"#;
    let proxy_b = r#"Digest realm="b.example.com", nonce="n2""#;

    let mut unauthorized_a = branch_response(401, "realm-a");
    unauthorized_a
        .headers
        .set("WWW-Authenticate", www_a.to_string());
    let mut proxy_challenge_b = branch_response(407, "realm-b");
    proxy_challenge_b
        .headers
        .set("Proxy-Authenticate", proxy_b.to_string());
    let mut unauthorized_c = branch_response(401, "realm-c");
    unauthorized_c
        .headers
        .set("WWW-Authenticate", www_c.to_string());

    aggregator.on_response(0, 401, &unauthorized_a);
    aggregator.on_response(1, 486, &branch_response(486, "busy"));
    aggregator.on_response(2, 401, &unauthorized_c);
    assert_eq!(
        aggregator.on_response(3, 407, &proxy_challenge_b),
        ForkAction::ForwardBestError(407),
        "among the resubmission hints the highest code wins"
    );

    let chosen = aggregator.take_best_response().expect("407 was fed");
    assert_eq!(to_tag(&chosen).as_deref(), Some("realm-b"));
    assert_eq!(header_values(&chosen, "Proxy-Authenticate"), vec![proxy_b]);
    assert_eq!(
        header_values(&chosen, "WWW-Authenticate"),
        vec![www_a, www_c],
        "every other 401's challenge, in branch order"
    );
}

#[test]
fn a_chosen_401_keeps_its_own_challenge_first() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    let first = r#"Digest realm="first.example.com", nonce="n1""#;
    let second = r#"Digest realm="second.example.com", nonce="n2""#;
    let mut first_401 = branch_response(401, "first");
    first_401.headers.set("WWW-Authenticate", first.to_string());
    let mut second_401 = branch_response(401, "second");
    second_401
        .headers
        .set("WWW-Authenticate", second.to_string());

    aggregator.on_response(0, 401, &first_401);
    assert_eq!(
        aggregator.on_response(1, 401, &second_401),
        ForkAction::ForwardBestError(401)
    );

    // Either 401 may be chosen (§16.7 step 6 leaves equal responses to the
    // proxy); whichever it is keeps its own challenge first and gains the other.
    let chosen = aggregator.take_best_response().expect("401 was fed");
    let (own, other) = match to_tag(&chosen).as_deref() {
        Some("first") => (first, second),
        Some("second") => (second, first),
        tag => panic!("chosen response is from neither branch: {tag:?}"),
    };
    assert_eq!(header_values(&chosen, "WWW-Authenticate"), vec![own, other]);
}

#[test]
fn challenges_are_not_added_to_a_response_that_is_not_a_challenge() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    let mut unauthorized = branch_response(401, "auth");
    unauthorized
        .headers
        .set("WWW-Authenticate", r#"Digest realm="a""#.to_string());
    aggregator.on_response(0, 401, &unauthorized);
    assert_eq!(
        aggregator.on_response(1, 302, &branch_response(302, "moved")),
        ForkAction::ForwardBestError(302)
    );

    let chosen = aggregator.take_best_response().expect("302 was fed");
    assert!(header_values(&chosen, "WWW-Authenticate").is_empty());
}

/// Kept branch responses live only while the fork is open: every one is
/// released the moment a final goes upstream, and nothing arriving after that
/// is kept.  The per-fork analogue of a store draining to baseline.
#[test]
fn kept_branch_responses_are_released_once_a_final_goes_upstream() {
    // A 2xx wins: the failure kept so far is released, and the straggler
    // the CANCEL draws back is never kept.
    let mut answered = make_aggregator(3, ForkStrategy::Parallel);
    for index in 0..3 {
        answered.mark_trying(index);
    }
    answered.on_response(0, 180, &branch_response(180, "ringing"));
    assert_eq!(
        answered.kept_response_count(),
        0,
        "a provisional is not kept"
    );
    answered.on_response(0, 486, &branch_response(486, "busy"));
    assert_eq!(answered.kept_response_count(), 1);
    assert_eq!(
        answered.on_response(1, 200, &branch_response(200, "answered")),
        ForkAction::Forward2xx
    );
    assert_eq!(answered.kept_response_count(), 0, "a 2xx went upstream");
    answered.on_response(2, 487, &branch_response(487, "cancelled"));
    assert_eq!(answered.kept_response_count(), 0, "a straggler is not kept");
    assert!(answered.take_best_response().is_none());

    // A 6xx ends the fork the same way.
    let mut declined = make_aggregator(2, ForkStrategy::Parallel);
    declined.mark_trying(0);
    declined.mark_trying(1);
    declined.on_response(0, 486, &branch_response(486, "busy"));
    declined.on_response(1, 603, &branch_response(603, "decline"));
    assert_eq!(declined.kept_response_count(), 0, "a 6xx went upstream");

    // Every branch failing: the chosen response is handed over once and
    // nothing else is left behind.
    let mut failed = make_aggregator(2, ForkStrategy::Parallel);
    failed.mark_trying(0);
    failed.mark_trying(1);
    failed.on_response(0, 486, &branch_response(486, "busy"));
    failed.on_response(1, 480, &branch_response(480, "away"));
    assert_eq!(failed.kept_response_count(), 0);
    assert!(failed.take_best_response().is_some());
    assert!(failed.take_best_response().is_none());
}
