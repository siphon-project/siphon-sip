//! Unit tests for proxy fork aggregation — RFC 3261 §16.7.

use super::*;
use crate::sip::uri::SipUri;

/// Helper: build a `SipUri` from a user@host string.
fn uri(user: &str, host: &str) -> SipUri {
    SipUri {
        scheme: "sip".to_string(),
        user: Some(user.to_string()),
        host: host.to_string(),
        port: None,
        params: Vec::new(),
        headers: Vec::new(),
        user_params: Vec::new(),
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
    // All branches done — best error is 503 (5xx beats 4xx)
    assert_eq!(action, ForkAction::ForwardBestError(503));
}

#[test]
fn test_parallel_best_error_priority() {
    // 6xx > 5xx > 4xx; within a class, highest code wins
    let mut aggregator = make_aggregator(4, ForkStrategy::Parallel);
    for index in 0..4 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 404);
    aggregator.on_branch_response(1, 486);
    aggregator.on_branch_response(2, 500);

    let action = aggregator.on_branch_response(3, 503);
    // 503 wins over 500 (same class, higher code)
    assert_eq!(action, ForkAction::ForwardBestError(503));
}

#[test]
fn test_parallel_6xx_beats_5xx_in_best_error() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    for index in 0..2 {
        aggregator.mark_trying(index);
    }

    aggregator.on_branch_response(0, 500);
    // Note: 6xx in on_branch_response returns Forward6xx immediately,
    // so test the best_error fallback with only 4xx/5xx branches
    // and verify 5xx outranks 4xx.
    let action = aggregator.on_branch_response(1, 404);
    assert_eq!(action, ForkAction::ForwardBestError(500));
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

    // Branch 2: 503 — all exhausted
    aggregator.mark_trying(2);
    let action = aggregator.on_branch_response(2, 503);
    assert_eq!(action, ForkAction::ForwardBestError(503));
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

    assert_eq!(
        aggregator.on_branch_response(1, 408),
        ForkAction::ForwardBestError(503),
        "with nothing real to prefer, normal class ordering applies"
    );
}

#[test]
fn peer_responses_keep_their_class_ordering_among_themselves() {
    let mut aggregator = make_aggregator(2, ForkStrategy::Parallel);
    aggregator.mark_trying(0);
    aggregator.mark_trying(1);

    aggregator.on_branch_response(0, 486);
    assert_eq!(
        aggregator.on_branch_response(1, 503),
        ForkAction::ForwardBestError(503)
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
