//! The called party a controller-issued `dial` target names with `to`.
//!
//! A B-leg's `To` is framework-managed: the builder takes the caller's own,
//! drops its tag and rewrites only the authority to the dial target's, keeping
//! the user part. That is right for a forward, where the B-leg reaches the party
//! the caller asked for, and wrong for a divert (call-forward, follow-me,
//! overflow to a mobile), where the controller sends the call to a different
//! number: the R-URI names the new party and `To` still names the old one. A
//! next hop that routes on `To` serves the call as one to the original number
//! and can send it straight back, a loop `Diversion`'s counter never sees.
//!
//! `to` is applied in the builder, before the leg's dialog state is captured
//! from the INVITE, so siphon's own later requests on the dialog (BYE,
//! re-INVITE, session refresh) carry the same `To` (RFC 3261 §12.2.1.1). An
//! injected `headers: {"To": …}` reaches only the INVITE.

use super::control_dial_identity_tests::{
    advance_from_the_stored_invite, dial_targets, park, wire, FIRST_TARGET, SECOND_TARGET,
};
use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

/// The number the call is diverted to, at the trunk.
const DIVERT_TO: &str = "sip:15550100199@trunk.example.com";
const SECOND_DIVERT_TO: &str = "sip:15550100188@trunk.example.com";

fn divert_target(address: &str, to: &str) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100199@{address}"),
        to: Some(to.to_string()),
        ..Default::default()
    }
}

fn to_header(sent: &Sent) -> &str {
    sent.message
        .headers
        .get("To")
        .map(String::as_str)
        .expect("every INVITE carries a To")
}

/// The `To` siphon recorded for the leg's dialog, which is what its own later
/// in-dialog requests are addressed with.
fn recorded_to(dispatcher: &TestDispatcher, call_id: &str) -> Vec<String> {
    dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .expect("the call exists")
        .b_legs
        .iter()
        .filter_map(|leg| leg.dialog.remote_to_uri.clone())
        .collect()
}

/// The diverted-to party reaches the wire as `To`, without a tag, and is the
/// `To` the leg's dialog keeps. Connect dials both ways: a fork's branches are
/// built from the dial's template, a sequential hunt's from its routes.
#[tokio::test(flavor = "multi_thread")]
async fn a_targets_to_is_the_b_legs_called_party() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        let call_id = park(&dispatcher);
        assert!(dial_targets(
            &dispatcher,
            vec![divert_target(FIRST_TARGET, DIVERT_TO)],
            parallel,
            &DialShaping::default(),
        )
        .expect("the dial runs"));

        let sent = wire(&dispatcher);
        assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_TARGET}")]);
        let to = to_header(&sent[0]);
        assert_eq!(
            to,
            format!("<{DIVERT_TO}>"),
            "parallel={parallel}: the B-leg To is not the diverted-to party"
        );
        assert!(
            !to.contains("15550100077"),
            "parallel={parallel}: the originally dialled number survived in To: {to}"
        );
        assert_eq!(
            recorded_to(&dispatcher, &call_id),
            [format!("<{DIVERT_TO}>")],
            "parallel={parallel}: the dialog keeps a To the INVITE did not carry"
        );
    }
}

/// Positive control: a target naming no `to` keeps today's B-leg `To`, the
/// caller's user at the dial target's authority.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_without_to_keeps_the_callers_called_party() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![DialTarget {
            uri: format!("sip:15550100199@{FIRST_TARGET}"),
            ..Default::default()
        }],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(
        to_header(&sent[0]),
        format!("<sip:15550100077@{FIRST_TARGET}>")
    );
}

/// Each branch of a fork is addressed to its own target's `to`, and a branch
/// naming none keeps the default: a hunt across two trunks can reach two
/// different numbers.
#[tokio::test(flavor = "multi_thread")]
async fn each_branch_of_a_fork_names_its_own_called_party() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            divert_target(FIRST_TARGET, DIVERT_TO),
            DialTarget {
                uri: format!("sip:15550100077@{SECOND_TARGET}"),
                ..Default::default()
            },
        ],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(sent.len(), 2);
    assert_eq!(to_header(&sent[0]), format!("<{DIVERT_TO}>"));
    assert_eq!(
        to_header(&sent[1]),
        format!("<sip:15550100077@{SECOND_TARGET}>")
    );
}

/// The attempt a sequential hunt makes after the first is rebuilt from the
/// stored A-leg INVITE, so a target's `to` has to ride its own route or the
/// second carrier would be addressed to the caller's number again.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_hunt_names_each_targets_own_called_party() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            divert_target(FIRST_TARGET, DIVERT_TO),
            divert_target(SECOND_TARGET, SECOND_DIVERT_TO),
        ],
        false,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let first = wire(&dispatcher);
    assert_eq!(to_header(&first[0]), format!("<{DIVERT_TO}>"));

    advance_from_the_stored_invite(&dispatcher, &call_id);

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_TARGET}")]);
    assert_eq!(to_header(&sent[0]), format!("<{SECOND_DIVERT_TO}>"));
}

/// A `to` that is not a SIP URI is refused before anything rings, including
/// the targets listed before it.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_to_is_refused_before_anything_rings() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let refused = dial_targets(
            &dispatcher,
            vec![
                divert_target(FIRST_TARGET, DIVERT_TO),
                divert_target(SECOND_TARGET, "not a uri"),
            ],
            parallel,
            &DialShaping::default(),
        );
        assert!(
            matches!(refused, Err(DialError::InvalidIdentity(_))),
            "parallel={parallel}: {refused:?}"
        );
        assert!(
            wire(&dispatcher).is_empty(),
            "parallel={parallel}: something rang before the refusal"
        );
    }
}
