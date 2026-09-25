//! The identity a controller-issued `dial` presents on the B-leg.
//!
//! A B-leg's `From` is framework-managed: the builder swaps in a fresh dialog
//! tag and rewrites the host to siphon's own advertised address for topology
//! hiding. So without these arguments a dial out to a trunk presents the
//! caller's own `From` — the internal extension — and a carrier that looks its
//! account up by the `From` user does not recognise it, challenges the INVITE,
//! and keeps challenging however correct the digest is. An injected
//! `headers: {"From": …}` cannot fix that: it is overwritten after the fact and
//! a `From` written without its tag drops the mandatory dialog tag
//! (RFC 3261 §8.1.1.3).
//!
//! Each case is driven through the dispatcher's own `dial` entry point on a test
//! dispatcher, with what siphon sent read back off the UDP egress — including
//! the *second* attempt of a sequential hunt, which is built from the stored
//! A-leg INVITE rather than from the dial's own template and so is where an
//! identity that only reached the first phone would show up.

use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const FIRST_TARGET: &str = "198.51.100.7:5060";
const SECOND_TARGET: &str = "198.51.100.8:5060";
const SIP_CALL_ID: &str = "control-dial-identity@192.0.2.10";

/// The identity the controller wants the trunk to see, in place of the caller's
/// own extension.
const PRESENTED_FROM: &str = "sip:15550100042@trunk.example.com";
const PRESENTED_DISPLAY: &str = "Example Ltd";
const ASSERTED_IDENTITY: &str = "<sip:15550100042@trunk.example.com>";

const SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// A caller INVITE from an extension: the `From` carries the extension as both
/// display name and userpart, which is exactly what must not reach a carrier.
fn caller_invite() -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:15550100077@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-dial-identity\r\n",
            "Max-Forwards: 70\r\n",
            "From: \"203\" <sip:203@pbx.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100077@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:203@192.0.2.10:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = SIP_CALL_ID,
        length = SDP.len(),
        sdp = SDP,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
}

/// A caller parked under external control with nothing dialed yet.
fn park(dispatcher: &TestDispatcher) -> String {
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        SIP_CALL_ID.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-dial-identity".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    dispatcher
        .state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite())));
    call_id
}

fn wire(dispatcher: &TestDispatcher) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        });
    }
    sent
}

fn targets(addresses: &[&str]) -> Vec<DialTarget> {
    addresses
        .iter()
        .map(|address| DialTarget {
            uri: format!("sip:15550100077@{address}"),
            ..Default::default()
        })
        .collect()
}

fn dial(
    dispatcher: &TestDispatcher,
    addresses: &[&str],
    parallel: bool,
    shaping: &DialShaping,
) -> Result<bool, DialError> {
    b2bua_dial_call_with_state(
        SIP_CALL_ID,
        targets(addresses),
        parallel,
        30,
        &[],
        shaping,
        &dispatcher.state,
    )
}

/// The shaping the reported outbound-call fault needed: a presented number, the
/// company's display name, and an asserted identity for the trunk.
fn trunk_identity() -> DialShaping {
    DialShaping {
        from: Some(PRESENTED_FROM.to_string()),
        from_display: Some(PRESENTED_DISPLAY.to_string()),
        p_asserted_identity: Some(ASSERTED_IDENTITY.to_string()),
        ..Default::default()
    }
}

fn from_header(sent: &Sent) -> &str {
    sent.message
        .headers
        .get("From")
        .map(String::as_str)
        .expect("every INVITE carries a From")
}

/// The From header up to its tag. The tag is random hex, so a substring check
/// for the caller's extension over the whole header fails whenever the tag
/// happens to contain those digits.
fn without_tag(from: &str) -> &str {
    from.split(";tag=").next().unwrap_or(from)
}

/// The one thing a `From` rewrite must never lose: the dialog tag, which is the
/// B-leg's own and not the caller's (RFC 3261 §8.1.1.3).
fn assert_has_a_fresh_dialog_tag(sent: &Sent, label: &str) {
    let from = from_header(sent);
    let tag = from
        .split(";tag=")
        .nth(1)
        .unwrap_or_else(|| panic!("{label}: no From tag on {from}"));
    assert!(!tag.is_empty(), "{label}: empty From tag on {from}");
    assert_ne!(tag, "caller-tag", "{label}: the B-leg reused the A-leg tag");
}

/// The presented identity reaches the wire whole: userpart, host and display
/// name, with a dialog tag of the B-leg's own.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_presents_the_identity_the_controller_named() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial(&dispatcher, &[FIRST_TARGET], true, &trunk_identity()).expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_TARGET}")]);
    let from = from_header(&sent[0]);
    assert!(
        from.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <{PRESENTED_FROM}>")),
        "the presented identity is not on the wire: {from}"
    );
    assert!(
        !without_tag(from).contains("203"),
        "the caller's extension reached the trunk: {from}"
    );
    assert!(
        !from.contains("pbx.example.com"),
        "the From host was not pinned to the presented one: {from}"
    );
    assert_has_a_fresh_dialog_tag(&sent[0], "presented identity");
    assert_eq!(
        sent[0]
            .message
            .headers
            .get("P-Asserted-Identity")
            .map(String::as_str),
        Some(ASSERTED_IDENTITY),
    );
}

/// A display name is part of an identity. Replacing the number but keeping
/// `"203"` beside it would present the extension the `from` exists to hide, so
/// an unnamed display is dropped rather than carried over.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_that_names_no_display_drops_the_callers() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let shaping = DialShaping {
        from: Some(PRESENTED_FROM.to_string()),
        ..Default::default()
    };
    assert!(dial(&dispatcher, &[FIRST_TARGET], true, &shaping).expect("the dial runs"));

    let from = from_header(&wire(&dispatcher)[0]).to_string();
    assert!(
        from.starts_with(&format!("<{PRESENTED_FROM}>")),
        "an unnamed display should leave no display name: {from}"
    );
}

/// Naming only a display name leaves the caller's own URI alone — it is the
/// same call, presented under a name.
#[tokio::test(flavor = "multi_thread")]
async fn a_display_name_on_its_own_leaves_the_callers_uri() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let shaping = DialShaping {
        from_display: Some(PRESENTED_DISPLAY.to_string()),
        ..Default::default()
    };
    assert!(dial(&dispatcher, &[FIRST_TARGET], true, &shaping).expect("the dial runs"));

    let sent = wire(&dispatcher);
    let from = from_header(&sent[0]);
    assert!(
        from.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <sip:203@")),
        "the caller's own userpart should survive: {from}"
    );
    assert_has_a_fresh_dialog_tag(&sent[0], "display only");
}

/// Every branch of a fork is the same call presenting the same identity.
#[tokio::test(flavor = "multi_thread")]
async fn every_branch_of_a_fork_presents_the_same_identity() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial(
        &dispatcher,
        &[FIRST_TARGET, SECOND_TARGET],
        true,
        &trunk_identity()
    )
    .expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(
        summaries(&sent),
        [
            format!("INVITE to {FIRST_TARGET}"),
            format!("INVITE to {SECOND_TARGET}")
        ]
    );
    for (index, branch) in sent.iter().enumerate() {
        let from = from_header(branch);
        assert!(
            from.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <{PRESENTED_FROM}>")),
            "branch {index} presents {from}"
        );
        assert_eq!(
            branch
                .message
                .headers
                .get("P-Asserted-Identity")
                .map(String::as_str),
            Some(ASSERTED_IDENTITY),
            "branch {index}"
        );
    }
}

/// The attempt a sequential hunt makes *after* the first is built from the
/// stored A-leg INVITE, which holds the caller's own identity. Without the dial
/// carrying its shaping on the call, only the first phone would see what the
/// controller asked to present — and on a hunt through trunks that is the
/// difference between one carrier accepting the call and the next challenging
/// it for ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_hunt_presents_the_identity_on_every_attempt() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial(
        &dispatcher,
        &[FIRST_TARGET, SECOND_TARGET],
        false,
        &trunk_identity()
    )
    .expect("the dial runs"));
    assert_eq!(
        summaries(&wire(&dispatcher)),
        [format!("INVITE to {FIRST_TARGET}")],
        "a sequential dial rings one target at a time"
    );

    // What the failover path does when the first target fails: advance the
    // sequence from the *stored* A-leg INVITE.
    advance_from_the_stored_invite(&dispatcher, &call_id);

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_TARGET}")]);
    let from = from_header(&sent[0]);
    assert!(
        from.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <{PRESENTED_FROM}>")),
        "the second attempt presents {from}"
    );
    assert!(
        !without_tag(from).contains("203"),
        "the second attempt leaked the caller's extension: {from}"
    );
    assert_has_a_fresh_dialog_tag(&sent[0], "second attempt");
    assert_eq!(
        sent[0]
            .message
            .headers
            .get("P-Asserted-Identity")
            .map(String::as_str),
        Some(ASSERTED_IDENTITY),
    );
}

/// CLIR (RFC 3323 §4.1 / TS 24.607): the presented `From` is anonymised and
/// `Privacy: id` asserted, while `P-Asserted-Identity` keeps the real identity
/// for the trusted next hop — which is the whole mechanism, and is why
/// anonymising without it leaks the number to every carrier that renders
/// `From`.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_dial_anonymises_from_and_keeps_the_asserted_identity() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let shaping = DialShaping {
            privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
            ..trunk_identity()
        };
        assert!(dial(&dispatcher, &[FIRST_TARGET], parallel, &shaping).expect("the dial runs"));

        let sent = wire(&dispatcher);
        let from = from_header(&sent[0]);
        assert!(
            from.contains(crate::sip::privacy::ANONYMOUS_URI),
            "parallel={parallel}: {from}"
        );
        assert!(
            !from.contains("15550100042"),
            "parallel={parallel}: the withheld number reached the wire in From: {from}"
        );
        assert_has_a_fresh_dialog_tag(&sent[0], "restricted");
        assert!(
            sent[0]
                .message
                .headers
                .get("Privacy")
                .is_some_and(|value| value.contains("id")),
            "parallel={parallel}: no Privacy: id"
        );
        assert_eq!(
            sent[0]
                .message
                .headers
                .get("P-Asserted-Identity")
                .map(String::as_str),
            Some(ASSERTED_IDENTITY),
            "parallel={parallel}: the network can still identify the caller",
        );
    }
}

/// A sequential hunt withholds the identity on every attempt, not just the
/// first: the presentation rides on each route the failover engine takes.
#[tokio::test(flavor = "multi_thread")]
async fn a_restricted_sequential_hunt_stays_restricted_on_the_next_attempt() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    let shaping = DialShaping {
        privacy: Some(crate::sip::privacy::CallerIdPresentation::Restricted),
        ..trunk_identity()
    };
    assert!(dial(&dispatcher, &[FIRST_TARGET, SECOND_TARGET], false, &shaping).expect("dial runs"));
    let _first = wire(&dispatcher);

    advance_from_the_stored_invite(&dispatcher, &call_id);

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_TARGET}")]);
    let from = from_header(&sent[0]);
    assert!(from.contains(crate::sip::privacy::ANONYMOUS_URI), "{from}");
    assert!(
        !from.contains("15550100042"),
        "the second attempt un-withheld the number: {from}"
    );
}

/// A URI siphon cannot put on the wire is refused before anything rings — the
/// caller is still parked and the controller still owns the decision, so a
/// typed refusal is strictly better than a ringing phone under a wrong
/// identity.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_presented_identity_is_refused_before_anything_rings() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let shaping = DialShaping {
        from: Some("not a uri".to_string()),
        ..Default::default()
    };
    let refused = dial(&dispatcher, &[FIRST_TARGET], true, &shaping);
    assert!(
        matches!(refused, Err(DialError::InvalidIdentity(_))),
        "{refused:?}"
    );
    assert!(wire(&dispatcher).is_empty(), "nothing rang");
}

/// Drive the sequence forward exactly as the B-leg failure path does: from the
/// stored A-leg INVITE, not from the dial's template.
fn advance_from_the_stored_invite(dispatcher: &TestDispatcher, call_id: &str) {
    let invite_arc = dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .and_then(|call| call.a_leg_invite.clone())
        .expect("the parked call stores its A-leg INVITE");
    let stored = invite_arc.lock().expect("the invite lock");
    let advanced = b2bua_advance_route(call_id, &stored, &dispatcher.state);
    assert!(advanced.dialed, "the sequence had another target to try");
}

/// The account a carrier assigned, at the carrier's own host: what a target
/// names when the carrier validates or routes on the `From` domain.
const CARRIER_FROM: &str = "sip:account@198.51.100.20";

fn target_with_identity(address: &str, from: &str) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100077@{address}"),
        from: Some(from.to_string()),
        ..Default::default()
    }
}

fn dial_targets(
    dispatcher: &TestDispatcher,
    targets: Vec<DialTarget>,
    parallel: bool,
    shaping: &DialShaping,
) -> Result<bool, DialError> {
    b2bua_dial_call_with_state(
        SIP_CALL_ID,
        targets,
        parallel,
        30,
        &[],
        shaping,
        &dispatcher.state,
    )
}

/// A target's `from` is the same identity argument as the dial's: the whole
/// URI, host included, and not the caller's display name beside it. Before it
/// was only the user part, substituted as a number, so the carrier saw the
/// account at siphon's advertised address and `"203"` in front of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_targets_own_from_pins_its_host_and_drops_the_callers_display() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        assert!(dial_targets(
            &dispatcher,
            vec![target_with_identity(FIRST_TARGET, CARRIER_FROM)],
            parallel,
            &DialShaping::default(),
        )
        .expect("the dial runs"));

        let sent = wire(&dispatcher);
        assert_eq!(summaries(&sent), [format!("INVITE to {FIRST_TARGET}")]);
        let from = from_header(&sent[0]);
        assert!(
            from.starts_with(&format!("<{CARRIER_FROM}>")),
            "parallel={parallel}: the target's identity is not on the wire whole: {from}"
        );
        assert!(
            !without_tag(from).contains("203"),
            "parallel={parallel}: the caller's display name or extension leaked: {from}"
        );
        assert_has_a_fresh_dialog_tag(&sent[0], "target identity");
    }
}

/// A target's host outranks the dial's, and a target naming nothing keeps the
/// dial's: each branch presents the host of the carrier it is going to.
#[tokio::test(flavor = "multi_thread")]
async fn each_branch_of_a_fork_pins_its_own_targets_host() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target_with_identity(FIRST_TARGET, CARRIER_FROM),
            DialTarget {
                uri: format!("sip:15550100077@{SECOND_TARGET}"),
                ..Default::default()
            },
        ],
        true,
        &trunk_identity(),
    )
    .expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(sent.len(), 2);
    let first = from_header(&sent[0]);
    assert!(
        first.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <{CARRIER_FROM}>")),
        "the first branch presents its own URI under the dial's display name: {first}"
    );
    let second = from_header(&sent[1]);
    assert!(
        second.starts_with(&format!("\"{PRESENTED_DISPLAY}\" <{PRESENTED_FROM}>")),
        "the second branch keeps the dial's identity and host: {second}"
    );
}

/// The attempt a sequential hunt makes after the first is rebuilt from the
/// stored A-leg INVITE, so a target's identity has to ride its own route or
/// the second carrier would see the first one's host.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_hunt_pins_each_targets_own_host() {
    const SECOND_CARRIER_FROM: &str = "sip:other-account@203.0.113.30";
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![
            target_with_identity(FIRST_TARGET, CARRIER_FROM),
            target_with_identity(SECOND_TARGET, SECOND_CARRIER_FROM),
        ],
        false,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let first = wire(&dispatcher);
    assert!(from_header(&first[0]).starts_with(&format!("<{CARRIER_FROM}>")));

    advance_from_the_stored_invite(&dispatcher, &call_id);

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {SECOND_TARGET}")]);
    let from = from_header(&sent[0]);
    assert!(
        from.starts_with(&format!("<{SECOND_CARRIER_FROM}>")),
        "the second attempt presents {from}"
    );
    assert_has_a_fresh_dialog_tag(&sent[0], "second target identity");
}

/// A target's `from` is held to the dial's rule: not a SIP URI is refused
/// before anything rings, including the targets listed before it.
#[tokio::test(flavor = "multi_thread")]
async fn an_unparseable_target_identity_is_refused_before_anything_rings() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let refused = dial_targets(
        &dispatcher,
        vec![
            DialTarget {
                uri: format!("sip:15550100077@{FIRST_TARGET}"),
                ..Default::default()
            },
            target_with_identity(SECOND_TARGET, "not a uri"),
        ],
        true,
        &DialShaping::default(),
    );
    assert!(
        matches!(refused, Err(DialError::InvalidIdentity(_))),
        "{refused:?}"
    );
    assert!(wire(&dispatcher).is_empty(), "nothing rang");
}

/// RFC 3325 §9.1 permits a bare addr-spec, but the name-addr form is the one a
/// strict SBC accepts, so a bare identity goes out in angle brackets, on every
/// branch and every attempt.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_asserted_identity_goes_out_in_angle_brackets() {
    for parallel in [true, false] {
        let dispatcher = test_dispatcher();
        park(&dispatcher);
        let shaping = DialShaping {
            p_asserted_identity: Some("sip:+15550123@example.com".to_string()),
            ..Default::default()
        };
        let mut targets = targets(&[FIRST_TARGET]);
        targets.push(DialTarget {
            uri: format!("sip:15550100077@{SECOND_TARGET}"),
            p_asserted_identity: Some("tel:+15550124".to_string()),
            ..Default::default()
        });
        assert!(dial_targets(&dispatcher, targets, parallel, &shaping).expect("the dial runs"));

        let sent = wire(&dispatcher);
        assert_eq!(
            sent[0]
                .message
                .headers
                .get("P-Asserted-Identity")
                .map(String::as_str),
            Some("<sip:+15550123@example.com>"),
            "parallel={parallel}"
        );
        if parallel {
            assert_eq!(
                sent[1]
                    .message
                    .headers
                    .get("P-Asserted-Identity")
                    .map(String::as_str),
                Some("<tel:+15550124>"),
                "a target's own identity"
            );
        }
    }
}
