//! A caller's `Require` is checked on the paths that answer the call, or dial
//! for it, without passing through the script's routing action: siphon
//! answering the call itself (`call.answer()`, the control plane's `answer`), an
//! answer-first handover, the control plane's `dial` and `route`, and a
//! `Replaces` takeover.
//!
//! Each is driven through the dispatcher's own entry point for that path, on a
//! test dispatcher, with what siphon sent read back off the UDP egress. The
//! public wrappers add only the process-wide control handle, which a unit-test
//! binary never installs.

use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::b2bua::header_policy::ResolvedPolicy;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";
const SIP_CALL_ID: &str = "uas-require@192.0.2.10";

const SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// A caller INVITE with `require` as its `Require` and `extra` added before the
/// body (an SDP offer).
fn caller_invite(require: &str, extra: &str) -> String {
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-uas-require\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Supported: 100rel, timer\r\n",
            "Require: {require}\r\n",
            "{extra}",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = SIP_CALL_ID,
        require = require,
        extra = extra,
        length = SDP.len(),
        sdp = SDP,
    )
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
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

fn preset(name: &str) -> ResolvedPolicy {
    let preset = crate::b2bua::header_policy::builtin_presets()
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("no built-in preset {name}"));
    ResolvedPolicy::from_preset(preset)
}

/// A caller's call requiring `require`, parked on `dispatcher` under `policy`
/// with nothing sent yet: its internal id and INVITE.
fn new_call(dispatcher: &TestDispatcher, require: &str, policy: &str) -> (String, SipMessage) {
    let invite = parse(&caller_invite(require, ""));
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        SIP_CALL_ID.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-uas-require".to_string(),
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
        .set_a_leg_invite(&call_id, Arc::new(Mutex::new(invite.clone())));
    dispatcher
        .state
        .call_actors
        .get_call_mut(&call_id)
        .expect("the call exists")
        .resolved_header_policy = Some(Arc::new(preset(policy)));
    (call_id, invite)
}

/// The one message siphon sent is a 420 to the caller listing `unsupported`,
/// and the call is gone.
fn assert_refused(dispatcher: &TestDispatcher, call_id: &str, unsupported: &str, label: &str) {
    let sent = wire(dispatcher);
    assert_eq!(
        summaries(&sent),
        [format!("420 to {CALLER}")],
        "{label}: only a 420 goes out"
    );
    assert_eq!(
        sent[0]
            .message
            .headers
            .get("Unsupported")
            .map(String::as_str),
        Some(unsupported),
        "{label}"
    );
    assert!(
        dispatcher.state.call_actors.get_call(call_id).is_none(),
        "{label}: the refused call is gone"
    );
}

fn callee_uri() -> String {
    format!("sip:15550100042@{CALLEE}")
}

/// siphon answering the call itself is siphon as the only UAS: there is no
/// callee to honour anything, so a tag siphon does not implement is refused
/// even under a policy that would relay it to one.
#[tokio::test(flavor = "multi_thread")]
async fn answering_the_call_itself_refuses_an_extension_siphon_does_not_implement() {
    for policy in ["transparent-b2bua@2026", "ims-intra-trust-domain@2026"] {
        let dispatcher = test_dispatcher();
        let (call_id, invite) = new_call(&dispatcher, "precondition, 100rel", policy);
        let answered = b2bua_answer_call_with_state(
            &call_id,
            &invite,
            200,
            "OK",
            None,
            None,
            &dispatcher.state,
        );
        assert!(!answered, "under {policy}: the call was not answered");
        assert_refused(&dispatcher, &call_id, "precondition", policy);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn answering_the_call_itself_goes_ahead_when_siphon_implements_every_required_tag() {
    let dispatcher = test_dispatcher();
    let (call_id, invite) = new_call(
        &dispatcher,
        "100rel, timer, replaces",
        "transparent-b2bua@2026",
    );
    assert!(b2bua_answer_call_with_state(
        &call_id,
        &invite,
        200,
        "OK",
        None,
        None,
        &dispatcher.state,
    ));
    assert_eq!(summaries(&wire(&dispatcher)), [format!("200 to {CALLER}")]);
}

/// `call.handover(answer=True)` and the control plane's anchored `answer`
/// answer the call themselves too, and are refused before any media is
/// anchored for a call that will not be connected.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_first_handover_refuses_before_anchoring_media() {
    let dispatcher = test_dispatcher();
    let (call_id, invite) = new_call(&dispatcher, "precondition", "transparent-b2bua@2026");
    let result = answer_first_anchor(
        &call_id,
        &invite,
        "192.0.2.10".parse().expect("a literal address"),
        200,
        "OK",
        None,
        None,
        &dispatcher.state,
    );
    assert!(result.is_err(), "no answer went out");
    assert_refused(&dispatcher, &call_id, "precondition", "answer-first");
}

/// The control plane's `dial` rings B-legs under the call's policy, so it is
/// checked the way `call.dial()` is, when it dials. The caller cannot be
/// connected under that policy on any dial, so it is refused there and then.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_dial_refuses_when_the_policy_cannot_relay_a_required_extension() {
    let dispatcher = test_dispatcher();
    let (call_id, _) = new_call(&dispatcher, "precondition", "transparent-b2bua@2026");
    let dialled = b2bua_dial_call_with_state(
        SIP_CALL_ID,
        vec![DialTarget {
            uri: callee_uri(),
            ..Default::default()
        }],
        true,
        30,
        &[],
        &dispatcher.state,
    );
    assert!(matches!(dialled, Ok(true)), "{dialled:?}");
    assert_refused(&dispatcher, &call_id, "precondition", "control dial");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_dial_goes_ahead_under_a_policy_that_relays_the_extension() {
    let dispatcher = test_dispatcher();
    new_call(&dispatcher, "precondition", "ims-intra-trust-domain@2026");
    let dialled = b2bua_dial_call_with_state(
        SIP_CALL_ID,
        vec![DialTarget {
            uri: callee_uri(),
            ..Default::default()
        }],
        true,
        30,
        &[],
        &dispatcher.state,
    );
    assert!(matches!(dialled, Ok(true)), "{dialled:?}");
    assert_eq!(
        summaries(&wire(&dispatcher)),
        [format!("INVITE to {CALLEE}")]
    );
}

fn route_target() -> RouteTarget {
    RouteTarget {
        uri: callee_uri(),
        next_hop: None,
        headers: Vec::new(),
        timeout_secs: None,
        reroute_after_progress: false,
    }
}

/// `route` hands the call back to siphon's own routing, checked like
/// `call.route()`: refused here, dialled under a relaying policy below.
#[tokio::test(flavor = "multi_thread")]
async fn a_control_route_refuses_when_the_policy_cannot_relay_a_required_extension() {
    let dispatcher = test_dispatcher();
    let (call_id, _) = new_call(&dispatcher, "x-lab-extension", "transparent-b2bua@2026");
    let routed =
        b2bua_route_call_with_state(SIP_CALL_ID, vec![route_target()], &[], &dispatcher.state);
    assert!(matches!(routed, Ok(true)), "{routed:?}");
    assert_refused(&dispatcher, &call_id, "x-lab-extension", "control route");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_control_route_goes_ahead_under_a_policy_that_relays_the_extension() {
    let dispatcher = test_dispatcher();
    new_call(&dispatcher, "precondition", "ims-intra-trust-domain@2026");
    let routed =
        b2bua_route_call_with_state(SIP_CALL_ID, vec![route_target()], &[], &dispatcher.state);
    assert!(matches!(routed, Ok(true)), "{routed:?}");
    assert_eq!(
        summaries(&wire(&dispatcher)),
        [format!("INVITE to {CALLEE}")]
    );
}

/// A takeover INVITE is answered by siphon itself as well, joined to a call it
/// already holds, so it is refused on its own transaction before the takeover
/// touches the call it names.
#[tokio::test(flavor = "multi_thread")]
async fn a_replaces_takeover_refuses_an_extension_siphon_does_not_implement() {
    let dispatcher = test_dispatcher();
    let raw = caller_invite(
        "precondition",
        "Replaces: held-call@198.51.100.20;to-tag=held-to;from-tag=held-from\r\n",
    );
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.clone().into_bytes()),
    };
    let pending = crate::b2bua::actor::PendingReplaces {
        replaced_call_id: "held-call".to_string(),
        replaced_on_a_leg: true,
        early_only: false,
    };
    b2bua_bridge_inbound_replaces(
        &inbound,
        &parse(&raw),
        "taking-over-call",
        &pending,
        &dispatcher.state,
    );
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("420 to {CALLER}")]);
    assert_eq!(
        sent[0]
            .message
            .headers
            .get("Unsupported")
            .map(String::as_str),
        Some("precondition")
    );
}
