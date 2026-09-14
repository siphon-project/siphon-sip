//! A B-leg response relayed to the caller answers the INVITE the caller sent
//! (RFC 3261 §8.2.6.2): the response From is the caller's own From, and the
//! response To is the caller's own To with the tag of the A-leg dialog.
//!
//! The relayed message is the B-leg's, so before siphon puts it on the A-leg its
//! From and To carry the B-leg dialog: siphon's own B-leg identity, shaped for
//! the far side, and the far side's address. Swapping the dialog tags alone left
//! both URIs in place.
//!
//! Every test drives the real response path and reads what the caller would
//! have been sent off the UDP egress channel.

use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::numbers::policy::{NumberPolicyConfig, NumberRegistry, NumberingConfig};
use std::collections::HashMap;

/// Where the caller's INVITE came from, and where its responses go.
const CALLER: &str = "192.0.2.10:5060";
/// The far side of the B-leg.
const CARRIER: &str = "198.51.100.20:5060";

/// The caller's From and To, as its INVITE arrived.
const ARRIVAL_FROM: &str = "<sip:+15550100001@example.com>;tag=a1";
const ARRIVAL_TO: &str = "<sip:+15550100002@example.com>";

const B_LEG_CALL_ID: &str = "b-leg@192.0.2.1";
const B_LEG_BRANCH: &str = "z9hG4bK-b-leg";
const B_LEG_FROM_TAG: &str = "b-leg-from-tag";

/// What the handler did to the stored A-leg INVITE before routing the call.
#[derive(Debug, Clone, Copy)]
enum Stored {
    /// Left it as it arrived.
    AsArrived,
    /// Reshaped its numbers for the far side, as `call.rewrite_identities()`
    /// or a route's number policy does.
    ShapedForTheCarrier,
}

fn caller_invite() -> SipMessage {
    parse_sip_message_bytes(
        concat!(
            "INVITE sip:+15550100002@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:+15550100001@example.com>;tag=a1\r\n",
            "To: <sip:+15550100002@example.com>\r\n",
            "Call-ID: relayed-identity@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .expect("the caller's INVITE parses")
}

/// The INVITE siphon sent the carrier.
fn b_leg_invite() -> SipMessage {
    parse_sip_message_bytes(
        concat!(
            "INVITE sip:15550100002@198.51.100.20:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-b-leg\r\n",
            "Max-Forwards: 69\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag=b-leg-from-tag\r\n",
            "To: <sip:15550100002@198.51.100.20:5060>\r\n",
            "Call-ID: b-leg@192.0.2.1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:192.0.2.1:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .expect("the B-leg INVITE parses")
}

/// A response from the carrier, in the B-leg's dialog: siphon's B-leg From and
/// the carrier's own address in To. `to_tag` is the carrier's tag, when it sent
/// one; `extra` is appended to the header block.
fn b_leg_response(status_code: u16, reason: &str, to_tag: Option<&str>, extra: &str) -> SipMessage {
    let to_tag = to_tag.map(|tag| format!(";tag={tag}")).unwrap_or_default();
    let raw = format!(
        concat!(
            "SIP/2.0 {status_code} {reason}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag={from_tag}\r\n",
            "To: <sip:15550100002@198.51.100.20:5060>{to_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status_code = status_code,
        reason = reason,
        branch = B_LEG_BRANCH,
        from_tag = B_LEG_FROM_TAG,
        to_tag = to_tag,
        call_id = B_LEG_CALL_ID,
        extra = extra,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the B-leg response parses")
}

/// A `plain` number policy over a plan whose bare digits are country-code-first,
/// so `+15550100001` is shaped to `15550100001`.
fn plain_policy() -> Arc<crate::numbers::policy::NumberPolicy> {
    let numbering = NumberingConfig {
        country_code: "1".to_string(),
        assume: crate::numbers::AssumeForm::International,
        ..Default::default()
    };
    let mut policies = HashMap::new();
    policies.insert(
        "plain@test".to_string(),
        serde_yaml_ng::from_str::<NumberPolicyConfig>("default: plain\n")
            .expect("the policy parses"),
    );
    let (registry, warnings) = NumberRegistry::build(&numbering, &policies);
    assert!(warnings.is_empty(), "policy warnings: {warnings:?}");
    registry
        .get("plain@test")
        .expect("the policy is configured")
}

fn userpart(name_addr: &str) -> String {
    crate::sip::headers::nameaddr::NameAddr::parse(name_addr)
        .expect("a name-addr")
        .uri
        .user
        .unwrap_or_default()
}

/// A B2BUA call from the caller with one B-leg out to the carrier. Returns the
/// call's id and the A-leg dialog's local tag, the tag every final response to
/// the caller must carry.
fn b2bua_call(dispatcher: &TestDispatcher, stored: Stored) -> (String, String) {
    let arrival = caller_invite();
    let mut a_leg = Leg::new_a_leg(
        "relayed-identity@192.0.2.10".to_string(),
        "a1".to_string(),
        "z9hG4bK-caller".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    // The arrival snapshot, taken before the handler runs (see invite.rs).
    a_leg.stored_from = arrival.headers.from().cloned();
    a_leg.stored_to = arrival.headers.to().cloned();
    let local_tag = a_leg.dialog.local_tag.clone();
    let state = &dispatcher.state;
    let call_id = state.call_actors.create_call(a_leg);

    let mut stored_invite = arrival;
    if let Stored::ShapedForTheCarrier = stored {
        // What `call.rewrite_identities()` runs on the stored INVITE.
        crate::script::api::numbers::apply_to_message(&mut stored_invite, &plain_policy());
        assert_eq!(
            userpart(stored_invite.headers.from().expect("a From")),
            "15550100001",
            "the handler's shaping did not reach the stored INVITE"
        );
        assert_eq!(
            userpart(stored_invite.headers.to().expect("a To")),
            "15550100002"
        );
    }
    state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(stored_invite)));

    let mut b_leg = Leg::new_b_leg(
        B_LEG_CALL_ID.to_string(),
        B_LEG_FROM_TAG.to_string(),
        "sip:15550100002@198.51.100.20:5060".to_string(),
        B_LEG_BRANCH.to_string(),
        LegTransport {
            remote_addr: CARRIER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    // On the wire, so the leg is a live branch until it fails.
    b_leg.b_leg_invite = Some(Arc::new(std::sync::Mutex::new(b_leg_invite())));
    assert!(state.call_actors.add_b_leg(&call_id, b_leg));
    (call_id, local_tag)
}

fn snapshot(call_id: &str, dispatcher: &TestDispatcher) -> BLegResponseSnapshot {
    b_leg_response_snapshot(call_id, B_LEG_BRANCH, &dispatcher.state).expect("the call is live")
}

/// Everything the caller was sent since the last call, in order.
fn sent_to_caller(dispatcher: &TestDispatcher) -> Vec<SipMessage> {
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    dispatcher
        .udp
        .try_iter()
        .filter(|sent| sent.destination == caller)
        .map(|sent| parse_sip_message_bytes(&sent.data).expect("what the caller was sent parses"))
        .collect()
}

fn the_one_sent_to_caller(dispatcher: &TestDispatcher) -> SipMessage {
    let mut sent = sent_to_caller(dispatcher);
    assert_eq!(sent.len(), 1, "the caller was sent {} messages", sent.len());
    sent.remove(0)
}

fn reason_phrase(response: &SipMessage) -> &str {
    match &response.start_line {
        StartLine::Response(status_line) => &status_line.reason_phrase,
        StartLine::Request(_) => panic!("the caller was sent a request"),
    }
}

/// The caller's own From byte for byte, its own To with `to_tag`, and nothing
/// of the far side's address anywhere in the message.
fn assert_caller_identity(response: &SipMessage, to_tag: Option<&str>) {
    assert_eq!(
        response.headers.from().map(String::as_str),
        Some(ARRIVAL_FROM),
        "From is not the caller's own"
    );
    let expected_to = match to_tag {
        Some(tag) => format!("{ARRIVAL_TO};tag={tag}"),
        None => ARRIVAL_TO.to_string(),
    };
    assert_eq!(
        response.headers.to().map(String::as_str),
        Some(expected_to.as_str()),
        "To is not the caller's own"
    );
    let wire = String::from_utf8(response.to_bytes()).expect("utf-8");
    assert!(
        !wire.contains("198.51.100.20"),
        "the carrier's address reached the caller:\n{wire}"
    );
}

/// The shape a relayed failure used to reach the caller in: its dialog tags,
/// under siphon's B-leg From and the carrier's To.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_b_leg_failure_echoes_the_callers_own_from_and_to() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::AsArrived);
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut not_found = b_leg_response(404, "Not Found", Some("carrier-tag"), "");

    relay_failure_to_a_leg(&call_id, &mut not_found, &snapshot, &dispatcher.state);

    let relayed = the_one_sent_to_caller(&dispatcher);
    // The response itself stays the carrier's.
    assert_eq!(relayed.status_code(), Some(404));
    assert_eq!(reason_phrase(&relayed), "Not Found");
    assert_caller_identity(&relayed, Some(&local_tag));
}

/// The stored INVITE is the buffer a handler reshapes for the far side, so it
/// cannot be what the caller's identity is restored from.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_b_leg_failure_echoes_the_arrival_form_after_the_handler_reshaped_it() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::ShapedForTheCarrier);
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut not_found = b_leg_response(404, "Not Found", Some("carrier-tag"), "");

    relay_failure_to_a_leg(&call_id, &mut not_found, &snapshot, &dispatcher.state);

    assert_caller_identity(&the_one_sent_to_caller(&dispatcher), Some(&local_tag));
}

/// A call with no arrival snapshot still answers with the caller's identity,
/// read off the stored INVITE.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_b_leg_failure_without_a_snapshot_echoes_the_stored_invite() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::AsArrived);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.a_leg.stored_from = None;
        call.a_leg.stored_to = None;
    }
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut not_found = b_leg_response(404, "Not Found", Some("carrier-tag"), "");

    relay_failure_to_a_leg(&call_id, &mut not_found, &snapshot, &dispatcher.state);

    assert_caller_identity(&the_one_sent_to_caller(&dispatcher), Some(&local_tag));
}

/// The failure path's own relay: a B-leg challenge passed through to the caller
/// (`call.dial(auth_passthrough=True)`).
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_auth_challenge_echoes_the_callers_own_from_and_to() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::ShapedForTheCarrier);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.auth_passthrough = true;
    }
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut challenge = b_leg_response(
        407,
        "Proxy Authentication Required",
        Some("carrier-tag"),
        "Proxy-Authenticate: Digest realm=\"carrier.example.com\", nonce=\"0123abcd\"\r\n",
    );

    b_leg_failed(
        &call_id,
        B_LEG_BRANCH,
        &mut challenge,
        407,
        &dispatcher.state,
        &snapshot,
    );

    let relayed = the_one_sent_to_caller(&dispatcher);
    assert_eq!(relayed.status_code(), Some(407));
    assert_caller_identity(&relayed, Some(&local_tag));
}

/// A failure that ends the call is relayed once `@b2bua.on_failure` has left it
/// to end: a `call.dial()` whose callee answered 404.
#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_failure_that_ends_the_call_echoes_the_callers_own_from_and_to() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::ShapedForTheCarrier);
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut not_found = b_leg_response(404, "Not Found", Some("carrier-tag"), "");

    b_leg_failed(
        &call_id,
        B_LEG_BRANCH,
        &mut not_found,
        404,
        &dispatcher.state,
        &snapshot,
    );

    let relayed = the_one_sent_to_caller(&dispatcher);
    assert_eq!(relayed.status_code(), Some(404));
    assert_eq!(reason_phrase(&relayed), "Not Found");
    assert_caller_identity(&relayed, Some(&local_tag));
    assert!(
        dispatcher.state.call_actors.get_call(&call_id).is_none(),
        "the failed call was not ended"
    );
}

/// A provisional keeps whatever To-tag it has once its dialog headers are
/// swapped: none on a plain 180, the A-leg's early-dialog tag on an 18x that
/// opened one. Its URIs are the caller's own either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_provisional_echoes_the_callers_identity_and_keeps_its_own_to_tag() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::ShapedForTheCarrier);
    let carrier: SocketAddr = CARRIER.parse().expect("a literal address");

    let mut ringing = b_leg_response(180, "Ringing", None, "");
    b_leg_provisional(
        &call_id,
        &mut ringing,
        180,
        carrier,
        &dispatcher.state,
        &snapshot(&call_id, &dispatcher),
    );
    assert_caller_identity(&the_one_sent_to_caller(&dispatcher), None);

    let mut progress = b_leg_response(183, "Session Progress", Some("carrier-tag"), "");
    b_leg_provisional(
        &call_id,
        &mut progress,
        183,
        carrier,
        &dispatcher.state,
        &snapshot(&call_id, &dispatcher),
    );
    assert_caller_identity(&the_one_sent_to_caller(&dispatcher), Some(&local_tag));
}

/// The answer the caller is sent carries its own From and To, with the A-leg
/// dialog's tag.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_answer_echoes_the_callers_own_from_and_to() {
    let dispatcher = test_dispatcher();
    let (call_id, local_tag) = b2bua_call(&dispatcher, Stored::ShapedForTheCarrier);
    let snapshot = snapshot(&call_id, &dispatcher);
    let mut answer = b_leg_response(200, "OK", Some("carrier-tag"), "");

    prepare_a_leg_answer(&call_id, &mut answer, &dispatcher.state, &snapshot);

    assert_caller_identity(&answer, Some(&local_tag));
}
