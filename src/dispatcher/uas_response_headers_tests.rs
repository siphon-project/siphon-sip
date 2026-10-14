//! Headers a script adds to a response siphon sends the caller as its UAS
//! (`call.progress(headers=…)`, `call.answer(headers=…)`,
//! `call.reject(headers=…)`) reach the wire, beside the headers siphon owns on
//! it: the dialog's To-tag and Contact, and on a reliable provisional its
//! `Require: 100rel` and `RSeq` (RFC 3262 §3).
//!
//! The typical case is an announcement or early-media server telling the
//! caller's network how to gate the early media it is about to play:
//! `P-Early-Media` on the 183 (RFC 5009 §8).
//!
//! Driven through the dispatcher with the harness of
//! [`super::a_leg_reliable_provisional_tests`], what siphon sent read back off
//! the UDP egress.

use super::a_leg_reliable_provisional_tests::{
    caller_invite, default_dial, dial_script, drain, is_reliable, Call, CALLER, CALLER_SDP, PLAIN,
    REQUIRES,
};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

/// The single response to the caller with `status_code` among `sent`.
fn only(sent: Vec<SipMessage>, status_code: u16) -> SipMessage {
    let statuses: Vec<_> = sent.iter().map(SipMessage::status_code).collect();
    let mut matching: Vec<_> = sent
        .into_iter()
        .filter(|message| message.status_code() == Some(status_code))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "one {status_code} to the caller, sent {statuses:?}"
    );
    matching.remove(0)
}

/// A 183 siphon sends itself carries the script's `P-Early-Media` beside the
/// To-tag and Contact it always puts on an early-dialog provisional.
#[tokio::test(flavor = "multi_thread")]
async fn a_uas_provisional_carries_the_scripts_headers() {
    let call = Call::place(PLAIN, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        183,
        "Session Progress",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        false,
        &headers(&[("P-Early-Media", "sendrecv")]),
    ));
    let progress = only(call.to_caller(), 183);
    assert_eq!(
        header(&progress, "P-Early-Media").as_deref(),
        Some("sendrecv")
    );
    assert!(header(&progress, "To").is_some_and(|to| to.contains(";tag=")));
    assert!(header(&progress, "Contact").is_some());
    assert_eq!(progress.body, CALLER_SDP.as_bytes());
}

/// Toward a caller that requires `100rel` the provisional is still siphon's
/// reliable one, with its `Require` and `RSeq`, and still carries the script's
/// header.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_uas_provisional_keeps_siphons_100rel_beside_the_scripts_headers() {
    let call = Call::place(REQUIRES, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        183,
        "Session Progress",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        false,
        &headers(&[("P-Early-Media", "sendonly")]),
    ));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress));
    assert_eq!(
        header(&progress, "P-Early-Media").as_deref(),
        Some("sendonly")
    );
}

/// The 2xx siphon answers with carries the script's headers, one replacing a
/// header siphon would otherwise have put there.
#[tokio::test(flavor = "multi_thread")]
async fn a_uas_answer_carries_the_scripts_headers() {
    let call = Call::place(PLAIN, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        200,
        "OK",
        Some(CALLER_SDP.as_bytes().to_vec()),
        Some("application/sdp"),
        true,
        &headers(&[
            ("Server", "announcement-service"),
            ("X-Lab-Tag", "answered-by-the-script"),
        ]),
    ));
    let answer = only(call.to_caller(), 200);
    assert_eq!(
        header(&answer, "X-Lab-Tag").as_deref(),
        Some("answered-by-the-script")
    );
    assert_eq!(answer.headers.get_all("Server").map(Vec::len), Some(1));
    assert_eq!(
        header(&answer, "Server").as_deref(),
        Some("announcement-service")
    );
}

/// No headers is today's response, unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn a_uas_response_without_headers_is_unchanged() {
    let call = Call::place(PLAIN, &default_dial());
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        180,
        "Ringing",
        None,
        None,
        false,
        &[],
    ));
    let ringing = only(call.to_caller(), 180);
    assert_eq!(header(&ringing, "P-Early-Media"), None);
    assert!(ringing.body.is_empty());
}

/// `call.reject(…, headers=…)` from `@b2bua.on_invite`: the final response the
/// caller gets carries them.
#[tokio::test(flavor = "multi_thread")]
async fn a_reject_from_on_invite_carries_the_scripts_headers() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.reject(480, \"Temporarily Unavailable\",\n",
        "                headers={\"Reason\": \"SIP;cause=480\", \"Retry-After\": \"120\"})\n",
    );
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    let raw = caller_invite(PLAIN, true);
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.into_bytes()),
    };
    tokio::task::block_in_place(|| handle_b2bua_invite(inbound, invite, &state));
    let sent = drain(&udp).into_iter().map(|sent| sent.message).collect();
    let rejected = only(sent, 480);
    assert_eq!(
        header(&rejected, "Reason").as_deref(),
        Some("SIP;cause=480")
    );
    assert_eq!(header(&rejected, "Retry-After").as_deref(), Some("120"));
    assert!(header(&rejected, "To").is_some_and(|to| to.contains(";tag=")));
}

/// `call.reject(…, headers=…)` from `@b2bua.on_failure`: the caller gets the
/// script's response, with the script's headers, instead of the callee's.
#[tokio::test(flavor = "multi_thread")]
async fn a_reject_from_on_failure_carries_the_scripts_headers() {
    let script = dial_script(
        "transparent-b2bua@2026",
        concat!(
            "\n",
            "@b2bua.on_failure\n",
            "def on_failure(call, code, reason):\n",
            "    call.reject(480, \"Temporarily Unavailable\", headers={\"Reason\": \"SIP;cause=486\"})\n",
        ),
    );
    let call = Call::place(PLAIN, &script);
    call.callee_sends(486, "Busy Here", &[], None);
    let rejected = only(call.to_caller(), 480);
    assert_eq!(
        header(&rejected, "Reason").as_deref(),
        Some("SIP;cause=486")
    );
}

/// A framework-owned header in `call.reject(headers=…)` raises in the script,
/// so `@b2bua.on_invite` decides nothing and the call is not answered with the
/// header the script could not have.
#[tokio::test(flavor = "multi_thread")]
async fn a_reject_naming_a_framework_owned_header_raises_in_the_script() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.reject(480, \"Temporarily Unavailable\", headers={\"Contact\": \"<sip:x@192.0.2.99>\"})\n",
    );
    let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
    let raw = caller_invite(PLAIN, true);
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw.into_bytes()),
    };
    tokio::task::block_in_place(|| handle_b2bua_invite(inbound, invite, &state));
    for sent in drain(&udp) {
        assert!(
            header(&sent.message, "Contact").is_none_or(|contact| !contact.contains("192.0.2.99")),
            "the script's Contact reached the wire: {:?}",
            sent.message.status_code()
        );
        assert_ne!(sent.message.status_code(), Some(480));
    }
}
