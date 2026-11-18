//! `StasisEnd` for a BYE names the party that sent it.
//!
//! A bridged call ends with a BYE from either side, and the channel's owner
//! needs to tell a caller who gave up from a callee who finished. The BYE's
//! direction is known from its dialog identity (RFC 3261 §12), so the
//! `StasisEnd` carries `initiator` relative to the call the app owns: on a call
//! siphon received, the A leg is the caller; on a call siphon placed
//! (`originate`), siphon is the caller and whoever hangs up is a callee.

use super::dialog_state_events_tests::{
    bye, header, invite_raw, invites, place_call, responds, response_to, script, wire,
};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use crate::control::channel_event_capture;
use crate::sip::message::SipMessage;

const CALLER: &str = "192.0.2.71:5060";
const CALLEE: &str = "198.51.100.71:5060";

/// An answered call from [`CALLER`] to [`CALLEE`]: the internal call id, the
/// 200 the caller got and the INVITE the callee got, answered with To-tag
/// `callee-tag`.
fn answered_call(
    dispatcher: &TestDispatcher,
    sip_call_id: &str,
) -> (String, SipMessage, SipMessage) {
    let raw = invite_raw(
        CALLER,
        sip_call_id,
        "<sip:15550100071@example.com>;tag=caller-tag",
        "sip:15550100072@example.com",
    );
    channel_event_capture::watch(sip_call_id);
    let call_id = place_call(dispatcher, CALLER, &raw);
    let callee_invite = invites(&wire(dispatcher))
        .into_iter()
        .find(|(destination, _)| destination == CALLEE)
        .map(|(_, invite)| invite)
        .expect("the callee was dialled");
    responds(
        dispatcher,
        &call_id,
        CALLEE,
        &callee_invite,
        200,
        "OK",
        "callee-tag",
    );
    let answer = response_to(&wire(dispatcher), CALLER, 200).clone();
    (call_id, answer, callee_invite)
}

/// The single `StasisEnd` captured for `sip_call_id`.
fn stasis_end(sip_call_id: &str) -> serde_json::Value {
    let ends: Vec<_> = channel_event_capture::take(sip_call_id)
        .into_iter()
        .filter(|(event, _)| event == "StasisEnd")
        .map(|(_, payload)| payload)
        .collect();
    assert_eq!(ends.len(), 1, "exactly one StasisEnd: {ends:?}");
    ends.into_iter().next().expect("one StasisEnd")
}

fn dispatcher() -> TestDispatcher {
    test_dispatcher_with_script(&script(&format!("call.dial(\"sip:15550100072@{CALLEE}\")")))
}

/// The caller hangs up a bridged call: `initiator: caller`.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_from_the_caller_is_reported_as_the_callers() {
    let dispatcher = dispatcher();
    let sip_call_id = "initiator-caller@192.0.2.71";
    let (_, answer, _) = answered_call(&dispatcher, sip_call_id);

    bye(
        &dispatcher,
        CALLER,
        &header(&answer, "From"),
        &header(&answer, "To"),
        sip_call_id,
    );

    let payload = stasis_end(sip_call_id);
    assert_eq!(payload["reason"], "bye", "{payload}");
    assert_eq!(payload["initiator"], "caller", "{payload}");
    assert!(payload.get("code").is_none(), "no status was on the wire");
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// The callee hangs up a bridged call: `initiator: callee`, still keyed on the
/// caller's Call-ID, the channel the app owns.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_from_the_callee_is_reported_as_the_callees() {
    let dispatcher = dispatcher();
    let sip_call_id = "initiator-callee@192.0.2.71";
    let (_, _, callee_invite) = answered_call(&dispatcher, sip_call_id);

    bye(
        &dispatcher,
        CALLEE,
        &format!("{};tag=callee-tag", header(&callee_invite, "To")),
        &header(&callee_invite, "From"),
        &header(&callee_invite, "Call-ID"),
    );

    let payload = stasis_end(sip_call_id);
    assert_eq!(payload["reason"], "bye", "{payload}");
    assert_eq!(payload["initiator"], "callee", "{payload}");
    assert_eq!(dispatcher.state.call_actors.count(), 0);
}

/// On a call siphon placed, the A leg is the party siphon called: its BYE is a
/// callee's, never reported as the caller's.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_an_originated_call_is_reported_as_the_callees() {
    let dispatcher = dispatcher();
    let sip_call_id = "initiator-originated@192.0.2.71";
    let (call_id, answer, _) = answered_call(&dispatcher, sip_call_id);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.originated = true;
    }

    bye(
        &dispatcher,
        CALLER,
        &header(&answer, "From"),
        &header(&answer, "To"),
        sip_call_id,
    );

    let payload = stasis_end(sip_call_id);
    assert_eq!(payload["initiator"], "callee", "{payload}");
}
