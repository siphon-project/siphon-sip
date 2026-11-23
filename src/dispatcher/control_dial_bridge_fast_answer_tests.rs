//! A phone that answers the moment it is rung: its 100, 180 and 200 all
//! processed before the dial's coordinator has run once.

use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, controller_owning, dial, events, events_through,
    invite_to, register, reinvites_to, sent_until, wait_drained,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_answers_at_once_is_bridged_not_released() {
    const DESK: &str = "198.51.100.191:5060";
    let aor = "sip:bd9241@siphon.example.com";
    register(aor, &format!("sip:bd9241@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-fast@192.0.2.10");
    let controller = controller_owning("bridge-fast", dispatcher, &caller, "caller-fast", "hangup");
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-fast",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let desk = invite_to(&drain(&controller.dispatcher.udp), DESK);
    let contact = format!("sip:bd9241@{DESK}");
    for (code, reason, body) in [
        (100, "Trying", None),
        (180, "Ringing", None),
        (200, "OK", Some(phone_offer("198.51.100.191"))),
    ] {
        phone_sends(
            state,
            socket(DESK),
            &phone_response(&desk, code, reason, "desk-tag", &contact, body.as_deref()),
        );
    }
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, DESK).is_empty()
    })
    .await;
    assert_eq!(reinvites_to(&sent, DESK).len(), 1, "the bridge begins");
    let _ = events(&controller).await;
}

/// RFC 3261 §8.1.3.1: a transport error on a phone's INVITE is a 503 received.
/// The first target's TCP connect is refused (nothing listens on port 1), so a
/// sequential dial moves on to the next phone at once, not at the ring timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_the_transport_cannot_reach_is_hunted_past_at_once() {
    const REFUSED: &str = "sip:bd9243@127.0.0.1:1;transport=tcp";
    const DESK: &str = "198.51.100.193:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-unsent@192.0.2.10");
    let controller = controller_owning(
        "bridge-unsent",
        dispatcher,
        &caller,
        "caller-unsent",
        "hangup",
    );
    let (reply, mut heard) = dial(
        &controller,
        "caller-unsent",
        serde_json::json!({
            "targets": [REFUSED, format!("sip:bd9243@{DESK}")],
            "on_answer": "bridge",
            "strategy": "sequential",
            "timeout": 20,
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Invite).is_empty()
    })
    .await;
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Invite).len(),
        1,
        "the next phone is rung without waiting out the first"
    );
    // The failure is reported while the dial is still being placed, so it may
    // already be queued ahead of the reply.
    if !heard.iter().any(|event| event.event == "DialBranchFailed") {
        heard.extend(events_through(&controller, "DialBranchFailed").await);
    }
    let failed = heard
        .iter()
        .find(|event| event.event == "DialBranchFailed")
        .expect("the unreachable phone's branch failed");
    assert_eq!(failed.payload["cause"], "unsent");
    assert_eq!(failed.payload["code"], 503);
}

/// With no phone left the dial fails at once and says why.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_whose_only_phone_is_unreachable_fails_with_the_cause() {
    const REFUSED: &str = "sip:bd9244@127.0.0.1:1;transport=tcp";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-unsent-only@192.0.2.10");
    let controller = controller_owning(
        "bridge-unsent-only",
        dispatcher,
        &caller,
        "caller-unsent-only",
        "hangup",
    );
    let (reply, mut heard) = dial(
        &controller,
        "caller-unsent-only",
        serde_json::json!({ "targets": [REFUSED], "on_answer": "bridge", "timeout": 20 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    if !heard.iter().any(|event| event.event == "DialFailed") {
        heard.extend(events_through(&controller, "DialFailed").await);
    }
    let failed = heard
        .iter()
        .find(|event| event.event == "DialFailed")
        .expect("DialFailed");
    assert_eq!(failed.payload["code"], 503);
    assert_eq!(failed.payload["branches"][0]["cause"], "unsent");
    wait_drained(&controller.dispatcher.state).await;
}

/// The plain `originate` verb dials through the same path: a transport that
/// refuses the INVITE is answered with an error at once, and nothing is left.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_the_transport_refuses_is_an_error_and_leaves_nothing() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let controller = super::control_originate_tests::controller_on("originate-unsent", dispatcher);
    let baseline = controller.dispatcher.state.call_actors.count();
    let reply = super::control_originate_tests::originate(
        &controller,
        serde_json::json!({
            "channel": "originate-unsent-1",
            "to": "sip:bd9245@127.0.0.1:1;transport=tcp",
            "timeout": 20,
        }),
    )
    .await;
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(
        controller.dispatcher.state.call_actors.count(),
        baseline,
        "the call went with its INVITE"
    );
    assert!(controller
        .bus
        .sip_call_id_for_channel("originate-unsent-1")
        .is_none());
}
