//! RFC 3261 §9.1 for an INVITE siphon placed itself, with `originate`, an
//! originate group or a bridging `dial`: giving up on one the far end has not
//! answered at all sends no CANCEL until that far end's first provisional.
//!
//! Driven as a controller's commands reach it, with the fixtures of
//! [`super::cancel_awaits_provisional_tests`]: what the controller hears is
//! checked to come at once, and what siphon sends the phone is read off the
//! egress channel afterwards.

use super::cancel_awaits_provisional_tests::{
    assert_no_cancel, branch_of, phone_answers, the_cancel, until_invite_retransmitted, wire_until,
};
use super::control_cancel_dial_tests::through_dial_failed;
use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, command, controller_owning, dial,
    invite_to, names, register,
};
use super::originate_test_harness::{drain, phone_offer, requests_to, socket};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Fire the expiry of every branch kept answerable, as its timer does once the
/// far end's own transaction has run out, and assert nothing is left.
fn assert_released_at_expiry(state: &DispatcherState, branch: &str) {
    assert_eq!(
        state.call_actors.deferred_cancel_count(),
        0,
        "no CANCEL is still owed"
    );
    state.call_actors.expire_cancelled_branch(
        branch,
        tokio::time::Instant::now() + crate::b2bua::actor::CANCELLED_BRANCH_LIFETIME,
    );
    assert_eq!(
        state.call_actors.cancelled_branch_count(),
        0,
        "the branch kept answerable is released"
    );
    assert!(
        state.b2bua_retransmits.is_empty(),
        "nothing is left retransmitting"
    );
}

/// A bridging dial rung for an answered caller, to one phone that has said
/// nothing, and cancelled by its controller. Returns the controller and the
/// INVITE the phone was sent.
async fn cancelled_bridge_dial_to_a_silent_phone(
    name: &str,
    phone: &str,
) -> (
    super::control_originate_tests::Controller,
    NativeTestEngine,
    SipMessage,
) {
    let aor = format!("sip:{name}@siphon.example.com");
    register(&aor, &format!("sip:{name}@{phone}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, &format!("{name}@192.0.2.10"));
    let controller = controller_owning(name, dispatcher, &caller, name, "hangup");
    let (reply, _) = dial(
        &controller,
        name,
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge", "timeout": 60 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = invite_to(&drain(&controller.dispatcher.udp), phone);

    let (reply, queued) = command(&controller, "cancel_dial", name, serde_json::json!({})).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["state"], "cancelled");
    // What the controller is told does not wait for the phone.
    let heard = through_dial_failed(&controller, queued);
    assert_eq!(names(&heard), ["DialBranchFailed", "DialFailed"]);
    assert_eq!(heard[0].payload["code"], 487);
    assert_eq!(heard[0].payload["cause"], "cancelled");
    assert_eq!(heard[1].payload["code"], 487);
    assert_drained(&controller.dispatcher.state);
    (controller, engine, invite)
}

/// The dial is given up on with the phone silent: the INVITE retransmits and
/// no CANCEL goes out. The phone's late 180 draws the CANCEL, and the 487 that
/// answers the INVITE is ACKed.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_bridge_dial_cancels_a_silent_phone_on_its_first_provisional() {
    const PHONE: &str = "198.51.100.191:5060";
    let (controller, _engine, invite) =
        cancelled_bridge_dial_to_a_silent_phone("cw5501", PHONE).await;
    let dispatcher = &controller.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&invite);

    let sent = until_invite_retransmitted(dispatcher, PHONE, &branch).await;
    assert_no_cancel(&sent, PHONE);
    assert_eq!(state.call_actors.deferred_cancel_count(), 1);

    phone_answers(state, PHONE, &invite, 180, "Ringing", None);
    let sent = drain(&dispatcher.udp);
    let cancel = the_cancel(&sent, PHONE, &invite);
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);

    phone_answers(state, PHONE, &cancel, 200, "OK", None);
    phone_answers(state, PHONE, &invite, 487, "Request Terminated", None);
    let sent = wire_until(dispatcher, |_| true).await;
    let acks = requests_to(&sent, socket(PHONE), Method::Ack);
    assert_eq!(acks.len(), 1, "the 487 is ACKed (RFC 3261 §17.1.1.3)");
    assert_eq!(branch_of(&acks[0].message), branch);
    assert!(
        requests_to(&sent, socket(PHONE), Method::Invite).is_empty()
            && requests_to(&sent, socket(PHONE), Method::Cancel).is_empty(),
        "nothing retransmits once the INVITE and its CANCEL are answered"
    );
    assert_released_at_expiry(state, &branch);
}

/// A 100 Trying is a provisional too: it draws the CANCEL.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_100_trying_draws_the_cancel() {
    const PHONE: &str = "198.51.100.192:5060";
    let (controller, _engine, invite) =
        cancelled_bridge_dial_to_a_silent_phone("cw5502", PHONE).await;
    let dispatcher = &controller.dispatcher;
    assert_no_cancel(&drain(&dispatcher.udp), PHONE);

    phone_answers(&dispatcher.state, PHONE, &invite, 100, "Trying", None);
    the_cancel(&drain(&dispatcher.udp), PHONE, &invite);
}

/// The phone answers instead: its 2xx is ACKed and the dialog released with a
/// BYE (RFC 3261 §13.2.2.4, §15). No CANCEL is ever sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_2xx_to_a_cancelled_dial_is_acked_and_released_without_a_cancel() {
    const PHONE: &str = "198.51.100.193:5060";
    let (controller, _engine, invite) =
        cancelled_bridge_dial_to_a_silent_phone("cw5503", PHONE).await;
    let dispatcher = &controller.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&invite);
    let mut sent = until_invite_retransmitted(dispatcher, PHONE, &branch).await;

    phone_answers(
        state,
        PHONE,
        &invite,
        200,
        "OK",
        Some(&phone_offer("198.51.100.193")),
    );
    sent.extend(drain(&dispatcher.udp));
    assert_no_cancel(&sent, PHONE);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Bye).len(), 1);
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);

    // A provisional that straggles in behind the final draws nothing.
    phone_answers(state, PHONE, &invite, 180, "Ringing", None);
    assert_no_cancel(&drain(&dispatcher.udp), PHONE);

    // The BYE is the phone's to answer; its schedule goes with that answer.
    let bye = requests_to(&sent, socket(PHONE), Method::Bye)[0]
        .message
        .clone();
    phone_answers(state, PHONE, &bye, 200, "OK", None);
    assert_released_at_expiry(state, &branch);
}

/// The phone declines instead: its final response is ACKed and nothing else is
/// sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_failure_to_a_cancelled_dial_is_acked_and_nothing_else() {
    const PHONE: &str = "198.51.100.194:5060";
    let (controller, _engine, invite) =
        cancelled_bridge_dial_to_a_silent_phone("cw5504", PHONE).await;
    let dispatcher = &controller.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&invite);
    let _ = drain(&dispatcher.udp);

    phone_answers(state, PHONE, &invite, 486, "Busy Here", None);
    let sent = wire_until(dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK and nothing else: {sent:?}");
    assert!(sent[0].is(Method::Ack));
    assert_eq!(branch_of(&sent[0].message), branch);
    assert_released_at_expiry(state, &branch);
}

/// The phone never says anything: the INVITE retransmits to Timer B and no
/// CANCEL is ever sent, not for a provisional that turns up after it either.
/// A 2xx that turns up after it is ACKed and released with a BYE, and the
/// branch is released at its expiry.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_dial_to_a_phone_that_never_responds_ends_at_timer_b_without_a_cancel() {
    const PHONE: &str = "198.51.100.195:5060";
    let (controller, _engine, invite) =
        cancelled_bridge_dial_to_a_silent_phone("cw5505", PHONE).await;
    let dispatcher = &controller.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&invite);
    let sent = until_invite_retransmitted(dispatcher, PHONE, &branch).await;
    assert_no_cancel(&sent, PHONE);
    assert_eq!(state.call_actors.cancelled_branch_count(), 1);

    super::timers::sweep_b2bua_retransmits_at(
        state,
        std::time::Instant::now() + state.b2bua_retransmits.transaction_timeout(),
    );
    assert_no_cancel(&drain(&dispatcher.udp), PHONE);
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);
    assert_eq!(
        state.call_actors.cancelled_branch_count(),
        1,
        "still answerable, for a final response that turns up late"
    );
    assert!(state.b2bua_retransmits.is_empty());

    // The transaction is over: a provisional after it draws no CANCEL.
    phone_answers(state, PHONE, &invite, 180, "Ringing", None);
    assert_no_cancel(&drain(&dispatcher.udp), PHONE);

    // A 2xx after it created a dialog all the same: ACKed, and released.
    phone_answers(
        state,
        PHONE,
        &invite,
        200,
        "OK",
        Some(&phone_offer("198.51.100.195")),
    );
    let sent = wire_until(dispatcher, |sent| {
        !requests_to(sent, socket(PHONE), Method::Bye).is_empty()
    })
    .await;
    assert_no_cancel(&sent, PHONE);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    let byes = requests_to(&sent, socket(PHONE), Method::Bye);
    assert_eq!(byes.len(), 1);
    // The BYE is the phone's to answer; its schedule goes with that answer.
    phone_answers(state, PHONE, &byes[0].message.clone(), 200, "OK", None);
    assert_released_at_expiry(state, &branch);
}
