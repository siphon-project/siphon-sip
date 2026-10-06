//! A transfer the controlling application carries out itself: `accept_refer`
//! in mode `controller`, then `complete_refer`.
//!
//! The verbs are driven as a controller's commands reach them — the frame, the
//! command consumer, the SIP adapter — against a dispatcher of the test's own,
//! and what siphon sent the referrer is read off the egress channel. The
//! referrer there is the one party of a call its controller answered; the last
//! tests put it on the callee's side of a two-party call instead, where its
//! dialog has a Call-ID siphon generated.

use super::control_originate_tests::Controller;
use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, caller_sends, command, controller_owning, Caller,
};
use super::dialog_state_events_tests::{header, inbound, wire};
use super::dialog_state_transfer_tests::{
    control_plane, establish, hang_up, in_dialog, parsed_refer_to, Established,
};
use super::originate_test_harness::{drain, socket, Sent};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// Where the transfers in these tests are referred to.
const TARGET: &str = "sip:15550100042@198.51.100.42:5060";

/// An answered caller owned by a controller as channel `channel`.
async fn controlled_caller(name: &str, channel: &str) -> (NativeTestEngine, Caller, Controller) {
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, &format!("{name}@192.0.2.10"));
    let controller = controller_owning(name, dispatcher, &caller, channel, "hangup");
    (engine, caller, controller)
}

/// The caller sends a REFER numbered `cseq` in its dialog, as the dispatcher's
/// B2BUA gate hands one on a controlled call to the control plane. Returns
/// whether it was taken, which it is whenever an application owns the call.
fn caller_refers(controller: &Controller, caller: &Caller, cseq: u32) -> bool {
    let raw = format!(
        concat!(
            "REFER sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {address};branch=z9hG4bK-{call_id}-refer-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} REFER\r\n",
            "Contact: <sip:15550100001@{address}>\r\n",
            "Refer-To: <{target}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        address = caller.address,
        call_id = caller.call_id,
        cseq = cseq,
        from = caller.answer.headers.from().expect("a From"),
        to = caller.answer.headers.to().expect("a To"),
        target = TARGET,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the REFER parses");
    let refer_to = parsed_refer_to(&message);
    let referrer = Referrer {
        call_id: &caller.internal_call_id,
        from_a_leg: true,
        from_tag: Some("caller-tag"),
    };
    tokio::task::block_in_place(|| {
        hold_controlled_refer(
            &controller.bus,
            inbound(&caller.address, &raw),
            message,
            &refer_to,
            &referrer,
            &controller.dispatcher.state,
        )
    })
    .is_none()
}

fn body(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

fn cseq_number(message: &SipMessage) -> u32 {
    header(message, "CSeq")
        .split_whitespace()
        .next()
        .and_then(|number| number.parse().ok())
        .expect("a CSeq number")
}

/// The one message among `sent`, a NOTIFY to the caller that ends the
/// subscription numbered `event_id` with the sipfrag `status_line`.
fn terminating_notify(
    sent: &[Sent],
    caller: &Caller,
    event_id: u32,
    status_line: &str,
) -> SipMessage {
    assert_eq!(sent.len(), 1, "exactly the terminating NOTIFY");
    let notify = &sent[0];
    assert_eq!(notify.destination, socket(&caller.address));
    assert!(notify.is(Method::Notify));
    assert_eq!(header(&notify.message, "Call-ID"), caller.call_id);
    assert_eq!(
        header(&notify.message, "Event"),
        format!("refer;id={event_id}")
    );
    assert!(
        header(&notify.message, "Subscription-State").starts_with("terminated"),
        "the subscription is over"
    );
    assert_eq!(header(&notify.message, "Content-Type"), "message/sipfrag");
    assert_eq!(body(&notify.message), format!("{status_line}\r\n"));
    notify.message.clone()
}

fn assert_refused(reply: &serde_json::Value, code: &str, verb: &str, reason: &str) {
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert_eq!(reply["error"]["details"]["verb"], verb, "{reply}");
    assert_eq!(reply["error"]["details"]["reason"], reason, "{reply}");
}

async fn accept(
    controller: &Controller,
    channel: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    command(controller, "accept_refer", channel, args).await.0
}

async fn complete(
    controller: &Controller,
    channel: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    command(controller, "complete_refer", channel, args).await.0
}

/// THE leak gate: N calls each open a subscription, and each is drained by one
/// of its exits — the application's report, the referrer's BYE, the deadline.
/// The store must return to its baseline `len()`.
#[test]
fn controller_refer_store_drains_to_baseline() {
    let store = ControllerReferStore::default();
    let baseline = store.len();
    assert_eq!(baseline, 0);

    let now = std::time::Instant::now();
    let record = |deadline, referrer_on_a_leg| ControllerRefer {
        referrer_on_a_leg,
        event_id: 2,
        deadline,
    };
    let future = now + std::time::Duration::from_secs(60);
    let past = now - std::time::Duration::from_secs(1);

    for cycle in 0..64 {
        let reported = format!("reported-{cycle}");
        let hung_up = format!("hung-up-{cycle}");
        let timed_out = format!("timed-out-{cycle}");

        assert!(store.insert(&reported, record(future, true)));
        assert!(store.insert(&hung_up, record(future, false)));
        assert!(store.insert(&timed_out, record(past, true)));
        assert_eq!(store.len(), baseline + 3);

        // One subscription per call: a second does not displace the first.
        assert!(!store.insert(&reported, record(past, false)));
        assert_eq!(store.open_for(&reported), Some((true, 2)));
        assert_eq!(store.len(), baseline + 3);

        assert!(store.take(&reported).is_some());
        assert!(store.take(&reported).is_none(), "taken once");
        // A BYE from the other party is not the referrer leaving.
        assert!(store.take_for_leg(&hung_up, true).is_none());
        assert!(store.take_for_leg(&hung_up, false).is_some());
        let expired = store.take_expired(now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].0, timed_out);

        assert_eq!(
            store.len(),
            baseline,
            "store must drain to baseline after cycle {cycle}"
        );
    }
    assert_eq!(store.open_for("reported-0"), None);
    assert!(store.take_expired(now).is_empty());
}

/// Accepted in mode `controller`, a REFER is answered 202 and then notified
/// `100 Trying`, in that order, and nothing is dialled. `complete_refer` then
/// ends the subscription with the status it is given, once.
#[tokio::test(flavor = "multi_thread")]
async fn a_transfer_its_controller_carries_out_is_accepted_then_reported() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-ok", "ctl-ok").await;
    let state = &controller.dispatcher.state;

    assert!(caller_refers(&controller, &caller, 2));
    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "nothing is answered until the application decides"
    );

    let (reply, queued) = command(
        &controller,
        "accept_refer",
        "ctl-ok",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_eq!(
        queued
            .iter()
            .map(|event| event.event.as_str())
            .collect::<Vec<_>>(),
        ["TransferRequested"]
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["transfer"], "accepted");
    assert_eq!(reply["result"]["mode"], "controller");
    assert_eq!(reply["result"]["timeout"], 60);
    assert_eq!(reply["result"]["channel"], "ctl-ok");

    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(sent.len(), 2, "a 202 and a NOTIFY, and no INVITE to anyone");
    assert!(sent
        .iter()
        .all(|frame| frame.destination == socket(&caller.address)));
    let accepted = &sent[0].message;
    assert_eq!(accepted.status_code(), Some(202), "the 202 goes first");
    assert_eq!(header(accepted, "CSeq"), "2 REFER");
    assert!(
        accepted.headers.get("Contact").is_some(),
        "a REFER's 2xx carries a Contact"
    );
    let trying = &sent[1].message;
    assert!(sent[1].is(Method::Notify));
    assert_eq!(header(trying, "Call-ID"), caller.call_id);
    assert_eq!(header(trying, "Event"), "refer;id=2");
    assert_eq!(header(trying, "Subscription-State"), "active;expires=60");
    assert_eq!(header(trying, "Content-Type"), "message/sipfrag");
    assert_eq!(body(trying), "SIP/2.0 100 Trying\r\n");

    assert_eq!(state.pending_inbound_refer.len(), 0, "the REFER is decided");
    assert_eq!(state.controller_refers.len(), 1);
    // What `replace_peer` refuses on is a replacement in flight, read off the
    // call's own subscriptions: this one is not among them.
    let replacement_in_flight = state
        .call_actors
        .get_call(&caller.internal_call_id)
        .map(|call| {
            call.refer_subscriptions
                .iter()
                .any(|subscription| subscription.siphon_notifies)
        });
    assert_eq!(replacement_in_flight, Some(false));

    let reply = complete(&controller, "ctl-ok", serde_json::json!({ "code": 200 })).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["transfer"], "completed");
    assert_eq!(reply["result"]["code"], 200);
    let done = terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        2,
        "SIP/2.0 200 OK",
    );
    assert!(
        cseq_number(&done) > cseq_number(trying),
        "a later request in the same dialog"
    );
    assert_eq!(state.controller_refers.len(), 0, "the record is gone");
    let answered = state
        .call_actors
        .get_call(&caller.internal_call_id)
        .map(|call| call.state == CallState::Answered);
    assert_eq!(answered, Some(true), "reporting moves nobody");
    assert_eq!(state.deferred_referrer_bye.len(), 0);

    // Reported once: a second report has nothing to end.
    let again = complete(&controller, "ctl-ok", serde_json::json!({ "code": 200 })).await;
    assert_refused(
        &again,
        "invalid_state",
        "complete_refer",
        "no_transfer_pending",
    );
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// A transfer that failed is reported with its status: the phrase siphon uses
/// for it when none is given, and the application's own verbatim when one is.
/// The subscription's `expires` is the timeout asked for, capped.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_transfer_is_reported_with_its_status_and_reason() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-busy", "ctl-busy").await;
    let state = &controller.dispatcher.state;

    assert!(caller_refers(&controller, &caller, 2));
    let reply = accept(
        &controller,
        "ctl-busy",
        serde_json::json!({ "mode": "controller", "timeout": 90 }),
    )
    .await;
    assert_eq!(reply["result"]["timeout"], 90, "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(
        header(&sent[1].message, "Subscription-State"),
        "active;expires=90"
    );
    let reply = complete(&controller, "ctl-busy", serde_json::json!({ "code": 486 })).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let busy = terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        2,
        "SIP/2.0 486 Busy Here",
    );
    assert!(cseq_number(&busy) > cseq_number(&sent[1].message));
    assert_eq!(state.controller_refers.len(), 0);

    // The referrer tries again, and this time the application names the reason.
    assert!(caller_refers(&controller, &caller, 3));
    let reply = accept(
        &controller,
        "ctl-busy",
        serde_json::json!({ "mode": "controller", "timeout": 900 }),
    )
    .await;
    assert_eq!(reply["result"]["timeout"], 180, "capped: {reply}");
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(header(&sent[1].message, "Event"), "refer;id=3");
    assert_eq!(
        header(&sent[1].message, "Subscription-State"),
        "active;expires=180"
    );
    let reply = complete(
        &controller,
        "ctl-busy",
        serde_json::json!({ "code": 480, "reason": "Nobody Is Here" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        3,
        "SIP/2.0 480 Nobody Is Here",
    );
    assert_eq!(state.controller_refers.len(), 0);
}

/// An application that never reports: at the deadline the sweep tells the
/// referrer `503` and drops the record. Before it, the sweep does nothing; and
/// a record whose call is gone is dropped with nothing sent.
#[tokio::test(flavor = "multi_thread")]
async fn an_unreported_transfer_is_failed_at_its_deadline() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-late", "ctl-late").await;
    let state = &controller.dispatcher.state;

    assert!(caller_refers(&controller, &caller, 2));
    let reply = accept(
        &controller,
        "ctl-late",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);

    tokio::task::block_in_place(|| check_controller_refer_timeouts(state));
    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "the deadline has not passed"
    );
    assert_eq!(state.controller_refers.len(), 1);

    // The deadline passes, and so does that of a record left behind by a call
    // that ended some other way.
    let past = std::time::Instant::now() - std::time::Duration::from_secs(1);
    state
        .controller_refers
        .entries
        .get_mut(&caller.internal_call_id)
        .expect("the open subscription")
        .deadline = past;
    assert!(state.controller_refers.insert(
        "a-call-that-is-gone",
        ControllerRefer {
            referrer_on_a_leg: false,
            event_id: 7,
            deadline: past,
        },
    ));
    tokio::task::block_in_place(|| check_controller_refer_timeouts(state));
    terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        2,
        "SIP/2.0 503 Service Unavailable",
    );
    assert_eq!(state.controller_refers.len(), 0, "both records are gone");

    let late = complete(&controller, "ctl-late", serde_json::json!({ "code": 200 })).await;
    assert_refused(
        &late,
        "invalid_state",
        "complete_refer",
        "no_transfer_pending",
    );
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// The events queued for the controller since the last look. An event is
/// pushed before the call that raises it returns, so the queue is read as it
/// stands.
async fn queued_events(controller: &Controller) -> Vec<crate::control::EventFrame> {
    if controller.connection.events.depth() == 0 {
        return Vec::new();
    }
    controller
        .connection
        .events
        .recv_many()
        .await
        .into_iter()
        .filter_map(|frame| match frame {
            crate::control::OutboundFrame::Event(event) => Some(event),
            crate::control::OutboundFrame::Reply(_) => None,
        })
        .collect()
}

/// An application that accepted a transfer to carry out and then missed its
/// deadline is told so: siphon reported `503` to the referrer on its behalf,
/// and `TransferTimedOut` on the channel says that, once. A transfer reported
/// in time raises nothing when the sweep next runs.
#[tokio::test(flavor = "multi_thread")]
async fn an_application_that_misses_its_deadline_is_told() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-told", "ctl-told").await;
    let state = &controller.dispatcher.state;
    let sweep =
        || tokio::task::block_in_place(|| expire_controller_refers(Some(&controller.bus), state));

    assert!(caller_refers(&controller, &caller, 2));
    let reply = accept(
        &controller,
        "ctl-told",
        serde_json::json!({ "mode": "controller", "timeout": 30 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);

    sweep();
    assert!(
        queued_events(&controller).await.is_empty(),
        "the deadline has not passed"
    );

    state
        .controller_refers
        .entries
        .get_mut(&caller.internal_call_id)
        .expect("the open subscription")
        .deadline = std::time::Instant::now() - std::time::Duration::from_secs(1);
    sweep();
    terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        2,
        "SIP/2.0 503 Service Unavailable",
    );
    let events = queued_events(&controller).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event.event.as_str())
            .collect::<Vec<_>>(),
        ["TransferTimedOut"]
    );
    assert_eq!(events[0].channel.as_deref(), Some("ctl-told"));
    assert_eq!(events[0].payload["reason"], "timeout");
    assert_eq!(events[0].payload["code"], 503);
    assert_eq!(events[0].payload["referrer_leg"], "a");

    // Told once: the record went with the deadline.
    sweep();
    assert!(queued_events(&controller).await.is_empty());
    assert!(drain(&controller.dispatcher.udp).is_empty());

    // A transfer reported in time is not one that timed out.
    assert!(caller_refers(&controller, &caller, 3));
    let reply = accept(
        &controller,
        "ctl-told",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let reply = complete(&controller, "ctl-told", serde_json::json!({ "code": 200 })).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);
    sweep();
    assert!(queued_events(&controller).await.is_empty());
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// The referrer hangs up before the report: its BYE is answered, the record
/// goes with its dialog, and no NOTIFY follows it there.
#[tokio::test(flavor = "multi_thread")]
async fn a_referrer_that_hangs_up_takes_its_subscription_with_it() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-bye", "ctl-bye").await;
    let state = &controller.dispatcher.state;

    assert!(caller_refers(&controller, &caller, 2));
    let reply = accept(
        &controller,
        "ctl-bye",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);
    assert_eq!(state.controller_refers.len(), 1);

    caller_sends(state, &caller, "BYE", "3 BYE");
    let sent = drain(&controller.dispatcher.udp);
    assert!(
        sent.iter()
            .any(|frame| frame.message.status_code() == Some(200)),
        "the BYE is answered"
    );
    assert!(
        sent.iter().all(|frame| !frame.is(Method::Notify)),
        "nothing is notified in a dialog that is over"
    );
    assert_eq!(state.controller_refers.len(), 0);

    // The call went with its only party, so there is nothing left to report on.
    let reply = complete(&controller, "ctl-bye", serde_json::json!({ "code": 200 })).await;
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], "not_found", "{reply}");
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// While a transfer awaits its report, another REFER on the call is answered
/// 491 and never reaches the application; a retransmission of the accepted one
/// is answered 202 again. Once reported, the call takes a REFER as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_refer_waits_for_the_first_to_be_reported() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-491", "ctl-491").await;
    let state = &controller.dispatcher.state;

    assert!(caller_refers(&controller, &caller, 2));
    let reply = accept(
        &controller,
        "ctl-491",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);

    assert!(caller_refers(&controller, &caller, 3));
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(sent.len(), 1, "exactly the 491");
    assert_eq!(sent[0].message.status_code(), Some(491));
    assert_eq!(header(&sent[0].message, "CSeq"), "3 REFER");
    assert_eq!(state.pending_inbound_refer.len(), 0, "it is not held");

    assert!(caller_refers(&controller, &caller, 2));
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(sent.len(), 1, "exactly the 202, again");
    assert_eq!(sent[0].message.status_code(), Some(202));
    assert_eq!(header(&sent[0].message, "CSeq"), "2 REFER");
    assert_eq!(state.pending_inbound_refer.len(), 0);
    assert_eq!(state.controller_refers.len(), 1, "still the first");

    // Neither was reported to the application: only the report's own reply
    // comes back.
    let (reply, queued) = command(
        &controller,
        "complete_refer",
        "ctl-491",
        serde_json::json!({ "code": 200 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert!(queued.is_empty(), "{queued:?}");
    let _ = drain(&controller.dispatcher.udp);

    // Positive control: with nothing open, a REFER is held for a decision.
    assert!(caller_refers(&controller, &caller, 4));
    assert!(drain(&controller.dispatcher.udp).is_empty());
    assert_eq!(state.pending_inbound_refer.len(), 1);
    assert!(take_held_refer(state, &caller.call_id).is_some());
}

/// Mode `controller` dials nothing, so it refuses every argument describing a
/// leg, and a timeout that is not a whole number of seconds; the other modes
/// refuse a timeout. A refused accept leaves the REFER pending and unanswered.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_mode_accept_refuses_what_it_would_never_use() {
    let (_engine, caller, controller) = controlled_caller("refer-ctl-args", "ctl-args").await;
    let state = &controller.dispatcher.state;
    assert!(caller_refers(&controller, &caller, 2));

    for (name, value) in [
        ("target", serde_json::json!("sip:15550100043@198.51.100.43")),
        ("next_hop", serde_json::json!("sip:198.51.100.44:5060")),
        ("profile", serde_json::json!("rtp_passthrough")),
        ("number_policy", serde_json::json!("trunk")),
        ("format", serde_json::json!("e164")),
        ("from", serde_json::json!("sip:15550100000@example.com")),
        ("from_display", serde_json::json!("Main Line")),
        (
            "p_asserted_identity",
            serde_json::json!("sip:15550100000@example.com"),
        ),
        ("privacy", serde_json::json!("restricted")),
        ("headers", serde_json::json!({ "X-Account": "main" })),
    ] {
        let mut args = serde_json::json!({ "mode": "controller" });
        args[name] = value;
        let reply = accept(&controller, "ctl-args", args).await;
        assert_eq!(reply["error"]["code"], "bad_request", "{name}: {reply}");
        assert_eq!(reply["error"]["details"]["argument"], name, "{reply}");
        assert_eq!(reply["error"]["details"]["reason"], "not_dialled");
    }
    for timeout in [
        serde_json::json!("soon"),
        serde_json::json!(0),
        serde_json::json!(-5),
        serde_json::json!(1.5),
    ] {
        let reply = accept(
            &controller,
            "ctl-args",
            serde_json::json!({ "mode": "controller", "timeout": timeout }),
        )
        .await;
        assert_eq!(reply["error"]["code"], "bad_request", "{timeout}: {reply}");
    }
    let reply = accept(
        &controller,
        "ctl-args",
        serde_json::json!({ "mode": "terminate", "timeout": 30 }),
    )
    .await;
    assert_eq!(reply["error"]["code"], "bad_request", "{reply}");

    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "a refused accept answers nothing"
    );
    assert_eq!(state.pending_inbound_refer.len(), 1, "still pending");
    assert_eq!(state.controller_refers.len(), 0);

    // Positive control: with none of them, the same REFER is accepted.
    let reply = accept(
        &controller,
        "ctl-args",
        serde_json::json!({ "mode": "controller", "timeout": null, "target": null }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(state.controller_refers.len(), 1);
    let _ = drain(&controller.dispatcher.udp);

    // A report needs a final status, and a reason that fits on a status line.
    for args in [
        serde_json::json!({}),
        serde_json::json!({ "code": 199 }),
        serde_json::json!({ "code": 700 }),
        serde_json::json!({ "code": "200" }),
        serde_json::json!({ "code": 200, "reason": 7 }),
        serde_json::json!({ "code": 200, "reason": "  " }),
        serde_json::json!({ "code": 200, "reason": "OK\r\nSubscription-State: active" }),
    ] {
        let reply = complete(&controller, "ctl-args", args.clone()).await;
        assert_eq!(reply["error"]["code"], "bad_request", "{args}: {reply}");
    }
    assert!(drain(&controller.dispatcher.udp).is_empty());
    assert_eq!(
        state.controller_refers.len(),
        1,
        "a refused report ends nothing"
    );
    let reply = complete(&controller, "ctl-args", serde_json::json!({ "code": 603 })).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    terminating_notify(
        &drain(&controller.dispatcher.udp),
        &caller,
        2,
        "SIP/2.0 603 Decline",
    );
}

/// With no REFER pending there is nothing to accept, and on a call that never
/// accepted one in this mode nothing to report.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_transfer_needs_a_refer_to_accept_and_one_accepted_to_report() {
    let (_engine, _caller, controller) = controlled_caller("refer-ctl-none", "ctl-none").await;
    let reply = accept(
        &controller,
        "ctl-none",
        serde_json::json!({ "mode": "controller" }),
    )
    .await;
    assert_refused(&reply, "not_found", "accept_refer", "no_pending_refer");
    let reply = complete(&controller, "ctl-none", serde_json::json!({ "code": 200 })).await;
    assert_refused(
        &reply,
        "invalid_state",
        "complete_refer",
        "no_transfer_pending",
    );
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// The callee of a two-party call refers, and the application holds the REFER.
fn callee_refers(
    call: &Established,
    bus: &crate::control::ControlBus,
    internal_call_id: &str,
    cseq: u32,
) {
    let (raw, message) = in_dialog(
        "REFER",
        call.b.1,
        &format!("{};tag=b-tag", header(&call.to_b, "To")),
        &header(&call.to_b, "From"),
        &header(&call.to_b, "Call-ID"),
        cseq,
        &format!("Refer-To: <{}>\r\n", call.c_uri()),
    );
    let refer_to = parsed_refer_to(&message);
    let taken = hold_controlled_refer(
        bus,
        inbound(call.b.1, &raw),
        message,
        &refer_to,
        &Referrer {
            call_id: internal_call_id,
            from_a_leg: false,
            from_tag: Some("b-tag"),
        },
        &call.dispatcher.state,
    );
    assert!(taken.is_none(), "a controlled call's REFER is held");
}

/// The referrer is the callee, on a dialog of its own: the 202 and both
/// NOTIFYs go to it there, nobody is dialled, the call's two parties stay as
/// they are, and no replacement is recorded against the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_callees_transfer_is_notified_on_its_own_dialog_and_dials_nobody() {
    let call = establish(9400, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let (bus, connection) = control_plane("transfer-9400");
    bus.register_channel(
        "channel-9400",
        &connection,
        &internal_call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let b_call_id = header(&call.to_b, "Call-ID");
    let _ = wire(&call.dispatcher);

    callee_refers(&call, &bus, &internal_call_id, 2);
    let accepted = tokio::task::block_in_place(|| {
        b2bua_accept_refer_controller_with_state(state, &call.a_call_id, None)
    });
    assert_eq!(accepted, Ok(60));
    let sent = wire(&call.dispatcher);
    assert_eq!(sent.len(), 2, "a 202 and a NOTIFY, and no INVITE to anyone");
    assert!(sent.iter().all(|sent| sent.destination == call.b.1));
    assert_eq!(sent[0].message.status_code(), Some(202));
    assert_eq!(sent[1].message.method(), Some(&Method::Notify));
    assert_eq!(header(&sent[1].message, "Call-ID"), b_call_id);
    assert_eq!(header(&sent[1].message, "Event"), "refer;id=2");
    assert_eq!(body(&sent[1].message), "SIP/2.0 100 Trying\r\n");

    let (legs, replacement_in_flight) = state
        .call_actors
        .get_call(&internal_call_id)
        .map(|held| {
            (
                held.b_legs.len(),
                held.refer_subscriptions
                    .iter()
                    .any(|subscription| subscription.siphon_notifies),
            )
        })
        .expect("the call");
    assert_eq!(legs, 1, "no leg was added");
    assert!(
        !replacement_in_flight,
        "replace_peer is not held off by a transfer its controller carries out"
    );
    // Accepting twice is refused: the REFER is no longer pending.
    assert_eq!(
        b2bua_accept_refer_controller_with_state(state, &call.a_call_id, None),
        Err(ControllerReferRefusal::NoPendingRefer)
    );

    let reported = tokio::task::block_in_place(|| {
        b2bua_complete_refer_with_state(state, &call.a_call_id, 200, None)
    });
    assert_eq!(reported, Ok(()));
    let sent = wire(&call.dispatcher);
    assert_eq!(sent.len(), 1, "exactly the terminating NOTIFY");
    assert_eq!(sent[0].destination, call.b.1);
    assert_eq!(header(&sent[0].message, "Call-ID"), b_call_id);
    assert!(header(&sent[0].message, "Subscription-State").starts_with("terminated"));
    assert_eq!(body(&sent[0].message), "SIP/2.0 200 OK\r\n");
    assert_eq!(state.controller_refers.len(), 0);
    assert_eq!(
        state.deferred_referrer_bye.len(),
        0,
        "no BYE is owed anyone"
    );
    assert_eq!(
        b2bua_complete_refer_with_state(state, &call.a_call_id, 200, None),
        Err(ControllerReferRefusal::NoTransferPending)
    );
    assert_eq!(
        b2bua_complete_refer_with_state(state, "no-such-call@192.0.2.9", 200, None),
        Err(ControllerReferRefusal::Gone)
    );
}

/// The callee refers and then hangs up before the report: the record goes with
/// its dialog and it is sent no NOTIFY. A BYE from the other party would not
/// have been the referrer leaving.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_hangs_up_mid_transfer_is_not_notified() {
    let call = establish(9450, "terminate");
    let state = &call.dispatcher.state;
    let internal_call_id = call.call_id();
    let (bus, connection) = control_plane("transfer-9450");
    bus.register_channel(
        "channel-9450",
        &connection,
        &internal_call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    callee_refers(&call, &bus, &internal_call_id, 2);
    assert_eq!(
        tokio::task::block_in_place(|| {
            b2bua_accept_refer_controller_with_state(state, &call.a_call_id, Some(30))
        }),
        Ok(30)
    );
    let _ = wire(&call.dispatcher);

    controller_refer_referrer_left(state, &internal_call_id, true);
    assert_eq!(
        state.controller_refers.len(),
        1,
        "the caller is not the referrer"
    );

    hang_up(
        &call.dispatcher,
        call.b.1,
        &format!("{};tag=b-tag", header(&call.to_b, "To")),
        &header(&call.to_b, "From"),
        &header(&call.to_b, "Call-ID"),
    );
    let sent = wire(&call.dispatcher);
    assert!(
        sent.iter()
            .all(|sent| sent.message.method() != Some(&Method::Notify)),
        "nothing is notified in a dialog that is over"
    );
    assert_eq!(state.controller_refers.len(), 0);
}
