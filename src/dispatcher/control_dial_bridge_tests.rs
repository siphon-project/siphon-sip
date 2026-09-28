//! The control plane's `dial {on_answer: "bridge"}`: phones rung for a caller
//! a controller already answered and anchored, and the one that picks up
//! bridged to it.
//!
//! Driven the way a controller's command reaches it — the frame, the command
//! consumer, the SIP adapter — against a dispatcher of the test's own whose
//! media is a native engine in the test process. What siphon sent is read off
//! the egress channel, what the controller heard off its event stream, and
//! what the engine was asked to do off the engine's own log.

use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, caller_sends, controller_owning, dial,
    events, eventually, in_dialog_response, invite_to, names, register, reinvites_to, sent_until,
    Caller, CALLER,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::{NativeTestEngine, NATIVE_ENGINE_OFFER};

fn body_text(message: &SipMessage) -> &str {
    std::str::from_utf8(&message.body).expect("a text body")
}

/// The caller is still up, still answered and still its controller's.
fn assert_caller_untouched(
    controller: &super::control_originate_tests::Controller,
    caller: &Caller,
    channel: &str,
) {
    let answered = controller
        .dispatcher
        .state
        .call_actors
        .get_call(&caller.internal_call_id)
        .map(|call| call.state == CallState::Answered);
    assert_eq!(answered, Some(true), "the caller is still answered");
    assert_eq!(
        controller.bus.sip_call_id_for_channel(channel).as_deref(),
        Some(caller.call_id.as_str()),
        "the caller is still its controller's"
    );
}

/// Parallel: every phone rings, nothing reaches the caller, the first to
/// answer is ACKed and the other CANCELled, the controller learns the answered
/// phone's channel, and the bridge re-INVITEs the phone first, then the caller.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_phone_to_answer_is_bridged_to_the_answered_caller() {
    const DESK: &str = "198.51.100.141:5060";
    const MOBILE: &str = "198.51.100.142:5060";
    let aor = "sip:bd3201@siphon.example.com";
    register(aor, &format!("sip:bd3201@{DESK}"), 1.0);
    register(aor, &format!("sip:bd3201@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-win@192.0.2.10");
    crate::control::channel_event_capture::watch(&caller.call_id);
    let controller = controller_owning("bridge-win", dispatcher, &caller, "caller-win", "hangup");
    let state = &controller.dispatcher.state;

    let (reply, queued) = dial(
        &controller,
        "caller-win",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge", "timeout": 20 }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let result = &reply["result"];
    assert_eq!(result["on_answer"], "bridge");
    assert_eq!(result["ringback"], "ringback_eu", "the default ringback");
    assert_eq!(result["strategy"], "parallel");
    assert_eq!(result["branches"].as_array().map(Vec::len), Some(2));
    assert_eq!(names(&queued), ["DialBranch", "DialBranch"]);
    assert!(queued
        .iter()
        .all(|event| event.channel.as_deref() == Some("caller-win")));

    let sent = drain(&controller.dispatcher.udp);
    let desk_invite = invite_to(&sent, DESK);
    let mobile_invite = invite_to(&sent, MOBILE);
    for invite in [&desk_invite, &mobile_invite] {
        assert!(invite.body.is_empty(), "each phone is anchored: offerless");
        assert_eq!(
            invite.headers.to().map(String::as_str),
            Some(format!("<{aor}>").as_str()),
            "each phone is called as the AoR it registered"
        );
        let from = invite.headers.from().expect("a From");
        assert!(
            from.contains("\"Caller One\" <sip:15550100001@siphon.example.com>"),
            "the phones are shown the caller: {from}"
        );
    }
    assert!(
        requests_to(&sent, socket(CALLER), Method::Invite).is_empty()
            && sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "nothing goes to the caller while the phones ring"
    );
    assert!(
        engine.commands("play_media").is_empty(),
        "no ringback before a phone alerts"
    );

    // The mobile alerts: the caller hears ringback, on its own anchor.
    phone_sends(
        state,
        socket(MOBILE),
        &phone_response(
            &mobile_invite,
            180,
            "Ringing",
            "mobile-tag",
            &format!("sip:bd3201@{MOBILE}"),
            None,
        ),
    );
    assert!(eventually(|| engine.commands("play_media").len() == 1).await);
    let plays = engine.commands("play_media");
    assert_eq!(plays[0].call_id, caller.call_id);
    assert_eq!(plays[0].detail.as_deref(), Some("ringback_eu"));
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["PlayStarted"]);
    assert_eq!(heard[0].payload["origin"], "ringback");
    assert_eq!(heard[0].payload["source"], "tone");
    assert!(heard[0].payload["play_id"].is_u64());

    // The mobile answers: ACKed, and the bridge begins with a re-INVITE to it.
    // Its answer is provisional until the bridge forms, so the desk rings on.
    phone_sends(
        state,
        socket(MOBILE),
        &phone_response(
            &mobile_invite,
            200,
            "OK",
            "mobile-tag",
            &format!("sip:bd3201@{MOBILE}"),
            Some(&phone_offer("198.51.100.142")),
        ),
    );
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, MOBILE).is_empty()
    })
    .await;
    assert_eq!(requests_to(&sent, socket(MOBILE), Method::Ack).len(), 1);
    assert!(
        requests_to(&sent, socket(DESK), Method::Cancel).is_empty(),
        "the desk rings on while the mobile's bridge is in motion"
    );
    let offer = reinvites_to(&sent, MOBILE);
    assert_eq!(offer.len(), 1, "the bridge offers the phone first");
    // The engine's relay side, under siphon's own session origin.
    let offered = body_text(&offer[0]);
    for line in ["c=IN IP4 203.0.113.61", "m=audio 52000 RTP/AVP 0 101"] {
        assert!(NATIVE_ENGINE_OFFER.contains(line));
        assert!(offered.contains(line), "the engine's offer: {offered}");
    }
    assert!(
        sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "nothing reaches the caller before the bridge's own re-INVITE"
    );
    // The ringback is stopped, by its own play_id, before the caller's media
    // is re-pointed.
    let stops = engine.commands("stop_media");
    assert_eq!(stops.len(), 1, "the ringback is stopped at the bridge");
    assert_eq!(stops[0].call_id, caller.call_id);
    assert!(stops[0].detail.is_some());
    assert!(
        events(&controller).await.is_empty(),
        "nothing is reported for a provisional answer"
    );

    // The mobile accepts: the caller is re-INVITEd with the engine's answer.
    phone_sends(
        state,
        socket(MOBILE),
        &in_dialog_response(
            &offer[0],
            200,
            "OK",
            &format!("sip:bd3201@{MOBILE}"),
            Some(&phone_offer("198.51.100.142")),
        ),
    );
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, CALLER).is_empty()
    })
    .await;
    let to_caller = reinvites_to(&sent, CALLER);
    assert_eq!(to_caller.len(), 1, "then the caller");
    assert!(
        requests_to(&sent, socket(DESK), Method::Cancel).is_empty(),
        "still ringing until the bridge forms"
    );
    phone_sends(
        state,
        socket(CALLER),
        &in_dialog_response(
            &to_caller[0],
            200,
            "OK",
            "sip:15550100001@192.0.2.10:5060",
            Some(&phone_offer("192.0.2.10")),
        ),
    );
    // Bridged: only now is the desk CANCELled and the mobile reported.
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Cancel).len(),
        1,
        "the desk is CANCELled once the bridge formed"
    );
    assert!(requests_to(&sent, socket(MOBILE), Method::Cancel).is_empty());
    let answered = events(&controller).await;
    assert_eq!(names(&answered), ["DialBranchFailed", "DialAnswered"]);
    assert_eq!(answered[0].payload["target"], format!("sip:bd3201@{DESK}"));
    assert_eq!(answered[0].payload["cause"], "cancelled");
    let winner_channel = answered[1].payload["channel"]
        .as_str()
        .expect("DialAnswered names the phone's channel")
        .to_string();
    assert_eq!(
        answered[1].payload["target"],
        format!("sip:bd3201@{MOBILE}")
    );
    let mobile_call_id = mobile_invite.headers.call_id().cloned().expect("a Call-ID");
    assert_eq!(
        controller.bus.sip_call_id_for_channel(&winner_channel),
        Some(mobile_call_id.clone()),
        "the phone's channel is its call"
    );
    assert!(
        controller
            .bus
            .owned_channels("bridge-win")
            .iter()
            .any(|channel| channel.channel_id == winner_channel),
        "owned by the caller's controller"
    );
    assert!(
        crate::control::channel_event_capture::take(&caller.call_id)
            .iter()
            .any(|(event, _)| event == "ChannelBridged"),
        "the caller is bridged to the phone"
    );
    assert_drained(state);
}

/// Sequential: the next phone is tried when one is busy, and when one rings
/// out; URIs dialled as written are each their own callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_bridge_dial_moves_on_when_a_phone_is_busy_or_rings_out() {
    const FIRST: &str = "198.51.100.151:5060";
    const SECOND: &str = "198.51.100.152:5060";
    const THIRD: &str = "198.51.100.153:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-hunt@192.0.2.10");
    let controller = controller_owning("bridge-hunt", dispatcher, &caller, "caller-hunt", "hangup");
    let state = &controller.dispatcher.state;
    let targets: Vec<String> = [FIRST, SECOND, THIRD]
        .iter()
        .map(|phone| format!("sip:bd3202@{phone}"))
        .collect();

    let (reply, _) = dial(
        &controller,
        "caller-hunt",
        serde_json::json!({
            "targets": targets,
            "on_answer": "bridge",
            "strategy": "sequential",
            "timeout": 5,
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    let first = invite_to(&sent, FIRST);
    assert_eq!(
        first.headers.to().map(String::as_str),
        Some(format!("<sip:bd3202@{FIRST}>").as_str())
    );
    assert!(
        requests_to(&sent, socket(SECOND), Method::Invite).is_empty(),
        "one phone at a time"
    );

    // Busy: the second phone is tried.
    phone_sends(
        state,
        socket(FIRST),
        &phone_response(&first, 486, "Busy Here", "first-tag", &targets[0], None),
    );
    let sent = drain(&controller.dispatcher.udp);
    let second = invite_to(&sent, SECOND);
    assert!(requests_to(&sent, socket(THIRD), Method::Invite).is_empty());

    // It rings out: CANCELled, and the third is tried.
    check_b2bua_answer_timeouts_at(
        state,
        std::time::Instant::now() + std::time::Duration::from_secs(6),
    );
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !requests_to(sent, socket(THIRD), Method::Invite).is_empty()
    })
    .await;
    assert_eq!(requests_to(&sent, socket(SECOND), Method::Cancel).len(), 1);
    let third = invite_to(&sent, THIRD);

    // The last one is busy too: the dial fails, listing all three.
    phone_sends(
        state,
        socket(THIRD),
        &phone_response(&third, 486, "Busy Here", "third-tag", &targets[2], None),
    );
    let heard = events(&controller).await;
    let failed = heard
        .iter()
        .find(|event| event.event == "DialFailed")
        .expect("DialFailed");
    assert_eq!(failed.payload["branches"].as_array().map(Vec::len), Some(3));
    let causes: Vec<_> = heard
        .iter()
        .filter(|event| event.event == "DialBranchFailed")
        .map(|event| {
            event.payload["cause"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    assert_eq!(causes, ["rejected", "timeout", "rejected"]);
    let _ = second;
    assert_caller_untouched(&controller, &caller, "caller-hunt");
    assert_drained(state);
}

/// Nobody answers: the ringback is stopped before the controller hears so,
/// the caller is sent nothing and stays answered and owned — and can be
/// dialled for again.
#[tokio::test(flavor = "multi_thread")]
async fn when_nobody_answers_the_ringback_stops_and_the_caller_stays_up() {
    const DESK: &str = "198.51.100.161:5060";
    const MOBILE: &str = "198.51.100.162:5060";
    let aor = "sip:bd3203@siphon.example.com";
    register(aor, &format!("sip:bd3203@{DESK}"), 1.0);
    register(aor, &format!("sip:bd3203@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-busy@192.0.2.10");
    let controller = controller_owning("bridge-busy", dispatcher, &caller, "caller-busy", "hangup");
    let state = &controller.dispatcher.state;

    let (reply, _) = dial(
        &controller,
        "caller-busy",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    let desk = invite_to(&sent, DESK);
    let mobile = invite_to(&sent, MOBILE);
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &desk,
            180,
            "Ringing",
            "desk-tag",
            &format!("sip:bd3203@{DESK}"),
            None,
        ),
    );
    assert!(eventually(|| engine.commands("play_media").len() == 1).await);
    let _ = events(&controller).await;

    for (phone, invite) in [(DESK, &desk), (MOBILE, &mobile)] {
        phone_sends(
            state,
            socket(phone),
            &phone_response(
                invite,
                486,
                "Busy Here",
                "busy",
                &format!("sip:bd3203@{phone}"),
                None,
            ),
        );
    }
    let heard = events(&controller).await;
    assert_eq!(
        names(&heard),
        ["DialBranchFailed", "DialBranchFailed", "DialFailed"]
    );
    let failed = &heard[2].payload;
    assert_eq!(failed["code"], 486);
    assert_eq!(failed["reason"], "Busy Here");
    assert_eq!(failed["cause"], "rejected");
    assert_eq!(failed["timed_out"], false);
    assert_eq!(failed["branches"].as_array().map(Vec::len), Some(2));
    // Stopped before DialFailed went out, and only the ringback: the stop names
    // the play it started.
    let play_id = engine.commands("play_media")[0].call_id.clone();
    assert_eq!(play_id, caller.call_id);
    let stops = engine.commands("stop_media");
    assert_eq!(stops.len(), 1, "the ringback is stopped");
    assert!(
        stops[0].detail.is_some(),
        "a targeted stop of the ringback alone"
    );

    assert!(
        drain(&controller.dispatcher.udp)
            .iter()
            .all(|frame| frame.destination != socket(CALLER)),
        "nothing is sent to the caller"
    );
    assert_caller_untouched(&controller, &caller, "caller-busy");
    assert_drained(state);

    // Positive control: the caller can be dialled for again.
    let (again, _) = dial(
        &controller,
        "caller-busy",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(again["status"], "ok", "{again}");
}

/// The caller hangs up while the phones ring: every phone is CANCELled, the
/// controller hears DialFailed before the StasisEnd, and nothing is kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_hangs_up_while_the_phones_ring_cancels_every_phone() {
    const DESK: &str = "198.51.100.171:5060";
    const MOBILE: &str = "198.51.100.172:5060";
    let aor = "sip:bd3204@siphon.example.com";
    register(aor, &format!("sip:bd3204@{DESK}"), 1.0);
    register(aor, &format!("sip:bd3204@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-gone@192.0.2.10");
    let controller = controller_owning("bridge-gone", dispatcher, &caller, "caller-gone", "hangup");
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-gone",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    let desk = invite_to(&sent, DESK);
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &desk,
            180,
            "Ringing",
            "desk-tag",
            &format!("sip:bd3204@{DESK}"),
            None,
        ),
    );
    assert!(eventually(|| engine.commands("play_media").len() == 1).await);
    let _ = events(&controller).await;
    assert_eq!(state.dial_bridges.ringing_count(), 1);

    caller_sends(state, &caller, "BYE", "2 BYE");
    let sent = drain(&controller.dispatcher.udp);
    for phone in [DESK, MOBILE] {
        assert_eq!(
            requests_to(&sent, socket(phone), Method::Cancel).len(),
            1,
            "{phone} is CANCELled"
        );
    }
    assert!(
        sent.iter()
            .any(|frame| frame.destination == socket(CALLER)
                && frame.message.status_code() == Some(200)),
        "the caller's BYE is answered"
    );
    // Published while the teardown runs, before the StasisEnd it ends in (that
    // goes to the process's control plane, which this test does not install).
    let heard = events(&controller).await;
    assert_eq!(
        names(&heard),
        ["DialBranchFailed", "DialBranchFailed", "DialFailed"]
    );
    assert_eq!(heard[2].payload["cause"], "caller_hangup");
    assert_eq!(heard[2].payload["code"], 487);
    assert_drained(state);
    assert_eq!(state.dial_bridges.ringback_count(), 0);
    assert!(
        state
            .call_actors
            .get_call(&caller.internal_call_id)
            .is_none(),
        "the caller is gone"
    );
    // The ringback was not stopped: the caller's media went with it.
    assert!(engine.commands("stop_media").is_empty());
}

/// The same when siphon ends the caller itself — a controller's `hangup`, a
/// control-loss policy, a session timer: every teardown of an answered call.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_siphon_hangs_up_while_the_phones_ring_cancels_every_phone() {
    const DESK: &str = "198.51.100.173:5060";
    let aor = "sip:bd3205@siphon.example.com";
    register(aor, &format!("sip:bd3205@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-ended@192.0.2.10");
    let controller = controller_owning(
        "bridge-ended",
        dispatcher,
        &caller,
        "caller-ended",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-ended",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    drain(&controller.dispatcher.udp);

    assert!(b2bua_terminate_call_inner(
        &caller.internal_call_id,
        None,
        "b2bua",
        state
    ));
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(DESK), Method::Cancel).len(), 1);
    assert_eq!(
        requests_to(&sent, socket(CALLER), Method::Bye).len(),
        1,
        "positive control: the caller itself is BYEd"
    );
    assert_drained(state);
}

/// A phone that answered but whose bridge fails is not left up with nobody on
/// it: it is hung up, the controller hears BridgeFailed, and the caller stays
/// answered and owned for the controller to decide on.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_whose_bridge_fails_is_hung_up_and_the_caller_kept() {
    const DESK: &str = "198.51.100.181:5060";
    let aor = "sip:bd3206@siphon.example.com";
    register(aor, &format!("sip:bd3206@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-refused@192.0.2.10");
    crate::control::channel_event_capture::watch(&caller.call_id);
    let controller = controller_owning(
        "bridge-refused",
        dispatcher,
        &caller,
        "caller-refused",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-refused",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let desk = invite_to(&drain(&controller.dispatcher.udp), DESK);
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &desk,
            200,
            "OK",
            "desk-tag",
            &format!("sip:bd3206@{DESK}"),
            Some(&phone_offer("198.51.100.181")),
        ),
    );
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, DESK).is_empty()
    })
    .await;
    let offer = reinvites_to(&sent, DESK);
    assert_eq!(offer.len(), 1);
    // The phone refuses the bridge's re-INVITE.
    phone_sends(
        state,
        socket(DESK),
        &in_dialog_response(
            &offer[0],
            488,
            "Not Acceptable Here",
            &format!("sip:bd3206@{DESK}"),
            None,
        ),
    );
    let sent = drain(&controller.dispatcher.udp);
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Bye).len(),
        1,
        "the phone is released"
    );
    assert!(
        requests_to(&sent, socket(CALLER), Method::Bye).is_empty(),
        "the caller is not"
    );
    assert!(crate::control::channel_event_capture::take(&caller.call_id)
        .iter()
        .any(|(event, payload)| event == "BridgeFailed" && payload["code"] == 488));
    // With no other phone to fall back on, the dial fails; the phone that
    // answered was never kept, so it is never reported as DialAnswered.
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["DialBranchFailed", "DialFailed"]);
    assert_eq!(heard[0].payload["cause"], "bridge_failed");
    assert_eq!(heard[0].payload["code"], 488);
    assert_eq!(heard[1].payload["cause"], "bridge_failed");
    assert_caller_untouched(&controller, &caller, "caller-refused");
    assert_drained(state);
}

/// The same when the bridge cannot even start — here the caller is mid
/// re-INVITE (RFC 3261 §14.1 glare): BridgeFailed on the caller's channel
/// comes from the dial, and the phone is released.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_whose_bridge_cannot_start_is_hung_up_and_the_caller_kept() {
    const DESK: &str = "198.51.100.182:5060";
    let aor = "sip:bd3207@siphon.example.com";
    register(aor, &format!("sip:bd3207@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "bridge-glare@192.0.2.10");
    let controller = controller_owning(
        "bridge-glare",
        dispatcher,
        &caller,
        "caller-glare",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-glare",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge", "ringback": false }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let desk = invite_to(&drain(&controller.dispatcher.udp), DESK);
    let _ = events(&controller).await;
    // A re-INVITE of the caller's own is in flight.
    assert!(!state
        .call_actors
        .set_pending_reinvite(&caller.internal_call_id, true, true));
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &desk,
            200,
            "OK",
            "desk-tag",
            &format!("sip:bd3207@{DESK}"),
            Some(&phone_offer("198.51.100.182")),
        ),
    );
    let sent = sent_until(&controller.dispatcher.udp, |sent| {
        !requests_to(sent, socket(DESK), Method::Bye).is_empty()
    })
    .await;
    assert_eq!(
        requests_to(&sent, socket(DESK), Method::Bye).len(),
        1,
        "the phone is released"
    );
    assert!(
        reinvites_to(&sent, DESK).is_empty(),
        "no bridge was offered"
    );
    let bye = requests_to(&sent, socket(DESK), Method::Bye);
    assert!(bye[0]
        .message
        .headers
        .get("Reason")
        .is_some_and(|reason| reason.contains("cause=41")));
    let heard = events(&controller).await;
    let failed = heard
        .iter()
        .find(|event| {
            event.event == "BridgeFailed" && event.channel.as_deref() == Some("caller-glare")
        })
        .expect("BridgeFailed on the caller's channel");
    assert_eq!(failed.payload["stage"], "setup");
    assert_eq!(
        names(&heard),
        ["BridgeFailed", "DialBranchFailed", "DialFailed"],
        "a phone never bridged is never reported as DialAnswered"
    );
    assert_eq!(heard[1].payload["cause"], "bridge_failed");
    assert!(
        requests_to(&sent, socket(CALLER), Method::Bye).is_empty(),
        "the caller is kept"
    );
    assert_caller_untouched(&controller, &caller, "caller-glare");
    assert_drained(state);
}

/// Per-module leak gate: after a batch of complete bridge dials — a phone
/// answering and being bridged, every phone busy, the caller hanging up while
/// they ring — the dial store, the group store and the call store are back
/// where they started.
#[tokio::test(flavor = "multi_thread")]
async fn the_bridge_dial_stores_drain_after_complete_dials() {
    const DESK: &str = "198.51.100.191:5060";
    const MOBILE: &str = "198.51.100.192:5060";
    let aor = "sip:bd3299@siphon.example.com";
    register(aor, &format!("sip:bd3299@{DESK}"), 1.0);
    register(aor, &format!("sip:bd3299@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let controller =
        super::control_originate_tests::controller_on("bridge-leak", bridging_dispatcher(&engine));
    let state = &controller.dispatcher.state;
    let baseline_calls = state.call_actors.count();
    let baseline_groups = state.originate_groups.group_count();
    let dial_args = serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" });

    for round in 0..8 {
        // A win, bridged, then the caller hangs up (the phone goes with it).
        let caller = answered_caller(
            &controller.dispatcher,
            &format!("bridge-leak-w{round}@192.0.2.10"),
        );
        register_caller(&controller, &caller, &format!("leak-w{round}"));
        let (reply, _) = dial(&controller, &format!("leak-w{round}"), dial_args.clone()).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let sent = drain(&controller.dispatcher.udp);
        let mobile = invite_to(&sent, MOBILE);
        phone_sends(
            state,
            socket(MOBILE),
            &phone_response(
                &mobile,
                180,
                "Ringing",
                &format!("m{round}"),
                &format!("sip:bd3299@{MOBILE}"),
                None,
            ),
        );
        phone_sends(
            state,
            socket(MOBILE),
            &phone_response(
                &mobile,
                200,
                "OK",
                &format!("m{round}"),
                &format!("sip:bd3299@{MOBILE}"),
                Some(&phone_offer("198.51.100.192")),
            ),
        );
        let sent = sent_until(&controller.dispatcher.udp, |sent| {
            !reinvites_to(sent, MOBILE).is_empty()
        })
        .await;
        let offer = reinvites_to(&sent, MOBILE);
        phone_sends(
            state,
            socket(MOBILE),
            &in_dialog_response(
                &offer[0],
                200,
                "OK",
                &format!("sip:bd3299@{MOBILE}"),
                Some(&phone_offer("198.51.100.192")),
            ),
        );
        let sent = sent_until(&controller.dispatcher.udp, |sent| {
            !reinvites_to(sent, CALLER).is_empty()
        })
        .await;
        let to_caller = reinvites_to(&sent, CALLER);
        phone_sends(
            state,
            socket(CALLER),
            &in_dialog_response(
                &to_caller[0],
                200,
                "OK",
                "sip:15550100001@192.0.2.10:5060",
                Some(&phone_offer("192.0.2.10")),
            ),
        );
        caller_sends(state, &caller, "BYE", "3 BYE");
        drain(&controller.dispatcher.udp);

        // The mobile answers and refuses its bridge, the desk answers as a
        // standby meanwhile and is bridged; then the caller hangs up.
        let caller = answered_caller(
            &controller.dispatcher,
            &format!("bridge-leak-s{round}@192.0.2.10"),
        );
        register_caller(&controller, &caller, &format!("leak-s{round}"));
        let (reply, _) = dial(&controller, &format!("leak-s{round}"), dial_args.clone()).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let sent = drain(&controller.dispatcher.udp);
        let (desk, mobile) = (invite_to(&sent, DESK), invite_to(&sent, MOBILE));
        for (phone, invite, host) in [
            (MOBILE, &mobile, "198.51.100.192"),
            (DESK, &desk, "198.51.100.191"),
        ] {
            phone_sends(
                state,
                socket(phone),
                &phone_response(
                    invite,
                    200,
                    "OK",
                    &format!("s{round}"),
                    &format!("sip:bd3299@{phone}"),
                    Some(&phone_offer(host)),
                ),
            );
        }
        let sent = sent_until(&controller.dispatcher.udp, |sent| {
            !reinvites_to(sent, MOBILE).is_empty()
        })
        .await;
        let offer = reinvites_to(&sent, MOBILE);
        phone_sends(
            state,
            socket(MOBILE),
            &in_dialog_response(
                &offer[0],
                488,
                "Not Acceptable Here",
                &format!("sip:bd3299@{MOBILE}"),
                None,
            ),
        );
        let sent = sent_until(&controller.dispatcher.udp, |sent| {
            !reinvites_to(sent, DESK).is_empty()
        })
        .await;
        let offer = reinvites_to(&sent, DESK);
        phone_sends(
            state,
            socket(DESK),
            &in_dialog_response(
                &offer[0],
                200,
                "OK",
                &format!("sip:bd3299@{DESK}"),
                Some(&phone_offer("198.51.100.191")),
            ),
        );
        let sent = sent_until(&controller.dispatcher.udp, |sent| {
            !reinvites_to(sent, CALLER).is_empty()
        })
        .await;
        let to_caller = reinvites_to(&sent, CALLER);
        phone_sends(
            state,
            socket(CALLER),
            &in_dialog_response(
                &to_caller[0],
                200,
                "OK",
                "sip:15550100001@192.0.2.10:5060",
                Some(&phone_offer("192.0.2.10")),
            ),
        );
        caller_sends(state, &caller, "BYE", "3 BYE");
        drain(&controller.dispatcher.udp);

        // Every phone busy, then the caller is ended.
        let caller = answered_caller(
            &controller.dispatcher,
            &format!("bridge-leak-f{round}@192.0.2.10"),
        );
        register_caller(&controller, &caller, &format!("leak-f{round}"));
        let (reply, _) = dial(&controller, &format!("leak-f{round}"), dial_args.clone()).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let sent = drain(&controller.dispatcher.udp);
        for phone in [DESK, MOBILE] {
            let invite = invite_to(&sent, phone);
            phone_sends(
                state,
                socket(phone),
                &phone_response(
                    &invite,
                    486,
                    "Busy Here",
                    "busy",
                    &format!("sip:bd3299@{phone}"),
                    None,
                ),
            );
        }
        assert!(eventually(|| !state.dial_bridges.is_ringing(&caller.call_id)).await);
        assert!(b2bua_terminate_call_inner(
            &caller.internal_call_id,
            None,
            "b2bua",
            state
        ));
        drain(&controller.dispatcher.udp);

        // The caller hangs up while the phones ring.
        let caller = answered_caller(
            &controller.dispatcher,
            &format!("bridge-leak-c{round}@192.0.2.10"),
        );
        register_caller(&controller, &caller, &format!("leak-c{round}"));
        let (reply, _) = dial(&controller, &format!("leak-c{round}"), dial_args.clone()).await;
        assert_eq!(reply["status"], "ok", "{reply}");
        drain(&controller.dispatcher.udp);
        caller_sends(state, &caller, "BYE", "2 BYE");
        drain(&controller.dispatcher.udp);
        let _ = events(&controller).await;
    }

    assert!(eventually(|| state.dial_bridges.ringing_count() == 0).await);
    assert_eq!(state.originate_groups.group_count(), baseline_groups);
    assert_drained(state);
    assert_eq!(
        state.dial_bridges.ringback_count(),
        0,
        "a ringback record leaked"
    );
    assert_eq!(
        state.call_actors.count(),
        baseline_calls,
        "every caller's and every phone's call is gone"
    );
}

/// Own `caller` under `channel` on the controller's connection.
fn register_caller(
    controller: &super::control_originate_tests::Controller,
    caller: &Caller,
    channel: &str,
) {
    controller.bus.register_channel(
        channel,
        &controller.connection,
        &caller.internal_call_id,
        &caller.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
}
