//! The control plane's `cancel_dial`: a controller giving up on a dial that
//! still rings, with the caller left exactly as the dial found it.
//!
//! Driven as a controller's command reaches it — the frame, the command
//! consumer, the SIP adapter — against a dispatcher of the test's own. What
//! siphon sent is read off the egress channel and what the controller heard
//! off its event stream.

use super::dial_bridge_test_harness::{
    answered_caller, assert_drained, bridging_dispatcher, command, controller_owning, dial,
    events_through, invite_to, names, register, reinvites_to, sent_until, CALLER,
};
use super::originate_test_harness::{
    drain, phone_offer, phone_response, phone_sends, phone_tries, requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// The events an accepted cancel produced, which are all queued ahead of its
/// reply: `queued`, as [`command`] returned it.
///
/// The reply to a `cancel_dial` is held until the dial is over, so by the time
/// it is read the dial's `DialFailed` has been published and the caller is let
/// go of. Nothing is waited for here.
pub(super) fn through_dial_failed(
    controller: &super::control_originate_tests::Controller,
    queued: Vec<crate::control::EventFrame>,
) -> Vec<crate::control::EventFrame> {
    assert_eq!(
        queued.last().map(|event| event.event.as_str()),
        Some("DialFailed"),
        "the dial's DialFailed precedes the reply to its cancel: {:?}",
        names(&queued)
    );
    assert_eq!(
        controller.dispatcher.state.dial_bridges.ringing_count(),
        0,
        "the cancelled dial has let go of its caller"
    );
    queued
}

fn assert_refused(reply: &serde_json::Value, code: &str, reason: &str) {
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert_eq!(reply["error"]["details"]["verb"], "cancel_dial", "{reply}");
    assert_eq!(reply["error"]["details"]["reason"], reason, "{reply}");
}

/// Both phones ring, one alerts so the caller hears ringback, and the
/// controller cancels: every phone is CANCELled, the ringback stops, the dial
/// fails 487 with the controller's reason, and the caller is still answered,
/// still owned, and can be dialled for again.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_bridge_dial_cancels_every_phone_and_keeps_the_caller() {
    const DESK: &str = "198.51.100.181:5060";
    const MOBILE: &str = "198.51.100.182:5060";
    let aor = "sip:cd4401@siphon.example.com";
    register(aor, &format!("sip:cd4401@{DESK}"), 1.0);
    register(aor, &format!("sip:cd4401@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-ring@192.0.2.10");
    let controller = controller_owning("cancel-ring", dispatcher, &caller, "caller-ring", "hangup");
    let state = &controller.dispatcher.state;

    let (reply, _) = dial(
        &controller,
        "caller-ring",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge", "timeout": 60 }),
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
            &format!("sip:cd4401@{DESK}"),
            None,
        ),
    );
    // The mobile holds its INVITE without alerting yet: a 100 Trying is the
    // provisional its CANCEL has to wait for (RFC 3261 §9.1).
    phone_tries(state, MOBILE, &invite_to(&sent, MOBILE));
    // The ringback is started by the dial's own task: waited for by its event.
    let started = events_through(&controller, "PlayStarted").await;
    assert_eq!(
        started.last().map(|event| &event.payload["origin"]),
        Some(&serde_json::json!("ringback"))
    );
    assert_eq!(engine.commands("play_media").len(), 1);

    let (reply, queued) = command(
        &controller,
        "cancel_dial",
        "caller-ring",
        serde_json::json!({ "reason": "gave_up" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["state"], "cancelled");
    assert_eq!(reply["result"]["on_answer"], "bridge");
    assert_eq!(reply["result"]["channel"], "caller-ring");

    let sent = drain(&controller.dispatcher.udp);
    for phone in [DESK, MOBILE] {
        assert_eq!(
            requests_to(&sent, socket(phone), Method::Cancel).len(),
            1,
            "{phone} is CANCELled"
        );
    }
    assert!(
        sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "nothing is sent to the caller"
    );

    let heard = through_dial_failed(&controller, queued);
    assert_eq!(
        names(&heard),
        ["DialBranchFailed", "DialBranchFailed", "DialFailed"]
    );
    for branch in &heard[..2] {
        assert_eq!(branch.payload["cause"], "cancelled");
        assert_eq!(branch.payload["code"], 487);
    }
    let failed = &heard[2].payload;
    assert_eq!(failed["code"], 487);
    assert_eq!(failed["reason"], "Request Terminated");
    assert_eq!(failed["cause"], "gave_up");
    assert_eq!(failed["timed_out"], false);
    assert_eq!(failed["branches"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        engine.commands("stop_media").len(),
        1,
        "the ringback is stopped before the controller hears the dial failed"
    );

    let answered = state
        .call_actors
        .get_call(&caller.internal_call_id)
        .map(|call| call.state == CallState::Answered);
    assert_eq!(answered, Some(true), "the caller is still answered");
    assert_eq!(
        controller
            .bus
            .sip_call_id_for_channel("caller-ring")
            .as_deref(),
        Some(caller.call_id.as_str()),
        "the caller is still its controller's"
    );
    assert_drained(state);

    // Positive control: with nothing ringing a second cancel has nothing to act
    // on, and the caller can be dialled for again.
    let (again, _) = command(
        &controller,
        "cancel_dial",
        "caller-ring",
        serde_json::json!({}),
    )
    .await;
    assert_refused(&again, "invalid_state", "no_dial_in_progress");
    let (redial, _) = dial(
        &controller,
        "caller-ring",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(redial["status"], "ok", "{redial}");
}

/// With no reason given the dial fails with cause `cancelled`, and a reason
/// that is not a string is refused before anything is touched.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_names_cancelled_by_default_and_refuses_a_malformed_reason() {
    const DESK: &str = "198.51.100.183:5060";
    let aor = "sip:cd4402@siphon.example.com";
    register(aor, &format!("sip:cd4402@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-default@192.0.2.10");
    let controller = controller_owning(
        "cancel-default",
        dispatcher,
        &caller,
        "caller-default",
        "hangup",
    );
    let (reply, _) = dial(
        &controller,
        "caller-default",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);

    let (bad, _) = command(
        &controller,
        "cancel_dial",
        "caller-default",
        serde_json::json!({ "reason": 7 }),
    )
    .await;
    assert_eq!(bad["error"]["code"], "bad_request", "{bad}");
    assert!(
        requests_to(
            &drain(&controller.dispatcher.udp),
            socket(DESK),
            Method::Cancel
        )
        .is_empty(),
        "a refused cancel cancels nobody"
    );

    let (reply, queued) = command(
        &controller,
        "cancel_dial",
        "caller-default",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let heard = through_dial_failed(&controller, queued);
    assert_eq!(names(&heard), ["DialBranchFailed", "DialFailed"]);
    assert_eq!(heard[1].payload["cause"], "cancelled");
    assert_drained(&controller.dispatcher.state);
}

/// The reply to a cancel means the dial is over. With the ringback playing,
/// ending the dial takes a round trip to the media engine on the dial's own
/// task, and the reply waits for it: `DialFailed` is queued ahead of the reply,
/// the ringback is stopped, the caller is let go of, and a `dial` and a `route`
/// sent on reading the reply are both taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_replies_once_the_dial_has_let_go_of_the_caller() {
    const DESK: &str = "198.51.100.187:5060";
    let aor = "sip:cd4406@siphon.example.com";
    register(aor, &format!("sip:cd4406@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-reply@192.0.2.10");
    let controller = controller_owning(
        "cancel-reply",
        dispatcher,
        &caller,
        "caller-reply",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let dial_args =
        || serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge", "timeout": 60 });

    // Twice over: a dial placed on reading the first cancel's reply is itself
    // cancelled the same way.
    for round in 1..=2 {
        let (reply, _) = dial(&controller, "caller-reply", dial_args()).await;
        assert_eq!(reply["status"], "ok", "round {round}: {reply}");
        let desk = invite_to(&drain(&controller.dispatcher.udp), DESK);
        phone_sends(
            state,
            socket(DESK),
            &phone_response(
                &desk,
                180,
                "Ringing",
                "desk-tag",
                &format!("sip:cd4406@{DESK}"),
                None,
            ),
        );
        let _ = events_through(&controller, "PlayStarted").await;

        let (reply, queued) = command(
            &controller,
            "cancel_dial",
            "caller-reply",
            serde_json::json!({}),
        )
        .await;
        assert_eq!(reply["status"], "ok", "round {round}: {reply}");
        assert_eq!(
            names(&queued),
            ["DialBranchFailed", "DialFailed"],
            "round {round}: the dial's end is reported ahead of the reply"
        );
        assert!(
            !state.dial_bridges.is_ringing(&caller.call_id),
            "round {round}: the caller is let go of"
        );
        assert_eq!(
            engine.commands("stop_media").len(),
            round,
            "round {round}: the ringback is stopped"
        );
    }

    let (reply, _) = command(
        &controller,
        "route",
        "caller-reply",
        serde_json::json!({ "targets": ["sip:15550100099@198.51.100.9"] }),
    )
    .await;
    assert_ne!(
        reply["error"]["details"]["reason"], "dial_in_progress",
        "{reply}"
    );
}

/// A phone has answered and its bridge to the caller is in motion: the cancel
/// is refused, nobody is CANCELled, and the dial carries on to its own outcome.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_is_refused_once_a_phone_is_being_bridged() {
    const DESK: &str = "198.51.100.184:5060";
    const MOBILE: &str = "198.51.100.185:5060";
    let aor = "sip:cd4403@siphon.example.com";
    register(aor, &format!("sip:cd4403@{DESK}"), 1.0);
    register(aor, &format!("sip:cd4403@{MOBILE}"), 0.5);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-late@192.0.2.10");
    let controller = controller_owning("cancel-late", dispatcher, &caller, "caller-late", "hangup");
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-late",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    let mobile = invite_to(&sent, MOBILE);
    phone_sends(
        state,
        socket(MOBILE),
        &phone_response(
            &mobile,
            200,
            "OK",
            "mobile-tag",
            &format!("sip:cd4403@{MOBILE}"),
            Some(&phone_offer("198.51.100.185")),
        ),
    );
    let _ = sent_until(&controller.dispatcher.udp, |sent| {
        !reinvites_to(sent, MOBILE).is_empty()
    })
    .await;
    assert_eq!(state.dial_bridges.bridging_count(), 1);

    let (reply, _) = command(
        &controller,
        "cancel_dial",
        "caller-late",
        serde_json::json!({}),
    )
    .await;
    assert_refused(&reply, "invalid_state", "dial_answered");
    let sent = drain(&controller.dispatcher.udp);
    assert!(
        requests_to(&sent, socket(DESK), Method::Cancel).is_empty(),
        "the desk rings on"
    );
    assert!(
        requests_to(&sent, socket(MOBILE), Method::Bye).is_empty(),
        "the phone being bridged is not released"
    );
    assert_eq!(
        state.dial_bridges.bridging_count(),
        1,
        "the bridge is still awaited"
    );
    assert!(state.dial_bridges.is_ringing(&caller.call_id));
}

/// A channel with no dial at all.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_with_nothing_ringing_is_refused() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-none@192.0.2.10");
    let controller = controller_owning("cancel-none", dispatcher, &caller, "caller-none", "hangup");
    let (reply, _) = command(
        &controller,
        "cancel_dial",
        "caller-none",
        serde_json::json!({}),
    )
    .await;
    assert_refused(&reply, "invalid_state", "no_dial_in_progress");
    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "nothing goes on the wire"
    );
}

/// `route` hands the call back and releases its channel, so it is refused while
/// a dial still rings for it: the phones would otherwise ring on into a channel
/// that is gone. Nothing is sent, the dial is untouched, and once it is
/// cancelled the refusal no longer applies.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_is_refused_while_a_dial_rings_for_the_call() {
    const DESK: &str = "198.51.100.186:5060";
    let aor = "sip:cd4405@siphon.example.com";
    register(aor, &format!("sip:cd4405@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "cancel-route@192.0.2.10");
    let controller = controller_owning(
        "cancel-route",
        dispatcher,
        &caller,
        "caller-route",
        "hangup",
    );
    let state = &controller.dispatcher.state;
    let (reply, _) = dial(
        &controller,
        "caller-route",
        serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let _ = drain(&controller.dispatcher.udp);

    let (reply, _) = command(
        &controller,
        "route",
        "caller-route",
        serde_json::json!({ "targets": ["sip:15550100099@198.51.100.9"] }),
    )
    .await;
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], "invalid_state", "{reply}");
    assert_eq!(reply["error"]["details"]["verb"], "route");
    assert_eq!(reply["error"]["details"]["reason"], "dial_in_progress");
    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "a refused route sends nothing"
    );
    assert!(
        state.dial_bridges.is_ringing(&caller.call_id),
        "the dial rings on"
    );
    assert_eq!(
        controller
            .bus
            .sip_call_id_for_channel("caller-route")
            .as_deref(),
        Some(caller.call_id.as_str()),
        "the channel is not released"
    );

    // Positive control: with the dial cancelled, nothing holds the route back.
    let (cancelled, _) = command(
        &controller,
        "cancel_dial",
        "caller-route",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(cancelled["status"], "ok", "{cancelled}");
    let (reply, _) = command(
        &controller,
        "route",
        "caller-route",
        serde_json::json!({ "targets": ["sip:15550100099@198.51.100.9"] }),
    )
    .await;
    assert_ne!(
        reply["error"]["details"]["reason"], "dial_in_progress",
        "{reply}"
    );
}

/// An endless play reaches the engine as `inf`, a count as the count, and a
/// play that names neither carries none: what a backend is asked for is what
/// the engine is sent.
#[tokio::test(flavor = "multi_thread")]
async fn an_endless_play_reaches_the_engine_as_inf() {
    use siphon_rtp_proto::PlayRepeat;
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "play-forever@192.0.2.10");
    let state = &dispatcher.state;
    let backend = state.rtpengine_set.clone().expect("a media backend");
    let from_tag = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(&caller.call_id))
        .map(|session| session.from_tag.clone())
        .expect("the caller's media session");
    let source = crate::rtpengine::client::PlayMediaSource::File("/prompts/hold.wav".to_string());
    for repeat in [Some(PlayRepeat::Forever), Some(PlayRepeat::Times(3)), None] {
        backend
            .play_media(
                &caller.call_id,
                &from_tag,
                &source,
                repeat,
                None,
                None,
                None,
                false,
                None,
                false,
            )
            .await
            .expect("the play is accepted");
    }
    let repeats: Vec<Option<String>> = engine
        .commands("play_media")
        .into_iter()
        .map(|command| command.repeat)
        .collect();
    assert_eq!(
        repeats,
        [Some("inf".to_string()), Some("3".to_string()), None]
    );
}
