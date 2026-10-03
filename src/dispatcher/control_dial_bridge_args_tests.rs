//! `dial {on_answer: "bridge"}`: what it refuses, the identity its phones are
//! shown, and the ringback it plays.
//!
//! Every refusal names the verb and the reason in `error.details`, the way the
//! adapter's other typed refusals do, and each has a positive control beside
//! it: the same caller, or the same argument, accepted once the one thing the
//! refusal names is right.

use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, controller_owning, dial, events, eventually, names,
    register, Caller, CALLER,
};
use super::originate_test_harness::{drain, phone_response, phone_sends, requests_to, socket};
use super::*;
use crate::rtpengine::test_native_engine::{NativeTestEngine, NATIVE_ENGINE_FIRST_PLAY_ID};

/// A bridge dial to `aor`, with `extra` merged into its arguments.
fn bridge_args(aor: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut args = serde_json::json!({ "targets": [{ "aor": aor }], "on_answer": "bridge" });
    if let (Some(args), Some(extra)) = (args.as_object_mut(), extra.as_object()) {
        for (name, value) in extra {
            args.insert(name.clone(), value.clone());
        }
    }
    args
}

fn assert_refused(reply: &serde_json::Value, code: &str, reason: &str) {
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["error"]["code"], code, "{reply}");
    assert_eq!(reply["error"]["details"]["verb"], "dial", "{reply}");
    assert_eq!(reply["error"]["details"]["reason"], reason, "{reply}");
}

/// A caller that has not been answered, parked the way a controller gets it.
fn parked_caller(state: &DispatcherState, call_id: &str) -> Caller {
    // Borrow the answered-caller fixture's shape without answering: a fresh
    // actor with the INVITE stored and nothing sent.
    let invite = parse_sip_message_bytes(
        format!(
            concat!(
                "INVITE sip:4000@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-{call_id}\r\n",
                "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
                "To: <sip:4000@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            call_id = call_id
        )
        .as_bytes(),
    )
    .expect("the INVITE parses");
    let leg = Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: socket(CALLER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    Caller {
        call_id: call_id.to_string(),
        internal_call_id,
        answer: invite,
        address: CALLER.to_string(),
    }
}

/// `bridge` is for a caller that is answered and anchored; one still ringing,
/// or answered with its media off the engine, is refused with nothing rung.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_needs_an_answered_anchored_caller() {
    const DESK: &str = "198.51.100.201:5060";
    let aor = "sip:bd3301@siphon.example.com";
    register(aor, &format!("sip:bd3301@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let parked = parked_caller(&dispatcher.state, "refuse-parked@192.0.2.10");
    let controller = controller_owning("refuse-state", dispatcher, &parked, "parked", "hangup");
    let state = &controller.dispatcher.state;

    let (reply, _) = dial(
        &controller,
        "parked",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_refused(&reply, "invalid_state", "not_answered");
    assert_eq!(reply["error"]["details"]["call_state"], "calling");
    assert!(drain(&controller.dispatcher.udp).is_empty());

    // Answered, but with no media session: nothing to ring back on or bridge.
    assert!(b2bua_answer_call_with_state(
        &parked.internal_call_id,
        &parked.answer,
        200,
        "OK",
        None,
        None,
        state
    ));
    drain(&controller.dispatcher.udp);
    let (reply, _) = dial(
        &controller,
        "parked",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_refused(&reply, "invalid_state", "not_anchored");
    assert!(drain(&controller.dispatcher.udp).is_empty());
    assert_eq!(state.dial_bridges.ringing_count(), 0);

    // Positive control: an answered, anchored caller rings.
    let caller = answered_caller(&controller.dispatcher, "refuse-anchored@192.0.2.10");
    controller.bus.register_channel(
        "anchored",
        &controller.connection,
        &caller.internal_call_id,
        &caller.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let (reply, _) = dial(
        &controller,
        "anchored",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        requests_to(
            &drain(&controller.dispatcher.udp),
            socket(DESK),
            Method::Invite
        )
        .len(),
        1
    );
}

/// `connect`, the default, is still refused on an answered caller: it would
/// answer a call that is already answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_connecting_dial_is_still_refused_on_an_answered_caller() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "refuse-connect@192.0.2.10");
    let target = || DialTarget {
        uri: "sip:bd3302@198.51.100.202".to_string(),
        ..Default::default()
    };
    let refused = b2bua_dial_call_with_state(
        &caller.call_id,
        vec![target()],
        true,
        30,
        &[],
        &DialShaping::default(),
        &dispatcher.state,
    );
    assert!(matches!(refused, Err(DialError::AlreadyAnswered { .. })));
    assert!(drain(&dispatcher.udp).is_empty());
    // Positive control: the same caller, before it is answered, dials.
    let parked = parked_caller(&dispatcher.state, "refuse-connect-parked@192.0.2.10");
    let dialled = tokio::task::block_in_place(|| {
        b2bua_dial_call_with_state(
            &parked.call_id,
            vec![target()],
            true,
            30,
            &[],
            &DialShaping::default(),
            &dispatcher.state,
        )
    });
    assert!(matches!(dialled, Ok(true)), "{dialled:?}");
}

/// A value of `on_answer` or `ringback` siphon does not know is refused, and
/// names the argument, rather than falling back to a default.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_on_answer_or_a_malformed_ringback_is_refused() {
    let aor = "sip:bd3303@siphon.example.com";
    register(aor, "sip:bd3303@198.51.100.203:5060", 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "refuse-args@192.0.2.10");
    let controller = controller_owning("refuse-args", dispatcher, &caller, "args", "hangup");

    for on_answer in [serde_json::json!("transfer"), serde_json::json!(1)] {
        let (reply, _) = dial(
            &controller,
            "args",
            bridge_args(aor, serde_json::json!({ "on_answer": on_answer })),
        )
        .await;
        assert_refused(&reply, "bad_request", "unknown_value");
        assert_eq!(reply["error"]["details"]["argument"], "on_answer");
    }
    for ringback in [
        serde_json::json!(5),
        serde_json::json!({ "tone": "ringback_eu" }),
        serde_json::json!(""),
    ] {
        let (reply, _) = dial(
            &controller,
            "args",
            bridge_args(aor, serde_json::json!({ "ringback": ringback })),
        )
        .await;
        assert_refused(&reply, "bad_request", "invalid_value");
        assert_eq!(reply["error"]["details"]["argument"], "ringback");
    }
    // A ringback means nothing to a connecting dial.
    let (reply, _) = dial(
        &controller,
        "args",
        serde_json::json!({ "targets": [{ "aor": aor }], "ringback": "ringback_eu" }),
    )
    .await;
    assert_refused(&reply, "bad_request", "requires_bridge");
    assert!(drain(&controller.dispatcher.udp).is_empty());
    assert_eq!(controller.dispatcher.state.dial_bridges.ringing_count(), 0);

    // Positive control: a cadence of the controller's own is accepted.
    let (reply, _) = dial(
        &controller,
        "args",
        bridge_args(
            aor,
            serde_json::json!({ "ringback": "425/1000,0/4000*inf" }),
        ),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["result"]["ringback"], "425/1000,0/4000*inf");
}

/// One set of phones at a time: a second bridge dial while the first rings is
/// refused, and so is one for a caller already bridged.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_bridge_dial_or_a_bridged_caller_is_refused() {
    const DESK: &str = "198.51.100.204:5060";
    let aor = "sip:bd3304@siphon.example.com";
    register(aor, &format!("sip:bd3304@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "refuse-twice@192.0.2.10");
    let controller = controller_owning("refuse-twice", dispatcher, &caller, "twice", "hangup");
    let state = &controller.dispatcher.state;

    let (first, _) = dial(
        &controller,
        "twice",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_eq!(first["status"], "ok", "positive control: {first}");
    drain(&controller.dispatcher.udp);
    let (second, _) = dial(
        &controller,
        "twice",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_refused(&second, "invalid_state", "dial_in_progress");
    assert!(
        drain(&controller.dispatcher.udp).is_empty(),
        "no phone is rung twice"
    );

    let bridged = answered_caller(&controller.dispatcher, "refuse-bridged@192.0.2.10");
    controller.bus.register_channel(
        "bridged",
        &controller.connection,
        &bridged.internal_call_id,
        &bridged.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    state.call_actors.set_bridge(
        &bridged.internal_call_id,
        crate::b2bua::bridge::BridgeContext {
            peer_call_id: "someone-else".to_string(),
            peer_sip_call_id: "someone-else@192.0.2.20".to_string(),
            role: crate::b2bua::bridge::BridgeRole::Anchor,
            stage: crate::b2bua::bridge::BridgeStage::Bridged,
            on_peer_hangup: crate::b2bua::bridge::PeerHangupPolicy::default(),
            media_call_id: None,
            media_from_tag: None,
            media_profile: None,
            media_peer_profile: None,
            media_pending_adoption: false,
            last_local_offer: Vec::new(),
            release_reason: None,
        },
    );
    let (reply, _) = dial(
        &controller,
        "bridged",
        bridge_args(aor, serde_json::json!({})),
    )
    .await;
    assert_refused(&reply, "invalid_state", "already_bridged");
    assert!(drain(&controller.dispatcher.udp).is_empty());
}

/// The phones are shown what a connecting dial would show them: the dial's
/// identity arguments over the caller's own From, a target's own over the
/// dial's, and the dial's and each target's headers.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_dial_presents_the_dials_identity_to_each_phone() {
    const TRUNK: &str = "198.51.100.208:5060";
    const DESK: &str = "198.51.100.209:5060";
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "identity@192.0.2.10");
    let controller = controller_owning("identity", dispatcher, &caller, "identity", "hangup");
    let (reply, _) = dial(
        &controller,
        "identity",
        serde_json::json!({
            "on_answer": "bridge",
            "from": "sip:5550100@siphon.example.com",
            "from_display": "Reception",
            "p_asserted_identity": "sip:5550100@siphon.example.com",
            "headers": { "X-Queue": "sales" },
            "targets": [
                format!("sip:bd3308@{DESK}"),
                {
                    "uri": format!("sip:bd3309@{TRUNK}"),
                    "to": "sip:15550100199@trunk.example.com",
                    "from": "sip:5550199@siphon.example.com",
                    "privacy": "restricted",
                    "headers": { "X-Queue": "overflow" },
                },
            ],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let sent = drain(&controller.dispatcher.udp);
    let desk = requests_to(&sent, socket(DESK), Method::Invite)
        .remove(0)
        .message;
    let trunk = requests_to(&sent, socket(TRUNK), Method::Invite)
        .remove(0)
        .message;

    let desk_from = desk.headers.from().expect("a From");
    assert!(
        desk_from.starts_with("\"Reception\" <sip:5550100@siphon.example.com>"),
        "the dial's identity, not the caller's: {desk_from}"
    );
    assert_eq!(
        desk.headers.get("P-Asserted-Identity").map(String::as_str),
        Some("<sip:5550100@siphon.example.com>")
    );
    assert_eq!(
        desk.headers.get("X-Queue").map(String::as_str),
        Some("sales")
    );
    assert_eq!(
        desk.headers.to().map(String::as_str),
        Some(format!("<sip:bd3308@{DESK}>").as_str()),
        "a URI dialled as written is its own callee"
    );

    // The trunk's own identity, presented restricted (RFC 3323 §4.1): From
    // anonymised, the identity kept for the trusted hop in P-Asserted-Identity.
    let trunk_from = trunk.headers.from().expect("a From");
    assert!(
        trunk_from.contains("anonymous"),
        "a restricted presentation anonymises From: {trunk_from}"
    );
    assert!(trunk
        .headers
        .get("Privacy")
        .is_some_and(|privacy| privacy.contains("id")));
    assert_eq!(
        trunk.headers.get("X-Queue").map(String::as_str),
        Some("overflow"),
        "the target's header over the dial's"
    );
    assert_eq!(
        trunk.headers.to().map(String::as_str),
        Some("<sip:15550100199@trunk.example.com>"),
        "a target's own called party is its leg's To"
    );
    assert!(
        !desk_from.contains("Caller One"),
        "the caller's display name is not carried beside another identity"
    );
}

/// A `to` on an `{aor}` target is the called party of every contact the AoR
/// forks to, over the AoR the leg would otherwise be addressed to.
#[tokio::test(flavor = "multi_thread")]
async fn an_aor_targets_to_is_each_contacts_called_party() {
    const DESK: &str = "198.51.100.210:5060";
    let aor = "sip:bd3310@siphon.example.com";
    register(aor, &format!("sip:bd3310@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "aor-to@192.0.2.10");
    let controller = controller_owning("aor-to", dispatcher, &caller, "aor-to", "hangup");
    let (reply, _) = dial(
        &controller,
        "aor-to",
        serde_json::json!({
            "on_answer": "bridge",
            "targets": [{ "aor": aor, "to": "sip:15550100199@siphon.example.com" }],
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let desk = requests_to(
        &drain(&controller.dispatcher.udp),
        socket(DESK),
        Method::Invite,
    )
    .remove(0)
    .message;
    assert_eq!(
        desk.headers.to().map(String::as_str),
        Some("<sip:15550100199@siphon.example.com>")
    );
}

/// The ringback: nothing before a phone alerts, the controller's cadence as
/// given, and `ringback: false` plays nothing at all.
#[tokio::test(flavor = "multi_thread")]
async fn the_ringback_is_the_named_tone_and_false_plays_none() {
    const NAMED: &str = "198.51.100.205:5060";
    const SILENT: &str = "198.51.100.206:5060";
    let named_aor = "sip:bd3305@siphon.example.com";
    let silent_aor = "sip:bd3306@siphon.example.com";
    register(named_aor, &format!("sip:bd3305@{NAMED}"), 1.0);
    register(silent_aor, &format!("sip:bd3306@{SILENT}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let named = answered_caller(&dispatcher, "ringback-named@192.0.2.10");
    let silent = answered_caller(&dispatcher, "ringback-silent@192.0.2.10");
    let controller = controller_owning("ringback", dispatcher, &named, "named", "hangup");
    controller.bus.register_channel(
        "silent",
        &controller.connection,
        &silent.internal_call_id,
        &silent.call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let state = &controller.dispatcher.state;

    let (reply, _) = dial(
        &controller,
        "silent",
        bridge_args(silent_aor, serde_json::json!({ "ringback": false })),
    )
    .await;
    assert_eq!(reply["result"]["ringback"], false, "{reply}");
    let invite = requests_to(
        &drain(&controller.dispatcher.udp),
        socket(SILENT),
        Method::Invite,
    )
    .remove(0)
    .message;
    phone_sends(
        state,
        socket(SILENT),
        &phone_response(
            &invite,
            180,
            "Ringing",
            "s",
            &format!("sip:bd3306@{SILENT}"),
            None,
        ),
    );

    let cadence = "425/1000,0/4000*inf";
    let (reply, _) = dial(
        &controller,
        "named",
        bridge_args(named_aor, serde_json::json!({ "ringback": cadence })),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = requests_to(
        &drain(&controller.dispatcher.udp),
        socket(NAMED),
        Method::Invite,
    )
    .remove(0)
    .message;
    assert!(
        engine.commands("play_media").is_empty(),
        "nothing before an 18x"
    );
    phone_sends(
        state,
        socket(NAMED),
        &phone_response(
            &invite,
            183,
            "Session Progress",
            "n",
            &format!("sip:bd3305@{NAMED}"),
            None,
        ),
    );
    // Positive control for `false`: the named caller's ringback is played...
    assert!(eventually(|| engine.commands("play_media").len() == 1).await);
    let plays = engine.commands("play_media");
    assert_eq!(plays[0].call_id, named.call_id);
    assert_eq!(
        plays[0].detail.as_deref(),
        Some(cadence),
        "the cadence as given"
    );
    // ...and by then the silent one's phone has long been alerting.
    assert!(
        plays.iter().all(|play| play.call_id != silent.call_id),
        "ringback: false plays nothing"
    );
}

/// A ringback never talks over a prompt of the controller's: held until the
/// prompt's end is reported, then played, and its own end is labelled.
#[tokio::test(flavor = "multi_thread")]
async fn the_ringback_waits_for_a_playing_prompt_to_end() {
    const DESK: &str = "198.51.100.207:5060";
    let aor = "sip:bd3307@siphon.example.com";
    register(aor, &format!("sip:bd3307@{DESK}"), 1.0);
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "ringback-held@192.0.2.10");
    crate::control::channel_event_capture::watch(&caller.call_id);
    let controller = controller_owning("ringback-held", dispatcher, &caller, "held", "hangup");
    let state = &controller.dispatcher.state;
    let backend = state.rtpengine_set.clone().expect("a media backend");
    let from_tag = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(&caller.call_id))
        .map(|session| session.from_tag.clone())
        .expect("the caller's media session");

    // The controller's prompt is still playing when the phones start ringing.
    let prompt = backend
        .play_media(
            &caller.call_id,
            &from_tag,
            &crate::rtpengine::client::PlayMediaSource::File("/prompts/hold.wav".to_string()),
            None,
            None,
            None,
            None,
            false,
            None,
            false,
        )
        .await
        .expect("the prompt starts")
        .play_id
        .expect("a play_id");
    assert_eq!(prompt, NATIVE_ENGINE_FIRST_PLAY_ID);

    let (reply, _) = dial(&controller, "held", bridge_args(aor, serde_json::json!({}))).await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = requests_to(
        &drain(&controller.dispatcher.udp),
        socket(DESK),
        Method::Invite,
    )
    .remove(0)
    .message;
    phone_sends(
        state,
        socket(DESK),
        &phone_response(
            &invite,
            180,
            "Ringing",
            "d",
            &format!("sip:bd3307@{DESK}"),
            None,
        ),
    );
    let _ = events(&controller).await;
    assert_eq!(
        engine.commands("play_media").len(),
        1,
        "the prompt alone: the ringback is held"
    );

    // The prompt ends.
    let finished = |play_id| crate::rtpengine::events::PlayFinishedEvent {
        call_id: caller.call_id.clone(),
        from_tag: from_tag.clone(),
        to_tag: None,
        play_id,
        reason: crate::rtpengine::events::PlayEndReason::Completed,
        played_ms: Some(1200),
    };
    publish_play_finished(state, &finished(prompt));
    assert!(eventually(|| engine.commands("play_media").len() == 2).await);
    assert_eq!(
        engine.commands("play_media")[1].detail.as_deref(),
        Some("ringback_eu")
    );
    let heard = events(&controller).await;
    assert_eq!(names(&heard), ["PlayStarted"]);
    assert_eq!(heard[0].payload["origin"], "ringback");
    let ringback = heard[0].payload["play_id"].as_u64().expect("its play_id");

    // The prompt's end carried no origin; the ringback's does.
    publish_play_finished(state, &finished(ringback));
    let captured = crate::control::channel_event_capture::take(&caller.call_id);
    let finished: Vec<_> = captured
        .iter()
        .filter(|(event, _)| event == "PlayFinished")
        .map(|(_, payload)| payload.clone())
        .collect();
    assert_eq!(finished.len(), 2);
    assert!(
        finished[0].get("origin").is_none(),
        "the controller's own prompt"
    );
    assert_eq!(finished[1]["origin"], "ringback");
    assert_eq!(state.dial_bridges.ringback_count(), 0);
}
