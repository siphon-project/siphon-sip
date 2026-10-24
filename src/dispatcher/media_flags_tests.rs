//! A call's `media_flags` on the dispatcher's anchoring paths: merged over the
//! answer half of the profile the call anchors on, for that call only, and
//! carried to the engine command that anchors it. Absent, every frame is the
//! one sent before the argument existed.
//!
//! The answer-first anchor (a controller's `answer` / `progress`) and the
//! offerless originate's 2xx are driven through the in-process native engine,
//! which records the profile each command carried; the plan and the bridge
//! frame are checked on their encoded form.

use std::sync::{Arc, Mutex};

use super::dial_bridge_test_harness::caller_invite;
use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    requests_to, socket,
};
use super::test_dispatcher::TestDispatcher;
use super::*;
use crate::rtpengine::media_flags::MediaFlags;
use crate::rtpengine::siphon_rtp::profile_flags_from_ng;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const CALLER: &str = "192.0.2.40:5060";

/// What one bot needs and its profile does not give it: echo cancellation off,
/// and a leading speech run before barge-in.
fn bot_flags() -> MediaFlags {
    MediaFlags {
        echo_cancellation: Some(false),
        ws_vad_min_speech_ms: Some(60),
        ..MediaFlags::default()
    }
}

/// A native-backend handle over a dead address: the plan does no I/O.
fn idle_native_backend() -> crate::rtpengine::MediaBackend {
    let (event_tx, _events) =
        tokio::sync::mpsc::channel::<crate::rtpengine::events::RtpEngineEvent>(16);
    let set = crate::rtpengine::siphon_rtp::SiphonRtpClientSet::new(
        vec![(socket("127.0.0.1:1"), 200, 1)],
        None,
        5_000,
        event_tx,
    )
    .expect("a native client set");
    crate::rtpengine::MediaBackend::SiphonRtp(set)
}

/// The `answer_local` frame a plan's flags go on the wire as.
fn answer_local_frame(flags: &crate::rtpengine::NgFlags) -> String {
    serde_json::to_string(&siphon_rtp_proto::Command::AnswerLocal {
        call_id: "call".to_string(),
        from_tag: "tag".to_string(),
        sdp: "v=0\r\n".to_string(),
        profile: profile_flags_from_ng(flags),
    })
    .expect("the frame encodes")
}

/// A caller parked on `call_id`, not yet answered: what a controller's
/// `answer` / `progress` anchors.
fn parked_caller(dispatcher: &TestDispatcher, call_id: &str) -> (String, SipMessage) {
    let state = &dispatcher.state;
    let invite = caller_invite(call_id, CALLER);
    let mut leg = Leg::new_a_leg(
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
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.last_sdp = Some(invite.body.clone());
    let internal_call_id = state.call_actors.create_call(leg);
    state
        .call_actors
        .set_a_leg_invite(&internal_call_id, Arc::new(Mutex::new(invite.clone())));
    (internal_call_id, invite)
}

#[tokio::test]
async fn the_plan_merges_the_flags_over_the_profile_answer_half() {
    let backend = idle_native_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = caller_invite("plan-flags", CALLER);
    let profile = registry.get("voice_ai").expect("voice_ai").answer.clone();
    assert!(
        profile.echo_cancellation,
        "the built-in profile cancels echo"
    );
    let plan = answer_first_prepare(
        &invite,
        socket(CALLER).ip(),
        &backend,
        &registry,
        Some("voice_ai"),
        Some("wss://ai.example.test/agent"),
        Some(&bot_flags()),
    )
    .expect("the plan is made");
    assert!(!plan.flags.echo_cancellation, "overridden for this call");
    assert_eq!(plan.flags.ws_vad_min_speech_ms, Some(60));
    assert_eq!(plan.flags.noise_suppression, profile.noise_suppression);
    assert_eq!(plan.flags.ws_barge_in, profile.ws_barge_in);
    // The registry entry every other call reads is untouched.
    let after = registry.get("voice_ai").expect("voice_ai").answer.clone();
    assert!(after.echo_cancellation);
    assert_eq!(after.ws_vad_min_speech_ms, Some(100));
}

/// Absent `media_flags` the plan's `answer_local` frame is exactly the
/// profile's answer half with the per-call stamps it always got.
#[tokio::test]
async fn without_flags_the_answer_local_frame_is_unchanged() {
    let backend = idle_native_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = caller_invite("plan-no-flags", CALLER);
    let plan = answer_first_prepare(
        &invite,
        socket(CALLER).ip(),
        &backend,
        &registry,
        Some("voice_ai"),
        None,
        None,
    )
    .expect("the plan is made");
    let mut expected = registry.get("voice_ai").expect("voice_ai").answer.clone();
    expected.stamp_received_from(socket(CALLER).ip());
    expected.stamp_sip_call_id_of(&invite);
    assert_eq!(
        answer_local_frame(&plan.flags),
        answer_local_frame(&expected)
    );
}

#[tokio::test]
async fn the_plan_refuses_flags_boot_would_refuse_on_the_merged_profile() {
    let backend = idle_native_backend();
    let registry = crate::rtpengine::ProfileRegistry::new();
    let invite = caller_invite("plan-bad-flags", CALLER);
    let flags = MediaFlags {
        echo_delay_search_ms: Some(1_001),
        ..MediaFlags::default()
    };
    let refusal = answer_first_prepare(
        &invite,
        socket(CALLER).ip(),
        &backend,
        &registry,
        None,
        None,
        Some(&flags),
    )
    .map(|_| ())
    .expect_err("out of range");
    assert!(refusal.contains("echo_delay_search_ms"), "{refusal}");
}

/// The engine's `answer_local` for a controller's anchored answer carries the
/// merged flags, and the profile is left as it was for the next call.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_answer_hands_the_engine_the_merged_flags() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let (call_id, invite) = parked_caller(&dispatcher, "answer-flags");
    answer_first_anchor(
        &call_id,
        &invite,
        socket(CALLER).ip(),
        200,
        "OK",
        Some("voice_ai"),
        None,
        Some(&bot_flags()),
        &[],
        &dispatcher.state,
    )
    .expect("answered and anchored");
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1);
    let profile = anchored[0].profile.as_ref().expect("a profile");
    assert!(!profile.echo_cancellation, "{profile:?}");
    assert_eq!(profile.ws_vad_min_speech_ms, Some(60));
    assert!(profile.noise_suppression, "kept from voice_ai");

    // A second call on the same profile, with no flags, gets the profile.
    let (second, invite) = parked_caller(&dispatcher, "answer-no-flags");
    answer_first_anchor(
        &second,
        &invite,
        socket(CALLER).ip(),
        200,
        "OK",
        Some("voice_ai"),
        None,
        None,
        &[],
        &dispatcher.state,
    )
    .expect("answered and anchored");
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 2);
    let profile = anchored[1].profile.as_ref().expect("a profile");
    assert!(profile.echo_cancellation, "{profile:?}");
    assert_eq!(profile.ws_vad_min_speech_ms, Some(100));
}

/// Anchored early media sets the flags once; the 2xx that follows repeats the
/// 18x's answer and does not anchor again. The anchor is made as the anchored
/// `progress` makes it ([`anchor_a_leg`], kept on the call); sending the 18x
/// itself needs the running dispatcher, which a unit test does not have.
#[tokio::test(flavor = "multi_thread")]
async fn anchored_progress_carries_the_flags_into_the_one_anchor() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let (call_id, invite) = parked_caller(&dispatcher, "progress-flags");
    let anchor = anchor_a_leg(
        &invite,
        socket(CALLER).ip(),
        Some("voice_ai"),
        None,
        Some(&bot_flags()),
        &dispatcher.state,
    )
    .expect("early media anchored");
    dispatcher
        .state
        .call_actors
        .set_early_media_anchor(&call_id, anchor);
    answer_first_anchor(
        &call_id,
        &invite,
        socket(CALLER).ip(),
        200,
        "OK",
        Some("voice_ai"),
        None,
        None,
        &[],
        &dispatcher.state,
    )
    .expect("answered");
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1, "anchored once, at the 18x");
    let profile = anchored[0].profile.as_ref().expect("a profile");
    assert!(!profile.echo_cancellation, "{profile:?}");
    assert_eq!(profile.ws_vad_min_speech_ms, Some(60));
}

/// Stage an anchored originate to `phone` with `media_flags`, have the phone
/// answer with its offer, and return the `answer_local` siphon sent.
async fn originate_answered(
    media_flags: Option<MediaFlags>,
    phone: &str,
) -> crate::rtpengine::test_native_engine::NativeCommand {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let mut params = anchored_params(&format!("sip:2201@{phone}"));
    params.media = OriginateMedia::Anchor {
        profile: "voice_ai".to_string(),
        ws_uri: None,
    };
    let prepared = prepare_originate_routed(
        &dispatcher.state,
        params,
        &OriginateRoute {
            media_flags,
            ..OriginateRoute::default()
        },
    )
    .expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(phone), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;
    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2201@{phone}"),
        Some(&phone_offer(socket(phone).ip().to_string().as_str())),
    );
    phone_sends(&dispatcher.state, socket(phone), &answered);
    let mut anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1, "the 2xx offer was anchored once");
    anchored.remove(0)
}

/// The flags ride the stored anchor from the originate to the callee's 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_carries_the_flags_to_the_callee_answer() {
    let command = originate_answered(Some(bot_flags()), "198.51.100.61:5060").await;
    let profile = command.profile.as_ref().expect("a profile");
    assert!(!profile.echo_cancellation, "{profile:?}");
    assert_eq!(profile.ws_vad_min_speech_ms, Some(60));
    assert!(profile.noise_suppression, "kept from voice_ai");
}

/// Without flags the originate's `answer_local` carries the profile's answer
/// half with the stamps it always had.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_without_flags_anchors_on_the_profile_unchanged() {
    const PHONE: &str = "198.51.100.62:5060";
    let command = originate_answered(None, PHONE).await;
    let registry = crate::rtpengine::ProfileRegistry::new();
    let mut expected = registry.get("voice_ai").expect("voice_ai").answer.clone();
    expected.stamp_received_from(socket(PHONE).ip());
    if let Some(sip_call_id) = command.sip_call_id.as_deref() {
        expected.stamp_sip_call_id(sip_call_id);
    }
    assert_eq!(command.profile, Some(profile_flags_from_ng(&expected)));
}

/// Only an offerless anchor gets a local answer to merge into, so flags on an
/// originate carrying its own offer are refused rather than dropped.
#[tokio::test(flavor = "multi_thread")]
async fn an_originate_with_its_own_offer_refuses_flags() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let mut params = anchored_params("sip:2201@198.51.100.63:5060");
    params.media = OriginateMedia::Offer {
        body: phone_offer("192.0.2.1").into_bytes(),
        content_type: "application/sdp".to_string(),
    };
    let refusal = prepare_originate_routed(
        &dispatcher.state,
        params,
        &OriginateRoute {
            media_flags: Some(bot_flags()),
            ..OriginateRoute::default()
        },
    )
    .map(|_| ())
    .expect_err("refused");
    assert!(
        matches!(refusal, OriginateError::Unsupported(_)),
        "{refusal:?}"
    );
}

/// A controller's `originate {media: true, media_flags}` read off the frame an
/// SDK sends, routed through the SIP adapter's table and handler, placed on a
/// dispatcher and answered by the phone: the engine's `answer_local` for the
/// phone's 2xx offer carries the flags. A handler test alone would prove none
/// of the frame, the table or the 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_originate_carries_its_media_flags_to_the_engine() {
    const PHONE: &str = "198.51.100.64:5060";
    let engine = NativeTestEngine::start().await;
    let controller = super::control_originate_tests::controller_on(
        "dialer-media-flags",
        anchored_dispatcher(&engine),
    );
    let reply = super::control_originate_tests::originate(
        &controller,
        serde_json::json!({
            "channel": "media-flags-1",
            "to": format!("sip:2201@{PHONE}"),
            "media": true,
            "profile": "voice_ai",
            "media_flags": { "echo_cancellation": false, "ws_vad_min_speech_ms": 60 },
        }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let invite = requests_to(
        &drain(&controller.dispatcher.udp),
        socket(PHONE),
        Method::Invite,
    )
    .pop()
    .expect("siphon sent the phone an INVITE")
    .message;
    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2201@{PHONE}"),
        Some(&phone_offer("198.51.100.64")),
    );
    phone_sends(&controller.dispatcher.state, socket(PHONE), &answered);
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1, "the 2xx offer was anchored once");
    let profile = anchored[0].profile.as_ref().expect("a profile");
    assert!(!profile.echo_cancellation, "{profile:?}");
    assert_eq!(profile.ws_vad_min_speech_ms, Some(60));
}

/// The same frame with an invalid value is refused at the verb and nothing
/// is placed.
#[tokio::test(flavor = "multi_thread")]
async fn a_controller_originate_with_a_bad_value_places_nothing() {
    const PHONE: &str = "198.51.100.65:5060";
    let engine = NativeTestEngine::start().await;
    let controller = super::control_originate_tests::controller_on(
        "dialer-media-flags-bad",
        anchored_dispatcher(&engine),
    );
    for (args, field) in [
        (
            serde_json::json!({ "media": true, "media_flags": { "ws_uri": "wss://x.invalid" } }),
            "ws_uri",
        ),
        (
            serde_json::json!({ "media": true, "offer": "early", "media_flags": { "ws_vad": true } }),
            "",
        ),
    ] {
        let mut args = args;
        args["channel"] = serde_json::json!("media-flags-bad");
        args["to"] = serde_json::json!(format!("sip:2201@{PHONE}"));
        let reply = super::control_originate_tests::originate(&controller, args).await;
        assert_eq!(reply["status"], "error", "{reply}");
        assert_eq!(reply["error"]["code"], "bad_request", "{reply}");
        if !field.is_empty() {
            assert_eq!(reply["error"]["details"]["field"], field, "{reply}");
        }
    }
    assert!(
        requests_to(
            &drain(&controller.dispatcher.udp),
            socket(PHONE),
            Method::Invite
        )
        .is_empty(),
        "nothing was placed"
    );
}
