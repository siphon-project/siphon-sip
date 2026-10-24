//! `media_flags` on the verbs that take it: what each refuses, with typed
//! details, before anything reaches the call, and that a valid value takes the
//! anchored path rather than being dropped.

use super::call::answer;
use super::media::{bridge_flags, stream_start};
use super::originate::{originate_media_flags, parse_originate_media};
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::rtpengine::media_flags::MediaFlags;
use serde_json::json;

fn channel() -> ChannelRef {
    ChannelRef {
        channel_id: "ch1".to_string(),
        call_actor_id: "call-uuid".to_string(),
        sip_call_id: "sipcid@host".to_string(),
        app: "ivr-app".to_string(),
    }
}

/// The `details` of a `bad_request`, or a panic naming what came back.
fn refusal_details(result: &ControlResult) -> serde_json::Value {
    match result {
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            details: Some(details),
            ..
        } => details.clone(),
        other => panic!("expected bad_request with details, got {other:?}"),
    }
}

fn is_code(result: &ControlResult, wanted: ControlErrorCode) -> bool {
    matches!(result, ControlResult::Error { code, .. } if *code == wanted)
}

#[test]
fn answer_and_progress_refuse_a_bad_value_naming_the_field() {
    for (final_response, verb) in [(true, "answer"), (false, "progress")] {
        let result = answer(
            &channel(),
            &json!({ "media_flags": { "ws_sample_rate": 44_100 } }),
            final_response,
        );
        let details = refusal_details(&result);
        assert_eq!(details["verb"], verb);
        assert_eq!(details["argument"], "media_flags");
        assert_eq!(details["field"], "ws_sample_rate");
        assert_eq!(details["reason"], "out_of_range");
    }
}

#[test]
fn answer_refuses_an_unknown_key_and_null_and_a_wrong_type() {
    for (flags, field, reason) in [
        (
            json!({ "received_from": "192.0.2.1" }),
            "received_from",
            "unknown_field",
        ),
        (
            json!({ "echo_cancellation": null }),
            "echo_cancellation",
            "null",
        ),
        (
            json!({ "ws_vad_threshold": "high" }),
            "ws_vad_threshold",
            "wrong_type",
        ),
        (
            json!({ "ws_vad_engine": "webrtc" }),
            "ws_vad_engine",
            "invalid_value",
        ),
    ] {
        let result = answer(&channel(), &json!({ "media_flags": flags }), true);
        let details = refusal_details(&result);
        assert_eq!(details["field"], field);
        assert_eq!(details["reason"], reason);
    }
}

/// `media_flags` alone implies `anchor`, as `profile` and `ws_uri` do: the
/// call reaches the media plan (no dispatcher in a unit context, so a typed
/// `unavailable`), never a plain answer that would drop the flags.
#[test]
fn media_flags_alone_take_the_anchored_path() {
    for final_response in [true, false] {
        let result = answer(
            &channel(),
            &json!({ "media_flags": { "echo_cancellation": false } }),
            final_response,
        );
        assert!(
            is_code(&result, ControlErrorCode::Unavailable),
            "{result:?}"
        );
    }
}

/// `null` is "not given": a plain answer stays plain.
#[test]
fn a_null_media_flags_leaves_a_plain_answer_plain() {
    let result = answer(&channel(), &json!({ "media_flags": null }), true);
    assert!(is_code(&result, ControlErrorCode::NotFound), "{result:?}");
}

#[test]
fn an_anchored_answer_with_flags_still_refuses_a_body() {
    let result = answer(
        &channel(),
        &json!({
            "media_flags": { "echo_cancellation": false },
            "body": "v=0\r\n",
            "content_type": "application/sdp",
        }),
        true,
    );
    assert!(is_code(&result, ControlErrorCode::BadRequest), "{result:?}");
}

/// A `profile` that is not a string used to be read as no profile at all,
/// anchoring the call on the default one the controller never named.
#[test]
fn answer_and_progress_refuse_a_profile_that_is_not_a_string() {
    for (final_response, verb) in [(true, "answer"), (false, "progress")] {
        let result = answer(&channel(), &json!({ "profile": 7 }), final_response);
        let details = refusal_details(&result);
        assert_eq!(details["verb"], verb);
        assert_eq!(details["argument"], "profile");
        assert_eq!(details["reason"], "wrong_type");
    }
}

#[tokio::test]
async fn a_tee_refuses_media_flags() {
    let result = stream_start(
        &channel(),
        &json!({ "ws_uri": "ws://ai.invalid:9000", "media_flags": { "ws_vad": true } }),
    )
    .await;
    let details = refusal_details(&result);
    assert_eq!(details["verb"], "stream_start");
    assert_eq!(details["argument"], "media_flags");
    assert_eq!(details["reason"], "tee");
}

/// Refused before the call is looked up: there is nothing to merge over.
#[tokio::test]
async fn a_bridge_refuses_media_flags_without_a_profile() {
    let result = stream_start(
        &channel(),
        &json!({
            "ws_uri": "ws://ai.invalid:9000",
            "mode": "bridge",
            "media_flags": { "echo_cancellation": false },
        }),
    )
    .await;
    let details = refusal_details(&result);
    assert_eq!(details["reason"], "needs_profile");
}

#[tokio::test]
async fn a_bridge_refuses_a_bad_value_before_touching_the_call() {
    let result = stream_start(
        &channel(),
        &json!({
            "ws_uri": "ws://ai.invalid:9000",
            "mode": "bridge",
            "media_flags": { "noise_suppression": 1 },
        }),
    )
    .await;
    let details = refusal_details(&result);
    assert_eq!(details["field"], "noise_suppression");
    assert_eq!(details["reason"], "wrong_type");
}

/// The `attach_ws_bridge` frame a bridge's flags go on the wire as.
fn attach_ws_bridge_frame(profile: Option<&crate::rtpengine::NgFlags>) -> String {
    serde_json::to_string(&siphon_rtp_proto::Command::AttachWsBridge {
        call_id: "call-bridge".to_string(),
        from_tag: "leg-a".to_string(),
        ws_uri: "wss://ai.invalid/agent".to_string(),
        profile: profile.map(crate::rtpengine::siphon_rtp::profile_flags_from_ng),
    })
    .expect("the frame encodes")
}

fn voice_ai_answer() -> crate::rtpengine::NgFlags {
    crate::rtpengine::ProfileRegistry::new()
        .get("voice_ai")
        .expect("voice_ai")
        .answer
        .clone()
}

/// Absent `media_flags` the bridge attaches with the profile exactly as it
/// did before the argument existed, and with no profile there is still no
/// profile key on the wire.
#[test]
fn without_flags_the_attach_ws_bridge_frame_is_unchanged() {
    let profile = voice_ai_answer();
    let flags = bridge_flags(Some(profile.clone()), None).expect("no flags");
    assert_eq!(
        attach_ws_bridge_frame(flags.as_ref()),
        attach_ws_bridge_frame(Some(&profile))
    );
    let none = bridge_flags(None, None).expect("no profile, no flags");
    assert!(none.is_none());
    let frame: serde_json::Value =
        serde_json::from_str(&attach_ws_bridge_frame(none.as_ref())).expect("json");
    assert!(frame.get("profile").is_none(), "no profile key: {frame}");
}

#[test]
fn with_flags_the_bridge_attaches_with_them_merged() {
    let flags = MediaFlags {
        echo_cancellation: Some(false),
        ws_vad_min_speech_ms: Some(60),
        ..MediaFlags::default()
    };
    let merged = bridge_flags(Some(voice_ai_answer()), Some(&flags))
        .expect("valid")
        .expect("a profile");
    let frame: serde_json::Value =
        serde_json::from_str(&attach_ws_bridge_frame(Some(&merged))).expect("json");
    let profile = &frame["profile"];
    // A false switch stays off the wire, which the engine reads as off; the
    // profile alone sends it on.
    let unmerged: serde_json::Value =
        serde_json::from_str(&attach_ws_bridge_frame(Some(&voice_ai_answer()))).expect("json");
    assert_eq!(unmerged["profile"]["echo_cancellation"], true, "{unmerged}");
    assert!(profile.get("echo_cancellation").is_none(), "{frame}");
    assert_eq!(profile["ws_vad_min_speech_ms"], 60, "{frame}");
    assert_eq!(profile["noise_suppression"], true, "kept: {frame}");
}

#[test]
fn bridge_flags_refuse_a_merged_echo_window_out_of_range() {
    let flags = MediaFlags {
        echo_delay_search_ms: Some(2_000),
        ..MediaFlags::default()
    };
    let result = bridge_flags(Some(voice_ai_answer()), Some(&flags)).expect_err("refused");
    let details = refusal_details(&result);
    assert_eq!(details["field"], "echo_delay_search_ms");
    assert_eq!(details["reason"], "out_of_range");
}

#[test]
fn an_originate_with_its_own_offer_refuses_media_flags() {
    for args in [
        json!({ "sdp": "v=0\r\n", "media_flags": { "ws_vad": true } }),
        json!({
            "body": "v=0\r\n",
            "content_type": "application/sdp",
            "media_flags": { "ws_vad": true },
        }),
    ] {
        let media = parse_originate_media(&args).expect("an offer plan");
        let result = originate_media_flags(&args, &media).expect_err("refused");
        let details = refusal_details(&result);
        assert_eq!(details["verb"], "originate");
        assert_eq!(details["reason"], "not_anchored");
    }
}

#[test]
fn an_anchored_originate_takes_media_flags() {
    let args = json!({ "media": true, "media_flags": { "echo_cancellation": false } });
    let media = parse_originate_media(&args).expect("an anchor plan");
    assert_eq!(
        originate_media_flags(&args, &media),
        Ok(Some(MediaFlags {
            echo_cancellation: Some(false),
            ..MediaFlags::default()
        }))
    );
    let plain = json!({ "media": true });
    let media = parse_originate_media(&plain).expect("an anchor plan");
    assert_eq!(originate_media_flags(&plain, &media), Ok(None));
}

#[test]
fn an_originate_refuses_a_bad_value() {
    let args = json!({ "media": true, "media_flags": { "ws_vad_hangover_ms": -1 } });
    let media = parse_originate_media(&args).expect("an anchor plan");
    let result = originate_media_flags(&args, &media).expect_err("refused");
    let details = refusal_details(&result);
    assert_eq!(details["field"], "ws_vad_hangover_ms");
    assert_eq!(details["reason"], "wrong_type");
}

#[test]
fn an_originate_refuses_a_profile_that_is_not_a_string() {
    let error = parse_originate_media(&json!({ "media": true, "profile": ["voice_ai"] }))
        .expect_err("refused");
    assert!(error.contains("must be a string"), "{error}");
}
