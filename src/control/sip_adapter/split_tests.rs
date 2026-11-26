//! `stream_start` / `stream_stop` with `mode: "split"`: what each refuses
//! before the call is touched, and what reaches the engine when it is not.

use serde_json::json;

use super::media::{parse_stream_mode, stream_start, StreamMode};
use super::split::{attach_split, detach_split, SplitRequest};
use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::control::ControlAdapter;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::rtpengine::NgFlags;

fn channel() -> ChannelRef {
    ChannelRef {
        channel_id: "ch-split".to_string(),
        call_actor_id: "call-uuid".to_string(),
        sip_call_id: "split-cid@host".to_string(),
        app: "ivr-app".to_string(),
    }
}

fn refusal(result: &ControlResult) -> (ControlErrorCode, String, serde_json::Value) {
    match result {
        ControlResult::Error {
            code,
            message,
            details,
        } => (
            *code,
            message.clone(),
            details.clone().unwrap_or(serde_json::Value::Null),
        ),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[test]
fn split_is_a_stream_mode() {
    assert_eq!(
        parse_stream_mode(Some(&json!("split")), "stream_start"),
        Ok(StreamMode::Split)
    );
    let refused = parse_stream_mode(Some(&json!("sideways")), "stream_start");
    let ControlResult::Error { message, .. } = refused.expect_err("not a mode") else {
        panic!("a typed error");
    };
    assert!(message.contains("tee/bridge/split"), "{message}");
}

/// A rate the engine does not serve is refused here with the rule, before the
/// call is looked up.
#[tokio::test]
async fn a_split_refuses_a_rate_the_engine_does_not_serve() {
    for rate in [json!(44_100), json!(0), json!("16000"), json!(-1)] {
        let result = stream_start(
            &channel(),
            &json!({"ws_uri": "wss://bot.example.net/s", "mode": "split", "sample_rate": rate}),
        )
        .await;
        let (code, message, _) = refusal(&result);
        assert_eq!(code, ControlErrorCode::BadRequest, "{rate}: {message}");
        assert!(message.contains("sample_rate"), "{message}");
        assert!(message.contains("8000"), "{message}");
    }
}

/// What shapes a tee or a takeover is not a split's: refused rather than
/// silently dropped.
#[tokio::test]
async fn a_split_refuses_the_arguments_of_the_other_modes() {
    for (name, value) in [
        ("direction", json!("both")),
        ("channels", json!(2)),
        ("profile", json!("voice_ai")),
        ("media_flags", json!({"noise_suppression": true})),
    ] {
        let mut args = json!({"ws_uri": "wss://bot.example.net/s", "mode": "split"});
        args[name] = value;
        let result = stream_start(&channel(), &args).await;
        let (code, message, _) = refusal(&result);
        assert_eq!(code, ControlErrorCode::BadRequest, "{name}: {message}");
        assert!(message.contains("mode=split"), "{name}: {message}");
    }
}

/// And the split's own party profiles are refused on the modes that have no
/// parties to name.
#[tokio::test]
async fn a_tee_and_a_bridge_refuse_party_profiles() {
    for mode in ["tee", "bridge"] {
        for name in ["offerer_profile", "answerer_profile"] {
            let mut args = json!({"ws_uri": "wss://bot.example.net/s", "mode": mode});
            args[name] = json!("voice_ai");
            let result = stream_start(&channel(), &args).await;
            let (code, message, _) = refusal(&result);
            assert_eq!(
                code,
                ControlErrorCode::BadRequest,
                "{mode} {name}: {message}"
            );
            assert!(
                message.contains("mode=split only"),
                "{mode} {name}: {message}"
            );
        }
    }
}

#[tokio::test]
async fn a_party_profile_must_name_a_profile_this_deployment_has() {
    let result = stream_start(
        &channel(),
        &json!({"ws_uri": "wss://bot.example.net/s", "mode": "split",
                "offerer_profile": "no_such_profile"}),
    )
    .await;
    let (code, _message, details) = refusal(&result);
    assert_eq!(code, ControlErrorCode::BadRequest);
    assert_eq!(details["argument"], "offerer_profile");
    assert_eq!(details["reason"], "unknown_profile");

    let result = stream_start(
        &channel(),
        &json!({"ws_uri": "wss://bot.example.net/s", "mode": "split", "answerer_profile": 7}),
    )
    .await;
    let (code, message, _) = refusal(&result);
    assert_eq!(code, ControlErrorCode::BadRequest);
    assert!(message.contains("answerer_profile"), "{message}");
}

/// Well-formed arguments get as far as the call's media, of which a unit test
/// has none.
#[tokio::test]
async fn a_well_formed_split_looks_for_the_calls_media() {
    let result = stream_start(
        &channel(),
        &json!({"ws_uri": "wss://bot.example.net/s", "mode": "split", "sample_rate": 24_000}),
    )
    .await;
    assert_eq!(refusal(&result).0, ControlErrorCode::NotFound);
}

fn request(sample_rate: Option<u32>) -> SplitRequest {
    SplitRequest {
        ws_uri: "wss://bot.example.net/s".to_string(),
        sample_rate,
        offerer_profile: Some(NgFlags {
            noise_suppression: true,
            ..NgFlags::default()
        }),
        answerer_profile: None,
    }
}

#[tokio::test]
async fn an_attach_and_a_detach_reach_the_engine() {
    let engine = NativeTestEngine::start_with_ws_split().await;
    engine.admit("split-cid@host");
    let backend = engine.backend();

    let attached = attach_split(
        &backend,
        "split-cid@host",
        "tag-a",
        &channel(),
        &request(Some(24_000)),
    )
    .await;
    assert_eq!(
        attached,
        ControlResult::Ok(json!({"channel": "ch-split", "state": "split"}))
    );
    let sent = engine.commands("attach_ws_split");
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].call_id, "split-cid@host");
    assert_eq!(sent[0].from_tag, "tag-a");
    assert_eq!(sent[0].detail.as_deref(), Some("wss://bot.example.net/s"));
    assert_eq!(sent[0].sample_rate, Some(24_000));
    assert!(sent[0]
        .profile
        .as_ref()
        .is_some_and(|profile| profile.noise_suppression));
    assert_eq!(engine.split_count(), 1);

    let detached = detach_split(&backend, "split-cid@host", "tag-a", &channel()).await;
    assert_eq!(
        detached,
        ControlResult::Ok(json!({"channel": "ch-split", "state": "detached"}))
    );
    assert_eq!(engine.split_count(), 0);
}

/// The engine's refusal comes back with its token as typed details, and the
/// text whole.
#[tokio::test]
async fn an_engine_refusal_keeps_its_token() {
    let engine = NativeTestEngine::start_with_ws_split().await;
    engine.admit("split-cid@host");
    let backend = engine.backend();
    attach_split(
        &backend,
        "split-cid@host",
        "tag-a",
        &channel(),
        &request(None),
    )
    .await;

    let again = attach_split(
        &backend,
        "split-cid@host",
        "tag-a",
        &channel(),
        &request(None),
    )
    .await;
    let (code, message, details) = refusal(&again);
    assert_eq!(code, ControlErrorCode::InvalidState);
    assert!(
        message.contains("attach_ws_split: ws-split-already-bridged: "),
        "{message}"
    );
    assert_eq!(details["token"], "ws-split-already-bridged");

    engine.refuse_next_split("ws-split-profile");
    engine.admit("other-cid@host");
    let profile = attach_split(
        &backend,
        "other-cid@host",
        "tag-a",
        &channel(),
        &request(None),
    )
    .await;
    let (code, _message, details) = refusal(&profile);
    assert_eq!(
        code,
        ControlErrorCode::BadRequest,
        "a bad profile is the controller's"
    );
    assert_eq!(details["token"], "ws-split-profile");
}

/// An engine that does not list `ws_split` is `unsupported_verb`, and nothing
/// reaches it.
#[tokio::test]
async fn an_engine_without_the_feature_is_unsupported() {
    let engine = NativeTestEngine::start().await;
    engine.admit("split-cid@host");
    let backend = engine.backend();

    let attached = attach_split(
        &backend,
        "split-cid@host",
        "tag-a",
        &channel(),
        &request(None),
    )
    .await;
    assert_eq!(refusal(&attached).0, ControlErrorCode::UnsupportedVerb);
    let detached = detach_split(&backend, "split-cid@host", "tag-a", &channel()).await;
    assert_eq!(refusal(&detached).0, ControlErrorCode::UnsupportedVerb);
    assert!(engine.commands("attach_ws_split").is_empty());
    assert!(engine.commands("detach_ws_split").is_empty());
}

#[test]
fn describe_lists_the_split_verb_and_its_events() {
    let schema = super::SipControlAdapter::new().describe();
    for expected in ["WsSplitStarted", "WsSplitEnded"] {
        assert!(
            schema.events.iter().any(|event| event == expected),
            "missing event {expected}"
        );
    }
    let stream_start = schema
        .verbs
        .iter()
        .find(|verb| verb.verb == "stream_start")
        .expect("stream_start is described");
    assert!(stream_start.summary.contains("mode=split"));
}
