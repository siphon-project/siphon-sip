use super::bridge::{bridge_error, bridge_with_bus, unbridge};
use super::call::{answer, drop_result, provisional_state, remove_header};
use super::media::{
    dtmf, hold_result, media_error, parse_play_options, parse_play_source, parse_stream_channels,
    parse_stream_mode, play, play_accept, play_source_kind, record_start, stream_start, stream_uri,
    StreamMode,
};
use super::originate::{
    default_total_timeout, originate, originate_error, originate_with_bus, parse_originate_media,
    parse_originate_target, parse_privacy, parse_session_timer, OriginateTarget,
};
use super::routing::{dial_error, parse_dial_target, parse_route_target, route};
use super::transfer::{
    accept_refer, controller_refer_refused, parse_accept_refer_mode, parse_refer_mode,
    parse_replaces_arg, parse_transfer_dial, refer, reject_refer, replace_error, replace_peer,
    AcceptReferMode,
};
use super::*;
use crate::control::registry::ControlBus;
use std::collections::HashMap;

fn channel() -> ChannelRef {
    ChannelRef {
        channel_id: "ch1".to_string(),
        call_actor_id: "call-uuid".to_string(),
        sip_call_id: "sipcid@host".to_string(),
        app: "ivr-app".to_string(),
    }
}

fn test_origin() -> crate::control::CommandOrigin {
    crate::control::CommandOrigin {
        app: "ivr-app".to_string(),
        conn_id: 1,
    }
}

fn sip_command(verb: &str, args: serde_json::Value) -> ControlResult {
    apply_sip(AdapterCommand {
        verb: verb.to_string(),
        args,
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    })
}

#[test]
fn ring_refuses_a_body_because_sdp_on_an_18x_is_early_media() {
    // RFC 3960 §3.1: SDP on an 18x opens an early-media path. `ring` says it
    // only alerts, so it must refuse rather than quietly put an early-media
    // offer on the wire under that name.
    for args in [
        serde_json::json!({ "body": "v=0\r\n" }),
        serde_json::json!({ "content_type": "application/sdp" }),
    ] {
        let result = sip_command("ring", args);
        let ControlResult::Error { code, message, .. } = result else {
            panic!("ring with a body must be refused");
        };
        assert_eq!(code, ControlErrorCode::BadRequest);
        assert!(
            message.contains("progress"),
            "the refusal must point at progress: {message}"
        );
    }
}

#[test]
fn ring_reads_an_explicit_null_body_as_absent() {
    // Most clients spell "not set" as an explicit JSON null; refusing that
    // would make `ring` unusable from a client that always sends the key.
    // With no dispatcher installed the call store is empty, so reaching
    // not_found proves the arg check let it through.
    let result = sip_command(
        "ring",
        serde_json::json!({ "body": null, "content_type": null }),
    );
    assert!(
        matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ),
        "a null body must read as absent and let ring reach the call store"
    );
}

#[test]
fn stream_mode_defaults_to_tee_and_rejects_anything_else() {
    // Absent and null both mean tee — every controller written before the
    // bridge existed keeps working, and tee is the safe default of the two
    // since a caller who meant tee and got bridge would have the call's
    // audio path silently replaced.
    assert_eq!(parse_stream_mode(None, "stream_start"), Ok(StreamMode::Tee));
    assert_eq!(
        parse_stream_mode(Some(&serde_json::Value::Null), "stream_start"),
        Ok(StreamMode::Tee)
    );
    assert_eq!(
        parse_stream_mode(Some(&serde_json::json!("tee")), "stream_start"),
        Ok(StreamMode::Tee)
    );
    assert_eq!(
        parse_stream_mode(Some(&serde_json::json!("bridge")), "stream_start"),
        Ok(StreamMode::Bridge)
    );

    // An unknown or wrongly-typed mode is refused rather than defaulted:
    // silently treating "bridged" as a tee would leave the controller
    // believing it had taken the call over.
    for bad in [
        serde_json::json!("bridged"),
        serde_json::json!("takeover"),
        serde_json::json!(""),
        serde_json::json!(1),
        serde_json::json!(true),
    ] {
        let result = parse_stream_mode(Some(&bad), "stream_start");
        assert!(
            matches!(
                result,
                Err(ControlResult::Error {
                    code: ControlErrorCode::BadRequest,
                    ..
                })
            ),
            "{bad} must be refused, got {result:?}"
        );
    }
}

/// `stream_start` expands its `ws_uri` like every other path that hands the
/// engine one: `{call_id}` is the channel's SIP Call-ID.
#[test]
fn stream_start_expands_the_uri_for_the_channels_call() {
    let uri = stream_uri(
        "wss://asr.example.test/{call_id}/{from_tag}?from={from_user}",
        "sipcid@host",
        "caller-tag",
        (Some("1001".to_string()), None),
    )
    .expect("expands");
    assert_eq!(
        uri,
        "wss://asr.example.test/sipcid@host/caller-tag?from=1001"
    );
    // No placeholder: passed through as written.
    assert_eq!(
        stream_uri("wss://asr.example.test/s", "sipcid@host", "t", (None, None))
            .expect("untouched"),
        "wss://asr.example.test/s"
    );
    // A misspelt placeholder, or one this call has no value for, is refused.
    for template in [
        "wss://asr.example.test/{callid}",
        "wss://asr.example.test/{to_user}",
    ] {
        assert!(
            matches!(
                stream_uri(
                    template,
                    "sipcid@host",
                    "t",
                    (Some("1001".to_string()), None)
                ),
                Err(ControlResult::Error {
                    code: ControlErrorCode::BadRequest,
                    ..
                })
            ),
            "{template} must be refused"
        );
    }
}

#[test]
fn provisional_state_matches_the_originate_side_vocabulary() {
    // The callee-side ChannelStateChange already splits these two by whether
    // the 1xx carried a body; the verb reply must use the identical rule, or
    // an app needs a second mapping for the same distinction. The old reply
    // said "ringing" for every provisional, including a 183 with early media.
    assert_eq!(provisional_state(false), "ringing");
    assert_eq!(provisional_state(true), "progress");
}

#[test]
fn play_accept_publishes_a_start_event_carrying_the_engines_handle() {
    use crate::rtpengine::client::PlayMediaSource;
    use crate::rtpengine::siphon_rtp::PlayMediaOutcome;

    let (reply, started) = play_accept(
        "ch1",
        &PlayMediaSource::File("/prompts/welcome.wav".to_string()),
        Ok(PlayMediaOutcome {
            play_id: Some(7),
            duration_ms: Some(1500),
        }),
    );
    let ControlResult::Ok(value) = reply else {
        panic!("an accepted play must reply ok");
    };
    assert_eq!(value["state"], "playing");
    assert_eq!(value["play_id"], 7);
    assert_eq!(value["duration_ms"], 1500);

    let started = started.expect("an accepted play must publish a start event");
    assert_eq!(started["play_id"], 7);
    assert_eq!(started["duration_ms"], 1500);
    assert_eq!(started["source"], "file");
}

#[test]
fn play_accept_omits_a_handle_the_engine_never_assigned() {
    use crate::rtpengine::client::PlayMediaSource;
    use crate::rtpengine::siphon_rtp::PlayMediaOutcome;

    // rtpengine / rtpproxy assign no play_id and a fetched source has no
    // known length at accept time. Both are omitted rather than faked — a
    // fabricated `play_id: 0` is a handle a later `stop` would aim at the
    // wrong playback.
    let (reply, started) = play_accept(
        "ch1",
        &PlayMediaSource::Http("https://example.com/prompt.wav".to_string()),
        Ok(PlayMediaOutcome {
            play_id: None,
            duration_ms: None,
        }),
    );
    let ControlResult::Ok(value) = reply else {
        panic!("an accepted play must reply ok");
    };
    assert!(value.get("play_id").is_none());
    assert!(value.get("duration_ms").is_none());
    let started = started.expect("a play with no handle still started");
    assert!(started.get("play_id").is_none());
    assert!(started.get("duration_ms").is_none());
    assert_eq!(started["source"], "url");
}

#[test]
fn play_the_backend_refuses_publishes_no_start_event() {
    use crate::rtpengine::client::PlayMediaSource;

    // The negative that makes the start event worth having: a playback that
    // never began must produce no PlayStarted, so "no start event yet" reads
    // as "not started" and never as "started, silently".
    let (reply, started) = play_accept(
        "ch1",
        &PlayMediaSource::File("/prompts/missing.wav".to_string()),
        Err(crate::rtpengine::RtpEngineError::Unsupported {
            operation: "play_media",
            backend: "rtpproxy",
        }),
    );
    assert!(
        matches!(reply, ControlResult::Error { .. }),
        "a refused play must answer with a typed error"
    );
    assert!(
        started.is_none(),
        "a play that never started must publish no start event"
    );
}

#[test]
fn play_source_kind_names_every_source() {
    use crate::rtpengine::client::PlayMediaSource;
    assert_eq!(
        play_source_kind(&PlayMediaSource::File("/a.wav".into())),
        "file"
    );
    assert_eq!(
        play_source_kind(&PlayMediaSource::Blob(vec![0u8; 2])),
        "blob"
    );
    assert_eq!(play_source_kind(&PlayMediaSource::DbId(3)), "db_id");
    assert_eq!(
        play_source_kind(&PlayMediaSource::Tone("ringback_eu".into())),
        "tone"
    );
    assert_eq!(
        play_source_kind(&PlayMediaSource::Http("https://h/x.wav".into())),
        "url"
    );
}

fn originate_command(args: serde_json::Value) -> AdapterCommand {
    AdapterCommand {
        verb: "originate".to_string(),
        args,
        target: ResolvedTarget::None,
        origin: test_origin(),
    }
}

/// Run `originate` against a fresh bus with a live owning connection, so a
/// test exercises the argument rules rather than the "no control plane"
/// short-circuit.
fn originate_args(args: serde_json::Value) -> ControlResult {
    let bus = test_bus();
    let conn = bus.register_connection("ivr-app");
    let mut command = originate_command(args);
    command.origin.conn_id = conn.id;
    originate_with_bus(&bus, command)
}

#[test]
fn module_is_sip() {
    assert_eq!(SipControlAdapter::new().module(), "sip");
}

// --- originate ---------------------------------------------------------

#[test]
fn originate_without_a_channel_id_is_bad_request() {
    // The id is the caller's to choose; siphon never mints one, so its
    // absence is a malformed command rather than a defaulted call.
    let result =
        originate_args(serde_json::json!({ "to": "sip:1@carrier.example", "media": true }));
    match result {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert!(message.contains("args.channel"), "message was: {message}");
        }
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[test]
fn originate_with_an_empty_channel_id_is_bad_request() {
    let result = originate_args(serde_json::json!({
        "channel": "   ",
        "to": "sip:1@carrier.example",
        "media": true,
    }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn originate_without_a_target_is_bad_request() {
    let result = originate_args(serde_json::json!({ "channel": "cb-1", "media": true }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn originate_without_a_media_plan_is_bad_request() {
    // An INVITE with no offer and no anchor cannot answer the callee's 2xx
    // offer (RFC 3261 §13.2.2.4) — that would connect a call with no audio.
    let result = originate_args(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
    }));
    match result {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert!(message.contains("media plan"), "message was: {message}");
        }
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[test]
fn originate_with_both_media_plans_is_bad_request() {
    let result = originate_args(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
        "sdp": "v=0\r\n",
        "media": true,
    }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn originate_with_a_bad_privacy_value_is_bad_request() {
    let result = originate_args(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
        "media": true,
        "privacy": "maybe",
    }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn originate_refuses_the_unimplemented_on_lost_fallback_policy() {
    // `fallback` would re-dispatch the call through the Python handlers, which
    // was never built: the control-loss path ends the call for every policy
    // that is not `continue`. Config load refuses it, so the verb that carries
    // it per call has to as well — otherwise a controller asking to keep its
    // calls alive when it dies gets them hung up, on every call.
    let result = originate_args(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
        "media": true,
        "on_lost": "fallback",
    }));
    match result {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_eq!(code, ControlErrorCode::BadRequest, "message was: {message}");
            assert!(
                message.contains("fallback") && message.contains("not implement"),
                "the refusal must say fallback is not implemented: {message}"
            );
            assert!(
                message.contains("hangup") && message.contains("continue"),
                "and name the policies that do exist: {message}"
            );
        }
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[test]
fn originate_accepts_the_implemented_control_loss_policies() {
    // The guard must refuse the policy that does not exist without refusing the
    // two that do; these fail later, on the dispatcher this process does not
    // run, which is a different code.
    for policy in ["hangup", "continue"] {
        let result = originate_args(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
            "media": true,
            "on_lost": policy,
        }));
        assert!(
            !matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::BadRequest,
                    ..
                }
            ),
            "on_lost {policy} must not be refused as malformed: {result:?}"
        );
    }
}

fn test_bus() -> std::sync::Arc<ControlBus> {
    use crate::config::ControlAppConfig;
    let (command_tx, _rx) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![ControlAppConfig {
            name: "ivr-app".to_string(),
            token: "tok".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: Some("hangup".to_string()),
            ca_file: None,
            events: Vec::new(),
        }],
        64,
        crate::control::SlowConsumerPolicy::DropOldest,
        10,
        3000,
    )
}

#[test]
fn originate_rejects_a_duplicate_caller_supplied_id_with_conflict() {
    // The caller owns the id, so a collision has to be told apart from a
    // malformed command: retrying the same id can never succeed, and
    // silently re-pointing it at a second call would strand the first.
    let bus = test_bus();
    let conn = bus.register_connection("ivr-app");
    bus.register_channel(
        "cb-1",
        &conn,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );

    let mut command = originate_command(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
        "media": true,
    }));
    command.origin.conn_id = conn.id;
    let result = originate_with_bus(&bus, command);
    match result {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_eq!(code, ControlErrorCode::Conflict, "message was: {message}");
            assert!(message.contains("cb-1"), "message was: {message}");
        }
        other => panic!("expected conflict, got {other:?}"),
    }
}

#[test]
fn originate_from_a_dead_connection_is_unavailable() {
    // Nothing would own the resulting channel, so it must fail before an
    // INVITE goes out — an ownerless channel is a leak with a live call
    // behind it.
    let bus = test_bus();
    let mut command = originate_command(serde_json::json!({
        "channel": "cb-ghost",
        "to": "sip:1@carrier.example",
        "media": true,
    }));
    command.origin.conn_id = 99;
    assert!(matches!(
        originate_with_bus(&bus, command),
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
    assert!(
        !bus.channel_exists("cb-ghost"),
        "a refused originate must register no channel"
    );
}

#[test]
fn a_refused_originate_registers_no_channel() {
    // The dispatcher is not running in this process, so prepare fails; the
    // caller's id must be left free for a retry.
    let bus = test_bus();
    let conn = bus.register_connection("ivr-app");
    let mut command = originate_command(serde_json::json!({
        "channel": "cb-2",
        "to": "sip:1@carrier.example",
        "media": true,
    }));
    command.origin.conn_id = conn.id;
    let result = originate_with_bus(&bus, command);
    assert!(
        matches!(result, ControlResult::Error { .. }),
        "got {result:?}"
    );
    assert!(!bus.channel_exists("cb-2"));
}

#[test]
fn originate_without_a_control_bus_is_unavailable_not_a_hollow_ok() {
    // No process-global bus in the unit-test process: the command must
    // answer, and must not answer "ok" for a call nothing would own.
    let result = originate(originate_command(serde_json::json!({
        "channel": "cb-1",
        "to": "sip:1@carrier.example",
        "media": true,
    })));
    assert!(
        matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ),
        "got {result:?}"
    );
}

#[tokio::test]
async fn originate_dispatches_through_apply_as_a_module_level_verb() {
    // No channel target: `originate` creates the channel rather than
    // addressing one, so it must not be rejected for a missing target.
    let adapter = SipControlAdapter::new();
    let result = adapter
        .apply(originate_command(serde_json::json!({
            "channel": "cb-1", "to": "sip:1@carrier.example", "media": true
        })))
        .await;
    match result {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_ne!(
                code,
                ControlErrorCode::BadRequest,
                "originate must not be rejected for the missing channel target: {message}"
            );
        }
        other => panic!("expected an error from the un-booted stack, got {other:?}"),
    }
}

#[test]
fn parse_session_timer_reads_absent_as_none_and_defaults_each_key_left_out() {
    use crate::b2bua::session_timer::SessionTimerOverride;
    use crate::config::SessionRefresher;

    // Absent or null runs the configured timer, if any: no override.
    assert_eq!(parse_session_timer(None), Ok(None));
    assert_eq!(
        parse_session_timer(Some(&serde_json::Value::Null)),
        Ok(None)
    );
    // Keys left out default as in call.session_timer().
    assert_eq!(
        parse_session_timer(Some(&serde_json::json!({}))),
        Ok(Some(SessionTimerOverride {
            session_expires: 1800,
            min_se: 90,
            refresher: SessionRefresher::B2bua,
        }))
    );
    assert_eq!(
        parse_session_timer(Some(&serde_json::json!({
            "expires": 900, "min_se": 120, "refresher": "UAS"
        }))),
        Ok(Some(SessionTimerOverride {
            session_expires: 900,
            min_se: 120,
            refresher: SessionRefresher::Uas,
        }))
    );
}

#[test]
fn parse_originate_media_variants() {
    use crate::dispatcher::OriginateMedia;
    assert_eq!(
        parse_originate_media(&serde_json::json!({ "sdp": "v=0\r\n" })),
        Ok(OriginateMedia::Offer {
            body: b"v=0\r\n".to_vec(),
            content_type: "application/sdp".to_string(),
        })
    );
    assert_eq!(
        parse_originate_media(&serde_json::json!({ "media": true })),
        Ok(OriginateMedia::Anchor {
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
        })
    );
    assert_eq!(
        parse_originate_media(&serde_json::json!({
            "media": true, "profile": "voice_ai", "ws_uri": "ws://ai.invalid/{call_id}",
        })),
        Ok(OriginateMedia::Anchor {
            profile: "voice_ai".to_string(),
            ws_uri: Some("ws://ai.invalid/{call_id}".to_string()),
        })
    );
    assert!(parse_originate_media(&serde_json::json!({})).is_err());
    assert!(parse_originate_media(&serde_json::json!({ "sdp": "" })).is_err());
    assert!(parse_originate_media(&serde_json::json!({ "sdp": "v=0", "media": true })).is_err());
}

#[test]
fn parse_originate_media_takes_a_body_with_its_own_content_type() {
    // RFC 5621 §3: the offer may ride as one part of a multipart body. The
    // controller assembles that body and names its type; siphon carries it.
    use crate::dispatcher::OriginateMedia;
    assert_eq!(
        parse_originate_media(&serde_json::json!({
            "body": "--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--\r\n",
            "content_type": "multipart/mixed;boundary=b",
        })),
        Ok(OriginateMedia::Offer {
            body: b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n--b--\r\n".to_vec(),
            content_type: "multipart/mixed;boundary=b".to_string(),
        })
    );
    // A body with no content_type is SDP, exactly like args.sdp.
    assert_eq!(
        parse_originate_media(&serde_json::json!({ "body": "v=0\r\n" })),
        Ok(OriginateMedia::Offer {
            body: b"v=0\r\n".to_vec(),
            content_type: "application/sdp".to_string(),
        })
    );

    // Two spellings of the same slot, an empty body, a content_type with no
    // body to describe, and a content_type contradicting args.sdp are each
    // a malformed request rather than a guess.
    assert!(
        parse_originate_media(&serde_json::json!({ "sdp": "v=0\r\n", "body": "v=0\r\n" })).is_err()
    );
    assert!(parse_originate_media(&serde_json::json!({ "body": "  " })).is_err());
    assert!(parse_originate_media(&serde_json::json!({ "body": "v=0", "media": true })).is_err());
    assert!(parse_originate_media(
        &serde_json::json!({ "media": true, "content_type": "application/sdp" })
    )
    .is_err());
    assert!(parse_originate_media(
        &serde_json::json!({ "sdp": "v=0", "content_type": "multipart/mixed;boundary=b" })
    )
    .is_err());
}

#[test]
fn originate_error_maps_an_invalid_body_to_bad_request() {
    // A body that carries no offer is the caller's frame to fix, not a
    // missing resource and not a backend that cannot do it.
    use crate::dispatcher::OriginateError;
    match originate_error(OriginateError::InvalidBody(
        "Content-Type 'text/plain' is neither application/sdp nor a multipart body carrying one"
            .to_string(),
    )) {
        ControlResult::Error {
            code, ref message, ..
        } => {
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert!(message.contains("text/plain"), "message was: {message}");
        }
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[test]
fn parse_privacy_variants() {
    use crate::sip::privacy::CallerIdPresentation;
    assert_eq!(parse_privacy("originate", None), Ok(None));
    assert_eq!(
        parse_privacy("originate", Some(&serde_json::Value::Null)),
        Ok(None)
    );
    assert_eq!(
        parse_privacy("originate", Some(&serde_json::json!("restricted"))),
        Ok(Some(CallerIdPresentation::Restricted))
    );
    assert_eq!(
        parse_privacy("originate", Some(&serde_json::json!("allowed"))),
        Ok(Some(CallerIdPresentation::Allowed))
    );
    assert!(parse_privacy("originate", Some(&serde_json::json!("sideways"))).is_err());
    assert!(parse_privacy("originate", Some(&serde_json::json!(1))).is_err());
}

#[test]
fn originate_error_maps_each_cause_to_its_own_code() {
    use crate::dispatcher::OriginateError;
    // Requirement: unknown target / bad argument / backend-cannot / stack-down
    // must each be separately actionable on the wire.
    assert!(matches!(
        originate_error(OriginateError::InvalidUri {
            field: "to",
            detail: "nope".to_string()
        }),
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
    assert!(matches!(
        originate_error(OriginateError::Unroutable("no route".to_string())),
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
    assert!(matches!(
        originate_error(OriginateError::Unsupported("no answer_local".to_string())),
        ControlResult::Error {
            code: ControlErrorCode::UnsupportedVerb,
            ..
        }
    ));
    assert!(matches!(
        originate_error(OriginateError::Unavailable("down".to_string())),
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
    assert!(matches!(
        originate_error(OriginateError::BuildFailed("bad".to_string())),
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
}

#[test]
fn string_arg_treats_empty_as_absent() {
    let args = serde_json::json!({ "from": "", "from_display": "Support", "x": 7 });
    assert_eq!(string_arg(&args, "from"), None);
    assert_eq!(
        string_arg(&args, "from_display"),
        Some("Support".to_string())
    );
    assert_eq!(string_arg(&args, "x"), None);
    assert_eq!(string_arg(&args, "missing"), None);
}

#[test]
fn describe_lists_core_verbs() {
    let schema = SipControlAdapter::new().describe();
    assert_eq!(schema.module, "sip");
    let verbs: Vec<&str> = schema.verbs.iter().map(|v| v.verb.as_str()).collect();
    for expected in [
        "answer",
        "ring",
        "progress",
        "reject",
        "hangup",
        "drop",
        "refer",
        "accept_refer",
        "reject_refer",
        "route",
        "set_header",
        "remove_header",
        "get_header",
        "play",
        "stop",
        "dtmf",
        "hold",
        "unhold",
        "stream_start",
        "stream_stop",
        "bridge",
        "unbridge",
    ] {
        assert!(verbs.contains(&expected), "missing verb {expected}");
    }
    let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
    for expected in [
        "StasisStart",
        "StasisEnd",
        "ChannelStateChange",
        "ChannelDtmfReceived",
        "PlayStarted",
        "TransferRequested",
        "TransferProgress",
        "TransferCompleted",
        "TransferFailed",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
}

/// The direction and channel selectors are closed sets: an unknown value
/// silently defaulting would record the wrong audio, and nobody finds out
/// until they play the file back.
#[tokio::test]
async fn record_start_rejects_unknown_selectors() {
    let channel = channel();
    for (key, value) in [("direction", "inbound"), ("channels", "quad")] {
        let result = record_start(&channel, &serde_json::json!({ key: value })).await;
        match result {
            ControlResult::Error { code, message, .. } => {
                assert_eq!(
                    code,
                    ControlErrorCode::BadRequest,
                    "{key}={value}: {message}"
                );
                assert!(message.contains(value), "{message}");
            }
            other => panic!("{key}={value} should be a bad request, got {other:?}"),
        }
    }
}

/// With no media session there is nothing to record; the typed `not_found`
/// is what tells an app to anchor the leg first rather than retry.
#[tokio::test]
async fn record_start_without_media_is_not_found() {
    let channel = channel();
    match record_start(&channel, &serde_json::json!({})).await {
        ControlResult::Error { code, .. } => {
            assert!(
                matches!(
                    code,
                    ControlErrorCode::NotFound | ControlErrorCode::Unavailable
                ),
                "unexpected code {code:?}"
            );
        }
        other => panic!("expected a typed error, got {other:?}"),
    }
}

#[test]
fn ring_and_progress_are_separate_verbs_in_the_schema() {
    // The declared schema is the only thing an app can discover the surface
    // from (`describe`), so the split has to be visible there: one verb that
    // says it only alerts, one that says it can open early media. A single
    // "1xx / early media" verb leaves the app guessing at status codes.
    let schema = SipControlAdapter::new().describe();
    let find = |name: &str| {
        schema
            .verbs
            .iter()
            .find(|verb| verb.verb == name)
            .map(|verb| verb.summary.clone())
            .unwrap_or_default()
    };
    let ring = find("ring");
    assert!(
        ring.contains("180"),
        "ring must name the status it sends: {ring}"
    );
    assert!(
        ring.contains("no early media") || ring.contains("alerting only"),
        "ring must say it does not open early media: {ring}"
    );
    let progress = find("progress");
    assert!(
        progress.contains("early-media") || progress.contains("early media"),
        "progress must name early media as its job: {progress}"
    );
}

#[test]
fn drop_is_advertised_as_the_verb_that_sends_nothing() {
    // `drop` only earns its place next to `reject` and `hangup` if an app can
    // discover *which* of the three puts nothing on the wire — that is the
    // entire difference between them, and `describe` is the only place an app
    // reads it from.
    let schema = SipControlAdapter::new().describe();
    let summary = schema
        .verbs
        .iter()
        .find(|verb| verb.verb == "drop")
        .map(|verb| verb.summary.clone())
        .expect("the drop verb is advertised");
    assert!(
        summary.contains("NOTHING on the wire"),
        "drop must say it sends nothing: {summary}"
    );
    assert!(
        summary.contains("hangup"),
        "drop must point an answered call at hangup: {summary}"
    );
    // And the classifier has to claim it, or `apply` answers unsupported_verb
    // however complete the handler is (the `record_start` trap).
    assert!(is_sip_verb("drop"));
    assert!(!is_media_verb("drop") && !is_bridge_verb("drop"));
}

#[test]
fn drop_refuses_an_answered_call_naming_the_verb_and_the_state() {
    // The mistake this refusal exists for: reaching for `drop` on a call that is
    // up. RFC 3261 §15 owes that dialog a BYE, so it must be refused rather than
    // orphaned, and the message has to say which verb was wrong and what state
    // the call is in — `invalid_state`, not `bad_request` (the frame is fine) and
    // not `not_found` (the call exists).
    let result = drop_result(&channel(), crate::dispatcher::DropOutcome::Answered);
    let ControlResult::Error { code, message, .. } = result else {
        panic!("drop on an answered call must be refused");
    };
    assert_eq!(code, ControlErrorCode::InvalidState);
    assert!(message.contains("drop"), "{message}");
    assert!(message.contains("answered"), "{message}");
    assert!(
        message.contains("hangup"),
        "the refusal must point at the verb that does work: {message}"
    );
}

#[test]
fn drop_refuses_a_ringing_originate_group_pointing_at_hangup() {
    let result = drop_result(&channel(), crate::dispatcher::DropOutcome::Ringing);
    let ControlResult::Error { code, message, .. } = result else {
        panic!("drop on a ringing originate group must be refused");
    };
    assert_eq!(code, ControlErrorCode::InvalidState);
    assert!(message.contains("hangup"), "{message}");
    assert!(message.contains("CANCEL"), "{message}");
}

#[test]
fn a_dropped_call_reports_that_nothing_was_sent() {
    // The reply is how an app confirms the whole point of the verb, so it says
    // so in a field rather than only in the absence of a `code`.
    let result = drop_result(&channel(), crate::dispatcher::DropOutcome::Dropped);
    let ControlResult::Ok(body) = result else {
        panic!("a dropped call must answer ok, got {result:?}");
    };
    assert_eq!(body["channel"], serde_json::json!("ch1"));
    assert_eq!(body["state"], serde_json::json!("terminated"));
    assert_eq!(body["response_sent"], serde_json::json!(false));
    assert!(
        body.get("code").is_none(),
        "a drop sent no response, so it must claim no status code: {body}"
    );
}

#[test]
fn drop_on_a_call_that_is_gone_is_not_found() {
    // With no dispatcher installed the call store is empty, which is the same
    // shape as a call that ended while the controller was deciding: a typed
    // not_found, never a hang and never a silent Ok for a call nobody dropped.
    let result = sip_command("drop", serde_json::json!({ "reason": "unsolicited" }));
    let ControlResult::Error { code, message, .. } = result else {
        panic!("drop on a missing call must be refused");
    };
    assert_eq!(code, ControlErrorCode::NotFound);
    assert_eq!(message, "call is gone");
}

#[test]
fn drop_refuses_a_ban_that_is_not_a_boolean() {
    // `"true"` read as false would drop the call and ban nothing while the
    // controller believed it had banned the source.
    let result = sip_command(
        "drop",
        serde_json::json!({ "reason": "unsolicited", "ban": "true" }),
    );
    let ControlResult::Error { code, message, .. } = result else {
        panic!("a non-boolean ban must be refused, got {result:?}");
    };
    assert_eq!(code, ControlErrorCode::BadRequest);
    assert_eq!(message, "ban must be a boolean");

    // Positive control: a boolean ban gets past the argument check and reaches
    // the dispatcher, which reports the (absent) call as gone.
    let result = sip_command(
        "drop",
        serde_json::json!({ "reason": "unsolicited", "ban": true }),
    );
    let ControlResult::Error { code, .. } = result else {
        panic!("drop on a missing call must be refused");
    };
    assert_eq!(code, ControlErrorCode::NotFound);
}

#[test]
fn refer_reply_reports_only_local_acceptance() {
    // The command/event split, asserted rather than assumed: the `refer`
    // verb's summary must promise the outcome as an event, because the reply
    // can only report that siphon sent the REFER. RFC 3515 §2.4.4 puts the
    // real verdict on the implicit subscription, which arrives later.
    let schema = SipControlAdapter::new().describe();
    let refer = schema
        .verbs
        .iter()
        .find(|verb| verb.verb == "refer")
        .expect("refer verb");
    assert!(
        refer.summary.contains("TransferCompleted") && refer.summary.contains("TransferFailed"),
        "the refer verb must point at its outcome events, got: {}",
        refer.summary
    );
}

#[test]
fn verb_without_channel_target_is_bad_request() {
    let result = apply_sip(AdapterCommand {
        verb: "answer".to_string(),
        args: serde_json::json!({}),
        target: ResolvedTarget::None,
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn unknown_verb_is_unsupported() {
    let result = apply_sip(AdapterCommand {
        verb: "teleport".to_string(),
        args: serde_json::json!({}),
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::UnsupportedVerb,
            ..
        }
    ));
}

// -----------------------------------------------------------------------
// bridge / unbridge
// -----------------------------------------------------------------------

fn bridge_command(args: serde_json::Value) -> AdapterCommand {
    AdapterCommand {
        verb: "bridge".to_string(),
        args,
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    }
}

/// A bus with `ch1` (the target) and `ch2` (the `with` leg) both owned by
/// the commanding connection.
fn bus_with_two_owned_channels() -> (std::sync::Arc<ControlBus>, u64) {
    let bus = test_bus();
    let conn = bus.register_connection("ivr-app");
    bus.register_channel(
        "ch1",
        &conn,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );
    bus.register_channel(
        "ch2",
        &conn,
        "call-uuid-2",
        "sipcid2@host",
        "hangup",
        HashMap::new(),
    );
    let conn_id = conn.id;
    (bus, conn_id)
}

fn error_code(result: &ControlResult) -> Option<ControlErrorCode> {
    match result {
        ControlResult::Error { code, .. } => Some(*code),
        ControlResult::Ok(_) => None,
    }
}

#[tokio::test]
async fn bridge_without_a_second_leg_is_a_bad_request() {
    let (bus, conn_id) = bus_with_two_owned_channels();
    let mut command = bridge_command(serde_json::json!({}));
    command.origin.conn_id = conn_id;
    let result = bridge_with_bus(&bus, &channel(), &command).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));

    let mut command = bridge_command(serde_json::json!({ "with": "   " }));
    command.origin.conn_id = conn_id;
    let result = bridge_with_bus(&bus, &channel(), &command).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
}

#[tokio::test]
async fn bridging_a_channel_to_itself_is_a_bad_request_not_a_not_found() {
    // Naming the same leg twice is a well-formed frame that is not a bridge.
    // It must read differently from "no such leg" and from "wrong state".
    let (bus, conn_id) = bus_with_two_owned_channels();
    let mut command = bridge_command(serde_json::json!({ "with": "ch1" }));
    command.origin.conn_id = conn_id;
    let result = bridge_with_bus(&bus, &channel(), &command).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
    match result {
        ControlResult::Error { message, .. } => {
            assert!(message.contains("itself"), "{message}");
        }
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test]
async fn bridging_to_an_unknown_channel_is_not_found() {
    let (bus, conn_id) = bus_with_two_owned_channels();
    let mut command = bridge_command(serde_json::json!({ "with": "ch-nope" }));
    command.origin.conn_id = conn_id;
    let result = bridge_with_bus(&bus, &channel(), &command).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::NotFound));
}

#[tokio::test]
async fn bridging_to_another_apps_channel_is_forbidden() {
    // One app must never be able to join another app's call to its own.
    let bus = test_bus();
    let mine = bus.register_connection("ivr-app");
    let theirs = bus.register_connection("edge-app");
    bus.register_channel(
        "ch1",
        &mine,
        "call-uuid",
        "sipcid@host",
        "hangup",
        HashMap::new(),
    );
    bus.register_channel(
        "ch2",
        &theirs,
        "other-uuid",
        "other@host",
        "hangup",
        HashMap::new(),
    );
    let mut command = bridge_command(serde_json::json!({ "with": "ch2" }));
    command.origin.conn_id = mine.id;
    let result = bridge_with_bus(&bus, &channel(), &command).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::Forbidden));
}

#[tokio::test]
async fn an_unrecognised_peer_hangup_policy_is_refused_never_defaulted() {
    // Guessing at a teardown policy is how a survivor gets stranded (or
    // hung up when the controller wanted to keep it).
    let (bus, conn_id) = bus_with_two_owned_channels();
    for bad in [serde_json::json!("continue"), serde_json::json!(7)] {
        let mut command =
            bridge_command(serde_json::json!({ "with": "ch2", "on_peer_hangup": bad }));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
    }
}

#[tokio::test]
async fn a_well_formed_bridge_reaches_the_dispatcher_and_never_answers_ok_without_one() {
    // Both legs resolve and are owned, so the verb gets past every argument
    // gate and calls into the B2BUA. With no dispatcher installed in a unit
    // -test binary that is a typed `unavailable` — never a hollow ok.
    let (bus, conn_id) = bus_with_two_owned_channels();
    for policy in [
        serde_json::json!("hangup"),
        serde_json::json!("hold"),
        serde_json::Value::Null,
    ] {
        let mut command =
            bridge_command(serde_json::json!({ "with": "ch2", "on_peer_hangup": policy }));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::Unavailable));
    }
}

#[tokio::test]
async fn unbridge_without_a_dispatcher_is_unavailable_not_a_hang() {
    let result = unbridge(&channel(), &serde_json::json!({})).await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::Unavailable));
}

#[test]
fn is_bridge_verb_splits_the_two_leg_verbs_from_the_rest() {
    for verb in ["bridge", "unbridge"] {
        assert!(
            is_bridge_verb(verb),
            "{verb} should route to the bridge path"
        );
    }
    for verb in ["answer", "hangup", "play", "originate", "refer", "route"] {
        assert!(
            !is_bridge_verb(verb),
            "{verb} should NOT route to the bridge path"
        );
    }
    // The bridge verbs must not also be classified as media verbs, or they
    // would run through the single-channel media dispatch.
    assert!(!is_media_verb("bridge"));
    assert!(!is_media_verb("unbridge"));
}

#[test]
fn every_bridge_refusal_has_its_own_wire_code_and_matches_the_shared_token() {
    use crate::b2bua::bridge::BridgeError;
    let cases = [
        (
            BridgeError::UnknownLeg {
                which: "with",
                id: "ch2".to_string(),
            },
            ControlErrorCode::NotFound,
        ),
        (
            BridgeError::SameLeg("ch1".to_string()),
            ControlErrorCode::BadRequest,
        ),
        (
            BridgeError::NotAnswered {
                id: "ch1".to_string(),
                state: "ringing".to_string(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            BridgeError::AlreadyBridged {
                id: "ch1".to_string(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            BridgeError::NotBridged {
                id: "ch1".to_string(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            BridgeError::Glare {
                id: "ch1".to_string(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            BridgeError::NoMediaDescription {
                id: "ch1".to_string(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            BridgeError::Unsupported("no reoffer".to_string()),
            ControlErrorCode::UnsupportedVerb,
        ),
        (
            BridgeError::Unavailable("gone".to_string()),
            ControlErrorCode::Unavailable,
        ),
    ];
    for (error, expected) in cases {
        // The token the in-process rail prefixes its ValueError with has to
        // name the same cause as the wire code, or the two rails disagree
        // about what went wrong.
        let token = error.code();
        let wire = serde_json::to_string(&expected).unwrap_or_default();
        assert_eq!(
            format!("\"{token}\""),
            wire,
            "{error:?}: token {token} vs wire code {wire}"
        );
        assert_eq!(
            error_code(&bridge_error(error.clone())),
            Some(expected),
            "{error:?}"
        );
    }
}

// -----------------------------------------------------------------------
// replace_peer
// -----------------------------------------------------------------------

#[test]
fn replace_peer_without_a_target_is_a_bad_request() {
    // There is no sensible default target, and guessing one would dial
    // somebody. A missing argument is the caller's bug, not the call's.
    let result = replace_peer(&channel(), &serde_json::json!({}));
    assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
}

#[test]
fn replace_peer_validates_both_uris_before_touching_the_call() {
    // Rejected on the frame, so an unparseable URI never reaches the dial
    // path and can never be reported as a routing failure of the call.
    let bad_target = replace_peer(
        &channel(),
        &serde_json::json!({ "target": "not a uri at all" }),
    );
    assert_eq!(error_code(&bad_target), Some(ControlErrorCode::BadRequest));

    let bad_next_hop = replace_peer(
        &channel(),
        &serde_json::json!({
            "target": "sip:agent@example.com",
            "next_hop": "not a uri at all",
        }),
    );
    assert_eq!(
        error_code(&bad_next_hop),
        Some(ControlErrorCode::BadRequest)
    );
}

#[test]
fn replace_peer_rejects_a_nonsense_timeout_rather_than_silently_defaulting() {
    // A negative or absurd timeout means the caller believes something
    // about the ring window that is not true; defaulting it would hide
    // that until a call rang for the wrong length of time.
    for timeout in [serde_json::json!(-5), serde_json::json!("soon")] {
        let result = replace_peer(
            &channel(),
            &serde_json::json!({ "target": "sip:agent@example.com", "timeout": timeout }),
        );
        assert_eq!(
            error_code(&result),
            Some(ControlErrorCode::BadRequest),
            "timeout {timeout} should be refused"
        );
    }
}

#[test]
fn replace_peer_without_a_dispatcher_is_unavailable_not_a_hang() {
    let result = replace_peer(
        &channel(),
        &serde_json::json!({ "target": "sip:agent@example.com" }),
    );
    assert_eq!(error_code(&result), Some(ControlErrorCode::Unavailable));
}

#[test]
fn every_replace_refusal_has_its_own_wire_code_on_the_control_rail() {
    use crate::b2bua::transfer::ReplaceError;
    // The controller branches on these: `not_found` means the call is gone,
    // `invalid_state` means try again later, `bad_request` means fix the
    // frame. Collapsing any two of them makes a retry loop wrong.
    let cases = [
        (
            ReplaceError::UnknownCall { id: "c".into() },
            ControlErrorCode::NotFound,
        ),
        (
            ReplaceError::NotAnswered {
                id: "c".into(),
                state: "ringing".into(),
            },
            ControlErrorCode::InvalidState,
        ),
        (
            ReplaceError::NoPeerLeg { id: "c".into() },
            ControlErrorCode::InvalidState,
        ),
        (
            ReplaceError::ReplacementInFlight { id: "c".into() },
            ControlErrorCode::InvalidState,
        ),
        (
            ReplaceError::Unroutable {
                target: "sip:nowhere".into(),
            },
            ControlErrorCode::BadRequest,
        ),
        (
            ReplaceError::Unavailable("down".into()),
            ControlErrorCode::Unavailable,
        ),
    ];
    for (error, expected) in cases {
        let described = error.to_string();
        assert_eq!(
            error_code(&replace_error(error)),
            Some(expected),
            "wrong wire code for: {described}"
        );
    }
}

#[test]
fn describe_lists_replace_peer_and_both_of_its_outcomes() {
    // The verb's reply says only that the INVITE left the box, so an app
    // that cannot see the outcome events cannot tell a replacement that
    // completed from one still ringing.
    let schema = SipControlAdapter::new().describe();
    assert!(
        schema
            .verbs
            .iter()
            .any(|entry| entry.verb == "replace_peer"),
        "replace_peer missing from the verb schema"
    );
    let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
    for expected in ["PeerReplaced", "ReplaceFailed"] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
}

#[test]
fn describe_lists_the_bridge_events() {
    let schema = SipControlAdapter::new().describe();
    let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
    for expected in ["ChannelBridged", "BridgeFailed", "ChannelUnbridged"] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
}

/// Every event a `dial` reports is discoverable: a controller that cannot find
/// DialBranch in `describe` has no way to learn its legs are named at all.
#[test]
fn describe_lists_the_dial_events() {
    let schema = SipControlAdapter::new().describe();
    let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
    for expected in [
        "DialBranch",
        "DialBranchFailed",
        "DialAnswered",
        "DialFailed",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
}

/// Every WebSocket stream a controller can start over this rail must have
/// its lifecycle on the same rail. `stream_start` shipped before the events
/// did, which left a controller able to start a tee and unable to learn it
/// had stopped — the stream just went quiet.
#[test]
fn describe_lists_a_lifecycle_for_every_stream_mode() {
    let schema = SipControlAdapter::new().describe();
    let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
    for expected in [
        "WsTeeStarted",
        "WsTeeEnded",
        "WsBridgeStarted",
        "WsBridgeEnded",
    ] {
        assert!(events.contains(&expected), "missing event {expected}");
    }
}

/// A transfer an app accepted to carry out and never reported on ends in an
/// event of its own, so it is discoverable next to the verbs that lead to it.
#[test]
fn describe_lists_the_transfer_report_timeout() {
    let schema = SipControlAdapter::new().describe();
    assert!(schema
        .events
        .iter()
        .any(|event| event == "TransferTimedOut"));
}

/// The media engine's summary is published on the rail, so it is discoverable.
#[test]
fn describe_lists_the_media_summary() {
    let schema = SipControlAdapter::new().describe();
    assert!(schema.events.iter().any(|event| event == "MediaSummary"));
}

#[test]
fn every_advertised_verb_is_claimed_by_a_dispatch_table() {
    // The wire-level version of the split test below: `apply` picks a table
    // by classifier, so a verb the schema advertises that no classifier
    // claims is answered `unsupported_verb` no matter how complete its
    // handler is. Caught exactly that on `record_start` / `record_stop`.
    for advertised in SipControlAdapter::new().describe().verbs {
        let verb = advertised.verb.as_str();
        assert!(
            verb == MODULE_VERB || is_bridge_verb(verb) || is_media_verb(verb) || is_sip_verb(verb),
            "describe() advertises '{verb}' but no dispatch table claims it — \
                 apply() would answer unsupported_verb"
        );
    }
}

#[test]
fn every_dispatchable_verb_is_advertised() {
    // The other direction: a verb siphon implements but never describes is
    // one an application cannot discover, so it may as well not exist.
    let advertised: Vec<String> = SipControlAdapter::new()
        .describe()
        .verbs
        .into_iter()
        .map(|verb| verb.verb)
        .collect();
    // Read off the dispatch tables themselves. A list kept here by hand went
    // stale the first time a verb was added without it, and a stale list
    // cannot notice that verb being dropped from describe().
    for verb in dispatch_tables() {
        assert!(
            advertised.iter().any(|name| name == verb),
            "'{verb}' dispatches but describe() never mentions it"
        );
    }
    assert_eq!(
        advertised.len(),
        dispatch_tables().len(),
        "describe() and the dispatch tables name the same verbs, each once"
    );
}

/// Every verb some dispatch table claims.
fn dispatch_tables() -> Vec<&'static str> {
    std::iter::once(MODULE_VERB)
        .chain(BRIDGE_VERBS)
        .chain(MEDIA_VERBS)
        .chain(SIP_VERBS)
        .collect()
}

/// No verb is claimed by two tables: `apply` takes the first classifier that
/// matches, so the second table's handler would never run.
#[test]
fn no_verb_is_claimed_by_two_dispatch_tables() {
    let mut claimed = dispatch_tables();
    claimed.sort_unstable();
    let total = claimed.len();
    claimed.dedup();
    assert_eq!(claimed.len(), total, "a verb sits in two dispatch tables");
    for verb in SIP_VERBS.iter().chain(&BRIDGE_VERBS).chain([&MODULE_VERB]) {
        assert!(!is_media_verb(verb), "{verb} is not a media verb");
    }
}

/// Every advertised verb, and every verb a table claims, sent through `apply`
/// the way a command reaches the adapter, is answered by a handler.
///
/// The classifier tests above compare names with names. This one runs the
/// dispatch: a verb in `describe()` and in a table but with no arm in the
/// table's `match`, or advertised and in no table at all, is answered
/// `unsupported_verb` here, exactly as it would be on the wire. No dispatcher
/// is running, so a real handler refuses for a reason of its own (nothing to
/// act on, a missing argument, no B2BUA), never with that code.
#[tokio::test]
async fn every_advertised_verb_reaches_a_handler_through_apply() {
    let adapter = SipControlAdapter::new();
    let mut verbs: Vec<String> = adapter
        .describe()
        .verbs
        .into_iter()
        .map(|verb| verb.verb)
        .collect();
    verbs.extend(dispatch_tables().into_iter().map(str::to_string));
    verbs.sort_unstable();
    verbs.dedup();
    assert!(verbs.iter().any(|verb| verb == "cancel_dial"));
    for verb in verbs {
        let result = adapter
            .apply(AdapterCommand {
                verb: verb.clone(),
                args: serde_json::json!({}),
                target: ResolvedTarget::Channel(channel()),
                origin: test_origin(),
            })
            .await;
        assert_ne!(
            error_code(&result),
            Some(ControlErrorCode::UnsupportedVerb),
            "'{verb}' is advertised or claimed by a dispatch table, and apply() answers unsupported_verb"
        );
    }
    // Positive control: a verb nobody claims is refused with exactly that code.
    let result = adapter
        .apply(AdapterCommand {
            verb: "teleport".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        })
        .await;
    assert_eq!(error_code(&result), Some(ControlErrorCode::UnsupportedVerb));
}

#[test]
fn is_media_verb_splits_media_from_sip() {
    for verb in [
        "play",
        "stop",
        "dtmf",
        "hold",
        "unhold",
        "stream_start",
        "stream_stop",
        "record_start",
        "record_stop",
    ] {
        assert!(
            is_media_verb(verb),
            "{verb} should route to the async media path"
        );
    }
    for verb in [
        "answer",
        "ring",
        "progress",
        "reject",
        "hangup",
        "drop",
        "refer",
        "accept_refer",
        "reject_refer",
        "route",
        "set_header",
        "remove_header",
        "get_header",
        "collect_dtmf",
        "teleport",
    ] {
        assert!(
            !is_media_verb(verb),
            "{verb} should NOT route to the async media path"
        );
    }
}

#[tokio::test]
async fn media_verbs_without_dispatcher_are_not_found_not_a_hang() {
    // The media verbs now EXIST (they no longer fall to unsupported_verb).
    // With no B2BUA_CONTROL installed, b2bua_media_target() is None, so each
    // resolves to a typed not_found and returns immediately — never a hang,
    // never a fabricated call-id. Args are well-formed so resolution is
    // reached (not short-circuited on a bad_request).
    let cases = [
        (
            "play",
            serde_json::json!({ "file": "/prompts/welcome.wav" }),
        ),
        ("stop", serde_json::json!({})),
        ("dtmf", serde_json::json!({ "digits": "123#" })),
        ("hold", serde_json::json!({})),
        ("unhold", serde_json::json!({})),
        (
            "stream_start",
            serde_json::json!({ "ws_uri": "ws://ai:9000/stream" }),
        ),
        ("stream_stop", serde_json::json!({})),
    ];
    let adapter = SipControlAdapter::new();
    for (verb, args) in cases {
        let result = adapter
            .apply(AdapterCommand {
                verb: verb.to_string(),
                args,
                target: ResolvedTarget::Channel(channel()),
                origin: test_origin(),
            })
            .await;
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::NotFound,
                    ..
                }
            ),
            "media verb {verb} without a dispatcher should be not_found, got {result:?}"
        );
    }
}

#[tokio::test]
async fn play_without_a_source_is_bad_request() {
    // Parsed before media-target resolution, so it holds with no dispatcher.
    let result = play(&channel(), &serde_json::json!({})).await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[tokio::test]
async fn play_with_two_sources_is_bad_request() {
    let result = play(
        &channel(),
        &serde_json::json!({ "file": "/a.wav", "db_id": 7 }),
    )
    .await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

/// The refusal a `play` argument draws: `bad_request`, naming the argument.
fn refused_play_argument(args: serde_json::Value, argument: &str) {
    match parse_play_options(&args) {
        Err(ControlResult::Error { code, details, .. }) => {
            assert_eq!(code, ControlErrorCode::BadRequest, "{args}");
            let details = details.unwrap_or_default();
            assert_eq!(details["verb"], "play", "{args}");
            assert_eq!(details["argument"], argument, "{args}");
            assert_eq!(details["reason"], "invalid_value", "{args}");
        }
        other => panic!("{args} was not refused: {other:?}"),
    }
}

#[test]
fn play_repeat_is_a_count_or_inf() {
    use siphon_rtp_proto::PlayRepeat;
    let repeat = |args: serde_json::Value| parse_play_options(&args).expect("accepted").repeat;
    assert_eq!(repeat(serde_json::json!({})), None);
    assert_eq!(repeat(serde_json::json!({ "repeat": null })), None);
    assert_eq!(
        repeat(serde_json::json!({ "repeat": 3 })),
        Some(PlayRepeat::Times(3))
    );
    // Until stopped: the token the tone cadence grammar already uses.
    assert_eq!(
        repeat(serde_json::json!({ "repeat": "inf" })),
        Some(PlayRepeat::Forever)
    );
}

#[test]
fn play_refuses_an_argument_it_cannot_use_rather_than_dropping_it() {
    // Each of these was read as absent before, so the prompt played once, from
    // the start, at full level, and the verb answered ok.
    for repeat in [
        serde_json::json!("forever"),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!(true),
        serde_json::json!([2]),
    ] {
        refused_play_argument(serde_json::json!({ "repeat": repeat }), "repeat");
    }
    refused_play_argument(serde_json::json!({ "start_ms": "250" }), "start_ms");
    refused_play_argument(serde_json::json!({ "duration_ms": -5 }), "duration_ms");
    refused_play_argument(
        serde_json::json!({ "gain_decibels": "-6" }),
        "gain_decibels",
    );
    refused_play_argument(
        serde_json::json!({ "gain_decibels": 9_000_000_000_i64 }),
        "gain_decibels",
    );
    refused_play_argument(serde_json::json!({ "to_tag": 7 }), "to_tag");

    // Positive control: the same arguments, well formed, are all carried.
    let options = parse_play_options(&serde_json::json!({
        "repeat": 2, "start_ms": 250, "duration_ms": 5000, "gain_decibels": -6, "to_tag": "peer"
    }))
    .expect("accepted");
    assert_eq!(options.start_ms, Some(250));
    assert_eq!(options.duration_ms, Some(5000));
    assert_eq!(options.gain_decibels, Some(-6));
    assert_eq!(options.to_tag.as_deref(), Some("peer"));
}

#[tokio::test]
async fn play_with_an_unusable_repeat_is_bad_request_before_the_engine_is_asked() {
    // Refused on its arguments, so it holds with no dispatcher: a well-formed
    // one reaches the media-target lookup instead and answers not_found here.
    let refused = play(
        &channel(),
        &serde_json::json!({ "file": "/a.wav", "repeat": "forever" }),
    )
    .await;
    assert!(matches!(
        refused,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
    let accepted = play(
        &channel(),
        &serde_json::json!({ "file": "/a.wav", "repeat": "inf" }),
    )
    .await;
    assert!(matches!(
        accepted,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn hold_on_a_call_the_engine_only_relays_is_an_invalid_state() {
    use crate::rtpengine::RtpEngineError;
    let relayed = || {
        Err(RtpEngineError::EngineError(
            "silence: call is not a media-processing call (transcode/record/stream required)"
                .to_string(),
        ))
    };
    for (engage, verb) in [(true, "hold"), (false, "unhold")] {
        match hold_result(&channel(), engage, relayed()) {
            ControlResult::Error { code, details, .. } => {
                assert_eq!(code, ControlErrorCode::InvalidState);
                let details = details.unwrap_or_default();
                assert_eq!(details["verb"], verb);
                assert_eq!(details["reason"], "media_not_processed");
            }
            other => panic!("{verb} on a relayed call was not refused: {other:?}"),
        }
    }
    // An engine that is really unreachable is still `unavailable`, and a call
    // the engine no longer has is still `not_found`.
    assert!(matches!(
        hold_result(
            &channel(),
            true,
            Err(RtpEngineError::Timeout { timeout_ms: 1000 })
        ),
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
    assert!(matches!(
        hold_result(
            &channel(),
            true,
            Err(RtpEngineError::EngineError(
                "unknown call: 1@host".to_string()
            ))
        ),
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
    // Positive control: an accept reports the state.
    match hold_result(&channel(), true, Ok(())) {
        ControlResult::Ok(reply) => assert_eq!(reply["state"], "held"),
        other => panic!("{other:?}"),
    }
    match hold_result(&channel(), false, Ok(())) {
        ControlResult::Ok(reply) => assert_eq!(reply["state"], "unheld"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn dtmf_without_digits_is_bad_request() {
    let missing = dtmf(&channel(), &serde_json::json!({})).await;
    assert!(matches!(
        missing,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
    let empty = dtmf(&channel(), &serde_json::json!({ "digits": "" })).await;
    assert!(matches!(
        empty,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[tokio::test]
async fn stream_start_without_ws_uri_is_bad_request() {
    let result = stream_start(&channel(), &serde_json::json!({})).await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[tokio::test]
async fn stream_start_with_bad_direction_is_bad_request() {
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "direction": "sideways" }),
    )
    .await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[tokio::test]
async fn stream_start_with_bad_channels_is_bad_request() {
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "channels": 3 }),
    )
    .await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn parse_play_source_variants() {
    use crate::rtpengine::client::PlayMediaSource;
    // file
    assert!(matches!(
        parse_play_source(&serde_json::json!({ "file": "/p.wav" })),
        Ok(PlayMediaSource::File(path)) if path == "/p.wav"
    ));
    // db_id
    assert!(matches!(
        parse_play_source(&serde_json::json!({ "db_id": 42 })),
        Ok(PlayMediaSource::DbId(42))
    ));
    // blob (base64 of "hi")
    assert!(matches!(
        parse_play_source(&serde_json::json!({ "blob": "aGk=" })),
        Ok(PlayMediaSource::Blob(bytes)) if bytes == b"hi"
    ));
    // none / two → error
    assert!(parse_play_source(&serde_json::json!({})).is_err());
    assert!(parse_play_source(&serde_json::json!({ "file": "/a", "db_id": 1 })).is_err());
    // invalid base64 → error
    assert!(parse_play_source(&serde_json::json!({ "blob": "not base64!!" })).is_err());
}

#[test]
fn parse_stream_channels_bounds() {
    assert_eq!(parse_stream_channels(None), Ok(None));
    assert_eq!(
        parse_stream_channels(Some(&serde_json::Value::Null)),
        Ok(None)
    );
    assert_eq!(
        parse_stream_channels(Some(&serde_json::json!(1))),
        Ok(Some(1))
    );
    assert_eq!(
        parse_stream_channels(Some(&serde_json::json!(2))),
        Ok(Some(2))
    );
    assert!(parse_stream_channels(Some(&serde_json::json!(3))).is_err());
    assert!(parse_stream_channels(Some(&serde_json::json!(0))).is_err());
}

#[test]
fn media_error_maps_each_backend_error() {
    use crate::rtpengine::error::RtpEngineError;
    // Engine has no such call → not_found.
    assert!(matches!(
        media_error(RtpEngineError::EngineError("Unknown call-id".to_string())),
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
    // Backend can't do it → unsupported_verb.
    assert!(matches!(
        media_error(RtpEngineError::Unsupported {
            operation: "attach_ws_tee",
            backend: "rtpengine"
        }),
        ControlResult::Error {
            code: ControlErrorCode::UnsupportedVerb,
            ..
        }
    ));
    // Anything else → unavailable.
    assert!(matches!(
        media_error(RtpEngineError::Timeout { timeout_ms: 1000 }),
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
}

#[test]
fn remove_header_without_name_is_bad_request() {
    let result = remove_header(&channel(), &serde_json::json!({}));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn remove_header_dispatches_through_apply_sip() {
    // Prove the "remove_header" arm is wired in apply_sip: with a name but no
    // stored invite (no call store for this call), it reaches remove_header and
    // returns not_found — not the unsupported_verb catch-all.
    let result = apply_sip(AdapterCommand {
        verb: "remove_header".to_string(),
        args: serde_json::json!({ "name": "X-Foo" }),
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn remove_header_removes_from_the_stored_invite() {
    use crate::b2bua::actor::{CallActorStore, Leg, TransportInfo};
    use crate::transport::{ConnectionId, Transport};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};

    // Build an A-leg INVITE carrying an X-Remove-Me header, park it in a fresh
    // call store, and install that store globally (unique call-actor-id so it
    // never collides with other tests that expect their own call absent).
    let raw = concat!(
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK-rm1\r\n",
        "From: <sip:alice@atlanta.com>;tag=rmtag\r\n",
        "To: <sip:bob@biloxi.com>\r\n",
        "Call-ID: remove-header-call@atlanta.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "X-Remove-Me: please\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let invite = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).unwrap();
    assert!(invite.headers.has("X-Remove-Me"));
    let invite_arc = Arc::new(Mutex::new(invite));

    let store = Arc::new(CallActorStore::new());
    let transport = TransportInfo {
        remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    };
    let a_leg = Leg::new_a_leg(
        "remove-header-call@atlanta.com".to_string(),
        "rmtag".to_string(),
        "z9hG4bK-rm1".to_string(),
        transport,
    );
    let internal_call_id = store.create_call(a_leg);
    store.set_a_leg_invite(&internal_call_id, Arc::clone(&invite_arc));
    crate::b2bua::actor::set_global_call_store(Arc::clone(&store));

    let controlled = ChannelRef {
        channel_id: "ch-rm".to_string(),
        call_actor_id: internal_call_id,
        sip_call_id: "remove-header-call@atlanta.com".to_string(),
        app: "ivr-app".to_string(),
    };

    let result = remove_header(&controlled, &serde_json::json!({ "name": "X-Remove-Me" }));
    // was_present = true → removed: true.
    match result {
        ControlResult::Ok(value) => {
            assert_eq!(value.get("removed").and_then(|v| v.as_bool()), Some(true));
        }
        other => panic!("expected Ok, got {other:?}"),
    }
    // The header is really gone from the stored invite.
    let invite = invite_arc.lock().unwrap();
    assert!(!invite.headers.has("X-Remove-Me"));
}

#[test]
fn answer_rejects_non_2xx_before_touching_the_store() {
    // No call store in a unit context; a bad code must be caught first so
    // this returns bad_request, not a store lookup.
    let result = answer(&channel(), &serde_json::json!({ "code": 486 }), true);
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn anchored_progress_reaches_the_media_path_instead_of_being_refused() {
    // This test used to assert the opposite: that `anchor` / `profile` /
    // `ws_uri` on a 1xx were refused, because a provisional had nothing to
    // anchor. Early media through the engine is exactly a provisional with
    // something to anchor (RFC 3960 §3.1 — ringback or an announcement
    // before answering), so the refusal is gone, deliberately. What is
    // asserted now is that the call reaches the dispatcher: none exists in a
    // unit context, so a typed `unavailable` — never a bad_request, and
    // never a hollow ok.
    for args in [
        serde_json::json!({ "anchor": true }),
        serde_json::json!({ "profile": "voice_ai" }),
        serde_json::json!({ "ws_uri": "wss://ai.example.test/{call_id}" }),
    ] {
        assert!(
            matches!(
                answer(&channel(), &args, /*final_response=*/ false),
                ControlResult::Error {
                    code: ControlErrorCode::Unavailable,
                    ..
                }
            ),
            "anchored progress must reach the media path for {args}"
        );
    }
}

#[test]
fn anchored_progress_refuses_a_100() {
    // A 100 opens no early dialog and carries no body, so it cannot carry
    // the engine's SDP — refused before any media is anchored for nothing.
    let result = answer(
        &channel(),
        &serde_json::json!({ "anchor": true, "code": 100 }),
        false,
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn anchored_progress_refuses_a_caller_supplied_body() {
    // Same rule as the anchored answer: the engine synthesizes the SDP, so a
    // body alongside it would be discarded.
    let result = answer(
        &channel(),
        &serde_json::json!({
            "anchor": true,
            "body": "v=0\r\n",
            "content_type": "application/sdp",
        }),
        false,
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn anchored_answer_refuses_a_caller_supplied_body() {
    // The anchored answer synthesizes the SDP itself (RFC 3264 against the
    // media engine), so a body passed with it would be discarded. Refusing
    // says which of the two the caller meant instead of picking one.
    let result = answer(
        &channel(),
        &serde_json::json!({
            "profile": "voice_ai",
            "body": "v=0\r\n",
            "content_type": "application/sdp",
        }),
        true,
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn anchored_answer_on_a_dead_call_is_unavailable_not_not_found() {
    // No dispatcher in a unit context, so b2bua_answer_call_anchored can
    // only fail. The distinction matters to an application: `not_found`
    // means the call is gone, `unavailable` means the media plan failed and
    // the call is still parked and answerable — retry with another profile
    // or reject it, but do not assume the caller hung up.
    let result = answer(
        &channel(),
        &serde_json::json!({ "profile": "voice_ai" }),
        true,
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
}

#[test]
fn plain_answer_is_unchanged_by_the_media_args() {
    // No anchor argument → the original path, which needs a stored INVITE
    // and so answers not_found in a unit context. Proves the new branch is
    // opt-in and does not intercept an ordinary answer, including when
    // `anchor` is present and explicitly false.
    for args in [
        serde_json::json!({ "code": 200 }),
        serde_json::json!({ "code": 200, "anchor": false }),
    ] {
        assert!(
            matches!(
                answer(&channel(), &args, true),
                ControlResult::Error {
                    code: ControlErrorCode::NotFound,
                    ..
                }
            ),
            "plain answer must stay on the original path for {args}"
        );
    }
}

#[test]
fn anchor_alone_takes_the_anchored_path() {
    // `answer_anchored(None, None)` sends `{"anchor": true}` and nothing
    // else — it has to mean "answer through the media engine on its default
    // profile", not "plain answer", or naming neither argument would be
    // indistinguishable from one.
    let result = answer(&channel(), &serde_json::json!({ "anchor": true }), true);
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
}

#[test]
fn refer_without_target_is_bad_request() {
    let result = refer(&channel(), &serde_json::json!({}));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn dead_call_returns_not_found_never_hangs() {
    // With no global call store installed, stored_invite() is None → the
    // synchronous core returns not_found immediately (it cannot await a far
    // end — there is no far end to await).
    let result = answer(&channel(), &serde_json::json!({ "code": 200 }), true);
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn route_without_targets_is_bad_request() {
    // No args.targets at all → bad_request before touching the store.
    let result = route(&channel(), &serde_json::json!({}));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn route_empty_targets_is_bad_request() {
    let result = route(&channel(), &serde_json::json!({ "targets": [] }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn route_target_object_without_uri_is_bad_request() {
    let result = route(
        &channel(),
        &serde_json::json!({ "targets": [{ "next_hop": "sip:gw@1.2.3.4" }] }),
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn route_unsupported_strategy_is_typed_error() {
    // A non-sequential strategy must be a typed unsupported error, NEVER a
    // silent fall-through to sequential. b2bua_route_call validates the
    // strategy before touching the dispatcher, so this holds without one.
    let result = route(
        &channel(),
        &serde_json::json!({ "targets": ["sip:1@carrier.example"], "strategy": "parallel" }),
    );
    assert!(
        matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            }
        ),
        "unsupported strategy must be a typed UnsupportedVerb, got {result:?}"
    );
}

#[test]
fn route_valid_targets_without_dispatcher_is_not_found() {
    // With no B2BUA_CONTROL installed (unit context), a well-formed route
    // reaches b2bua_route_call and returns not_found — never hangs.
    let result = route(
        &channel(),
        &serde_json::json!({ "targets": ["sip:1@carrier.example"] }),
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn route_dispatches_through_apply_sip() {
    // Prove the "route" arm is wired in apply_sip (reaches b2bua_route_call →
    // not_found with no dispatcher, rather than unsupported_verb).
    let result = apply_sip(AdapterCommand {
        verb: "route".to_string(),
        args: serde_json::json!({ "targets": ["sip:1@carrier.example"] }),
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

/// A bare URI is one branch, verbatim.
#[test]
fn dial_target_accepts_a_bare_uri() {
    let parsed = parse_dial_target(&serde_json::json!("sip:204@pbx.example"))
        .expect("a URI string is a target");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].uri, "sip:204@pbx.example");
    assert!(parsed[0].next_hop.is_none());
    assert!(parsed[0].flow.is_none());
}

#[test]
fn dial_refuses_malformed_media_policy_instead_of_silently_sending_plain_media() {
    for profile in [
        serde_json::json!(true),
        serde_json::json!(1),
        serde_json::json!(""),
        serde_json::json!(" "),
    ] {
        let result = sip_command(
            "dial",
            serde_json::json!({"targets": ["sip:201@example.com"], "profile": profile}),
        );
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }
}

/// Guessing at a privacy setting is how identities leak, so an unrecognised
/// one is refused rather than defaulted — and the refusal names the verb it
/// came from, not `originate`.
#[test]
fn dial_refuses_a_privacy_value_it_does_not_recognise() {
    let result = sip_command(
        "dial",
        serde_json::json!({"targets": ["sip:201@example.com"], "privacy": "maybe"}),
    );
    let ControlResult::Error { code, message, .. } = result else {
        panic!("a privacy siphon cannot honour has to be refused");
    };
    assert_eq!(code, ControlErrorCode::BadRequest);
    assert!(message.starts_with("dial args.privacy"), "{message}");
}

/// The object form carries the routing destination and per-target headers,
/// while the R-URI keeps the shape the app asked for.
#[test]
fn dial_target_accepts_uri_with_next_hop_and_headers() {
    let parsed = parse_dial_target(&serde_json::json!({
        "uri": "sip:+15550177@trunk.example",
        "next_hop": "sip:192.0.2.9:5060",
        "headers": {"X-Tag": "a"},
    }))
    .expect("the object form is a target");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].uri, "sip:+15550177@trunk.example");
    assert_eq!(parsed[0].next_hop.as_deref(), Some("sip:192.0.2.9:5060"));
    assert_eq!(
        parsed[0].headers.get("X-Tag").map(String::as_str),
        Some("a")
    );
}

/// A target's `to` is carried to the dispatcher as the branch's called party;
/// a target naming none leaves the default `To` in place.
#[test]
fn dial_target_carries_its_called_party() {
    let parsed = parse_dial_target(&serde_json::json!({
        "uri": "sip:+15550199@trunk.example",
        "to": "sip:+15550199@trunk.example",
    }))
    .expect("the object form is a target");
    assert_eq!(parsed[0].to.as_deref(), Some("sip:+15550199@trunk.example"));

    let bare = parse_dial_target(&serde_json::json!({"uri": "sip:+15550199@trunk.example"}))
        .expect("the object form is a target");
    assert_eq!(bare[0].to, None);
}

/// An `{aor}` target's identity fields reach every contact it forks to, as
/// its headers and `to` do. They used to be dropped without a word on this
/// form while the reference documented them on both.
#[test]
fn an_aor_targets_identity_reaches_every_contact() {
    let registrar = crate::script::api::test_registrar();
    for (instance, host) in [("a", "198.51.100.121"), ("b", "198.51.100.122")] {
        registrar
            .save(
                "sip:3202@siphon.example.com",
                crate::sip::uri::SipUri::new(host.to_string()),
                3600,
                1.0,
                format!("register-3202-{instance}"),
                1,
            )
            .expect("the binding saves");
    }
    let parsed = parse_dial_target(&serde_json::json!({
        "aor": "sip:3202@siphon.example.com",
        "from": "sip:+15550100@trunk.example",
        "from_display": "Example Ltd",
        "p_asserted_identity": "sip:+15550100@trunk.example",
        "privacy": "restricted",
        "headers": {"X-Queue": "sales"},
    }))
    .expect("the AoR form is a target");
    assert_eq!(parsed.len(), 2, "one branch per registered contact");
    for branch in &parsed {
        assert_eq!(branch.from.as_deref(), Some("sip:+15550100@trunk.example"));
        assert_eq!(branch.from_display.as_deref(), Some("Example Ltd"));
        assert_eq!(
            branch.p_asserted_identity.as_deref(),
            Some("sip:+15550100@trunk.example")
        );
        assert_eq!(
            branch.privacy,
            Some(crate::sip::privacy::CallerIdPresentation::Restricted)
        );
        assert_eq!(
            branch.headers.get("X-Queue").map(String::as_str),
            Some("sales")
        );
        assert!(branch.aor.is_some(), "still named for the AoR it rang");
    }

    // A privacy siphon cannot honour is refused on this form too, rather
    // than ignored with the rest of the identity.
    let refused = parse_dial_target(&serde_json::json!({
        "aor": "sip:3202@siphon.example.com",
        "privacy": "maybe",
    }));
    assert!(refused.is_err(), "{refused:?}");
}

/// An AoR with nobody registered is not a malformed request. It yields no
/// branch, and `dial` answers `not_found` once every target has been tried
/// — an app dialling a ring group must not be told its JSON is wrong
/// because one member happens to be offline.
#[test]
fn dial_target_with_an_unregistered_aor_is_no_branch_not_an_error() {
    let parsed = parse_dial_target(&serde_json::json!({"aor": "sip:nobody@pbx.example"}))
        .expect("an unregistered AoR is not a parse error");
    assert!(parsed.is_empty(), "no contact means no branch");
}

/// Neither a URI nor an AoR is a request the app has to fix.
#[test]
fn dial_target_without_uri_or_aor_is_rejected() {
    let error = parse_dial_target(&serde_json::json!({"next_hop": "sip:192.0.2.9"}))
        .expect_err("a target naming nothing must be rejected");
    assert!(
        error.contains("uri") && error.contains("aor"),
        "the error should name both accepted forms: {error}"
    );
    let error = parse_dial_target(&serde_json::json!(42)).expect_err("a number is not a target");
    assert!(error.contains("URI string"), "{error}");
}

#[test]
fn parse_route_target_string_and_object() {
    // Bare URI string form.
    let string_target = parse_route_target(&serde_json::json!("sip:1@carrier.example")).unwrap();
    assert_eq!(string_target.uri, "sip:1@carrier.example");
    assert!(string_target.next_hop.is_none());
    assert!(string_target.headers.is_empty());
    assert!(string_target.timeout_secs.is_none());
    assert!(!string_target.reroute_after_progress);

    // Full object form.
    let object_target = parse_route_target(&serde_json::json!({
        "uri": "sip:2@carrier.example",
        "next_hop": "sip:gw@203.0.113.7:5060",
        "headers": { "X-Carrier-Token": "abc" },
        "timeout": 12,
        "reroute_after_progress": true,
    }))
    .unwrap();
    assert!(object_target.reroute_after_progress);
    // Absent from an object, it is off.
    assert!(
        !parse_route_target(&serde_json::json!({ "uri": "sip:3@carrier.example" }))
            .unwrap()
            .reroute_after_progress
    );
    // A policy flag that is not a boolean is refused, not read as false.
    let error = parse_route_target(&serde_json::json!({
        "uri": "sip:3@carrier.example",
        "reroute_after_progress": "yes",
    }))
    .expect_err("a string is not a boolean");
    assert!(error.contains("reroute_after_progress"), "{error}");
    assert_eq!(object_target.uri, "sip:2@carrier.example");
    assert_eq!(
        object_target.next_hop.as_deref(),
        Some("sip:gw@203.0.113.7:5060")
    );
    assert_eq!(object_target.timeout_secs, Some(12));
    assert_eq!(
        object_target.headers,
        vec![("X-Carrier-Token".to_string(), "abc".to_string())]
    );

    // A bare number is neither a string nor an object → error.
    assert!(parse_route_target(&serde_json::json!(42)).is_err());
}

#[test]
fn parse_replaces_arg_roundtrips() {
    let value = serde_json::json!({
        "call_id": "abc", "from_tag": "ft", "to_tag": "tt", "early_only": true
    });
    let replaces = parse_replaces_arg(Some(&value)).unwrap().unwrap();
    assert_eq!(replaces.call_id, "abc");
    assert!(replaces.early_only);
    assert!(parse_replaces_arg(None).unwrap().is_none());
    assert!(parse_replaces_arg(Some(&serde_json::Value::Null))
        .unwrap()
        .is_none());
}

#[test]
fn parse_refer_mode_variants() {
    use crate::script::api::call::ReferMode;
    assert_eq!(parse_refer_mode(None), Ok(None));
    assert_eq!(parse_refer_mode(Some(&serde_json::Value::Null)), Ok(None));
    assert_eq!(
        parse_refer_mode(Some(&serde_json::json!("terminate"))),
        Ok(Some(ReferMode::Terminate))
    );
    assert_eq!(
        parse_refer_mode(Some(&serde_json::json!("transparent"))),
        Ok(Some(ReferMode::Transparent))
    );
    // An unrecognized mode is a typed error, never a silent default.
    assert!(parse_refer_mode(Some(&serde_json::json!("sideways"))).is_err());
    assert!(parse_refer_mode(Some(&serde_json::json!(42))).is_err());
}

#[test]
fn accept_refer_bad_mode_is_bad_request() {
    // Parsed before touching the rail, so it holds with no dispatcher.
    let result = accept_refer(&channel(), &serde_json::json!({ "mode": "sideways" }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn accept_refer_bad_target_is_bad_request() {
    let result = accept_refer(&channel(), &serde_json::json!({ "target": "not a uri" }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn accept_refer_without_pending_is_not_found() {
    // No B2BUA_CONTROL installed (unit context) → b2bua_accept_refer_call is
    // false (no pending REFER), mapped to not_found — never a hang.
    let result = accept_refer(&channel(), &serde_json::json!({}));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn accept_refer_dispatches_through_apply_sip() {
    // Prove the "accept_refer" arm is wired in apply_sip (reaches the rail →
    // not_found with no dispatcher, rather than the unsupported_verb catch-all).
    let result = apply_sip(AdapterCommand {
        verb: "accept_refer".to_string(),
        args: serde_json::json!({}),
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn reject_refer_bad_code_is_bad_request() {
    let result = reject_refer(&channel(), &serde_json::json!({ "code": 200 }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            ..
        }
    ));
}

#[test]
fn reject_refer_without_pending_is_not_found() {
    let result = reject_refer(
        &channel(),
        &serde_json::json!({ "code": 486, "reason": "Busy" }),
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn dial_on_an_answered_call_carries_typed_details() {
    // A controller must be able to tell "this call is already answered" from
    // every other invalid_state without matching the prose, so the refusal
    // names the verb, the reason and the state the call was found in.
    let result = dial_error(crate::dispatcher::DialError::AlreadyAnswered {
        call_state: crate::b2bua::actor::CallState::Answered,
    });
    let ControlResult::Error {
        code,
        message,
        details,
    } = result
    else {
        panic!("dial on an answered call must be refused");
    };
    assert_eq!(code, ControlErrorCode::InvalidState);
    assert_eq!(
        message, "the call is already answered — dial rings a caller that is still waiting",
        "the prose is unchanged; details ride beside it"
    );
    assert_eq!(
        details,
        Some(serde_json::json!({
            "verb": "dial",
            "reason": "already_answered",
            "call_state": "answered",
        }))
    );
}

#[test]
fn other_dial_refusals_do_not_claim_already_answered() {
    // The positive control: a refusal for any other cause keeps its own code
    // and never carries the already-answered reason a controller branches on.
    let refusals = [
        (
            crate::dispatcher::DialError::UnsupportedStrategy("ring-all".to_string()),
            ControlErrorCode::UnsupportedVerb,
        ),
        (
            crate::dispatcher::DialError::NoTargets,
            ControlErrorCode::BadRequest,
        ),
        (
            crate::dispatcher::DialError::NoContacts("sip:1001@example.com".to_string()),
            ControlErrorCode::NotFound,
        ),
        (
            crate::dispatcher::DialError::Media("no media engine".to_string()),
            ControlErrorCode::Unavailable,
        ),
        (
            crate::dispatcher::DialError::InvalidIdentity("bad from".to_string()),
            ControlErrorCode::BadRequest,
        ),
    ];
    for (refusal, expected) in refusals {
        let described = refusal.to_string();
        let ControlResult::Error { code, details, .. } = dial_error(refusal) else {
            panic!("{described} must be refused");
        };
        assert_eq!(code, expected, "{described}");
        assert!(
            details
                .as_ref()
                .and_then(|details| details.get("reason"))
                .is_none_or(|reason| reason != "already_answered"),
            "{described}: {details:?}"
        );
    }
}

#[test]
fn reject_refer_dispatches_through_apply_sip() {
    let result = apply_sip(AdapterCommand {
        verb: "reject_refer".to_string(),
        args: serde_json::json!({}),
        target: ResolvedTarget::Channel(channel()),
        origin: test_origin(),
    });
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn originate_target_is_exactly_one_of_to_and_aor() {
    assert_eq!(
        parse_originate_target(&serde_json::json!({ "to": "sip:1@198.51.100.1" })),
        Ok(OriginateTarget::Uri("sip:1@198.51.100.1".to_string()))
    );
    assert_eq!(
        parse_originate_target(&serde_json::json!({ "aor": "sip:201@example.com" })),
        Ok(OriginateTarget::Aor {
            aor: "sip:201@example.com".to_string(),
            strategy: crate::dispatcher::OriginateGroupStrategy::Parallel,
            total_timeout_secs: None,
        })
    );
    assert_eq!(
        parse_originate_target(&serde_json::json!({
            "aor": "sip:201@example.com",
            "strategy": "Sequential",
            "total_timeout": 45,
        })),
        Ok(OriginateTarget::Aor {
            aor: "sip:201@example.com".to_string(),
            strategy: crate::dispatcher::OriginateGroupStrategy::Sequential,
            total_timeout_secs: Some(45),
        })
    );
    for refused in [
        serde_json::json!({}),
        serde_json::json!({ "to": "sip:1@198.51.100.1", "aor": "sip:201@example.com" }),
        serde_json::json!({ "to": "" }),
        serde_json::json!({ "aor": 201 }),
        serde_json::json!({ "to": "sip:1@198.51.100.1", "strategy": "parallel" }),
        serde_json::json!({ "to": "sip:1@198.51.100.1", "total_timeout": 10 }),
        serde_json::json!({ "aor": "sip:201@example.com", "strategy": "hunt" }),
        serde_json::json!({ "aor": "sip:201@example.com", "total_timeout": "10" }),
        serde_json::json!({ "aor": "sip:201@example.com", "total_timeout": -1 }),
    ] {
        assert!(
            parse_originate_target(&refused).is_err(),
            "{refused} must be refused"
        );
    }
}

#[test]
fn a_group_deadline_defaults_to_the_time_its_legs_can_ring() {
    use crate::dispatcher::OriginateGroupStrategy::{Parallel, Sequential};
    assert_eq!(default_total_timeout(Parallel, 30, 3), 30);
    assert_eq!(default_total_timeout(Sequential, 30, 3), 90);
    assert_eq!(
        default_total_timeout(Sequential, 0, 3),
        0,
        "no ring timeout, no deadline"
    );
    assert_eq!(default_total_timeout(Sequential, u32::MAX, 2), u32::MAX);
}

#[test]
fn an_aor_originate_with_no_dispatcher_registers_no_channel() {
    // The AoR has a phone, but the B2BUA is not running in this process: the
    // group cannot be created and the id stays free.
    crate::script::api::test_registrar()
        .save(
            "sip:3201@siphon.example.com",
            crate::sip::uri::SipUri::new("198.51.100.120".to_string()),
            3600,
            1.0,
            "register-3201".to_string(),
            1,
        )
        .expect("the binding saves");
    let bus = test_bus();
    let conn = bus.register_connection("ivr-app");
    let mut command = originate_command(serde_json::json!({
        "channel": "cb-aor",
        "aor": "sip:3201@siphon.example.com",
        "media": true,
    }));
    command.origin.conn_id = conn.id;
    let result = originate_with_bus(&bus, command);
    assert!(!bus.channel_exists("cb-aor"));
    assert!(
        matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ),
        "got {result:?}"
    );
}

fn register_contact(aor: &str, contact: &str) {
    crate::script::api::test_registrar()
        .save(
            aor,
            crate::sip::parser::parse_uri_standalone(contact).expect("a contact URI"),
            3600,
            1.0,
            format!("register-{contact}"),
            1,
        )
        .expect("the binding saves");
}

fn transfer_refusal(verb: &str, args: serde_json::Value) -> (ControlErrorCode, serde_json::Value) {
    match parse_transfer_dial(verb, &args) {
        Err(ControlResult::Error { code, details, .. }) => (code, details.unwrap_or_default()),
        Err(ControlResult::Ok(reply)) => panic!("a refusal that is ok: {reply}"),
        Ok(_) => panic!("{args} was accepted"),
    }
}

#[test]
fn a_transfer_target_is_a_uri_or_a_registered_aor() {
    let named = |args: serde_json::Value| {
        parse_transfer_dial("replace_peer", &args)
            .unwrap_or_else(|refusal| panic!("{args} was refused: {refusal:?}"))
    };
    // No target at all is the verb's to judge: accept_refer has the Refer-To.
    assert_eq!(named(serde_json::json!({})).target, None);
    for args in [
        serde_json::json!({ "target": "sip:204@198.51.100.7" }),
        serde_json::json!({ "target": { "uri": "sip:204@198.51.100.7" } }),
    ] {
        let transfer = named(args);
        assert_eq!(transfer.target.as_deref(), Some("sip:204@198.51.100.7"));
        assert!(transfer.dial.aor.is_none() && transfer.dial.flow.is_none());
    }

    // An AoR with one phone: the contact is what is dialled, called as the AoR.
    register_contact(
        "sip:tx5501@siphon.example.com",
        "sip:tx5501@198.51.100.61:5060",
    );
    let transfer = named(serde_json::json!({
        "target": { "aor": "sip:tx5501@siphon.example.com" }
    }));
    assert_eq!(
        transfer.target.as_deref(),
        Some("sip:tx5501@198.51.100.61:5060")
    );
    assert_eq!(
        transfer.dial.aor.as_deref(),
        Some("sip:tx5501@siphon.example.com")
    );
}

/// An AoR with two phones rings both: the verb is accepted, and it yields one
/// target per registered contact, each with the AoR it is called as and all
/// sharing the identity and headers the verb named.
#[test]
fn a_transfer_to_an_aor_with_several_contacts_rings_every_one() {
    register_contact(
        "sip:tx5503@siphon.example.com",
        "sip:tx5503@198.51.100.62:5060",
    );
    register_contact(
        "sip:tx5503@siphon.example.com",
        "sip:tx5503@198.51.100.63:5060",
    );
    for verb in ["accept_refer", "replace_peer"] {
        let transfer = parse_transfer_dial(
            verb,
            &serde_json::json!({
                "target": { "aor": "sip:tx5503@siphon.example.com" },
                "from_display": "Main Line",
                "headers": { "X-Account": "main" },
            }),
        )
        .unwrap_or_else(|refusal| panic!("{verb} was refused: {refusal:?}"));
        let mut rung = vec![transfer.target.clone().expect("a first target")];
        rung.extend(transfer.dial.also.iter().map(|contact| contact.uri.clone()));
        rung.sort();
        assert_eq!(
            rung,
            [
                "sip:tx5503@198.51.100.62:5060",
                "sip:tx5503@198.51.100.63:5060"
            ],
            "{verb} rings both contacts"
        );
        assert_eq!(
            transfer.dial.aor.as_deref(),
            Some("sip:tx5503@siphon.example.com")
        );
        assert_eq!(transfer.dial.also.len(), 1);
        assert_eq!(
            transfer.dial.also[0].aor.as_deref(),
            Some("sip:tx5503@siphon.example.com"),
            "each contact is called as the AoR"
        );
        assert_eq!(
            transfer.dial.shaping.from_display.as_deref(),
            Some("Main Line")
        );
        assert_eq!(
            transfer.dial.headers,
            [("X-Account".to_string(), "main".to_string())]
        );
    }
}

#[test]
fn a_transfer_to_an_aor_nobody_registered_at_is_refused() {
    let (code, _) = transfer_refusal(
        "accept_refer",
        serde_json::json!({ "target": { "aor": "sip:tx5502@siphon.example.com" } }),
    );
    assert_eq!(code, ControlErrorCode::NotFound);

    // A registered phone is reached over its own flow, never a next hop.
    register_contact(
        "sip:tx5504@siphon.example.com",
        "sip:tx5504@198.51.100.64:5060",
    );
    let (code, _) = transfer_refusal(
        "replace_peer",
        serde_json::json!({
            "target": { "aor": "sip:tx5504@siphon.example.com" },
            "next_hop": "sip:edge.example.com"
        }),
    );
    assert_eq!(code, ControlErrorCode::BadRequest);
    for target in [
        serde_json::json!(7),
        serde_json::json!({}),
        serde_json::json!({ "uri": "sip:a@example.com", "aor": "sip:b@example.com" }),
        serde_json::json!("not a uri"),
    ] {
        let (code, _) = transfer_refusal("replace_peer", serde_json::json!({ "target": target }));
        assert_eq!(code, ControlErrorCode::BadRequest);
    }
}

#[test]
fn a_transfer_carries_the_identity_arguments_a_dial_takes() {
    let transfer = parse_transfer_dial(
        "accept_refer",
        &serde_json::json!({
            "from": "sip:+15550100000@trunk.example.com",
            "from_display": "",
            "p_asserted_identity": "sip:+15550100000@trunk.example.com",
            "privacy": "restricted",
            "headers": { "X-Account": "main" }
        }),
    )
    .unwrap_or_else(|refusal| panic!("refused: {refusal:?}"));
    let shaping = &transfer.dial.shaping;
    assert_eq!(
        shaping.from.as_deref(),
        Some("sip:+15550100000@trunk.example.com")
    );
    assert_eq!(
        shaping.from_display.as_deref(),
        Some(""),
        "an empty display name is kept: it removes the caller's"
    );
    assert_eq!(
        shaping.privacy,
        Some(crate::sip::privacy::CallerIdPresentation::Restricted)
    );
    assert_eq!(
        transfer.dial.headers,
        [("X-Account".to_string(), "main".to_string())]
    );

    for args in [
        serde_json::json!({ "from": "not a uri" }),
        serde_json::json!({ "p_asserted_identity": "not a uri" }),
        serde_json::json!({ "privacy": "sometimes" }),
    ] {
        let (code, _) = transfer_refusal("accept_refer", args);
        assert_eq!(code, ControlErrorCode::BadRequest);
    }
}

#[test]
fn a_transparent_transfer_refuses_what_it_would_never_use() {
    // It relays the REFER and dials no leg, so an identity or a flow named on
    // it would be accepted and silently dropped.
    for args in [
        serde_json::json!({ "mode": "transparent", "from": "sip:1@example.com" }),
        serde_json::json!({ "mode": "transparent", "headers": { "X-A": "b" } }),
        serde_json::json!({ "mode": "transparent", "privacy": "restricted" }),
    ] {
        let result = accept_refer(&channel(), &args);
        assert!(
            bad_request_message(&result).contains("transparent"),
            "{args}"
        );
    }
    // Positive control: with nothing to drop it gets as far as the pending
    // REFER, of which there is none here.
    let result = accept_refer(
        &channel(),
        &serde_json::json!({ "mode": "transparent", "target": "sip:c@example.com" }),
    );
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

fn bad_request_message(result: &ControlResult) -> String {
    match result {
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            message,
            ..
        } => message.clone(),
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[tokio::test]
async fn stream_start_tee_refuses_a_profile() {
    // A tee is shaped by direction/channels/sample_rate; a profile would be
    // dropped on the floor and the controller would believe it applied.
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "profile": "voice_ai" }),
    )
    .await;
    assert!(bad_request_message(&result).contains("mode=bridge only"));
}

#[tokio::test]
async fn stream_start_bridge_refuses_a_profile_that_is_not_a_string() {
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "mode": "bridge", "profile": 16000 }),
    )
    .await;
    assert!(bad_request_message(&result).contains("must be a string"));
}

#[tokio::test]
async fn stream_start_bridge_refuses_an_unknown_profile_before_touching_the_call() {
    // Refused before the media target is resolved: an unknown name must not
    // attach a bridge with default settings the controller did not ask for.
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "mode": "bridge", "profile": "no_such_profile" }),
    )
    .await;
    match result {
        ControlResult::Error {
            code: ControlErrorCode::BadRequest,
            details,
            ..
        } => {
            let details = details.expect("typed details");
            assert_eq!(details["reason"], "unknown_profile");
            assert_eq!(details["profile"], "no_such_profile");
        }
        other => panic!("expected bad_request, got {other:?}"),
    }
}

#[tokio::test]
async fn stream_start_bridge_with_a_null_profile_is_no_profile() {
    // `null` is "not given", as for the tee-only arguments: the verb goes on to
    // look for the call's media and answers not_found in a unit test with none.
    let result = stream_start(
        &channel(),
        &serde_json::json!({ "ws_uri": "ws://ai:9000", "mode": "bridge", "profile": null }),
    )
    .await;
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
}

#[test]
fn accept_refer_mode_controller_is_this_rails_own() {
    use crate::script::api::call::ReferMode;
    assert_eq!(
        parse_accept_refer_mode(Some(&serde_json::json!("controller"))),
        Ok(AcceptReferMode::Controller)
    );
    // The modes siphon carries out are the script rail's, parsed as before.
    assert_eq!(
        parse_accept_refer_mode(None),
        Ok(AcceptReferMode::Siphon(None))
    );
    assert_eq!(
        parse_accept_refer_mode(Some(&serde_json::json!("terminate"))),
        Ok(AcceptReferMode::Siphon(Some(ReferMode::Terminate)))
    );
    assert!(parse_accept_refer_mode(Some(&serde_json::json!("sideways"))).is_err());
    // It is not a mode a script or the configured default can name.
    assert!(parse_refer_mode(Some(&serde_json::json!("controller"))).is_err());
}

#[test]
fn a_controller_transfer_with_no_b2bua_running_is_answered_not_left_hanging() {
    // No dispatcher in a unit context. Accepting finds nothing pending, as the
    // other modes do; reporting says the B2BUA is not there to report through.
    let result = sip_command("accept_refer", serde_json::json!({ "mode": "controller" }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::NotFound,
            ..
        }
    ));
    let result = sip_command("complete_refer", serde_json::json!({ "code": 200 }));
    assert!(matches!(
        result,
        ControlResult::Error {
            code: ControlErrorCode::Unavailable,
            ..
        }
    ));
    // Arguments are judged before the rail is reached.
    let result = sip_command("complete_refer", serde_json::json!({}));
    assert!(bad_request_message(&result).contains("code"));
    let result = sip_command(
        "accept_refer",
        serde_json::json!({ "mode": "controller", "target": "sip:c@example.com" }),
    );
    assert!(bad_request_message(&result).contains("dials no leg"));
    let result = sip_command("accept_refer", serde_json::json!({ "timeout": 30 }));
    assert!(bad_request_message(&result).contains("controller"));
}

#[test]
fn a_refused_controller_transfer_names_its_verb_and_reason() {
    use crate::dispatcher::ControllerReferRefusal;
    for (refusal, code, reason) in [
        (
            ControllerReferRefusal::NoPendingRefer,
            ControlErrorCode::NotFound,
            "no_pending_refer",
        ),
        (
            ControllerReferRefusal::Gone,
            ControlErrorCode::NotFound,
            "call_gone",
        ),
        (
            ControllerReferRefusal::ReferrerGone,
            ControlErrorCode::NotFound,
            "referrer_gone",
        ),
        (
            ControllerReferRefusal::TransferOpen,
            ControlErrorCode::InvalidState,
            "transfer_in_progress",
        ),
        (
            ControllerReferRefusal::NoTransferPending,
            ControlErrorCode::InvalidState,
            "no_transfer_pending",
        ),
    ] {
        let ControlResult::Error {
            code: answered,
            details,
            ..
        } = controller_refer_refused("complete_refer", refusal)
        else {
            panic!("a refusal is an error");
        };
        assert_eq!(answered, code, "{refusal:?}");
        let details = details.expect("a refusal carries details");
        assert_eq!(details["verb"], "complete_refer");
        assert_eq!(details["reason"], reason);
    }
}
