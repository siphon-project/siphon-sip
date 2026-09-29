//! What `{call_id}` in a WebSocket URI means on the dispatcher's anchoring
//! paths: the SIP Call-ID of the leg the stream carries, for a tee (`ws_tee`)
//! exactly as for a takeover bridge (`ws_uri`).
//!
//! The answer-first anchor (a controller's `answer` / `progress` with a
//! profile, and a script handover) is checked on its pure plan; the anchor of
//! an offerless originate through the in-process native engine, which records
//! the URIs each command hands it.

use std::sync::Arc;

use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    requests_to, socket,
};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// A profile streaming the call to a tee and a bridge, both templated.
const TEMPLATED: &str = "templated_streams";

/// The built-in profiles plus [`TEMPLATED`], the same on both halves.
fn templated_profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
    let half = crate::config::NgFlagsConfig {
        ws_uri: Some("wss://ai.example.test/bridge/{call_id}".to_string()),
        ws_tee: Some("wss://asr.example.test/tee/{call_id}?leg={from_tag}".to_string()),
        ..Default::default()
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        TEMPLATED.to_string(),
        crate::config::MediaProfileConfig {
            offer: half.clone(),
            answer: half,
        },
    );
    Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
}

/// A native-backend handle over a dead address: the answer-first plan does no
/// I/O. Constructing it spawns its connection task, hence the tokio tests.
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

fn caller_invite() -> SipMessage {
    let sdp = phone_offer("192.0.2.30");
    let raw = format!(
        concat!(
            "INVITE sip:4000@example.test SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-wsuri\r\n",
            "From: <sip:1001@example.test>;tag=caller-tag\r\n",
            "To: <sip:4000@example.test>\r\n",
            "Call-ID: ws-uri-caller@example.test\r\n",
            "CSeq: 1 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        length = sdp.len(),
        sdp = sdp,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses")
}

/// A controller's `answer {profile}` (and a script handover) anchors the caller
/// with the profile's tee templated like its bridge.
#[tokio::test]
async fn answer_first_templates_the_profile_tee_like_its_bridge() {
    let backend = idle_native_backend();
    let registry = templated_profiles();
    let plan = answer_first_prepare(
        &caller_invite(),
        socket("192.0.2.30:5060").ip(),
        &backend,
        &registry,
        Some(TEMPLATED),
        None,
    )
    .expect("the plan is made");
    assert_eq!(
        plan.flags.ws_uri.as_deref(),
        Some("wss://ai.example.test/bridge/ws-uri-caller@example.test")
    );
    assert_eq!(
        plan.flags.ws_tee.as_deref(),
        Some("wss://asr.example.test/tee/ws-uri-caller@example.test?leg=caller-tag")
    );
}

/// A tee template with a placeholder that does not exist is refused, as a
/// bridge template with one is, rather than handed to the engine literally.
#[tokio::test]
async fn answer_first_refuses_a_misspelt_tee_placeholder() {
    let backend = idle_native_backend();
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "misspelt".to_string(),
        crate::config::MediaProfileConfig {
            offer: Default::default(),
            answer: crate::config::NgFlagsConfig {
                ws_tee: Some("wss://asr.example.test/{callid}".to_string()),
                ..Default::default()
            },
        },
    );
    let registry = crate::rtpengine::ProfileRegistry::from_config(&custom);
    let outcome = answer_first_prepare(
        &caller_invite(),
        socket("192.0.2.30:5060").ip(),
        &backend,
        &registry,
        Some("misspelt"),
        None,
    )
    .map(|_| ());
    let Err(error) = outcome else {
        panic!("a misspelt tee placeholder must be refused");
    };
    assert!(error.contains("{callid}"), "{error}");
}

/// An offerless originate anchored with the profile: both URIs name the
/// originated leg's own SIP Call-ID and the tag the engine keyed it on.
#[tokio::test(flavor = "multi_thread")]
async fn an_originated_leg_templates_both_streams_with_its_own_call_id() {
    const PHONE: &str = "198.51.100.51:5060";
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = anchored_dispatcher(&engine);
    dispatcher.state.rtpengine_profiles = Some(templated_profiles());
    let mut params = anchored_params(&format!("sip:2201@{PHONE}"));
    params.media = OriginateMedia::Anchor {
        profile: TEMPLATED.to_string(),
        ws_uri: None,
    };
    let prepared = prepare_originate(&dispatcher.state, params).expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let invite = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Invite)
        .pop()
        .expect("siphon sent the phone an INVITE")
        .message;
    let call_id = invite.headers.call_id().cloned().expect("a Call-ID");
    let answered = phone_response(
        &invite,
        200,
        "OK",
        "phone-tag",
        &format!("sip:2201@{PHONE}"),
        Some(&phone_offer("198.51.100.51")),
    );
    phone_sends(&dispatcher.state, socket(PHONE), &answered);
    let anchored = engine.commands("answer_local");
    assert_eq!(anchored.len(), 1, "the 2xx offer was anchored once");
    assert_eq!(
        anchored[0].ws_uri,
        Some(format!("wss://ai.example.test/bridge/{call_id}"))
    );
    assert_eq!(
        anchored[0].ws_tee,
        Some(format!(
            "wss://asr.example.test/tee/{call_id}?leg=phone-tag"
        ))
    );
}
