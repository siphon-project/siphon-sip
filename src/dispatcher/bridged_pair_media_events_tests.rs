//! The engine's events on a bridged pair.
//!
//! A formed pair relays through one engine call on an id of its own, so every
//! event the engine reports for it names that id, not either leg's SIP
//! Call-ID. A per-party event (a digit, a playback, a recording, a stream)
//! names its party by engine tag and reaches that party's channel alone; the
//! end-of-call summary covers both, and so does the media CDR written from it.
//!
//! Driven through a real `dial {on_answer: "bridge"}`, whose caller and phone
//! carry distinct tags. What each publisher put on the control rail is read
//! off the per-Call-ID capture, the process bus not being installed here.

use super::control_bridge_media_tests::{
    accepts, bridge_offer_to, caller_accepts, last, phone_answers, stored,
};
use super::control_originate_tests::Controller;
use super::dial_bridge_test_harness::{
    answered_caller, bridging_dispatcher, controller_owning, dial, eventually, invite_to, Caller,
};
use super::originate_test_harness::drain;
use super::*;
use crate::rtpengine::events::{
    CallSummary, DtmfEvent, MediaLeg, MediaStartedEvent, PlayEndReason, PlayFinishedEvent,
    RecordingFinished, WsBridgeEndReason, WsBridgeEnded, WsBridgeStarted, WsTeeEndReason,
    WsTeeEnded, WsTeeStarted,
};
use crate::rtpengine::profile::WsTeeDirection;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// A caller bridged to a phone by a bridge dial, on the pair's own engine call.
struct Pair {
    _engine: NativeTestEngine,
    controller: Controller,
    caller: Caller,
    phone_call_id: String,
    /// The pair's engine call-id.
    engine_call_id: String,
    /// The engine tag each party's media is on.
    caller_tag: String,
    phone_tag: String,
}

async fn formed_pair(name: &str, phone: &str) -> Pair {
    formed_pair_after(name, phone, |_, _| {}).await
}

/// [`formed_pair`], with `before` run on the answered caller ahead of the dial
/// that bridges it.
async fn formed_pair_after(
    name: &str,
    phone: &str,
    before: impl FnOnce(&DispatcherState, &Caller),
) -> Pair {
    let contact = format!("sip:{name}@{phone}");
    let engine = NativeTestEngine::start().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, &format!("{name}@192.0.2.10"));
    crate::control::channel_event_capture::watch(&caller.call_id);
    before(&dispatcher.state, &caller);
    let controller = controller_owning(name, dispatcher, &caller, "caller", "hangup");
    let (reply, _) = dial(
        &controller,
        "caller",
        serde_json::json!({ "targets": [contact], "on_answer": "bridge" }),
    )
    .await;
    assert_eq!(reply["status"], "ok", "{reply}");
    let (phone_call_id, engine_call_id) = {
        let state = &controller.dispatcher.state;
        let udp = &controller.dispatcher.udp;
        let invite = invite_to(&drain(udp), phone);
        let phone_call_id = invite.headers.call_id().cloned().expect("a Call-ID");
        phone_answers(state, phone, &invite, &contact);
        let offer = bridge_offer_to(udp, phone).await;
        let engine_call_id = last(&engine, "offer").call_id;
        accepts(state, phone, &offer, &contact);
        caller_accepts(state, udp, &caller).await;
        assert!(
            eventually(|| stored(state, &caller.call_id)
                .is_some_and(|session| session.rtpengine_id() == engine_call_id))
            .await,
            "the bridge formed on its own engine call"
        );
        (phone_call_id, engine_call_id)
    };
    let session = stored(&controller.dispatcher.state, &caller.call_id).expect("the pair");
    let caller_tag = session.from_tag.clone();
    let phone_tag = session.to_tag.clone().expect("the phone's tag");
    assert_ne!(caller_tag, phone_tag, "the parties are told apart by tag");
    assert_ne!(engine_call_id, caller.call_id);
    assert_ne!(engine_call_id, phone_call_id);
    crate::control::channel_event_capture::watch(&caller.call_id);
    crate::control::channel_event_capture::watch(&phone_call_id);
    Pair {
        _engine: engine,
        controller,
        caller,
        phone_call_id,
        engine_call_id,
        caller_tag,
        phone_tag,
    }
}

impl Pair {
    fn state(&self) -> &DispatcherState {
        &self.controller.dispatcher.state
    }

    /// The events published for each leg since the last look, as
    /// `(caller's, phone's)`.
    fn published(&self) -> (Published, Published) {
        (
            crate::control::channel_event_capture::take(&self.caller.call_id),
            crate::control::channel_event_capture::take(&self.phone_call_id),
        )
    }
}

/// The `(event, payload)` pairs published for one leg, in order.
type Published = Vec<(String, serde_json::Value)>;

fn names(events: &[(String, serde_json::Value)]) -> Vec<&str> {
    events.iter().map(|(event, _)| event.as_str()).collect()
}

fn dtmf(engine_call_id: &str, from_tag: &str, digit: &str) -> DtmfEvent {
    DtmfEvent {
        call_id: engine_call_id.to_string(),
        from_tag: from_tag.to_string(),
        to_tag: None,
        digit: digit.to_string(),
        duration_ms: 100,
        volume: -8,
        source: Some("rfc4733".to_string()),
    }
}

/// A digit detected on the pair's engine call goes to the channel of the
/// party that pressed it, named by the event's tag, and not to the other
/// party. A tag neither party carries goes nowhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_digit_on_a_pair_reaches_the_party_that_pressed_it() {
    let pair = formed_pair("pair-dtmf", "198.51.100.191:5060").await;
    let _ = pair.published();

    control_forward_dtmf(
        pair.state(),
        &dtmf(&pair.engine_call_id, &pair.phone_tag, "5"),
    );
    let (caller, phone) = pair.published();
    assert!(caller.is_empty(), "the caller did not press it: {caller:?}");
    assert_eq!(names(&phone), ["ChannelDtmfReceived"]);
    assert_eq!(phone[0].1["digit"], "5");

    control_forward_dtmf(
        pair.state(),
        &dtmf(&pair.engine_call_id, &pair.caller_tag, "1"),
    );
    let (caller, phone) = pair.published();
    assert_eq!(names(&caller), ["ChannelDtmfReceived"]);
    assert_eq!(caller[0].1["digit"], "1");
    assert!(phone.is_empty(), "the phone did not press it: {phone:?}");

    control_forward_dtmf(
        pair.state(),
        &dtmf(&pair.engine_call_id, "tag-stranger", "9"),
    );
    let (caller, phone) = pair.published();
    assert!(caller.is_empty() && phone.is_empty());
}

/// A playback, a recording and the WebSocket streams on the pair's engine
/// call each reach the leg whose tag the event names, and only that leg.
#[tokio::test(flavor = "multi_thread")]
async fn per_party_media_events_on_a_pair_reach_the_leg_they_name() {
    let pair = formed_pair("pair-events", "198.51.100.192:5060").await;
    let state = pair.state();
    let engine_call_id = pair.engine_call_id.clone();
    let _ = pair.published();

    publish_play_finished(
        state,
        &PlayFinishedEvent {
            call_id: engine_call_id.clone(),
            from_tag: pair.caller_tag.clone(),
            to_tag: None,
            play_id: 7,
            reason: PlayEndReason::Completed,
            played_ms: Some(1200),
        },
    );
    publish_recording_finished(
        state,
        &RecordingFinished {
            call_id: engine_call_id.clone(),
            from_tag: pair.caller_tag.clone(),
            recording_id: "rec-1".to_string(),
            path: Some("/var/spool/recordings/rec-1.wav".to_string()),
            reason: "stopped",
            duration_ms: 4000,
        },
    );
    let (caller, phone) = pair.published();
    assert_eq!(names(&caller), ["PlayFinished", "RecordingFinished"]);
    assert!(phone.is_empty(), "{phone:?}");

    publish_ws_tee_started(
        state,
        &WsTeeStarted {
            call_id: engine_call_id.clone(),
            from_tag: pair.phone_tag.clone(),
            stream_id: "tee-1".to_string(),
            ws_uri: "wss://stream.example.test/tee".to_string(),
            direction: WsTeeDirection::Both,
            channels: 2,
            sample_rate: 16000,
        },
    );
    publish_ws_tee_ended(
        state,
        &WsTeeEnded {
            call_id: engine_call_id.clone(),
            from_tag: pair.phone_tag.clone(),
            stream_id: "tee-1".to_string(),
            reason: WsTeeEndReason::ServerClosed,
            frames_sent: Some(10),
            frames_dropped: Some(0),
        },
    );
    publish_ws_bridge_started(
        state,
        &WsBridgeStarted {
            call_id: engine_call_id.clone(),
            from_tag: pair.phone_tag.clone(),
            stream_id: "bridge-1".to_string(),
            ws_uri: "wss://stream.example.test/bridge".to_string(),
            sample_rate: 16000,
        },
    );
    publish_ws_bridge_ended(
        state,
        &WsBridgeEnded {
            call_id: engine_call_id.clone(),
            from_tag: pair.phone_tag.clone(),
            stream_id: "bridge-1".to_string(),
            reason: WsBridgeEndReason::Detached,
        },
    );
    let (caller, phone) = pair.published();
    assert!(caller.is_empty(), "{caller:?}");
    assert_eq!(
        names(&phone),
        [
            "WsTeeStarted",
            "WsTeeEnded",
            "WsBridgeStarted",
            "WsBridgeEnded"
        ]
    );
}

/// Media starting on the pair's engine call reaches the leg it started on: the
/// near leg faces the caller (the pair's offerer), the far leg the phone. The
/// event carries both tags whichever leg it is about, so the leg picks the
/// party, and each report reaches one channel only.
#[tokio::test(flavor = "multi_thread")]
async fn media_started_on_a_pair_reaches_the_leg_it_started_on() {
    let pair = formed_pair("pair-started", "198.51.100.195:5060").await;
    let _ = pair.published();
    let started = |leg| MediaStartedEvent {
        call_id: pair.engine_call_id.clone(),
        from_tag: pair.caller_tag.clone(),
        to_tag: Some(pair.phone_tag.clone()),
        leg,
        source: Some("203.0.113.7:40000".parse().expect("an address")),
        signalled: Some("192.0.2.10:4000".parse().expect("an address")),
    };

    publish_media_started(pair.state(), &started(MediaLeg::Far));
    let (caller, phone) = pair.published();
    assert!(
        caller.is_empty(),
        "the caller's leg did not start: {caller:?}"
    );
    assert_eq!(names(&phone), ["MediaStarted"]);
    assert_eq!(phone[0].1["leg"], "far");
    assert_eq!(phone[0].1["nat_rewritten"], true);

    publish_media_started(pair.state(), &started(MediaLeg::Near));
    let (caller, phone) = pair.published();
    assert_eq!(names(&caller), ["MediaStarted"]);
    assert_eq!(caller[0].1["leg"], "near");
    assert!(phone.is_empty(), "{phone:?}");

    // A far leg with no answerer tag names no party of the pair.
    publish_media_started(
        pair.state(),
        &MediaStartedEvent {
            to_tag: None,
            ..started(MediaLeg::Far)
        },
    );
    let (caller, phone) = pair.published();
    assert!(caller.is_empty() && phone.is_empty());
}

/// The engine reaping the pair on media timeout clears the entry the pair is
/// stored under (the anchor's), so no teardown deletes it again, and the
/// timeout summary that follows reaches both legs.
#[tokio::test(flavor = "multi_thread")]
async fn a_media_timeout_on_a_pair_clears_the_anchors_entry() {
    let pair = formed_pair("pair-timeout", "198.51.100.193:5060").await;
    let state = pair.state();

    assert!(clear_media_session_on_timeout(
        state.rtpengine_sessions.as_ref(),
        &pair.engine_call_id
    ));
    assert!(stored(state, &pair.caller.call_id).is_none());

    let _ = pair.published();
    publish_media_summary(
        state,
        &CallSummary {
            call_id: pair.engine_call_id.clone(),
            reason: "media_timeout".to_string(),
            duration_ms: 30_000,
            legs: Vec::new(),
        },
    );
    let (caller, phone) = pair.published();
    assert_eq!(names(&caller), ["MediaSummary"]);
    assert_eq!(names(&phone), ["MediaSummary"]);
}

/// The pair's media CDR joins both legs' SIP CDRs: one record per leg, each
/// on that leg's Call-ID, both carrying the pair's engine call-id (the key a
/// collector de-duplicates the shared figures on) and how many legs share it.
#[tokio::test(flavor = "multi_thread")]
async fn a_pairs_media_cdr_joins_both_legs() {
    let pair = formed_pair("pair-cdr", "198.51.100.194:5060").await;
    let summary = CallSummary {
        call_id: pair.engine_call_id.clone(),
        reason: "delete".to_string(),
        duration_ms: 61_000,
        legs: Vec::new(),
    };
    let parties = media_summary_parties(pair.state(), &summary.call_id);
    let records = media_summary_to_cdrs(&summary, &parties);
    let call_ids: Vec<&str> = records.iter().map(|cdr| cdr.call_id.as_str()).collect();
    assert_eq!(
        call_ids,
        [pair.caller.call_id.as_str(), pair.phone_call_id.as_str()]
    );
    for cdr in &records {
        assert_eq!(cdr.method, "MEDIA");
        assert_eq!(
            cdr.extra.get("media_call_id"),
            Some(&pair.engine_call_id),
            "{}",
            cdr.call_id
        );
        assert_eq!(
            cdr.extra.get("media_parties").map(String::as_str),
            Some("2")
        );
        assert_eq!(
            cdr.extra.get("media_reason").map(String::as_str),
            Some("delete")
        );
    }
}

/// An ordinary call's media CDR is the one record it always was, on its own
/// Call-ID, now also naming the engine call (the same id) and one party.
#[test]
fn an_ordinary_calls_media_cdr_is_one_record_on_its_call_id() {
    let summary = CallSummary {
        call_id: "single-cdr@192.0.2.10".to_string(),
        reason: "delete".to_string(),
        duration_ms: 5_000,
        legs: Vec::new(),
    };
    let records = media_summary_to_cdrs(&summary, std::slice::from_ref(&summary.call_id));
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].call_id, "single-cdr@192.0.2.10");
    assert_eq!(
        records[0].extra.get("media_call_id").map(String::as_str),
        Some("single-cdr@192.0.2.10")
    );
    assert_eq!(
        records[0].extra.get("media_parties").map(String::as_str),
        Some("1")
    );
}

/// A recording running on an answered caller when it is bridged ends, because
/// the bridge moves the caller's media onto the pair's engine call and retires
/// the session the recording was on. The call is still up, so the application
/// is told `bridged`, not `call_ended`; a recording the bridge did not retire
/// keeps the engine's own reason.
#[tokio::test(flavor = "multi_thread")]
async fn a_recording_ended_by_a_bridge_is_not_reported_as_the_call_ending() {
    let before_bridge = std::sync::Arc::new(std::sync::Mutex::new(None));
    let noted = std::sync::Arc::clone(&before_bridge);
    let pair = formed_pair_after(
        "pair-recording",
        "198.51.100.195:5060",
        move |state, caller| {
            let session = stored(state, &caller.call_id).expect("the caller is anchored");
            crate::rtpengine::MediaBackend::recording_started(
                "rec-before-bridge",
                session.rtpengine_id(),
                std::time::Instant::now(),
            );
            *noted.lock().expect("unpoisoned") =
                Some((session.rtpengine_id().to_string(), session.from_tag.clone()));
        },
    )
    .await;
    let state = pair.state();
    let (old_engine_call_id, old_tag) = before_bridge
        .lock()
        .expect("unpoisoned")
        .clone()
        .expect("the caller's session before the bridge");
    assert_ne!(
        old_engine_call_id, pair.engine_call_id,
        "the bridge moved the caller onto another engine call"
    );
    let _ = pair.published();

    // The engine reports the recording finished the only way it can.
    on_recording_finished(
        state,
        RecordingFinished {
            call_id: old_engine_call_id.clone(),
            from_tag: old_tag.clone(),
            recording_id: "rec-before-bridge".to_string(),
            path: Some("/var/spool/recordings/rec-before-bridge.wav".to_string()),
            reason: "call_ended",
            duration_ms: 9000,
        },
    );
    let (caller, phone) = pair.published();
    assert_eq!(names(&caller), ["RecordingFinished"], "{caller:?}");
    assert_eq!(caller[0].1["reason"], "bridged");
    assert_eq!(caller[0].1["recording_id"], "rec-before-bridge");
    assert_eq!(caller[0].1["duration_ms"], 9000);
    assert!(phone.is_empty(), "{phone:?}");
    assert_eq!(
        crate::rtpengine::MediaBackend::recordings_awaited_on(&old_engine_call_id),
        0,
        "the record went with the report"
    );

    // Positive control: a recording on the pair's own engine call, which no
    // bridge retired, ends with the reason the engine gave.
    crate::rtpengine::MediaBackend::recording_started(
        "rec-on-the-pair",
        &pair.engine_call_id,
        std::time::Instant::now(),
    );
    on_recording_finished(
        state,
        RecordingFinished {
            call_id: pair.engine_call_id.clone(),
            from_tag: pair.caller_tag.clone(),
            recording_id: "rec-on-the-pair".to_string(),
            path: Some("/var/spool/recordings/rec-on-the-pair.wav".to_string()),
            reason: "call_ended",
            duration_ms: 3000,
        },
    );
    let (caller, _) = pair.published();
    assert_eq!(names(&caller), ["RecordingFinished"], "{caller:?}");
    assert_eq!(caller[0].1["reason"], "call_ended");
}

#[test]
fn only_a_call_ended_on_a_retired_session_reads_as_bridged() {
    assert_eq!(recording_end_reason("call_ended", true), "bridged");
    assert_eq!(recording_end_reason("call_ended", false), "call_ended");
    // The controller's own stop, a cap or silence is what it is either way.
    for reason in ["stopped", "max_duration", "silence", "error"] {
        assert_eq!(recording_end_reason(reason, true), reason);
    }
}
