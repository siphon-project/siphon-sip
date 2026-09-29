//! The media engine's per-party events on the control rail, and which channel
//! each one is for.
//!
//! The engine names a call by the engine call-id siphon offered it. That is the
//! SIP Call-ID a channel is keyed on, except for a bridged pair, which relays
//! through one engine call on an id of its own and carries both legs, and a
//! re-anchored session. A per-party event (a digit, a playback, a recording, a
//! stream) also names the party by its engine tag, which is how it is mapped to
//! the one leg it belongs to.

use super::*;

/// The SIP Call-ID of the channel a per-party engine event belongs to: the one
/// party of engine call `engine_call_id` whose media is on engine tag `tag`.
/// `None` when the tag names no party of a pair, or both: the event is dropped
/// rather than handed to the party it is not about.
pub(super) fn engine_event_channel(
    state: &DispatcherState,
    engine_call_id: &str,
    tag: &str,
) -> Option<String> {
    match state.rtpengine_sessions.as_ref() {
        Some(store) => store.event_party(engine_call_id, tag),
        None => Some(engine_call_id.to_string()),
    }
}

/// Forward a digit the media engine detected to the control plane as
/// `ChannelDtmfReceived`, on the channel of the party that sent it.
pub fn control_forward_dtmf(state: &DispatcherState, dtmf: &crate::rtpengine::events::DtmfEvent) {
    match engine_event_channel(state, &dtmf.call_id, &dtmf.from_tag) {
        Some(sip_call_id) => forward_dtmf_to(&sip_call_id, dtmf),
        None => tracing::debug!(
            engine_call_id = %dtmf.call_id,
            from_tag = %dtmf.from_tag,
            "control plane: a digit on an engine call whose tag names no single party, dropped"
        ),
    }
}

/// Forward a digit carried in SIP (an INFO) to the control plane. Its Call-ID
/// is already the channel's SIP Call-ID, and its tag siphon's own, so there is
/// nothing to resolve.
pub fn control_forward_signalled_dtmf(dtmf: &crate::rtpengine::events::DtmfEvent) {
    forward_dtmf_to(&dtmf.call_id, dtmf);
}

fn forward_dtmf_to(sip_call_id: &str, dtmf: &crate::rtpengine::events::DtmfEvent) {
    // The library tests install no process bus; they read the forward here.
    #[cfg(test)]
    crate::control::channel_event_capture::record(
        sip_call_id,
        "ChannelDtmfReceived",
        &serde_json::json!({ "digit": dtmf.digit, "from_tag": dtmf.from_tag }),
    );
    if let Some(bus) = crate::control::ControlBus::global() {
        bus.forward_dtmf(
            sip_call_id,
            &dtmf.digit,
            dtmf.duration_ms,
            dtmf.volume,
            &dtmf.from_tag,
        );
    }
}

/// Publish a per-party engine event `event` to the channel of the party it
/// names; dropped, with a debug line, when it names none.
pub(super) fn publish_engine_event(
    state: &DispatcherState,
    engine_call_id: &str,
    tag: &str,
    event: &str,
    payload: serde_json::Value,
) {
    match engine_event_channel(state, engine_call_id, tag) {
        Some(sip_call_id) => crate::control::notify_channel_event(&sip_call_id, event, payload),
        None => tracing::debug!(
            %engine_call_id,
            %tag,
            event,
            "control plane: an engine event whose tag names no single party, dropped"
        ),
    }
}

/// A recording's file is closed: `RecordingFinished` to the channel that owns
/// the call, the only thing that knows what the recording was for.
pub(super) fn publish_recording_finished(
    state: &DispatcherState,
    recording: &crate::rtpengine::events::RecordingFinished,
) {
    publish_engine_event(
        state,
        &recording.call_id,
        &recording.from_tag,
        "RecordingFinished",
        serde_json::json!({
            "recording_id": recording.recording_id,
            "path": recording.path,
            "reason": recording.reason,
            "duration_ms": recording.duration_ms,
        }),
    );
}

/// A WebSocket tee started. Same rail as the takeover bridge's lifecycle: a
/// controller that started this stream has no other way to learn its shape.
pub(super) fn publish_ws_tee_started(
    state: &DispatcherState,
    tee: &crate::rtpengine::events::WsTeeStarted,
) {
    publish_engine_event(
        state,
        &tee.call_id,
        &tee.from_tag,
        "WsTeeStarted",
        serde_json::json!({
            "from_tag": tee.from_tag,
            "stream_id": tee.stream_id,
            "ws_uri": tee.ws_uri,
            "direction": tee.direction.as_str(),
            "channels": tee.channels,
            "sample_rate": tee.sample_rate,
        }),
    );
}

/// A WebSocket tee ended, or died while the call carried on.
pub(super) fn publish_ws_tee_ended(
    state: &DispatcherState,
    tee: &crate::rtpengine::events::WsTeeEnded,
) {
    publish_engine_event(
        state,
        &tee.call_id,
        &tee.from_tag,
        "WsTeeEnded",
        serde_json::json!({
            "from_tag": tee.from_tag,
            "stream_id": tee.stream_id,
            "reason": tee.reason.as_str(),
            // `detached` and `call_ended` are the orderly ends; anything else
            // means audio stopped reaching the consumer while the call carried
            // on.
            "unexpected": tee.reason.is_unexpected(),
            // Non-zero means the consumer could not keep up. The call was never
            // affected — this is the one number that tells a controller its own
            // side is the bottleneck.
            "frames_sent": tee.frames_sent,
            "frames_dropped": tee.frames_dropped,
        }),
    );
}

/// A WebSocket takeover bridge started.
pub(super) fn publish_ws_bridge_started(
    state: &DispatcherState,
    bridge: &crate::rtpengine::events::WsBridgeStarted,
) {
    publish_engine_event(
        state,
        &bridge.call_id,
        &bridge.from_tag,
        "WsBridgeStarted",
        serde_json::json!({
            "from_tag": bridge.from_tag,
            "stream_id": bridge.stream_id,
            "ws_uri": bridge.ws_uri,
            "sample_rate": bridge.sample_rate,
        }),
    );
}

/// A WebSocket takeover bridge ended.
pub(super) fn publish_ws_bridge_ended(
    state: &DispatcherState,
    bridge: &crate::rtpengine::events::WsBridgeEnded,
) {
    publish_engine_event(
        state,
        &bridge.call_id,
        &bridge.from_tag,
        "WsBridgeEnded",
        serde_json::json!({
            "from_tag": bridge.from_tag,
            "stream_id": bridge.stream_id,
            "reason": bridge.reason.as_str(),
            // Only `detached` and `call_ended` are orderly. A controller that
            // branches on nothing else still has to be able to see that this
            // one needs acting on.
            "unexpected": bridge.reason.is_unexpected(),
        }),
    );
}

/// The control plane's `MediaStarted` payload: which engine leg media started
/// on, the engine call's tags, where the first packet came from and where the
/// SDP said it would. `nat_rewritten` is present only when the engine reported
/// both addresses, and says whether they differ; an address the engine did not
/// report is absent rather than null.
pub(super) fn media_started_payload(
    started: &crate::rtpengine::events::MediaStartedEvent,
) -> serde_json::Value {
    let mut payload = serde_json::json!({
        "leg": started.leg.as_str(),
        "from_tag": started.from_tag,
    });
    if let Some(fields) = payload.as_object_mut() {
        if let Some(to_tag) = &started.to_tag {
            fields.insert("to_tag".into(), to_tag.as_str().into());
        }
        if let Some(source) = started.source {
            fields.insert("source".into(), source.to_string().into());
        }
        if let Some(signalled) = started.signalled {
            fields.insert("signalled".into(), signalled.to_string().into());
        }
        if let Some(nat_rewritten) = started.nat_rewritten() {
            fields.insert("nat_rewritten".into(), nat_rewritten.into());
        }
    }
    payload
}

/// Media started on one engine leg: `MediaStarted` to the channel of the party
/// that leg faces. The event names the engine call's tags and the leg; the
/// leg's own tag (the offerer's on the near leg, the answerer's on the far one)
/// picks the party on a bridged pair. A call nobody controls publishes nothing.
pub(super) fn publish_media_started(
    state: &DispatcherState,
    started: &crate::rtpengine::events::MediaStartedEvent,
) {
    publish_engine_event(
        state,
        &started.call_id,
        started.leg_tag().unwrap_or_default(),
        "MediaStarted",
        media_started_payload(started),
    );
}
