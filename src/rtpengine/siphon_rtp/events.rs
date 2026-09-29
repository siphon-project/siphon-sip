//! The engine's events, as siphon's own [`RtpEngineEvent`].
//!
//! Every proto event the engine pushes is mapped here onto the generic event
//! enum the dispatcher consumes, so that enum stays free of the proto types.

use siphon_rtp_proto::{
    Event, LegSide, LegSummary as ProtoLegSummary, PlayEndReason,
    WsBridgeEndReason as ProtoWsBridgeEndReason, WsTeeEndReason as ProtoWsTeeEndReason,
    X3EndReason,
};
use tracing::debug;

use super::super::events::{
    BeepDetectedEvent, CallLegSummary, CallSummary, DtmfEvent, MediaLeg, MediaStartedEvent,
    PlayEndReason as SiphonPlayEndReason, PlayFinishedEvent, RecordingFinished, RtpEngineEvent,
    TextEvent, TextStreamStats, WsBridgeEndReason, WsBridgeEnded, WsBridgeStarted, WsTeeEndReason,
    WsTeeEnded, WsTeeStarted, X3EndedEvent, X3LossEvent, X3StartedEvent,
};
use super::ws_tee_direction_from_proto;

/// Convert a proto [`Event`] to siphon's [`RtpEngineEvent`].
///
/// `Event::Dtmf` is a field-for-field twin of [`DtmfEvent`]; `MediaTimeout`
/// maps to the dedicated variant. The conference/quality events
/// (`ActiveSpeaker`, `CallQuality`) are not modelled by a typed handler yet, so
/// they surface through `Unknown` (logged, not dropped) carrying their stream
/// identifiers — a typed Python handler is a follow-up.
pub(super) fn convert_event(event: Event) -> RtpEngineEvent {
    match event {
        Event::Dtmf {
            call_id,
            from_tag,
            to_tag,
            digit,
            duration_ms,
            volume,
            source,
        } => RtpEngineEvent::Dtmf(DtmfEvent {
            call_id,
            from_tag,
            to_tag,
            digit,
            duration_ms,
            volume,
            source,
        }),
        Event::RecordingFinished {
            call_id,
            from_tag,
            recording_id,
            path,
            reason,
            duration_ms,
            // Room recording names a conference instead of a call; siphon-sip
            // has no conference concept to map it onto yet.
            ..
        } => RtpEngineEvent::RecordingFinished(RecordingFinished {
            call_id,
            from_tag,
            recording_id,
            path,
            reason: recording_end_reason_from_proto(reason),
            duration_ms,
        }),
        Event::MediaTimeout {
            call_id,
            from_tag,
            reason,
        } => RtpEngineEvent::MediaTimeout {
            call_id,
            from_tag,
            reason: match reason {
                siphon_rtp_proto::MediaTimeoutReason::NoMedia => "no_media",
                siphon_rtp_proto::MediaTimeoutReason::HeldTooLong => "held_too_long",
                // The reason set can grow; an unrecognised one is still a
                // timeout, and naming it that is better than refusing to build.
                _ => "unknown",
            },
        },
        Event::CallSummary {
            call_id,
            reason,
            duration_ms,
            // The wall-clock bounds feed an RFC 6035 report, which siphon does
            // not send; named rather than `..` so the next field is a decision.
            started_at_unix_ms: _,
            ended_at_unix_ms: _,
            legs,
        } => RtpEngineEvent::CallSummary(CallSummary {
            call_id,
            reason,
            duration_ms,
            legs: legs.into_iter().map(convert_leg_summary).collect(),
        }),
        Event::Text {
            call_id,
            from_tag,
            to_tag,
            text,
            direction,
        } => RtpEngineEvent::Text(TextEvent {
            call_id,
            from_tag,
            to_tag,
            text,
            direction,
        }),
        Event::ActiveSpeaker {
            conference_id,
            from_tag,
        } => RtpEngineEvent::Unknown {
            event: "active_speaker".to_string(),
            call_id: Some(conference_id),
            from_tag,
        },
        Event::CallQuality {
            conference_id,
            call_id,
            from_tag,
            ..
        } => RtpEngineEvent::Unknown {
            event: "call_quality".to_string(),
            call_id: call_id.or(conference_id),
            from_tag: Some(from_tag),
        },
        Event::PlayFinished {
            call_id,
            from_tag,
            to_tag,
            play_id,
            reason,
            played_ms,
            // Room playback (`conference_id`) has no siphon-sip concept to map
            // onto yet — it lands with the conference verbs, not here.
            ..
        } => RtpEngineEvent::PlayFinished(PlayFinishedEvent {
            call_id,
            from_tag,
            to_tag,
            play_id,
            reason: play_end_reason_from_proto(reason),
            played_ms,
        }),
        Event::WsTeeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            direction,
            channels,
            sample_rate,
        } => RtpEngineEvent::WsTeeStarted(WsTeeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            direction: ws_tee_direction_from_proto(direction),
            channels,
            sample_rate,
        }),
        Event::WsTeeEnded {
            call_id,
            from_tag,
            stream_id,
            reason,
            frames_sent,
            frames_dropped,
        } => RtpEngineEvent::WsTeeEnded(WsTeeEnded {
            call_id,
            from_tag,
            stream_id,
            reason: ws_tee_end_reason_from_proto(reason),
            frames_sent,
            frames_dropped,
        }),
        Event::WsBridgeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            sample_rate,
        } => RtpEngineEvent::WsBridgeStarted(WsBridgeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            sample_rate,
        }),
        Event::WsBridgeEnded {
            call_id,
            from_tag,
            stream_id,
            reason,
        } => RtpEngineEvent::WsBridgeEnded(WsBridgeEnded {
            call_id,
            from_tag,
            stream_id,
            reason: ws_bridge_end_reason_from_proto(reason),
        }),
        Event::BeepDetected {
            call_id,
            from_tag,
            to_tag,
            frequency_hz,
            duration_ms,
            offset_ms,
        } => RtpEngineEvent::BeepDetected(BeepDetectedEvent {
            call_id,
            from_tag,
            to_tag,
            frequency_hz,
            duration_ms,
            offset_ms,
        }),
        Event::X3Started {
            call_id,
            from_tag,
            delivery,
            xid,
            correlation_id,
            // The target leg is what siphon told the engine, so it carries no
            // information back; the compliance record already has it.
            target_leg: _,
        } => RtpEngineEvent::X3Started(X3StartedEvent {
            call_id,
            from_tag,
            delivery,
            xid: *xid.as_bytes(),
            correlation_id,
        }),
        Event::X3Loss {
            call_id,
            from_tag,
            dropped,
            delivered,
            dropped_since_ms,
        } => RtpEngineEvent::X3Loss(X3LossEvent {
            call_id,
            from_tag,
            dropped,
            delivered,
            dropped_since_ms,
        }),
        Event::X3Ended {
            call_id,
            from_tag,
            reason,
            delivered,
            dropped,
        } => RtpEngineEvent::X3Ended(X3EndedEvent {
            call_id,
            from_tag,
            // `X3EndReason` is `#[non_exhaustive]`, so it is rendered rather
            // than mirrored: a reason this build has not heard of still means
            // delivery stopped, and the counts are what the record needs.
            reason: format!("{reason:?}"),
            // Only a controller-driven detach is an orderly end. A reason this
            // build does not recognise is treated as *not* orderly, because
            // assuming otherwise would silently downgrade a new failure mode
            // into a clean shutdown and skip the report the agency is owed.
            orderly: matches!(reason, X3EndReason::Detached),
            delivered,
            dropped,
        }),
        Event::MediaStarted {
            call_id,
            from_tag,
            to_tag,
            leg,
            source,
            signalled,
        } => RtpEngineEvent::MediaStarted(MediaStartedEvent {
            call_id,
            from_tag,
            to_tag,
            // Not `#[non_exhaustive]` upstream: a call has exactly two engine
            // legs, so this match stays exhaustive and a third breaks the build.
            leg: match leg {
                LegSide::Near => MediaLeg::Near,
                LegSide::Far => MediaLeg::Far,
            },
            source,
            signalled,
        }),
        Event::Unknown => RtpEngineEvent::Unknown {
            event: "unknown".to_string(),
            call_id: None,
            from_tag: None,
        },
        // `Event` is `#[non_exhaustive]` upstream, so a build newer than this one
        // can push a variant this one has no arm for. Surfaced through `Unknown`
        // (which the dispatcher logs) rather than dropped — the correlation ids
        // are unreachable behind the wildcard, but the fact that an unmodelled
        // event arrived is exactly what tells an operator siphon is behind the
        // engine. A serde-level `Event::Unknown` (an event tag the *proto* did
        // not recognise) is the arm above; this is a tag it did.
        other => {
            debug!(?other, "siphon-rtp event not modelled by this build");
            RtpEngineEvent::Unknown {
                event: "unmodelled".to_string(),
                call_id: None,
                from_tag: None,
            }
        }
    }
}

/// Map the proto tee end-reason onto siphon's own enum.
///
/// `WsTeeEndReason` is `#[non_exhaustive]` upstream. The wildcard maps to
/// [`WsTeeEndReason::TransportError`] rather than a silent
/// [`WsTeeEndReason::Detached`]: `Detached` and `CallEnded` are the only
/// orderly ends, and the dispatcher keys its WARN-when-unexpected logging on
/// that distinction, so
/// treating an unknown reason as orderly would hide a dead stream on a live
/// call — the exact failure this event exists to surface.
pub(super) fn ws_tee_end_reason_from_proto(reason: ProtoWsTeeEndReason) -> WsTeeEndReason {
    match reason {
        ProtoWsTeeEndReason::Detached => WsTeeEndReason::Detached,
        ProtoWsTeeEndReason::ServerClosed => WsTeeEndReason::ServerClosed,
        ProtoWsTeeEndReason::ServerStopped => WsTeeEndReason::ServerStopped,
        ProtoWsTeeEndReason::CallEnded => WsTeeEndReason::CallEnded,
        ProtoWsTeeEndReason::TransportError => WsTeeEndReason::TransportError,
        _ => WsTeeEndReason::TransportError,
    }
}

/// Map the proto play end-reason onto siphon's own enum.
///
/// `PlayEndReason` is `#[non_exhaustive]` upstream. The wildcard maps to
/// [`SiphonPlayEndReason::Error`] rather than [`SiphonPlayEndReason::Completed`], for the
/// same reason the two stream mappings never guess "orderly": `Completed` is
/// the only reason that means the prompt was actually heard in full, and an app
/// that queues its next step on that would take an unknown ending as a
/// successful one.
/// Why a recording ended, as a stable string for the scripting and control
/// surfaces.
///
/// `RecordingEndReason` is `#[non_exhaustive]`, so a reason the engine adds
/// later reads as `unknown` rather than failing the build — the recording still
/// finished and its file is still there.
pub(super) fn recording_end_reason_from_proto(
    reason: siphon_rtp_proto::RecordingEndReason,
) -> &'static str {
    use siphon_rtp_proto::RecordingEndReason;
    match reason {
        RecordingEndReason::Stopped => "stopped",
        RecordingEndReason::MaxDuration => "max_duration",
        RecordingEndReason::Silence => "silence",
        RecordingEndReason::CallEnded => "call_ended",
        RecordingEndReason::Error => "error",
        _ => "unknown",
    }
}

pub(super) fn play_end_reason_from_proto(reason: PlayEndReason) -> SiphonPlayEndReason {
    match reason {
        PlayEndReason::Completed => SiphonPlayEndReason::Completed,
        PlayEndReason::Stopped => SiphonPlayEndReason::Stopped,
        PlayEndReason::Superseded => SiphonPlayEndReason::Superseded,
        PlayEndReason::Error => SiphonPlayEndReason::Error,
        _ => SiphonPlayEndReason::Error,
    }
}

/// Map the proto bridge end-reason onto siphon's own enum.
///
/// `WsBridgeEndReason` is `#[non_exhaustive]` upstream. The wildcard maps to
/// [`WsBridgeEndReason::TransportError`] rather than a silent
/// [`WsBridgeEndReason::Detached`], for the same reason
/// [`ws_tee_end_reason_from_proto`] does and with more at stake: `Detached` and
/// `CallEnded` are the only orderly ends, and a bridge is the call's *whole*
/// media path, so
/// reading an unknown reason as orderly hides a live call whose far side has
/// gone away.
pub(super) fn ws_bridge_end_reason_from_proto(reason: ProtoWsBridgeEndReason) -> WsBridgeEndReason {
    match reason {
        ProtoWsBridgeEndReason::Detached => WsBridgeEndReason::Detached,
        ProtoWsBridgeEndReason::ServerClosed => WsBridgeEndReason::ServerClosed,
        ProtoWsBridgeEndReason::ServerStopped => WsBridgeEndReason::ServerStopped,
        ProtoWsBridgeEndReason::CallEnded => WsBridgeEndReason::CallEnded,
        ProtoWsBridgeEndReason::TransportError => WsBridgeEndReason::TransportError,
        _ => WsBridgeEndReason::TransportError,
    }
}

/// Convert a proto [`ProtoLegSummary`] into siphon's [`CallLegSummary`] — a
/// field-for-field copy that keeps the generic event enum free of the proto type.
pub(super) fn convert_leg_summary(leg: ProtoLegSummary) -> CallLegSummary {
    CallLegSummary {
        tag: leg.tag,
        codec: leg.codec,
        packets_in: leg.packets_in,
        bytes_in: leg.bytes_in,
        packets_out: leg.packets_out,
        bytes_out: leg.bytes_out,
        packets_dropped: leg.packets_dropped,
        ssrc: leg.ssrc,
        packets_lost: leg.packets_lost,
        loss_percent: leg.loss_percent,
        jitter_ms: leg.jitter_ms,
        rtt_ms: leg.rtt_ms,
        mos_average: leg.mos_average,
        mos_min: leg.mos_min,
        mos_max: leg.mos_max,
        mos_basis: leg.mos_basis,
        text: leg.text.map(|stats| TextStreamStats {
            packets: stats.packets,
            characters: stats.characters,
            missing_markers: stats.missing_markers,
            recovered_from_redundancy: stats.recovered_from_redundancy,
        }),
        local_address: leg.local_address,
        remote_address: leg.remote_address,
        egress_ssrc: leg.egress_ssrc,
        payload_type: leg.payload_type,
        media_started_at_unix_ms: leg.media_started_at_unix_ms,
    }
}
