//! The `start_recording` frame, and the check an `ogg_opus` one needs first.
//!
//! An engine from before `ogg_opus` cannot parse the variant and closes the
//! whole control connection rather than refusing the one command, which drops
//! the control of every call on it. So an `ogg_opus` recording is asked for
//! only once `node_info` lists `record_ogg_opus`, on every start: one more
//! round trip per recording, and nothing to go stale when the connection comes
//! back on a different engine.

use siphon_rtp_proto::{CmdResult, Command};

use super::super::error::RtpEngineError;
use super::super::events::{
    RecordingChannels, RecordingDirection, RecordingFormat, RecordingRequest,
};
use super::result_kind;

/// What an engine that writes Ogg Opus lists in `node_info.features`.
const RECORD_OGG_OPUS_FEATURE: &str = "record_ogg_opus";

/// Whether a recording in `format` needs the engine checked first.
pub(super) fn needs_feature_check(format: RecordingFormat) -> bool {
    format == RecordingFormat::OggOpus
}

/// Whether a `node_info` answer lists the Ogg Opus feature.
pub(super) fn require_ogg_opus(result: CmdResult) -> Result<(), RtpEngineError> {
    match result {
        CmdResult::NodeInfo { node }
            if node
                .features
                .iter()
                .any(|feature| feature == RECORD_OGG_OPUS_FEATURE) =>
        {
            Ok(())
        }
        CmdResult::NodeInfo { node } => Err(RtpEngineError::Protocol(format!(
            "an ogg_opus recording was asked for but the engine (version {}) does not list \
             '{RECORD_OGG_OPUS_FEATURE}' in node_info features; it needs siphon-rtp 0.15.0 \
             or later",
            node.version
        ))),
        CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
            "node_info refused while checking for ogg_opus recording: {reason}"
        ))),
        other => Err(RtpEngineError::Protocol(format!(
            "unexpected '{}' response for node_info",
            result_kind(&other)
        ))),
    }
}

/// The `start_recording` command for `request`.
pub(super) fn start_command(
    call_id: &str,
    from_tag: &str,
    request: &RecordingRequest<'_>,
) -> Command {
    Command::StartRecording {
        call_id: call_id.to_string(),
        from_tag: from_tag.to_string(),
        recording_dir: None,
        format: Some(match request.format {
            RecordingFormat::Wav => siphon_rtp_proto::RecordingFormat::Wav,
            RecordingFormat::OggOpus => siphon_rtp_proto::RecordingFormat::OggOpus,
        }),
        direction: Some(match request.direction {
            RecordingDirection::Ingress => siphon_rtp_proto::RecordingDirection::Ingress,
            RecordingDirection::Egress => siphon_rtp_proto::RecordingDirection::Egress,
            RecordingDirection::Both => siphon_rtp_proto::RecordingDirection::Both,
        }),
        channels: Some(match request.channels {
            RecordingChannels::Mono => siphon_rtp_proto::RecordingChannels::Mono,
            RecordingChannels::Stereo => siphon_rtp_proto::RecordingChannels::Stereo,
        }),
        max_duration_ms: request.max_duration_ms,
        silence_ms: request.silence_ms,
        path: request.path.map(str::to_string),
        bitrate_bps: request.bitrate_bps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_info(features: &[&str]) -> CmdResult {
        serde_json::from_value(serde_json::json!({
            "result": "node_info",
            "node": {
                "node_id": "engine-1",
                "version": "0.14.0",
                "media_addresses": [],
                "codecs": [],
                "features": features,
                "max_sessions": 0,
                "draining": false,
            },
        }))
        .expect("a node_info result")
    }

    #[test]
    fn only_ogg_opus_asks_the_engine_first() {
        assert!(needs_feature_check(RecordingFormat::OggOpus));
        assert!(!needs_feature_check(RecordingFormat::Wav));
    }

    #[test]
    fn the_feature_is_read_off_node_info() {
        assert!(require_ogg_opus(node_info(&["relay", "record_ogg_opus"])).is_ok());
        let missing = require_ogg_opus(node_info(&["relay"])).unwrap_err();
        assert!(missing.to_string().contains("0.14.0"), "{missing}");
        let refused = require_ogg_opus(CmdResult::Error {
            reason: "busy".into(),
        })
        .unwrap_err();
        assert!(refused.to_string().contains("busy"), "{refused}");
    }

    #[test]
    fn the_command_carries_the_format_and_the_bitrate() {
        let request = RecordingRequest {
            format: RecordingFormat::OggOpus,
            bitrate_bps: Some(32_000),
            channels: RecordingChannels::Stereo,
            ..RecordingRequest::default()
        };
        match start_command("call-1", "tag-a", &request) {
            Command::StartRecording {
                format,
                bitrate_bps,
                channels,
                ..
            } => {
                assert_eq!(format, Some(siphon_rtp_proto::RecordingFormat::OggOpus));
                assert_eq!(bitrate_bps, Some(32_000));
                assert_eq!(channels, Some(siphon_rtp_proto::RecordingChannels::Stereo));
            }
            other => panic!("a start_recording, got {other:?}"),
        }
    }
}
