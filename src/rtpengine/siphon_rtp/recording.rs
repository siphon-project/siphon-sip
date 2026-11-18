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

/// What an engine that records several calls into one file lists.
const RECORD_MULTI_SOURCE_FEATURE: &str = "record_multi_source";

/// The `node_info` features a recording of `request` needs the engine to list
/// first: Ogg Opus, and several sources. Empty when it needs none.
pub(super) fn required_features(request: &RecordingRequest<'_>) -> Vec<&'static str> {
    let mut features = Vec::new();
    if request.format == RecordingFormat::OggOpus {
        features.push(RECORD_OGG_OPUS_FEATURE);
    }
    if !request.additional_sources.is_empty() {
        features.push(RECORD_MULTI_SOURCE_FEATURE);
    }
    features
}

/// Whether a `node_info` answer lists every one of `features`; `what` names
/// the verb for the refusal.
pub(super) fn require_features(
    result: CmdResult,
    features: &[&str],
    what: &str,
) -> Result<(), RtpEngineError> {
    match result {
        CmdResult::NodeInfo { node } => {
            let missing: Vec<&str> = features
                .iter()
                .copied()
                .filter(|wanted| !node.features.iter().any(|feature| feature == wanted))
                .collect();
            if missing.is_empty() {
                Ok(())
            } else {
                Err(RtpEngineError::Protocol(format!(
                    "{what} needs the engine (version {}) to list {} in node_info features; \
                     the multi-source verbs need siphon-rtp 0.21.0 or later, ogg_opus 0.15.0",
                    node.version,
                    missing.join(", ")
                )))
            }
        }
        CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
            "node_info refused while checking the engine for {what}: {reason}"
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
        additional_sources: request
            .additional_sources
            .iter()
            .map(|source| siphon_rtp_proto::RecordingSource {
                call_id: source.call_id.clone(),
                from_tag: source.from_tag.clone(),
            })
            .collect(),
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
    fn only_ogg_opus_and_several_sources_ask_the_engine_first() {
        assert_eq!(
            required_features(&RecordingRequest {
                format: RecordingFormat::OggOpus,
                ..Default::default()
            }),
            ["record_ogg_opus"]
        );
        assert!(required_features(&RecordingRequest::default()).is_empty());
        let sources = [crate::rtpengine::events::MediaSource {
            call_id: "c~1".into(),
            from_tag: "t".into(),
        }];
        assert_eq!(
            required_features(&RecordingRequest {
                format: RecordingFormat::OggOpus,
                additional_sources: &sources,
                ..Default::default()
            }),
            ["record_ogg_opus", "record_multi_source"]
        );
    }

    #[test]
    fn the_features_are_read_off_node_info() {
        let wanted = ["record_ogg_opus", "record_multi_source"];
        assert!(require_features(
            node_info(&["relay", "record_ogg_opus", "record_multi_source"]),
            &wanted,
            "a recording"
        )
        .is_ok());
        let missing = require_features(
            node_info(&["relay", "record_ogg_opus"]),
            &wanted,
            "a recording",
        )
        .unwrap_err()
        .to_string();
        assert!(
            missing.contains("0.14.0"),
            "the engine's version: {missing}"
        );
        assert!(missing.contains("record_multi_source"), "{missing}");
        assert!(
            !missing.contains("record_ogg_opus,"),
            "only what is missing: {missing}"
        );
        let refused = require_features(
            CmdResult::Error {
                reason: "busy".into(),
            },
            &wanted,
            "a recording",
        )
        .unwrap_err();
        assert!(refused.to_string().contains("busy"), "{refused}");
    }

    #[test]
    fn the_command_carries_the_additional_sources_in_order() {
        let sources = [
            crate::rtpengine::events::MediaSource {
                call_id: "c~1".into(),
                from_tag: "t".into(),
            },
            crate::rtpengine::events::MediaSource {
                call_id: "c~2".into(),
                from_tag: "t".into(),
            },
        ];
        let command = start_command(
            "c~0",
            "t",
            &RecordingRequest {
                additional_sources: &sources,
                ..Default::default()
            },
        );
        let json = serde_json::to_value(&command).expect("encodes");
        assert_eq!(json["call_id"], "c~0");
        assert_eq!(
            json["additional_sources"],
            serde_json::json!([
                { "call_id": "c~1", "from_tag": "t" },
                { "call_id": "c~2", "from_tag": "t" }
            ])
        );
        let single = serde_json::to_value(start_command("c~0", "t", &RecordingRequest::default()))
            .expect("encodes");
        assert!(
            single.get("additional_sources").is_none(),
            "omitted when empty: {single}"
        );
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
