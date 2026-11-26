//! Gating a verb on what the engine's `node_info` lists.

use siphon_rtp_proto::CmdResult;

use super::result_kind;
use crate::rtpengine::error::RtpEngineError;

/// Whether a `node_info` answer lists `feature`; refused as `operation` not
/// implemented by `backend` when it does not, so nothing is sent.
pub(super) fn require_feature(
    result: CmdResult,
    feature: &str,
    operation: &'static str,
    backend: &'static str,
) -> Result<(), RtpEngineError> {
    match result {
        CmdResult::NodeInfo { node } if node.features.iter().any(|listed| listed == feature) => {
            Ok(())
        }
        CmdResult::NodeInfo { node } => {
            tracing::warn!(
                version = %node.version,
                "{operation} asked for, but the media engine does not list \
                 '{feature}' in node_info features"
            );
            Err(RtpEngineError::Unsupported { operation, backend })
        }
        CmdResult::Error { reason } => Err(RtpEngineError::EngineError(format!(
            "node_info refused while checking for {feature}: {reason}"
        ))),
        other => Err(RtpEngineError::Protocol(format!(
            "unexpected '{}' response for node_info",
            result_kind(&other)
        ))),
    }
}
