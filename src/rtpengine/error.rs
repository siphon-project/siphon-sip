//! RTPEngine error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RtpEngineError {
    #[error("RTPEngine I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("RTPEngine bencode decode error: {0}")]
    Decode(String),

    #[error("RTPEngine protocol error: {0}")]
    Protocol(String),

    #[error("RTPEngine timeout: no response within {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("RTPEngine returned error: {0}")]
    EngineError(String),

    /// The configured media backend has no way to perform this operation.
    ///
    /// Returned rather than a silent `Ok(())` — a hollow success on, say, an
    /// `attach_ws_tee` against rtpengine reads as "the tee is attached" while no
    /// audio ever reaches the consumer, which is exactly the failure the
    /// config-load rejection of WS profile fields exists to prevent.  The
    /// declarative path is caught at boot; this is its per-call twin for
    /// operations a script issues directly.
    #[error("{operation} is not supported by the {backend} media backend")]
    Unsupported {
        /// The operation asked for, e.g. `"attach_ws_tee"`.
        operation: &'static str,
        /// The configured backend's name as it appears in `media.backend`.
        backend: &'static str,
    },
}

impl RtpEngineError {
    /// True when the error means "the engine has no such call" — the media
    /// session was already torn down (media-timeout reaper, a prior delete,
    /// glare). On a *safety-net* delete this is success, not failure: the net
    /// exists precisely to catch the not-yet-deleted case, so a not-found
    /// result confirms the media is already gone.
    ///
    /// No typed not-found variant crosses the wire; each backend surfaces it as
    /// an [`RtpEngineError::EngineError`] carrying its own reason text:
    ///   - rtpengine NG -> `"Unknown call-id"`
    ///   - siphon-rtp   -> `"unknown call: <call-id>"`
    ///   - rtpproxy     -> `"rtpproxy delete error E8"` (E8 = unknown call id)
    ///
    /// so match on the reason text. `"unknown call"` (lowercased) covers both
    /// rtpengine NG and siphon-rtp; `"delete error e8"` covers rtpproxy.
    pub fn is_call_not_found(&self) -> bool {
        match self {
            RtpEngineError::EngineError(reason) => {
                let lower = reason.to_ascii_lowercase();
                lower.contains("unknown call") || lower.contains("delete error e8")
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_display() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "socket gone");
        let error: RtpEngineError = io_error.into();
        assert!(error.to_string().contains("socket gone"));
    }

    #[test]
    fn decode_error_display() {
        let error = RtpEngineError::Decode("unexpected byte 0xff".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine bencode decode error: unexpected byte 0xff"
        );
    }

    #[test]
    fn protocol_error_display() {
        let error = RtpEngineError::Protocol("missing result field".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine protocol error: missing result field"
        );
    }

    #[test]
    fn timeout_error_display() {
        let error = RtpEngineError::Timeout { timeout_ms: 1000 };
        assert_eq!(
            error.to_string(),
            "RTPEngine timeout: no response within 1000ms"
        );
    }

    #[test]
    fn engine_error_display() {
        let error = RtpEngineError::EngineError("session not found".to_string());
        assert_eq!(
            error.to_string(),
            "RTPEngine returned error: session not found"
        );
    }

    #[test]
    fn error_is_debug() {
        let error = RtpEngineError::Decode("test".to_string());
        let debug = format!("{:?}", error);
        assert!(debug.contains("Decode"));
    }

    #[test]
    fn is_call_not_found_matches_siphon_rtp_reason() {
        // siphon-rtp surfaces not-found as "unknown call: <call-id>".
        let error = RtpEngineError::EngineError("unknown call: 1-abc@host".to_string());
        assert!(error.is_call_not_found());
    }

    #[test]
    fn is_call_not_found_matches_rtpengine_ng_reason() {
        // rtpengine NG surfaces not-found as "Unknown call-id" (note the case).
        let error = RtpEngineError::EngineError("Unknown call-id".to_string());
        assert!(error.is_call_not_found());
    }

    #[test]
    fn is_call_not_found_matches_rtpproxy_reason() {
        // rtpproxy surfaces not-found as error code E8.
        let error = RtpEngineError::EngineError("rtpproxy delete error E8".to_string());
        assert!(error.is_call_not_found());
    }

    #[test]
    fn is_call_not_found_false_for_transport_and_unrelated_errors() {
        // Real failures — a safety-net delete must still warn on these.
        assert!(!RtpEngineError::Timeout { timeout_ms: 1000 }.is_call_not_found());
        assert!(!RtpEngineError::Protocol("missing result field".to_string()).is_call_not_found());
        assert!(!RtpEngineError::Decode("bad bytes".to_string()).is_call_not_found());
        let io_error = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        assert!(!RtpEngineError::from(io_error).is_call_not_found());
        // An engine error that is NOT a not-found must still warn.
        assert!(!RtpEngineError::EngineError("no-encodable-codec".to_string()).is_call_not_found());
    }

    #[test]
    fn unsupported_error_names_the_operation_and_backend() {
        let error = RtpEngineError::Unsupported {
            operation: "attach_ws_tee",
            backend: "rtpengine",
        };
        assert_eq!(
            error.to_string(),
            "attach_ws_tee is not supported by the rtpengine media backend"
        );
        // Never mistaken for "the call is already gone" — a safety-net delete
        // must not treat an unsupported operation as success.
        assert!(!error.is_call_not_found());
    }
}
