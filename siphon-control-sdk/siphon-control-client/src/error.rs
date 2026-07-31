//! The client error type.

use siphon_control_proto::ControlErrorCode;

/// Everything that can go wrong driving the control plane.
///
/// The load-bearing variant is [`ControlError::Command`]: a `status:"error"`
/// reply from the server maps to it, carrying the stable [`ControlErrorCode`] so
/// callers can `match` on the cause (e.g. treat `UnsupportedVerb` as "the server
/// doesn't do media yet" rather than a hard failure).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The server rejected a command with a typed error reply.
    #[error("control command rejected ({code:?}): {message}")]
    Command {
        /// The stable machine-readable error code from the reply.
        code: ControlErrorCode,
        /// The human-readable detail from the reply.
        message: String,
    },

    /// The WebSocket upgrade was rejected before it opened (bad/missing token →
    /// HTTP 401). Distinct from [`ControlError::Handshake`] so a caller can tell
    /// "wrong credentials" from "protocol handshake failed".
    #[error("unauthorized: the control token was rejected (HTTP {status})")]
    Unauthorized {
        /// The HTTP status the server returned on the upgrade (usually 401).
        status: u16,
    },

    /// The `hello` handshake (or subprotocol negotiation) failed after the socket
    /// opened.
    #[error("handshake failed: {0}")]
    Handshake(String),

    /// The connection is closed (or was never established) — no reply can arrive.
    #[error("control connection is closed")]
    Closed,

    /// A command was sent but no reply arrived within the configured window.
    #[error("timed out awaiting a reply after {0:?}")]
    Timeout(std::time::Duration),

    /// A transport-level WebSocket error.
    #[error("websocket error: {0}")]
    WebSocket(String),

    /// A frame could not be (de)serialized.
    #[error("serialization error: {0}")]
    Serde(String),

    /// A configuration value was invalid (bad URL, bad listen address, …).
    #[error("configuration error: {0}")]
    Config(String),
}

impl ControlError {
    /// The stable error code, when this error came from a server reply.
    ///
    /// Returns `None` for transport / handshake / local errors that never had a
    /// wire code.
    pub fn code(&self) -> Option<ControlErrorCode> {
        match self {
            ControlError::Command { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// True when this is a server-side `unsupported_verb` rejection — the state a
    /// media verb (`play`/`dtmf`/…) lands in until the server implements it.
    pub fn is_unsupported_verb(&self) -> bool {
        matches!(
            self,
            ControlError::Command {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            }
        )
    }
}

impl From<serde_json::Error> for ControlError {
    fn from(error: serde_json::Error) -> Self {
        ControlError::Serde(error.to_string())
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for ControlError {
    fn from(error: tokio_tungstenite::tungstenite::Error) -> Self {
        use tokio_tungstenite::tungstenite::Error as WsError;
        match error {
            WsError::Http(response) => ControlError::Unauthorized {
                status: response.status().as_u16(),
            },
            WsError::ConnectionClosed | WsError::AlreadyClosed => ControlError::Closed,
            other => ControlError::WebSocket(other.to_string()),
        }
    }
}
