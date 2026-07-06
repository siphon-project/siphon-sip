//! Wire protocol for the external control plane (`siphon-control.v1`).
//!
//! Single WebSocket per application, JSON text frames both directions:
//!
//! - **command** (client → siphon): `{id, type:"command", verb, target, args}`
//! - **reply** (siphon → client, `id` echoed): `{id, type:"reply", status, result|error}`
//! - **event** (siphon → client, un-id'd, pushed): `{type:"event", event, channel, payload}`
//!
//! The substrate never interprets `verb`/`args`/`target` beyond routing — they
//! are handed opaquely (`serde_json::Value`) to the adapter that applies them.

use serde::{Deserialize, Serialize};

/// Discriminator for the `type` field of every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameType {
    /// A command from the client.
    Command,
    /// A correlated reply to a command.
    Reply,
    /// A pushed event (no id).
    Event,
}

/// A command frame received from a control application (client → siphon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandFrame {
    /// Client-owned request id, echoed verbatim in the reply.
    pub id: String,
    /// Always [`FrameType::Command`].
    #[serde(rename = "type")]
    pub frame_type: FrameType,
    /// The verb to apply (e.g. `"answer"`, `"hangup"`, `"hello"`).
    pub verb: String,
    /// Adapter-defined target (e.g. `{"channel": "…"}`). Absent → JSON null.
    #[serde(default)]
    pub target: serde_json::Value,
    /// Adapter-defined arguments. Absent → JSON null.
    #[serde(default)]
    pub args: serde_json::Value,
}

impl CommandFrame {
    /// Extract the `target.channel` string when present.
    pub fn channel_target(&self) -> Option<String> {
        self.target
            .get("channel")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
    }
}

/// Status of a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReplyStatus {
    /// The command was accepted (the *local* action was performed).
    Ok,
    /// The command was rejected.
    Error,
}

/// Stable error codes returned in a reply's `error.code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    /// Authentication failed (bad/missing token).
    Unauthorized,
    /// The connection's app does not own the target resource.
    Forbidden,
    /// The target channel does not exist.
    NotFound,
    /// The frame or its arguments were malformed.
    BadRequest,
    /// The command exceeded a rate limit.
    RateLimited,
    /// The verb is not implemented by the adapter.
    UnsupportedVerb,
    /// The frame violated the protocol (e.g. duplicate id, bad handshake).
    ProtocolError,
    /// The control plane could not service the command right now.
    Unavailable,
}

/// The error body of a failed reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyError {
    /// Stable machine-readable code.
    pub code: ControlErrorCode,
    /// Human-readable detail.
    pub message: String,
}

/// A reply frame (siphon → client, `id` echoed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyFrame {
    /// The command id this reply correlates to.
    pub id: String,
    /// Always [`FrameType::Reply`].
    #[serde(rename = "type")]
    pub frame_type: FrameType,
    /// Whether the command was accepted.
    pub status: ReplyStatus,
    /// Present on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Present on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ReplyError>,
}

/// A pushed event frame (siphon → client, un-id'd).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFrame {
    /// Always [`FrameType::Event`].
    #[serde(rename = "type")]
    pub frame_type: FrameType,
    /// Event name (e.g. `"StasisStart"`, `"StasisEnd"`).
    pub event: String,
    /// The channel this event concerns, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The application the channel was handed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Event-specific payload.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

impl EventFrame {
    /// Build an event frame for a channel.
    pub fn new(
        event: impl Into<String>,
        channel: impl Into<String>,
        app: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            frame_type: FrameType::Event,
            event: event.into(),
            channel: Some(channel.into()),
            app: Some(app.into()),
            payload,
        }
    }
}

/// The outcome of applying a command — carried back to the connection's read
/// task over a `oneshot` and rendered into a [`ReplyFrame`].
///
/// A `ControlResult` is the reply to the *local* action only. It is emphatically
/// **not** a far-end outcome: an accepted `answer`/`hangup` returns `Ok`
/// immediately, and the callee's actual answer / BYE-200 arrive later as events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlResult {
    /// The local action was accepted.
    Ok(serde_json::Value),
    /// The command was rejected.
    Error {
        /// Machine-readable error code.
        code: ControlErrorCode,
        /// Human-readable detail.
        message: String,
    },
}

impl ControlResult {
    /// Convenience constructor for an error result.
    pub fn error(code: ControlErrorCode, message: impl Into<String>) -> Self {
        ControlResult::Error {
            code,
            message: message.into(),
        }
    }

    /// Render into a wire reply frame for the given command id.
    pub fn into_reply(self, id: String) -> ReplyFrame {
        match self {
            ControlResult::Ok(result) => ReplyFrame {
                id,
                frame_type: FrameType::Reply,
                status: ReplyStatus::Ok,
                result: Some(result),
                error: None,
            },
            ControlResult::Error { code, message } => ReplyFrame {
                id,
                frame_type: FrameType::Reply,
                status: ReplyStatus::Error,
                result: None,
                error: Some(ReplyError { code, message }),
            },
        }
    }
}

/// Arguments of the `hello` handshake command (`args`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloArgs {
    /// The application name — must equal the token's configured app.
    pub app: String,
    /// Protocol version the client speaks. Optional; defaults to 1.
    #[serde(default)]
    pub protocol: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frame_round_trip() {
        let frame = CommandFrame {
            id: "c-42".to_string(),
            frame_type: FrameType::Command,
            verb: "answer".to_string(),
            target: serde_json::json!({ "channel": "ch_9f3a" }),
            args: serde_json::json!({ "code": 200 }),
        };
        let text = serde_json::to_string(&frame).unwrap();
        assert!(text.contains("\"type\":\"command\""));
        let parsed: CommandFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(parsed.channel_target().as_deref(), Some("ch_9f3a"));
    }

    #[test]
    fn command_frame_defaults_missing_target_and_args() {
        let text = r#"{"id":"1","type":"command","verb":"hello"}"#;
        let parsed: CommandFrame = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.verb, "hello");
        assert!(parsed.target.is_null());
        assert!(parsed.args.is_null());
        assert_eq!(parsed.channel_target(), None);
    }

    #[test]
    fn ok_reply_round_trip() {
        let reply = ControlResult::Ok(serde_json::json!({ "state": "answered" }))
            .into_reply("c-42".to_string());
        let text = serde_json::to_string(&reply).unwrap();
        assert!(text.contains("\"status\":\"ok\""));
        assert!(!text.contains("\"error\""));
        let parsed: ReplyFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, reply);
        assert_eq!(parsed.status, ReplyStatus::Ok);
    }

    #[test]
    fn error_reply_round_trip() {
        let reply = ControlResult::error(ControlErrorCode::NotFound, "no such channel")
            .into_reply("c-7".to_string());
        let text = serde_json::to_string(&reply).unwrap();
        assert!(text.contains("\"status\":\"error\""));
        assert!(text.contains("\"code\":\"not_found\""));
        assert!(!text.contains("\"result\""));
        let parsed: ReplyFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, reply);
    }

    #[test]
    fn event_frame_round_trip() {
        let event = EventFrame::new(
            "StasisStart",
            "ch_9f3a",
            "ivr-app",
            serde_json::json!({ "call_id": "abc" }),
        );
        let text = serde_json::to_string(&event).unwrap();
        assert!(text.contains("\"type\":\"event\""));
        assert!(text.contains("\"event\":\"StasisStart\""));
        let parsed: EventFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn event_frame_omits_null_payload() {
        let event = EventFrame::new("StasisEnd", "ch_1", "ivr-app", serde_json::Value::Null);
        let text = serde_json::to_string(&event).unwrap();
        assert!(!text.contains("payload"));
    }

    #[test]
    fn hello_args_parse() {
        let args = serde_json::json!({ "app": "ivr-app", "protocol": 1 });
        let hello: HelloArgs = serde_json::from_value(args).unwrap();
        assert_eq!(hello.app, "ivr-app");
        assert_eq!(hello.protocol, Some(1));
    }

    #[test]
    fn error_code_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&ControlErrorCode::UnsupportedVerb).unwrap(),
            "\"unsupported_verb\""
        );
    }
}
