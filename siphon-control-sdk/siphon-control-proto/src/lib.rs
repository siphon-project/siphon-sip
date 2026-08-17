//! Wire protocol for the SIPhon external control plane (`siphon-control.v1`).
//!
//! This crate is the **single source of truth** for the on-the-wire types shared
//! between a SIPhon server and a control application (ARI/ESL-class). It is
//! dependency-light on purpose (only `serde` + `serde_json`) so it can be
//! adopted by the server *and* linked by client SDKs without pulling a runtime.
//!
//! # Transport
//!
//! Single WebSocket per connection (inbound-persistent or outbound
//! per-call-connect), JSON text frames both directions:
//!
//! - **command** (client → siphon):
//!   `{id, type:"command", module, verb, target, args}`
//! - **reply** (siphon → client, `id` echoed):
//!   `{id, type:"reply", status, result|error}`
//! - **event** (siphon → client, un-id'd, pushed):
//!   `{type:"event", event, channel, call_id, sip_call_id, payload}`
//!
//! `module` routes a command to the registered adapter (`sip`|`smpp`|`ss7`);
//! the substrate never interprets `verb`/`args`/`target` beyond the routing +
//! ownership checks — they are handed opaquely (`serde_json::Value`) to the
//! adapter that applies them.
//!
//! # Byte-compatibility
//!
//! The frame types below are byte-identical to the server's inline definitions:
//! the same fields, in the same order, with the same `serde` attributes
//! (`#[serde(rename = "type")]`, `rename_all = "snake_case"` on error codes,
//! `skip_serializing_if`, …). This lets the server drop this crate in as
//! `use siphon_control_proto as protocol;` with no wire change, and lets a client
//! serialize a `CommandFrame` that the server parses without a translation layer.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod sip;
pub mod verbs;

// ---------------------------------------------------------------------------
// Frame envelope (byte-identical to the server's `src/control/protocol.rs`).
// ---------------------------------------------------------------------------

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
    /// The adapter routing key (`"sip"`, `"smpp"`, …). Substrate verbs
    /// (`hello`, `resync`, `describe`, `set_var`, `get_var`) omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
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
    /// Build a command frame, filling in the [`FrameType::Command`] discriminant.
    pub fn new(
        id: impl Into<String>,
        module: Option<String>,
        verb: impl Into<String>,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            frame_type: FrameType::Command,
            module,
            verb: verb.into(),
            target,
            args,
        }
    }

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
    /// The target channel does not exist / the call is already gone.
    NotFound,
    /// The frame or its arguments were malformed.
    BadRequest,
    /// The command exceeded a rate limit.
    RateLimited,
    /// An originate was denied by the toll-fraud gates.
    OriginateDenied,
    /// The verb is not implemented / not supported by the adapter or backend.
    UnsupportedVerb,
    /// The client asked for an unknown protocol version.
    UnsupportedVersion,
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

impl ReplyFrame {
    /// True when the reply carried `status: "ok"`.
    pub fn is_ok(&self) -> bool {
        matches!(self.status, ReplyStatus::Ok)
    }
}

/// A pushed event frame (siphon → client, un-id'd).
///
/// Carries the **stable id triple** `{channel, call_id, sip_call_id}` so a
/// controller joins CDR + HEP with no mapping table: `sip_call_id` is
/// byte-identical to the CDR `call_id` and the HEP correlation chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFrame {
    /// Always [`FrameType::Event`].
    #[serde(rename = "type")]
    pub frame_type: FrameType,
    /// Event name (e.g. `"StasisStart"`, `"StasisEnd"`).
    pub event: String,
    /// The channel this event concerns (leg-scoped id), when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    /// The application the channel was handed to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// The internal call UUID (`CallActor.id`) — the grouping key across legs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub call_id: Option<String>,
    /// The per-leg SIP Call-ID — the CDR / HEP join key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sip_call_id: Option<String>,
    /// Event-specific payload.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub payload: serde_json::Value,
}

impl EventFrame {
    /// Build an event frame for a channel, carrying the stable id triple.
    pub fn new(
        event: impl Into<String>,
        channel: impl Into<String>,
        app: impl Into<String>,
        call_id: impl Into<String>,
        sip_call_id: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            frame_type: FrameType::Event,
            event: event.into(),
            channel: Some(channel.into()),
            app: Some(app.into()),
            call_id: Some(call_id.into()),
            sip_call_id: Some(sip_call_id.into()),
            payload,
        }
    }

    /// The event name parsed into a [`sip::SipEvent`] (the SIP adapter's event
    /// model). For non-SIP modules, read [`EventFrame::event`] directly.
    pub fn sip_kind(&self) -> sip::SipEvent {
        sip::SipEvent::from(self.event.as_str())
    }
}

/// The outcome of applying a command — carried back to the connection's read
/// task and rendered into a [`ReplyFrame`].
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

/// The WebSocket subprotocol token this rail speaks.
pub const SUBPROTOCOL: &str = "siphon-control.v1";

/// The protocol version this build implements.
pub const PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Additive result DTOs — typed views over the `result` object of well-known
// substrate replies. The server emits these shapes as `serde_json::Value`; a
// client deserializes them for ergonomics. Purely additive (the server need
// not adopt them for the wire to stay identical).
// ---------------------------------------------------------------------------

/// The `result` of a successful `hello` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResult {
    /// The authenticated app name (echoed).
    pub app: String,
    /// The negotiated protocol version.
    pub protocol: u32,
    /// The negotiated subprotocol token.
    pub subprotocol: String,
}

/// One channel in a `resync` reply — the id triple plus its current state + vars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    /// The leg-scoped channel id.
    pub channel: String,
    /// The internal `CallActor` id.
    #[serde(default)]
    pub call_id: String,
    /// The per-leg SIP Call-ID.
    #[serde(default)]
    pub sip_call_id: String,
    /// The current call state string (`calling`/`ringing`/`answered`/…).
    #[serde(default)]
    pub state: String,
    /// Per-call variables set via `set_var`.
    #[serde(default)]
    pub vars: std::collections::HashMap<String, String>,
}

/// The `result` of a successful `resync` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResyncResult {
    /// The channels this connection re-claims.
    #[serde(default)]
    pub channels: Vec<ChannelSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frame_round_trip() {
        let frame = CommandFrame {
            id: "c-42".to_string(),
            frame_type: FrameType::Command,
            module: Some("sip".to_string()),
            verb: "answer".to_string(),
            target: serde_json::json!({ "channel": "ch_9f3a" }),
            args: serde_json::json!({ "code": 200 }),
        };
        let text = serde_json::to_string(&frame).unwrap();
        assert!(text.contains("\"type\":\"command\""));
        assert!(text.contains("\"module\":\"sip\""));
        let parsed: CommandFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, frame);
        assert_eq!(parsed.channel_target().as_deref(), Some("ch_9f3a"));
    }

    /// The exact bytes an answer command serializes to — this is the contract a
    /// client must reproduce and the server must parse. Field order follows the
    /// struct declaration order.
    #[test]
    fn command_frame_exact_bytes() {
        let frame = CommandFrame::new(
            "c-1",
            Some("sip".to_string()),
            "answer",
            serde_json::json!({ "channel": "ch1" }),
            serde_json::json!({ "code": 200 }),
        );
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"id":"c-1","type":"command","module":"sip","verb":"answer","target":{"channel":"ch1"},"args":{"code":200}}"#
        );
    }

    /// A substrate command (no module) still serializes `target`/`args` because
    /// the server's fields carry no `skip_serializing_if` — matched here so the
    /// bytes stay identical.
    #[test]
    fn substrate_command_serializes_null_target_and_args() {
        let frame = CommandFrame::new("c-2", None, "resync", serde_json::Value::Null, serde_json::Value::Null);
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"id":"c-2","type":"command","verb":"resync","target":null,"args":null}"#
        );
    }

    #[test]
    fn hello_command_exact_bytes() {
        let frame = CommandFrame::new(
            "c-0",
            None,
            "hello",
            serde_json::Value::Null,
            serde_json::json!({ "app": "ivr-app", "protocol": 1 }),
        );
        assert_eq!(
            serde_json::to_string(&frame).unwrap(),
            r#"{"id":"c-0","type":"command","verb":"hello","target":null,"args":{"app":"ivr-app","protocol":1}}"#
        );
    }

    #[test]
    fn command_frame_defaults_missing_module_target_and_args() {
        let text = r#"{"id":"1","type":"command","verb":"hello"}"#;
        let parsed: CommandFrame = serde_json::from_str(text).unwrap();
        assert_eq!(parsed.verb, "hello");
        assert!(parsed.module.is_none());
        assert!(parsed.target.is_null());
        assert!(parsed.args.is_null());
        assert_eq!(parsed.channel_target(), None);
    }

    #[test]
    fn ok_reply_round_trip() {
        let reply = ControlResult::Ok(serde_json::json!({ "state": "answered" }))
            .into_reply("c-42".to_string());
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            text,
            r#"{"id":"c-42","type":"reply","status":"ok","result":{"state":"answered"}}"#
        );
        let parsed: ReplyFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, reply);
        assert!(parsed.is_ok());
    }

    #[test]
    fn error_reply_round_trip() {
        let reply = ControlResult::error(ControlErrorCode::NotFound, "no such channel")
            .into_reply("c-7".to_string());
        let text = serde_json::to_string(&reply).unwrap();
        assert_eq!(
            text,
            r#"{"id":"c-7","type":"reply","status":"error","error":{"code":"not_found","message":"no such channel"}}"#
        );
        let parsed: ReplyFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, reply);
        assert!(!parsed.is_ok());
    }

    #[test]
    fn event_frame_round_trip_carries_id_triple() {
        let event = EventFrame::new(
            "StasisStart",
            "ch_9f3a",
            "ivr-app",
            "6f0e-uuid",
            "a84b4c76e66710@pc33",
            serde_json::json!({ "source_ip": "203.0.113.7" }),
        );
        let text = serde_json::to_string(&event).unwrap();
        assert!(text.contains("\"type\":\"event\""));
        assert!(text.contains("\"event\":\"StasisStart\""));
        assert!(text.contains("\"sip_call_id\":\"a84b4c76e66710@pc33\""));
        let parsed: EventFrame = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed, event);
        assert_eq!(parsed.call_id.as_deref(), Some("6f0e-uuid"));
        assert_eq!(parsed.sip_kind(), sip::SipEvent::StasisStart);
    }

    #[test]
    fn event_frame_omits_null_payload() {
        let event = EventFrame::new(
            "StasisEnd",
            "ch_1",
            "ivr-app",
            "uuid",
            "sipcid",
            serde_json::Value::Null,
        );
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
        assert_eq!(
            serde_json::to_string(&ControlErrorCode::OriginateDenied).unwrap(),
            "\"originate_denied\""
        );
        assert_eq!(
            serde_json::to_string(&ControlErrorCode::UnsupportedVersion).unwrap(),
            "\"unsupported_version\""
        );
    }

    #[test]
    fn hello_result_parses_from_reply() {
        let value = serde_json::json!({
            "app": "ivr-app", "protocol": 1, "subprotocol": "siphon-control.v1"
        });
        let parsed: HelloResult = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.protocol, 1);
        assert_eq!(parsed.subprotocol, SUBPROTOCOL);
    }

    #[test]
    fn resync_result_parses_channels() {
        let value = serde_json::json!({
            "channels": [{
                "channel": "ch-live",
                "call_id": "call-uuid",
                "sip_call_id": "sipcid@h",
                "state": "answered",
                "vars": { "queue": "support" }
            }]
        });
        let parsed: ResyncResult = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.channels.len(), 1);
        assert_eq!(parsed.channels[0].channel, "ch-live");
        assert_eq!(parsed.channels[0].vars.get("queue").map(String::as_str), Some("support"));
    }
}
