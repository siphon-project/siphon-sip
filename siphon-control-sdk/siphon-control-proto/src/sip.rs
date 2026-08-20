//! SIP-adapter (`module = "sip"`) verb + event helper types.
//!
//! These are **additive** over the generic frame envelope: the core
//! [`CommandFrame`](crate::CommandFrame) still carries `module`/`verb`/opaque
//! `args`, and this module just gives compile-time names for the SIP adapter's
//! verbs and the events it emits. A future `smpp` / `ss7` submodule sits beside
//! this one without touching the core.

use serde::{Deserialize, Serialize};

/// A verb the built-in SIP adapter (`module = "sip"`) accepts.
///
/// `as_str()` yields the exact wire token. The media verbs
/// (`play`/`stop`/`dtmf`/`hold`/`unhold`/`stream_start`/`stream_stop`) are
/// dispatched against the configured media backend; the WebSocket-tee pair is
/// siphon-rtp-only, so a non-siphon-rtp backend answers them `unsupported_verb`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipVerb {
    /// Send a UAS 2xx to the parked A-leg.
    Answer,
    /// Send a UAS 1xx / early media.
    Progress,
    /// Send a final non-2xx and tear the call down.
    Reject,
    /// BYE an answered call, or reject an unanswered one.
    Hangup,
    /// Send an in-dialog REFER on the A-leg.
    Refer,
    /// Accept a pending inbound REFER (from a `TransferRequested` event).
    AcceptRefer,
    /// Reject a pending inbound REFER with a final non-2xx.
    RejectRefer,
    /// Un-park the call and dial the B-leg via LCR sequential failover.
    Route,
    /// Set a header on the stored A-leg INVITE.
    SetHeader,
    /// Remove a header from the stored A-leg INVITE.
    RemoveHeader,
    /// Read a header from the stored A-leg INVITE.
    GetHeader,
    /// Play an announcement on the A-leg media (fire-and-forget).
    Play,
    /// Stop the announcement currently playing on the A-leg media.
    Stop,
    /// Inject DTMF digits toward the A-leg.
    Dtmf,
    /// Hold the A-leg media via silence.
    Hold,
    /// Resume the A-leg media after a hold.
    Unhold,
    /// Attach a WebSocket audio tee (siphon-rtp backend only).
    StreamStart,
    /// Detach the WebSocket audio tee.
    StreamStop,
}

impl SipVerb {
    /// The exact wire token for this verb.
    pub const fn as_str(self) -> &'static str {
        match self {
            SipVerb::Answer => "answer",
            SipVerb::Progress => "progress",
            SipVerb::Reject => "reject",
            SipVerb::Hangup => "hangup",
            SipVerb::Refer => "refer",
            SipVerb::AcceptRefer => "accept_refer",
            SipVerb::RejectRefer => "reject_refer",
            SipVerb::Route => "route",
            SipVerb::SetHeader => "set_header",
            SipVerb::RemoveHeader => "remove_header",
            SipVerb::GetHeader => "get_header",
            SipVerb::Play => "play",
            SipVerb::Stop => "stop",
            SipVerb::Dtmf => "dtmf",
            SipVerb::Hold => "hold",
            SipVerb::Unhold => "unhold",
            SipVerb::StreamStart => "stream_start",
            SipVerb::StreamStop => "stream_stop",
        }
    }
}

impl std::fmt::Display for SipVerb {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A pushed event the SIP adapter emits (the ARI *Stasis* model).
///
/// Deserializes from the wire event name; an unrecognised name maps to
/// [`SipEvent::Other`] rather than failing, so a newer server that adds events
/// never breaks an older client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub enum SipEvent {
    /// A call was handed to this application — the first frame it sees.
    StasisStart,
    /// The call left the application's control (teardown / handback).
    StasisEnd,
    /// The call's state changed (`calling`→`ringing`→`answered`→…).
    ChannelStateChange,
    /// The far end asked to hang up (a BYE arrived).
    ChannelHangupRequest,
    /// An in-band DTMF digit was detected on the call's media
    /// ([`ChannelDtmfPayload`]).
    ChannelDtmfReceived,
    /// An inbound REFER on a controlled call is asking the app to own the
    /// transfer decision ([`TransferRequestedPayload`]).
    TransferRequested,
    /// Any other event name (forward-compatible catch-all).
    Other(String),
}

impl SipEvent {
    /// The exact wire event name.
    pub fn as_str(&self) -> &str {
        match self {
            SipEvent::StasisStart => "StasisStart",
            SipEvent::StasisEnd => "StasisEnd",
            SipEvent::ChannelStateChange => "ChannelStateChange",
            SipEvent::ChannelHangupRequest => "ChannelHangupRequest",
            SipEvent::ChannelDtmfReceived => "ChannelDtmfReceived",
            SipEvent::TransferRequested => "TransferRequested",
            SipEvent::Other(name) => name.as_str(),
        }
    }
}

impl From<&str> for SipEvent {
    fn from(name: &str) -> Self {
        match name {
            "StasisStart" => SipEvent::StasisStart,
            "StasisEnd" => SipEvent::StasisEnd,
            "ChannelStateChange" => SipEvent::ChannelStateChange,
            "ChannelHangupRequest" => SipEvent::ChannelHangupRequest,
            "ChannelDtmfReceived" => SipEvent::ChannelDtmfReceived,
            "TransferRequested" => SipEvent::TransferRequested,
            other => SipEvent::Other(other.to_string()),
        }
    }
}

impl From<String> for SipEvent {
    fn from(name: String) -> Self {
        SipEvent::from(name.as_str())
    }
}

impl From<SipEvent> for String {
    fn from(event: SipEvent) -> Self {
        event.as_str().to_string()
    }
}

impl std::fmt::Display for SipEvent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Additive typed views over well-known SIP-adapter event payloads. The server
// emits these shapes as the `payload` object of an [`crate::EventFrame`]; a
// client deserializes them for ergonomics. Purely additive (the server need not
// adopt them for the wire to stay identical).
// ---------------------------------------------------------------------------

/// The `payload` of a [`SipEvent::ChannelDtmfReceived`] event: an in-band DTMF
/// digit the media engine detected on a controlled call's leg.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelDtmfPayload {
    /// The single detected digit (`0`–`9`, `*`, `#`, `A`–`D`).
    pub digit: String,
    /// The tone duration in milliseconds.
    #[serde(default)]
    pub duration_ms: u32,
    /// The tone volume in dBm0 (negative).
    #[serde(default)]
    pub volume: i32,
    /// The From-tag of the leg the digit came from.
    #[serde(default)]
    pub from_tag: String,
}

/// The RFC 3891 `Replaces` triple embedded in a [`TransferRequestedPayload`]
/// (an attended-transfer REFER).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferReplaces {
    /// The Call-ID of the dialog being replaced.
    pub call_id: String,
    /// The From-tag of the dialog being replaced.
    pub from_tag: String,
    /// The To-tag of the dialog being replaced.
    pub to_tag: String,
    /// Whether the REFER was `early-only`.
    #[serde(default)]
    pub early_only: bool,
}

/// The `payload` of a [`SipEvent::TransferRequested`] event: an inbound REFER on
/// a controlled call, handed to the app to accept / reject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRequestedPayload {
    /// The Refer-To URI (the transfer target).
    pub refer_to: String,
    /// The embedded `Replaces` triple for an attended transfer, if present.
    #[serde(default)]
    pub replaces: Option<TransferReplaces>,
    /// The From-tag of the referring party, if known.
    #[serde(default)]
    pub from_tag: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_verb_wire_tokens() {
        assert_eq!(SipVerb::Answer.as_str(), "answer");
        assert_eq!(SipVerb::Route.as_str(), "route");
        assert_eq!(SipVerb::SetHeader.as_str(), "set_header");
        assert_eq!(SipVerb::GetHeader.to_string(), "get_header");
        // The media / header / REFER verbs that shipped server-side.
        assert_eq!(SipVerb::RemoveHeader.as_str(), "remove_header");
        assert_eq!(SipVerb::AcceptRefer.as_str(), "accept_refer");
        assert_eq!(SipVerb::RejectRefer.as_str(), "reject_refer");
        assert_eq!(SipVerb::Play.as_str(), "play");
        assert_eq!(SipVerb::Stop.as_str(), "stop");
        assert_eq!(SipVerb::Dtmf.as_str(), "dtmf");
        assert_eq!(SipVerb::Hold.as_str(), "hold");
        assert_eq!(SipVerb::Unhold.as_str(), "unhold");
        assert_eq!(SipVerb::StreamStart.as_str(), "stream_start");
        assert_eq!(SipVerb::StreamStop.to_string(), "stream_stop");
    }

    #[test]
    fn sip_event_round_trip_known_and_unknown() {
        assert_eq!(SipEvent::from("StasisStart"), SipEvent::StasisStart);
        assert_eq!(
            SipEvent::from("ChannelHangupRequest"),
            SipEvent::ChannelHangupRequest
        );
        assert_eq!(
            SipEvent::from("ChannelDtmfReceived"),
            SipEvent::ChannelDtmfReceived
        );
        assert_eq!(
            SipEvent::from("TransferRequested"),
            SipEvent::TransferRequested
        );
        assert_eq!(
            SipEvent::from("SomethingNew"),
            SipEvent::Other("SomethingNew".to_string())
        );
        let json = serde_json::to_string(&SipEvent::StasisEnd).unwrap();
        assert_eq!(json, "\"StasisEnd\"");
        assert_eq!(
            serde_json::to_string(&SipEvent::ChannelDtmfReceived).unwrap(),
            "\"ChannelDtmfReceived\""
        );
        let parsed: SipEvent = serde_json::from_str("\"NovelEvent\"").unwrap();
        assert_eq!(parsed, SipEvent::Other("NovelEvent".to_string()));
    }

    #[test]
    fn channel_dtmf_payload_parses() {
        // Byte-identical to the server's ChannelDtmfReceived payload.
        let value = serde_json::json!({
            "digit": "5", "duration_ms": 100, "volume": -8, "from_tag": "alice-tag"
        });
        let parsed: ChannelDtmfPayload = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.digit, "5");
        assert_eq!(parsed.duration_ms, 100);
        assert_eq!(parsed.volume, -8);
        assert_eq!(parsed.from_tag, "alice-tag");
    }

    #[test]
    fn transfer_requested_payload_parses_with_and_without_replaces() {
        // Blind transfer: replaces + from_tag null.
        let blind = serde_json::json!({
            "refer_to": "sip:carol@example.com", "replaces": null, "from_tag": null
        });
        let parsed: TransferRequestedPayload = serde_json::from_value(blind).unwrap();
        assert_eq!(parsed.refer_to, "sip:carol@example.com");
        assert!(parsed.replaces.is_none());
        assert!(parsed.from_tag.is_none());

        // Attended transfer: an embedded Replaces triple + a referrer from_tag.
        let attended = serde_json::json!({
            "refer_to": "sip:dave@example.com",
            "replaces": { "call_id": "abc", "from_tag": "ft", "to_tag": "tt", "early_only": true },
            "from_tag": "referrer-tag"
        });
        let parsed: TransferRequestedPayload = serde_json::from_value(attended).unwrap();
        let replaces = parsed.replaces.expect("replaces present");
        assert_eq!(replaces.call_id, "abc");
        assert!(replaces.early_only);
        assert_eq!(parsed.from_tag.as_deref(), Some("referrer-tag"));
    }
}
