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
/// `as_str()` yields the exact wire token; media verbs (`play`/`dtmf`/…) are
/// deliberately absent — the server answers them `unsupported_verb` today, so a
/// client models them as ad-hoc verbs the enum does not promote.
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
    /// Un-park the call and dial the B-leg via LCR sequential failover.
    Route,
    /// Set a header on the stored A-leg INVITE.
    SetHeader,
    /// Read a header from the stored A-leg INVITE.
    GetHeader,
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
            SipVerb::Route => "route",
            SipVerb::SetHeader => "set_header",
            SipVerb::GetHeader => "get_header",
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_verb_wire_tokens() {
        assert_eq!(SipVerb::Answer.as_str(), "answer");
        assert_eq!(SipVerb::Route.as_str(), "route");
        assert_eq!(SipVerb::SetHeader.as_str(), "set_header");
        assert_eq!(SipVerb::GetHeader.to_string(), "get_header");
    }

    #[test]
    fn sip_event_round_trip_known_and_unknown() {
        assert_eq!(SipEvent::from("StasisStart"), SipEvent::StasisStart);
        assert_eq!(
            SipEvent::from("ChannelHangupRequest"),
            SipEvent::ChannelHangupRequest
        );
        assert_eq!(
            SipEvent::from("SomethingNew"),
            SipEvent::Other("SomethingNew".to_string())
        );
        let json = serde_json::to_string(&SipEvent::StasisEnd).unwrap();
        assert_eq!(json, "\"StasisEnd\"");
        let parsed: SipEvent = serde_json::from_str("\"NovelEvent\"").unwrap();
        assert_eq!(parsed, SipEvent::Other("NovelEvent".to_string()));
    }
}
