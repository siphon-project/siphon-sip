//! Payloads of the split bridge's two events: `stream_start` with
//! `mode: "split"` streams both legs of an answered two-party call to one
//! duplex stereo WebSocket and isolates the parties from each other.

use serde::{Deserialize, Serialize};

/// One channel of a split's stream and the SIP party on it.
///
/// Channel 0 is the **offerer**, the party whose engine tag is the call's
/// `from_tag`; channel 1 is the **answerer**. The engine only knows those two
/// roles, and which dialog siphon made the offerer is not visible to a
/// controller, so the event says which channel is whose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitChannel {
    /// `0` or `1`: the channel of the duplex stereo stream.
    #[serde(default)]
    pub channel: u8,
    /// `offerer` or `answerer`.
    #[serde(default)]
    pub party: String,
    /// The SIP Call-ID of that party's dialog, which is the id of its channel
    /// on this rail. `None` when siphon holds no dialog for the party: the
    /// answerer of a call that is not a bridged pair.
    #[serde(default)]
    pub sip_call_id: Option<String>,
}

/// Payload of [`SipEvent::WsSplitStarted`](crate::sip::SipEvent::WsSplitStarted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitStartedPayload {
    /// The offerer's engine tag.
    #[serde(default)]
    pub from_tag: String,
    /// Correlator between this event and the `start` frame on the socket.
    #[serde(default)]
    pub stream_id: String,
    /// The URI the engine dialled.
    #[serde(default)]
    pub ws_uri: String,
    /// The negotiated L16 wire rate in Hz.
    #[serde(default)]
    pub sample_rate: u32,
    /// Which SIP party is on which channel, in channel order.
    #[serde(default)]
    pub channels: Vec<WsSplitChannel>,
}

impl WsSplitStartedPayload {
    /// The SIP Call-ID of the party on `channel` (`0` the offerer, `1` the
    /// answerer), when siphon holds a dialog for it.
    pub fn sip_call_id_of(&self, channel: u8) -> Option<&str> {
        self.channels
            .iter()
            .find(|entry| entry.channel == channel)
            .and_then(|entry| entry.sip_call_id.as_deref())
    }
}

/// Payload of [`SipEvent::WsSplitEnded`](crate::sip::SipEvent::WsSplitEnded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsSplitEndedPayload {
    #[serde(default)]
    pub from_tag: String,
    /// The stream id from the matching `WsSplitStarted`.
    #[serde(default)]
    pub stream_id: String,
    /// The engine's reason, verbatim: `detached`, `ws_closed`, `ws_stopped`,
    /// `ws_error`, `call_deleted`, `renegotiated` or `restored`. An end with any
    /// other reason is not delivered (siphon-rtp 0.29's protocol cannot decode it).
    #[serde(default)]
    pub reason: String,
    /// Whether the parties are **still isolated and silent**: true after every
    /// end but `detached` and `call_deleted`. The engine lifts a split's
    /// isolation on a `stream_stop` the controller sent and on nothing else,
    /// so an app that branches on nothing else should branch on this: detach
    /// for direct audio, or detach and start again for a new server.
    #[serde(default)]
    pub isolated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The payloads as the server publishes them.
    #[test]
    fn the_events_parse_as_the_server_publishes_them() {
        let started: WsSplitStartedPayload = serde_json::from_value(serde_json::json!({
            "from_tag": "tag-a",
            "stream_id": "split-pair-1",
            "ws_uri": "wss://bot.example.net/call",
            "sample_rate": 16000,
            "channels": [
                {"channel": 0, "party": "offerer", "sip_call_id": "caller@example.com"},
                {"channel": 1, "party": "answerer", "sip_call_id": null},
            ],
        }))
        .expect("started payload");
        assert_eq!(started.sample_rate, 16_000);
        assert_eq!(started.sip_call_id_of(0), Some("caller@example.com"));
        assert_eq!(started.sip_call_id_of(1), None, "no dialog is held for it");
        assert_eq!(started.channels[1].party, "answerer");

        let ended: WsSplitEndedPayload = serde_json::from_value(serde_json::json!({
            "from_tag": "tag-a",
            "stream_id": "split-pair-1",
            "reason": "renegotiated",
            "isolated": true,
        }))
        .expect("ended payload");
        assert!(ended.isolated);
        assert_eq!(ended.reason, "renegotiated");
    }
}
