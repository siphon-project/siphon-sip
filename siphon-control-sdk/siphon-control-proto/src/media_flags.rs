//! `media_flags`: per-call overrides of a media profile's processing settings,
//! carried beside `profile` on `answer`, anchored `progress`, `stream_start`
//! with `mode: "bridge"` and `originate` with `media: true`.
//!
//! Each field set replaces the profile's value for that one call, and each
//! field left `None` is not sent, so the profile's value stands. The server
//! never changes the profile itself, and refuses an unknown key, a `null`, a
//! wrong type or a value the engine would refuse with `bad_request` whose
//! `details.field` names the key.

use serde::{Deserialize, Serialize};

/// Which detector the WebSocket uplink voice-activity detector runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VadEngine {
    /// Energy against a threshold, with a trailing hangover. Cheap, but it
    /// reads any loud noise as speech.
    Energy,
    /// A speech classifier: does not turn-start on noise, at a 32 ms
    /// detection floor.
    Neural,
}

/// Per-call processing settings, merged over the named profile's (answer
/// half) for this call only. Build one with struct-update syntax:
///
/// ```
/// use siphon_control_proto::media_flags::MediaFlags;
/// let flags = MediaFlags {
///     echo_cancellation: Some(false),
///     ws_vad_min_speech_ms: Some(100),
///     ..MediaFlags::default()
/// };
/// assert_eq!(
///     serde_json::to_value(&flags).unwrap(),
///     serde_json::json!({ "echo_cancellation": false, "ws_vad_min_speech_ms": 100 })
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MediaFlags {
    /// Echo cancellation on the leg's uplink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_cancellation: Option<bool>,
    /// How far the canceller searches for the echo, in ms: 16-1000 as a search
    /// window, or as a tail length when `echo_long_tail` (merged) is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_delay_search_ms: Option<u32>,
    /// Span the echo path with the adaptive filter, making
    /// `echo_delay_search_ms` a tail length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_long_tail: Option<bool>,
    /// Chain the residual-echo suppressor after the canceller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub echo_residual_suppression: Option<bool>,
    /// Noise suppression on the leg's uplink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noise_suppression: Option<bool>,
    /// Run the uplink voice-activity detector on a WebSocket bridge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad: Option<bool>,
    /// Which detector `ws_vad` runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_engine: Option<VadEngine>,
    /// Leading speech run, in ms, before `speech_started` (and barge-in) fires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_min_speech_ms: Option<u32>,
    /// Energy threshold for the energy detector; higher is less sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_threshold: Option<i64>,
    /// Trailing hangover, in ms, before `speech_stopped` fires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_vad_hangover_ms: Option<u32>,
    /// Flush the queued downlink when the caller starts speaking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_barge_in: Option<bool>,
    /// L16 wire rate of a WebSocket bridge, in Hz: a multiple of 1000 within
    /// 8000-48000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws_sample_rate: Option<u32>,
}

impl MediaFlags {
    /// The `media_flags` argument as it goes on the wire.
    pub fn to_json(&self) -> serde_json::Value {
        // A struct of options, bools and integers always serialises.
        serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unset_fields_stay_off_the_wire() {
        assert_eq!(MediaFlags::default().to_json(), json!({}));
    }

    #[test]
    fn every_field_goes_on_the_wire_under_its_server_name() {
        let flags = MediaFlags {
            echo_cancellation: Some(false),
            echo_delay_search_ms: Some(300),
            echo_long_tail: Some(true),
            echo_residual_suppression: Some(true),
            noise_suppression: Some(false),
            ws_vad: Some(true),
            ws_vad_engine: Some(VadEngine::Neural),
            ws_vad_min_speech_ms: Some(100),
            ws_vad_threshold: Some(-5),
            ws_vad_hangover_ms: Some(250),
            ws_barge_in: Some(true),
            ws_sample_rate: Some(16_000),
        };
        let wire = flags.to_json();
        assert_eq!(
            wire,
            json!({
                "echo_cancellation": false,
                "echo_delay_search_ms": 300,
                "echo_long_tail": true,
                "echo_residual_suppression": true,
                "noise_suppression": false,
                "ws_vad": true,
                "ws_vad_engine": "neural",
                "ws_vad_min_speech_ms": 100,
                "ws_vad_threshold": -5,
                "ws_vad_hangover_ms": 250,
                "ws_barge_in": true,
                "ws_sample_rate": 16000,
            })
        );
        let back: MediaFlags = serde_json::from_value(wire).expect("round trip");
        assert_eq!(back, flags);
    }

    #[test]
    fn an_unknown_key_does_not_parse() {
        assert!(serde_json::from_value::<MediaFlags>(json!({ "ws_uri": "x" })).is_err());
    }
}
