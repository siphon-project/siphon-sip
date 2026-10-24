//! Per-call media processing flags: the `media_flags` a control verb carries
//! beside `profile` (`answer`, anchored `progress`, `stream_start` with
//! `mode: "bridge"`, `originate` with `media: true`).
//!
//! A profile is shared configuration and cannot change without a restart, but
//! the engine reads every one of these settings per call (`AnswerLocal.profile`,
//! `AttachWsBridge.profile`). So a controller that hands one leg to a bot with
//! its own voice-activity detection can turn echo cancellation off for that leg
//! alone, merged over the profile it named, without a second profile and
//! without touching the registry entry other calls read.
//!
//! Only the uplink processing settings are accepted, under their
//! [`crate::config::NgFlagsConfig`] names and types. Everything else a profile
//! carries (`ws_uri`, `flags`, `ice`, `dtls`, `received_from`, codec, recording)
//! is refused: those change how a call is keyed or widen a source gate, which a
//! per-call argument must not be able to do.
//!
//! The rules are the ones config load applies to a profile, so a value boot
//! would refuse is refused here too: [`validate_ws_sample_rate`],
//! [`WsVadEngine::parse`], and [`check_echo_delay_search_ms`] on the **merged**
//! flags, whose bound depends on the merged `echo_long_tail`.

use crate::rtpengine::profile::{validate_ws_sample_rate, NgFlags, WsVadEngine};

/// The keys `media_flags` accepts, in the order they are documented.
pub const MEDIA_FLAG_FIELDS: [&str; 12] = [
    "echo_cancellation",
    "echo_delay_search_ms",
    "echo_long_tail",
    "echo_residual_suppression",
    "noise_suppression",
    "ws_vad",
    "ws_vad_engine",
    "ws_vad_min_speech_ms",
    "ws_vad_threshold",
    "ws_vad_hangover_ms",
    "ws_barge_in",
    "ws_sample_rate",
];

/// One call's overrides of its profile's processing settings. A field left
/// `None` keeps the profile's value; one that is set replaces it for this call
/// only. Field meanings are those of the same-named [`NgFlags`] fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MediaFlags {
    /// [`NgFlags::echo_cancellation`].
    pub echo_cancellation: Option<bool>,
    /// [`NgFlags::echo_delay_search_ms`].
    pub echo_delay_search_ms: Option<u32>,
    /// [`NgFlags::echo_long_tail`].
    pub echo_long_tail: Option<bool>,
    /// [`NgFlags::echo_residual_suppression`].
    pub echo_residual_suppression: Option<bool>,
    /// [`NgFlags::noise_suppression`].
    pub noise_suppression: Option<bool>,
    /// [`NgFlags::ws_vad`].
    pub ws_vad: Option<bool>,
    /// [`NgFlags::ws_vad_engine`].
    pub ws_vad_engine: Option<WsVadEngine>,
    /// [`NgFlags::ws_vad_min_speech_ms`].
    pub ws_vad_min_speech_ms: Option<u32>,
    /// [`NgFlags::ws_vad_threshold`].
    pub ws_vad_threshold: Option<i64>,
    /// [`NgFlags::ws_vad_hangover_ms`].
    pub ws_vad_hangover_ms: Option<u32>,
    /// [`NgFlags::ws_barge_in`].
    pub ws_barge_in: Option<bool>,
    /// [`NgFlags::ws_sample_rate`].
    pub ws_sample_rate: Option<u32>,
}

/// Why a `media_flags` value was refused: the key at fault (`None` when the
/// value as a whole is not an object), a stable reason token, the values the
/// key accepts when there is a closed set, and a message for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaFlagsRefusal {
    /// The key at fault, or `None` when `media_flags` is not an object.
    pub field: Option<String>,
    /// `not_an_object`, `unknown_field`, `null`, `wrong_type`,
    /// `invalid_value`, `out_of_range` or `unsupported_by_backend`.
    pub reason: &'static str,
    /// What the key accepts, for a closed set (the twelve keys, the VAD
    /// engines).
    pub allowed: Option<Vec<&'static str>>,
    /// A sentence saying what was wrong.
    pub message: String,
}

impl MediaFlagsRefusal {
    fn new(field: &str, reason: &'static str, message: String) -> Self {
        Self {
            field: Some(field.to_string()),
            reason,
            allowed: None,
            message,
        }
    }
}

/// An `echo_delay_search_ms` outside what the engine accepts in the reading
/// `echo_long_tail` selects: the bounds that applied and what the value meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoBoundError {
    /// Smallest accepted value, in milliseconds.
    pub low: u32,
    /// Largest accepted value, in milliseconds.
    pub high: u32,
    /// What the value is in this reading, phrased to follow "accepts for".
    pub meaning: &'static str,
}

/// Check `echo_delay_search_ms` against the engine's own bounds, in the reading
/// `long_tail` selects: a tail length with `echo_long_tail` set, a search
/// window without it.
///
/// The one copy of the rule, used by config load for a profile and by the
/// control rail for a call's merged flags, so the two cannot drift. They have
/// once already: boot checked a single hardcoded range for both readings while
/// the engine checked two. The bounds come from `siphon_rtp_proto`, which the
/// engine enforces, rather than from restated digits.
pub fn check_echo_delay_search_ms(window: u32, long_tail: bool) -> Result<(), EchoBoundError> {
    let bound = if long_tail {
        EchoBoundError {
            low: siphon_rtp_proto::ECHO_LONG_TAIL_MS_MIN,
            high: siphon_rtp_proto::ECHO_LONG_TAIL_MS_MAX,
            meaning: "a tail length, because echo_long_tail is set",
        }
    } else {
        EchoBoundError {
            low: siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MIN,
            high: siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MAX,
            meaning: "a search window",
        }
    };
    if (bound.low..=bound.high).contains(&window) {
        Ok(())
    } else {
        Err(bound)
    }
}

impl MediaFlags {
    /// Read `media_flags` off a verb's arguments.
    ///
    /// It must be an object whose keys are among [`MEDIA_FLAG_FIELDS`]. A key
    /// set to `null` is refused rather than read as "not given": a typo must
    /// not quietly mean the engine's default. A wrong type, a VAD engine other
    /// than `energy` / `neural`, and a sample rate the engine would fail the
    /// call on are refused here, before anything reaches the call.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, MediaFlagsRefusal> {
        let Some(object) = value.as_object() else {
            return Err(MediaFlagsRefusal {
                field: None,
                reason: "not_an_object",
                allowed: Some(MEDIA_FLAG_FIELDS.to_vec()),
                message: "media_flags must be an object of processing setting to value".to_string(),
            });
        };
        let mut flags = Self::default();
        for (key, value) in object {
            if !MEDIA_FLAG_FIELDS.contains(&key.as_str()) {
                return Err(MediaFlagsRefusal {
                    field: Some(key.clone()),
                    reason: "unknown_field",
                    allowed: Some(MEDIA_FLAG_FIELDS.to_vec()),
                    message: format!(
                        "media_flags has no setting {key:?}; it takes {}",
                        MEDIA_FLAG_FIELDS.join(", ")
                    ),
                });
            }
            if value.is_null() {
                return Err(MediaFlagsRefusal::new(
                    key,
                    "null",
                    format!(
                        "media_flags.{key} is null; leave the key out to keep the profile's value"
                    ),
                ));
            }
            match key.as_str() {
                "echo_cancellation" => flags.echo_cancellation = Some(boolean(key, value)?),
                "echo_long_tail" => flags.echo_long_tail = Some(boolean(key, value)?),
                "echo_residual_suppression" => {
                    flags.echo_residual_suppression = Some(boolean(key, value)?)
                }
                "noise_suppression" => flags.noise_suppression = Some(boolean(key, value)?),
                "ws_vad" => flags.ws_vad = Some(boolean(key, value)?),
                "ws_barge_in" => flags.ws_barge_in = Some(boolean(key, value)?),
                "echo_delay_search_ms" => flags.echo_delay_search_ms = Some(unsigned(key, value)?),
                "ws_vad_min_speech_ms" => flags.ws_vad_min_speech_ms = Some(unsigned(key, value)?),
                "ws_vad_hangover_ms" => flags.ws_vad_hangover_ms = Some(unsigned(key, value)?),
                "ws_vad_threshold" => {
                    flags.ws_vad_threshold = Some(value.as_i64().ok_or_else(|| {
                        MediaFlagsRefusal::new(
                            key,
                            "wrong_type",
                            format!("media_flags.{key} must be an integer"),
                        )
                    })?)
                }
                "ws_vad_engine" => flags.ws_vad_engine = Some(vad_engine(key, value)?),
                "ws_sample_rate" => {
                    let rate = unsigned(key, value)?;
                    validate_ws_sample_rate(rate).map_err(|reason| {
                        MediaFlagsRefusal::new(
                            key,
                            "out_of_range",
                            format!("media_flags.{key} {reason}"),
                        )
                    })?;
                    flags.ws_sample_rate = Some(rate);
                }
                // Every name in MEDIA_FLAG_FIELDS has an arm above; reaching
                // here means the list and the match disagree, which is refused
                // rather than accepted and dropped.
                _ => {
                    return Err(MediaFlagsRefusal {
                        field: Some(key.clone()),
                        reason: "unknown_field",
                        allowed: Some(MEDIA_FLAG_FIELDS.to_vec()),
                        message: format!("media_flags has no setting {key:?}"),
                    })
                }
            }
        }
        Ok(flags)
    }

    /// Apply these overrides to `flags`: each key that is set replaces the
    /// profile's value, each one left out keeps it.
    pub fn merge_into(&self, flags: &mut NgFlags) {
        if let Some(value) = self.echo_cancellation {
            flags.echo_cancellation = value;
        }
        if let Some(value) = self.echo_delay_search_ms {
            flags.echo_delay_search_ms = Some(value);
        }
        if let Some(value) = self.echo_long_tail {
            flags.echo_long_tail = value;
        }
        if let Some(value) = self.echo_residual_suppression {
            flags.echo_residual_suppression = value;
        }
        if let Some(value) = self.noise_suppression {
            flags.noise_suppression = value;
        }
        if let Some(value) = self.ws_vad {
            flags.ws_vad = value;
        }
        if let Some(value) = self.ws_vad_engine {
            flags.ws_vad_engine = Some(value);
        }
        if let Some(value) = self.ws_vad_min_speech_ms {
            flags.ws_vad_min_speech_ms = Some(value);
        }
        if let Some(value) = self.ws_vad_threshold {
            flags.ws_vad_threshold = Some(value);
        }
        if let Some(value) = self.ws_vad_hangover_ms {
            flags.ws_vad_hangover_ms = Some(value);
        }
        if let Some(value) = self.ws_barge_in {
            flags.ws_barge_in = value;
        }
        if let Some(value) = self.ws_sample_rate {
            flags.ws_sample_rate = Some(value);
        }
    }

    /// The flags this call runs with: `base` (the resolved profile's half)
    /// with these overrides merged over it, checked as config load checks a
    /// profile. `base` itself is left as it was.
    ///
    /// The `echo_delay_search_ms` bound is chosen by the **merged**
    /// `echo_long_tail`, so a window from the profile is checked as a tail
    /// length when this call turns long tail on, and the other way round.
    pub fn applied_to(&self, base: &NgFlags) -> Result<NgFlags, MediaFlagsRefusal> {
        let mut merged = base.clone();
        self.merge_into(&mut merged);
        if let Some(window) = merged.echo_delay_search_ms {
            if let Err(bound) = check_echo_delay_search_ms(window, merged.echo_long_tail) {
                // Name the key the caller set: the window when it was given,
                // otherwise the long-tail switch that changed its reading.
                let field = if self.echo_delay_search_ms.is_some() || self.echo_long_tail.is_none()
                {
                    "echo_delay_search_ms"
                } else {
                    "echo_long_tail"
                };
                return Err(MediaFlagsRefusal::new(
                    field,
                    "out_of_range",
                    format!(
                        "media_flags leaves echo_delay_search_ms at {window}, outside the {}-{} \
                         ms the engine accepts for {}",
                        bound.low, bound.high, bound.meaning
                    ),
                ));
            }
        }
        Ok(merged)
    }

    /// The keys this value sets, in [`MEDIA_FLAG_FIELDS`] order.
    pub fn set_fields(&self) -> Vec<&'static str> {
        let set = [
            self.echo_cancellation.is_some(),
            self.echo_delay_search_ms.is_some(),
            self.echo_long_tail.is_some(),
            self.echo_residual_suppression.is_some(),
            self.noise_suppression.is_some(),
            self.ws_vad.is_some(),
            self.ws_vad_engine.is_some(),
            self.ws_vad_min_speech_ms.is_some(),
            self.ws_vad_threshold.is_some(),
            self.ws_vad_hangover_ms.is_some(),
            self.ws_barge_in.is_some(),
            self.ws_sample_rate.is_some(),
        ];
        MEDIA_FLAG_FIELDS
            .iter()
            .zip(set)
            .filter_map(|(name, is_set)| is_set.then_some(*name))
            .collect()
    }

    /// Refuse a key this value sets that `backend` cannot honour on the merged
    /// flags ([`crate::rtpengine::MediaBackend::unsupported_flags`], the gate
    /// every anchored call already passes). A field the profile set and this
    /// value did not is the profile's problem and is reported where it always
    /// was, not blamed on `media_flags`.
    pub fn check_backend(
        &self,
        backend: &crate::rtpengine::MediaBackend,
        merged: &NgFlags,
    ) -> Result<(), MediaFlagsRefusal> {
        let given = self.set_fields();
        let unsupported = backend.unsupported_flags(merged);
        match unsupported.into_iter().find(|field| given.contains(field)) {
            None => Ok(()),
            Some(field) => Err(MediaFlagsRefusal::new(
                field,
                "unsupported_by_backend",
                format!(
                    "media_flags.{field} is a siphon-rtp setting the {} backend cannot honour",
                    backend.kind().as_str()
                ),
            )),
        }
    }
}

fn boolean(key: &str, value: &serde_json::Value) -> Result<bool, MediaFlagsRefusal> {
    value.as_bool().ok_or_else(|| {
        MediaFlagsRefusal::new(
            key,
            "wrong_type",
            format!("media_flags.{key} must be a boolean"),
        )
    })
}

fn unsigned(key: &str, value: &serde_json::Value) -> Result<u32, MediaFlagsRefusal> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .ok_or_else(|| {
            MediaFlagsRefusal::new(
                key,
                "wrong_type",
                format!("media_flags.{key} must be a non-negative integer of milliseconds or Hz"),
            )
        })
}

fn vad_engine(key: &str, value: &serde_json::Value) -> Result<WsVadEngine, MediaFlagsRefusal> {
    let Some(name) = value.as_str() else {
        return Err(MediaFlagsRefusal {
            allowed: Some(WsVadEngine::VALUES.to_vec()),
            ..MediaFlagsRefusal::new(
                key,
                "wrong_type",
                format!("media_flags.{key} must be a string"),
            )
        });
    };
    WsVadEngine::parse(name).ok_or_else(|| MediaFlagsRefusal {
        allowed: Some(WsVadEngine::VALUES.to_vec()),
        ..MediaFlagsRefusal::new(
            key,
            "invalid_value",
            format!(
                "media_flags.{key} must be one of {}, got {name:?}",
                WsVadEngine::VALUES.join(" / ")
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refused(value: serde_json::Value) -> MediaFlagsRefusal {
        MediaFlags::from_json(&value).expect_err("refused")
    }

    #[test]
    fn every_one_of_the_twelve_keys_parses() {
        let flags = MediaFlags::from_json(&json!({
            "echo_cancellation": false,
            "echo_delay_search_ms": 300,
            "echo_long_tail": true,
            "echo_residual_suppression": true,
            "noise_suppression": true,
            "ws_vad": true,
            "ws_vad_engine": "Neural",
            "ws_vad_min_speech_ms": 100,
            "ws_vad_threshold": -5,
            "ws_vad_hangover_ms": 250,
            "ws_barge_in": true,
            "ws_sample_rate": 16000,
        }))
        .expect("all twelve parse");
        assert_eq!(
            flags,
            MediaFlags {
                echo_cancellation: Some(false),
                echo_delay_search_ms: Some(300),
                echo_long_tail: Some(true),
                echo_residual_suppression: Some(true),
                noise_suppression: Some(true),
                ws_vad: Some(true),
                ws_vad_engine: Some(WsVadEngine::Neural),
                ws_vad_min_speech_ms: Some(100),
                ws_vad_threshold: Some(-5),
                ws_vad_hangover_ms: Some(250),
                ws_barge_in: Some(true),
                ws_sample_rate: Some(16_000),
            }
        );
        assert_eq!(flags.set_fields(), MEDIA_FLAG_FIELDS.to_vec());
    }

    #[test]
    fn an_empty_object_sets_nothing() {
        let flags = MediaFlags::from_json(&json!({})).expect("empty is no overrides");
        assert_eq!(flags, MediaFlags::default());
        assert!(flags.set_fields().is_empty());
    }

    #[test]
    fn a_value_that_is_not_an_object_is_refused() {
        for value in [
            json!(true),
            json!("echo_cancellation"),
            json!([1]),
            json!(3),
        ] {
            let refusal = refused(value);
            assert_eq!(refusal.reason, "not_an_object");
            assert_eq!(refusal.field, None);
        }
    }

    #[test]
    fn an_unknown_key_is_refused_naming_the_twelve() {
        let refusal = refused(json!({ "echo_cancelation": false }));
        assert_eq!(refusal.reason, "unknown_field");
        assert_eq!(refusal.field.as_deref(), Some("echo_cancelation"));
        assert_eq!(refusal.allowed, Some(MEDIA_FLAG_FIELDS.to_vec()));
    }

    /// The profile fields that key a call or widen a gate are not processing
    /// settings, so a per-call argument cannot reach them.
    #[test]
    fn the_non_processing_profile_fields_are_refused() {
        for key in [
            "ws_uri",
            "ws_tee",
            "flags",
            "transport_protocol",
            "ice",
            "dtls",
            "received_from",
            "carry_received_from",
            "codec",
            "record_call",
            "record_path",
            "direction",
            "rtcp_mux",
            "beep_detection",
        ] {
            let refusal = refused(json!({ key: true }));
            assert_eq!(refusal.reason, "unknown_field", "{key}");
            assert_eq!(refusal.field.as_deref(), Some(key));
        }
    }

    #[test]
    fn a_null_value_is_refused_rather_than_read_as_the_default() {
        let refusal = refused(json!({ "echo_cancellation": null }));
        assert_eq!(refusal.reason, "null");
        assert_eq!(refusal.field.as_deref(), Some("echo_cancellation"));
    }

    #[test]
    fn a_wrong_type_is_refused_per_key() {
        for (key, value) in [
            ("echo_cancellation", json!("false")),
            ("ws_barge_in", json!(1)),
            ("echo_delay_search_ms", json!(-1)),
            ("echo_delay_search_ms", json!(12.5)),
            ("ws_vad_min_speech_ms", json!("100")),
            ("ws_vad_hangover_ms", json!(u64::from(u32::MAX) + 1)),
            ("ws_vad_threshold", json!(1.5)),
            ("ws_vad_engine", json!(1)),
            ("ws_sample_rate", json!("16000")),
        ] {
            let refusal = refused(json!({ key: value }));
            assert_eq!(refusal.reason, "wrong_type", "{key}={value}");
            assert_eq!(refusal.field.as_deref(), Some(key));
        }
    }

    #[test]
    fn a_vad_engine_the_engine_does_not_run_is_refused_with_the_choices() {
        let refusal = refused(json!({ "ws_vad_engine": "webrtc" }));
        assert_eq!(refusal.reason, "invalid_value");
        assert_eq!(refusal.field.as_deref(), Some("ws_vad_engine"));
        assert_eq!(refusal.allowed, Some(vec!["energy", "neural"]));
    }

    #[test]
    fn a_sample_rate_the_engine_would_fail_is_refused() {
        for rate in [7_000, 16_500, 96_000] {
            let refusal = refused(json!({ "ws_sample_rate": rate }));
            assert_eq!(refusal.reason, "out_of_range", "{rate}");
            assert_eq!(refusal.field.as_deref(), Some("ws_sample_rate"));
        }
    }

    #[test]
    fn merge_overrides_only_the_keys_given() {
        let base = NgFlags {
            echo_cancellation: true,
            noise_suppression: true,
            ws_vad: true,
            ws_sample_rate: Some(16_000),
            ws_vad_hangover_ms: Some(300),
            ws_uri: Some("wss://ai.invalid/agent".to_string()),
            ..NgFlags::default()
        };
        let flags = MediaFlags {
            echo_cancellation: Some(false),
            ws_vad_min_speech_ms: Some(100),
            ..MediaFlags::default()
        };
        let merged = flags.applied_to(&base).expect("valid");
        assert!(!merged.echo_cancellation, "overridden");
        assert_eq!(merged.ws_vad_min_speech_ms, Some(100), "added");
        assert!(merged.noise_suppression, "kept");
        assert!(merged.ws_vad, "kept");
        assert_eq!(merged.ws_sample_rate, Some(16_000), "kept");
        assert_eq!(merged.ws_vad_hangover_ms, Some(300), "kept");
        assert_eq!(merged.ws_uri.as_deref(), Some("wss://ai.invalid/agent"));
        // The profile's own half is untouched: other calls read it.
        assert!(base.echo_cancellation);
        assert_eq!(base.ws_vad_min_speech_ms, None);
    }

    #[test]
    fn merge_sets_every_field_it_carries() {
        let flags = MediaFlags {
            echo_cancellation: Some(true),
            echo_delay_search_ms: Some(400),
            echo_long_tail: Some(true),
            echo_residual_suppression: Some(true),
            noise_suppression: Some(true),
            ws_vad: Some(true),
            ws_vad_engine: Some(WsVadEngine::Neural),
            ws_vad_min_speech_ms: Some(80),
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(150),
            ws_barge_in: Some(true),
            ws_sample_rate: Some(24_000),
        };
        let merged = flags.applied_to(&NgFlags::default()).expect("valid");
        assert!(merged.echo_cancellation);
        assert_eq!(merged.echo_delay_search_ms, Some(400));
        assert!(merged.echo_long_tail);
        assert!(merged.echo_residual_suppression);
        assert!(merged.noise_suppression);
        assert!(merged.ws_vad);
        assert_eq!(merged.ws_vad_engine, Some(WsVadEngine::Neural));
        assert_eq!(merged.ws_vad_min_speech_ms, Some(80));
        assert_eq!(merged.ws_vad_threshold, Some(2_000_000));
        assert_eq!(merged.ws_vad_hangover_ms, Some(150));
        assert!(merged.ws_barge_in);
        assert_eq!(merged.ws_sample_rate, Some(24_000));
    }

    #[test]
    fn the_echo_window_is_checked_on_the_merged_flags() {
        let refusal = MediaFlags {
            echo_delay_search_ms: Some(1_001),
            ..MediaFlags::default()
        }
        .applied_to(&NgFlags::default())
        .expect_err("outside the window");
        assert_eq!(refusal.reason, "out_of_range");
        assert_eq!(refusal.field.as_deref(), Some("echo_delay_search_ms"));
        assert!(
            refusal.message.contains("search window"),
            "{}",
            refusal.message
        );
        // A profile's out-of-range window cannot exist (boot refuses it), so a
        // per-call window inside the bounds always passes.
        assert!(MediaFlags {
            echo_delay_search_ms: Some(1_000),
            ..MediaFlags::default()
        }
        .applied_to(&NgFlags::default())
        .is_ok());
    }

    /// The reading flips with the merged `echo_long_tail`, whether the switch
    /// comes from the profile or from this call.
    #[test]
    fn the_echo_bound_follows_the_merged_long_tail() {
        let long_tail_profile = NgFlags {
            echo_long_tail: true,
            ..NgFlags::default()
        };
        let window = MediaFlags {
            echo_delay_search_ms: Some(1_001),
            ..MediaFlags::default()
        };
        let from_profile = window
            .applied_to(&long_tail_profile)
            .expect_err("outside the tail range");
        assert!(
            from_profile.message.contains("tail length"),
            "{}",
            from_profile.message
        );

        let window_profile = NgFlags {
            echo_delay_search_ms: Some(1_001),
            ..NgFlags::default()
        };
        let switch = MediaFlags {
            echo_long_tail: Some(true),
            ..MediaFlags::default()
        };
        let from_call = switch
            .applied_to(&window_profile)
            .expect_err("the profile's window read as a tail");
        assert_eq!(from_call.field.as_deref(), Some("echo_long_tail"));
        assert!(
            from_call.message.contains("tail length"),
            "{}",
            from_call.message
        );

        // And turning long tail off reads the same value as a window.
        let off = MediaFlags {
            echo_long_tail: Some(false),
            echo_delay_search_ms: Some(1_001),
            ..MediaFlags::default()
        };
        let refusal = off
            .applied_to(&long_tail_profile)
            .expect_err("outside the window");
        assert!(
            refusal.message.contains("search window"),
            "{}",
            refusal.message
        );
    }

    #[test]
    fn check_echo_delay_search_ms_uses_the_engine_bounds_for_each_reading() {
        assert_eq!(check_echo_delay_search_ms(16, false), Ok(()));
        assert_eq!(check_echo_delay_search_ms(1_000, true), Ok(()));
        let window = check_echo_delay_search_ms(15, false).expect_err("below");
        assert_eq!(window.low, siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MIN);
        assert_eq!(window.high, siphon_rtp_proto::ECHO_DELAY_SEARCH_MS_MAX);
        assert_eq!(window.meaning, "a search window");
        let tail = check_echo_delay_search_ms(1_001, true).expect_err("above");
        assert_eq!(tail.low, siphon_rtp_proto::ECHO_LONG_TAIL_MS_MIN);
        assert_eq!(tail.high, siphon_rtp_proto::ECHO_LONG_TAIL_MS_MAX);
        assert_eq!(tail.meaning, "a tail length, because echo_long_tail is set");
    }

    fn dead_address() -> std::net::SocketAddr {
        std::net::SocketAddr::from(([127, 0, 0, 1], 1))
    }

    #[tokio::test]
    async fn the_backend_gate_refuses_only_keys_this_call_set() {
        let set = crate::rtpengine::RtpProxyClientSet::new(vec![(dead_address(), 200, 1)], 0)
            .await
            .expect("an rtpproxy set");
        let rtpproxy = crate::rtpengine::MediaBackend::RtpProxy(set);
        let flags = MediaFlags {
            echo_cancellation: Some(true),
            ..MediaFlags::default()
        };
        let merged = flags.applied_to(&NgFlags::default()).expect("valid");
        let refusal = flags
            .check_backend(&rtpproxy, &merged)
            .expect_err("rtpproxy cannot cancel echo");
        assert_eq!(refusal.reason, "unsupported_by_backend");
        assert_eq!(refusal.field.as_deref(), Some("echo_cancellation"));

        // Turning a setting off asks nothing of the backend.
        let off = MediaFlags {
            echo_cancellation: Some(false),
            ..MediaFlags::default()
        };
        let merged = off.applied_to(&NgFlags::default()).expect("valid");
        assert!(off.check_backend(&rtpproxy, &merged).is_ok());

        // A field the profile set is not this call's to answer for.
        let profile = NgFlags {
            noise_suppression: true,
            ..NgFlags::default()
        };
        let merged = off.applied_to(&profile).expect("valid");
        assert!(off.check_backend(&rtpproxy, &merged).is_ok());
    }

    #[tokio::test]
    async fn the_backend_gate_passes_every_key_on_siphon_rtp() {
        let (event_tx, _events) =
            tokio::sync::mpsc::channel::<crate::rtpengine::events::RtpEngineEvent>(16);
        let set = crate::rtpengine::SiphonRtpClientSet::new(
            vec![(dead_address(), 200, 1)],
            None,
            5_000,
            event_tx,
        )
        .expect("a native set");
        let native = crate::rtpengine::MediaBackend::SiphonRtp(set);
        let flags = MediaFlags {
            echo_cancellation: Some(true),
            noise_suppression: Some(true),
            ws_vad: Some(true),
            ws_barge_in: Some(true),
            ws_vad_threshold: Some(1),
            ws_vad_hangover_ms: Some(100),
            ..MediaFlags::default()
        };
        let merged = flags.applied_to(&NgFlags::default()).expect("valid");
        assert!(flags.check_backend(&native, &merged).is_ok());
    }
}
