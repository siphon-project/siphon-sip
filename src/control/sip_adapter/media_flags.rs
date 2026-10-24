//! The `media_flags` argument of `answer`, anchored `progress`, `stream_start`
//! (`mode: "bridge"`) and `originate` (`media: true`): reading it, checking it
//! against the profile it is merged over, and the typed refusals.
//!
//! The value itself is [`crate::rtpengine::media_flags::MediaFlags`]; this file
//! is only the control rail's side of it. Every refusal is a `bad_request`
//! whose `details` are `{verb, argument: "media_flags", field?, reason,
//! allowed?}`, sent before anything reaches the call.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::rtpengine::media_flags::{MediaFlags, MediaFlagsRefusal};
use crate::rtpengine::NgFlags;

/// Read `args.media_flags`. Absent or `null` is none, as for every other
/// optional argument on this rail; anything present must be an object of the
/// twelve processing settings ([`MediaFlags::from_json`]).
pub(super) fn parse(
    verb: &str,
    args: &serde_json::Value,
) -> Result<Option<MediaFlags>, ControlResult> {
    match args.get("media_flags") {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => MediaFlags::from_json(value)
            .map(Some)
            .map_err(|refusal| refused(verb, &refusal)),
    }
}

/// The `bad_request` for a refused value.
pub(super) fn refused(verb: &str, refusal: &MediaFlagsRefusal) -> ControlResult {
    let mut details = serde_json::json!({
        "verb": verb,
        "argument": "media_flags",
        "reason": refusal.reason,
    });
    if let Some(fields) = details.as_object_mut() {
        if let Some(field) = &refusal.field {
            fields.insert("field".to_string(), field.clone().into());
        }
        if let Some(allowed) = &refusal.allowed {
            fields.insert("allowed".to_string(), allowed.clone().into());
        }
    }
    ControlResult::error_with_details(
        ControlErrorCode::BadRequest,
        format!("{verb} args.{}", refusal.message),
        details,
    )
}

/// The `bad_request` for `media_flags` where the call it would shape cannot
/// take it (a tee, an early offer, an originate siphon does not anchor, a
/// bridge with no profile to merge over). `reason` is the stable token.
pub(super) fn out_of_place(verb: &str, reason: &'static str, message: String) -> ControlResult {
    ControlResult::error_with_details(
        ControlErrorCode::BadRequest,
        message,
        serde_json::json!({
            "verb": verb,
            "argument": "media_flags",
            "reason": reason,
        }),
    )
}

/// `flags` merged over `base` and checked as boot checks a profile. The merged
/// flags are the ones the call runs with; what the backend can honour is
/// checked where the backend is known ([`MediaFlags::check_backend`]).
pub(super) fn merged(
    verb: &str,
    flags: &MediaFlags,
    base: &NgFlags,
) -> Result<NgFlags, ControlResult> {
    flags
        .applied_to(base)
        .map_err(|refusal| refused(verb, &refusal))
}

/// Check `flags` at the verb against the answer half of the profile the call
/// will anchor on, so an out-of-range merged value is a `bad_request` before
/// anything is anchored, not an `unavailable` from the media plan.
///
/// A profile this node does not have is left to the media plan, which refuses
/// it as it always has; there is nothing to merge over.
pub(super) fn check_against_profile(
    verb: &str,
    flags: &MediaFlags,
    profile: &str,
) -> Result<(), ControlResult> {
    match crate::dispatcher::b2bua_media_profile(profile) {
        Ok(base) => merged(verb, flags, &base).map(drop),
        Err(_) => Ok(()),
    }
}

/// Read a verb's `profile`: absent or `null` is none, a string is the name,
/// anything else is a `bad_request` rather than the default profile a
/// controller did not ask for.
pub(super) fn profile_name<'a>(
    verb: &str,
    args: &'a serde_json::Value,
) -> Result<Option<&'a str>, ControlResult> {
    match args.get("profile") {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => value.as_str().map(Some).ok_or_else(|| {
            ControlResult::error_with_details(
                ControlErrorCode::BadRequest,
                format!("{verb} args.profile must be a string naming a media profile"),
                serde_json::json!({
                    "verb": verb,
                    "argument": "profile",
                    "reason": "wrong_type",
                }),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn details(result: &ControlResult) -> serde_json::Value {
        match result {
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                details: Some(details),
                ..
            } => details.clone(),
            other => panic!("expected bad_request with details, got {other:?}"),
        }
    }

    #[test]
    fn absent_and_null_are_no_media_flags() {
        assert_eq!(parse("answer", &json!({})), Ok(None));
        assert_eq!(parse("answer", &json!({ "media_flags": null })), Ok(None));
    }

    #[test]
    fn a_refusal_carries_the_verb_the_argument_the_field_and_the_reason() {
        let result = parse(
            "answer",
            &json!({ "media_flags": { "ws_uri": "wss://x.invalid" } }),
        )
        .expect_err("refused");
        let details = details(&result);
        assert_eq!(details["verb"], "answer");
        assert_eq!(details["argument"], "media_flags");
        assert_eq!(details["field"], "ws_uri");
        assert_eq!(details["reason"], "unknown_field");
        assert_eq!(details["allowed"].as_array().map(Vec::len), Some(12));
    }

    #[test]
    fn a_refusal_without_a_closed_set_carries_no_allowed() {
        let result = parse(
            "stream_start",
            &json!({ "media_flags": { "echo_cancellation": "no" } }),
        )
        .expect_err("refused");
        let details = details(&result);
        assert_eq!(details["verb"], "stream_start");
        assert_eq!(details["field"], "echo_cancellation");
        assert_eq!(details["reason"], "wrong_type");
        assert!(details.get("allowed").is_none(), "{details}");
    }

    #[test]
    fn a_value_that_is_not_an_object_names_no_field() {
        let result = parse("originate", &json!({ "media_flags": [true] })).expect_err("refused");
        let details = details(&result);
        assert_eq!(details["reason"], "not_an_object");
        assert!(details.get("field").is_none(), "{details}");
    }

    #[test]
    fn merged_refuses_an_echo_window_the_merged_long_tail_rejects() {
        let base = NgFlags {
            echo_delay_search_ms: Some(1_001),
            ..NgFlags::default()
        };
        let flags = MediaFlags {
            echo_long_tail: Some(true),
            ..MediaFlags::default()
        };
        let result = merged("answer", &flags, &base).expect_err("refused");
        let details = details(&result);
        assert_eq!(details["field"], "echo_long_tail");
        assert_eq!(details["reason"], "out_of_range");
    }

    #[test]
    fn a_profile_that_is_not_a_string_is_a_bad_request() {
        for verb in ["answer", "progress", "originate"] {
            let result = profile_name(verb, &json!({ "profile": 16000 })).expect_err("refused");
            let details = details(&result);
            assert_eq!(details["verb"], verb);
            assert_eq!(details["argument"], "profile");
            assert_eq!(details["reason"], "wrong_type");
        }
        assert_eq!(profile_name("answer", &json!({})), Ok(None));
        assert_eq!(
            profile_name("answer", &json!({ "profile": null })),
            Ok(None)
        );
        assert_eq!(
            profile_name("answer", &json!({ "profile": "voice_ai" })),
            Ok(Some("voice_ai"))
        );
    }

    /// With no dispatcher there is no profile to merge over, and the media
    /// plan refuses the call as before; nothing is refused here for it.
    #[test]
    fn an_unresolvable_profile_is_left_to_the_media_plan() {
        let flags = MediaFlags {
            echo_delay_search_ms: Some(300),
            ..MediaFlags::default()
        };
        assert_eq!(check_against_profile("answer", &flags, "voice_ai"), Ok(()));
    }
}
