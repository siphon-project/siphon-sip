//! `ws_uri` templating: the one place a WebSocket URI's placeholders expand.
//!
//! A URI handed to the media engine for a takeover bridge (`ws_uri`) or a tee
//! (`ws_tee`) may name `{call_id}`, `{from_tag}`, `{from_user}` and
//! `{to_user}`. Every path that hands one over expands it here, so a
//! placeholder means the same thing whichever path it arrived by: a profile at
//! negotiation, a script's `ws_uri=` or `attach_ws_tee` / `attach_ws_bridge`,
//! and the control plane's `answer` / `progress` / `originate` and
//! `stream_start`.
//!
//! `{call_id}` is the **SIP Call-ID** of the call whose media the stream
//! carries — the leg's own dialog, which is also what the media engine keys
//! the call on and what every media event names. `{from_tag}` is the tag the
//! engine keyed the leg on (the offerer's). `{from_user}` / `{to_user}` are
//! the user parts of that dialog's From and To.

use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::message::SipMessage;

use super::NgFlags;

/// The per-call values a `ws_uri` template can interpolate.
#[derive(Debug, Clone, Copy)]
pub struct WsUriContext<'a> {
    /// The SIP Call-ID of the call.
    pub call_id: &'a str,
    /// The tag the engine keyed the leg on.
    pub from_tag: &'a str,
    /// The From user part, when the call has one.
    pub from_user: Option<&'a str>,
    /// The To user part, when the call has one.
    pub to_user: Option<&'a str>,
}

/// Why a template could not be expanded. Each is a refusal, never a literal
/// pass-through: a URI the engine dials with a `{placeholder}` still in it
/// reaches a route nobody meant to call.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WsUriError {
    #[error("ws_uri has an unclosed '{{' placeholder: {template:?}")]
    Unclosed { template: String },
    #[error(
        "ws_uri has unknown placeholder {{{name}}}; supported: \
         {{call_id}}, {{from_tag}}, {{from_user}}, {{to_user}}"
    )]
    UnknownPlaceholder { name: String },
    #[error("ws_uri placeholder {{{name}}} has no value on this call")]
    NoValue { name: String },
}

/// The From and To user parts of `message`, for [`WsUriContext`].
///
/// Parsed with [`NameAddr::parse`], so a display name with a comma or an
/// angle-bracketed URI is read the way `request.from_uri` reads it.
pub fn dialog_users(message: &SipMessage) -> (Option<String>, Option<String>) {
    let user_of = |raw: Option<&String>| -> Option<String> {
        raw.and_then(|value| NameAddr::parse(value).ok())
            .and_then(|name_addr| name_addr.uri.user)
    };
    (
        user_of(message.headers.from()),
        user_of(message.headers.to()),
    )
}

/// Expand `{call_id}` / `{from_tag}` / `{from_user}` / `{to_user}` in a URI.
///
/// An unrecognised placeholder is an error, not a literal, and so is one with
/// no value on this call (no From user part, say): an empty path segment is as
/// wrong as a literal one, only harder to spot. A URI with no `{` is returned
/// untouched.
pub fn expand_ws_uri(template: &str, context: &WsUriContext<'_>) -> Result<String, WsUriError> {
    if !template.contains('{') {
        return Ok(template.to_string());
    }

    let mut expanded = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        expanded.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(WsUriError::Unclosed {
                template: template.to_string(),
            });
        };
        let name = &after_open[..close];
        let value = match name {
            "call_id" => Some(context.call_id),
            "from_tag" => Some(context.from_tag),
            "from_user" => context.from_user,
            "to_user" => context.to_user,
            other => {
                return Err(WsUriError::UnknownPlaceholder {
                    name: other.to_string(),
                })
            }
        };
        let Some(value) = value else {
            return Err(WsUriError::NoValue {
                name: name.to_string(),
            });
        };
        expanded.push_str(value);
        rest = &after_open[close + 1..];
    }
    expanded.push_str(rest);

    Ok(expanded)
}

/// Expand both WebSocket URIs a set of engine flags carries, the takeover
/// bridge's `ws_uri` and the tee's `ws_tee`, in place.
///
/// Every negotiation path runs its flags through this once they are final, so
/// a profile's `ws_tee` templates exactly as its `ws_uri` does.
pub fn expand_flag_uris(flags: &mut NgFlags, context: &WsUriContext<'_>) -> Result<(), WsUriError> {
    if let Some(template) = flags.ws_uri.as_deref() {
        flags.ws_uri = Some(expand_ws_uri(template, context)?);
    }
    if let Some(template) = flags.ws_tee.as_deref() {
        flags.ws_tee = Some(expand_ws_uri(template, context)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context<'a>() -> WsUriContext<'a> {
        WsUriContext {
            call_id: "abc123@example.invalid",
            from_tag: "tag-a",
            from_user: Some("1001"),
            to_user: Some("2002"),
        }
    }

    #[test]
    fn a_uri_without_a_placeholder_is_untouched() {
        let expanded = expand_ws_uri("wss://ai.invalid/stream", &context()).expect("expands");
        assert_eq!(expanded, "wss://ai.invalid/stream");
    }

    #[test]
    fn every_placeholder_is_substituted() {
        let expanded = expand_ws_uri(
            "wss://ai.invalid/{call_id}/{from_tag}?from={from_user}&to={to_user}",
            &context(),
        )
        .expect("expands");
        assert_eq!(
            expanded,
            "wss://ai.invalid/abc123@example.invalid/tag-a?from=1001&to=2002"
        );
    }

    #[test]
    fn a_repeated_placeholder_is_substituted_each_time() {
        let expanded =
            expand_ws_uri("wss://ai.invalid/{call_id}/{call_id}", &context()).expect("expands");
        assert_eq!(
            expanded,
            "wss://ai.invalid/abc123@example.invalid/abc123@example.invalid"
        );
    }

    /// A typo'd placeholder must not reach the engine as a literal path segment.
    #[test]
    fn an_unknown_placeholder_is_refused() {
        let error = expand_ws_uri("wss://ai.invalid/{callid}", &context()).expect_err("refused");
        assert_eq!(
            error,
            WsUriError::UnknownPlaceholder {
                name: "callid".to_string()
            }
        );
        assert!(error.to_string().contains("unknown placeholder {callid}"));
    }

    #[test]
    fn an_unclosed_placeholder_is_refused() {
        let error = expand_ws_uri("wss://ai.invalid/{call_id", &context()).expect_err("refused");
        assert!(matches!(error, WsUriError::Unclosed { .. }));
        assert!(error.to_string().contains("unclosed"));
    }

    #[test]
    fn a_placeholder_with_no_value_is_refused() {
        let context = WsUriContext {
            from_user: None,
            ..context()
        };
        let error = expand_ws_uri("wss://ai.invalid/{from_user}", &context).expect_err("refused");
        assert_eq!(
            error,
            WsUriError::NoValue {
                name: "from_user".to_string()
            }
        );
        assert!(error.to_string().contains("has no value"));
    }

    #[test]
    fn both_stream_uris_on_the_flags_are_expanded() {
        let mut flags = NgFlags {
            ws_uri: Some("wss://ai.invalid/{call_id}".to_string()),
            ws_tee: Some("wss://asr.invalid/{call_id}/{from_tag}".to_string()),
            ..Default::default()
        };
        expand_flag_uris(&mut flags, &context()).expect("expands");
        assert_eq!(
            flags.ws_uri.as_deref(),
            Some("wss://ai.invalid/abc123@example.invalid")
        );
        assert_eq!(
            flags.ws_tee.as_deref(),
            Some("wss://asr.invalid/abc123@example.invalid/tag-a")
        );
    }

    #[test]
    fn flags_without_stream_uris_are_left_alone() {
        let mut flags = NgFlags::default();
        expand_flag_uris(&mut flags, &context()).expect("nothing to expand");
        assert!(flags.ws_uri.is_none());
        assert!(flags.ws_tee.is_none());
    }

    #[test]
    fn a_bad_tee_template_is_refused_like_a_bad_bridge_one() {
        let mut flags = NgFlags {
            ws_tee: Some("wss://asr.invalid/{callid}".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            expand_flag_uris(&mut flags, &context()),
            Err(WsUriError::UnknownPlaceholder { .. })
        ));
    }

    #[test]
    fn dialog_users_reads_the_from_and_to_user_parts() {
        let message = crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "INVITE sip:2002@example.invalid SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-1\r\n",
                "From: \"Doe, J\" <sip:1001@example.invalid>;tag=a\r\n",
                "To: <sip:2002@example.invalid>\r\n",
                "Call-ID: users@example.invalid\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("parses");
        assert_eq!(
            dialog_users(&message),
            (Some("1001".to_string()), Some("2002".to_string()))
        );
    }
}
