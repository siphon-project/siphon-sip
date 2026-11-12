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
//!
//! Each value is **percent-encoded** as one URI component before it goes in
//! (see [`push_percent_encoded`]): RFC 3261 §25.1 lets a Call-ID carry
//! `+ % / ? " < > { }` and more, and a user part may carry `%`-escapes, `+`,
//! `;` and `&`, each of which would change what the URI means. A receiver
//! decodes the value as it decodes any URI (a query parser, a path router),
//! and gets back the exact Call-ID / tag / user part. The template's own text
//! is never touched.

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

/// Expand `{call_id}` / `{from_tag}` / `{from_user}` / `{to_user}` in a URI,
/// each value percent-encoded (see the module docs).
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
        push_percent_encoded(&mut expanded, value);
        rest = &after_open[close + 1..];
    }
    expanded.push_str(rest);

    Ok(expanded)
}

/// Append `value` to `uri` as a single URI component: RFC 3986 §2.3
/// unreserved characters (`A-Z a-z 0-9 - . _ ~`) as they are, every other
/// byte of its UTF-8 as `%XX` with uppercase hex (RFC 3986 §2.1, §2.5).
///
/// Encoding everything outside the unreserved set is stricter than either a
/// path segment or a query needs, which is the point: the same encoded value
/// is safe in both, and no delimiter (`/ ? # & = +`) in a Call-ID can split a
/// path or a query parameter. `+` in particular is encoded, since a form
/// decoder (`application/x-www-form-urlencoded`) would read it as a space.
fn push_percent_encoded(uri: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }
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
            "wss://ai.invalid/abc123%40example.invalid/tag-a?from=1001&to=2002"
        );
    }

    #[test]
    fn a_repeated_placeholder_is_substituted_each_time() {
        let expanded =
            expand_ws_uri("wss://ai.invalid/{call_id}/{call_id}", &context()).expect("expands");
        assert_eq!(
            expanded,
            "wss://ai.invalid/abc123%40example.invalid/abc123%40example.invalid"
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
            Some("wss://ai.invalid/abc123%40example.invalid")
        );
        assert_eq!(
            flags.ws_tee.as_deref(),
            Some("wss://asr.invalid/abc123%40example.invalid/tag-a")
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

    fn call(call_id: &str) -> WsUriContext<'_> {
        WsUriContext {
            call_id,
            ..context()
        }
    }

    fn expand_call_id(call_id: &str) -> String {
        expand_ws_uri("{call_id}", &call(call_id)).expect("expands")
    }

    #[test]
    fn a_plus_and_an_at_sign_are_percent_encoded() {
        assert_eq!(expand_call_id("a+b@h"), "a%2Bb%40h");
    }

    /// An escape already in the value is data, not an escape of the URI.
    #[test]
    fn a_percent_sign_is_itself_encoded() {
        assert_eq!(expand_call_id("x%41y"), "x%2541y");
    }

    #[test]
    fn a_slash_and_a_question_mark_cannot_change_the_route() {
        assert_eq!(expand_call_id("p/q?r"), "p%2Fq%3Fr");
    }

    /// RFC 3261 §25.1 lets a Call-ID word carry `" < > { }`; none may reach a
    /// URI raw, nor may a space or a non-ASCII character (encoded per UTF-8 byte).
    #[test]
    fn characters_a_uri_cannot_carry_are_encoded_as_utf8_bytes() {
        assert_eq!(
            expand_call_id("\"a<b>{c} d\u{e9}"),
            "%22a%3Cb%3E%7Bc%7D%20d%C3%A9"
        );
    }

    #[test]
    fn query_delimiters_in_a_value_are_encoded() {
        assert_eq!(expand_call_id("a&b=c#d;e"), "a%26b%3Dc%23d%3Be");
    }

    #[test]
    fn an_all_unreserved_value_is_unchanged() {
        let unreserved = "AZaz09-._~";
        assert_eq!(expand_call_id(unreserved), unreserved);
    }

    #[test]
    fn the_template_text_around_a_placeholder_is_untouched() {
        let expanded = expand_ws_uri(
            "wss://ai.example.com:8443/stream/{call_id}?call={call_id}&from={from_user}#x",
            &WsUriContext {
                call_id: "a b",
                from_user: Some("+31"),
                ..context()
            },
        )
        .expect("expands");
        assert_eq!(
            expanded,
            "wss://ai.example.com:8443/stream/a%20b?call=a%20b&from=%2B31#x"
        );
    }

    /// The decoding a receiver does on a query string
    /// (`application/x-www-form-urlencoded`, WHATWG URL §5.1: `+` is a space,
    /// `%XX` a byte), written out here so the test does not lean on the encoder.
    fn form_decode_query(query: &str) -> Vec<(String, String)> {
        let decode = |text: &str| -> String {
            let bytes = text.as_bytes();
            let mut out = Vec::with_capacity(bytes.len());
            let mut index = 0;
            while index < bytes.len() {
                match bytes[index] {
                    b'+' => out.push(b' '),
                    b'%' if index + 2 < bytes.len() => {
                        let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).expect("ascii");
                        out.push(u8::from_str_radix(hex, 16).expect("hex escape"));
                        index += 2;
                    }
                    other => out.push(other),
                }
                index += 1;
            }
            String::from_utf8(out).expect("utf-8")
        };
        query
            .split('&')
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                (decode(name), decode(value))
            })
            .collect()
    }

    #[test]
    fn a_form_decoder_reads_back_the_exact_call_id() {
        // Every character RFC 3261 §25.1 allows in a Call-ID word, plus `@`.
        let call_id = "a-.!%*_+`'~()<>:\\\"/[]?{}@host";
        let expanded = expand_ws_uri(
            "wss://ai.example.com/s?call={call_id}&leg=1",
            &call(call_id),
        )
        .expect("expands");
        let (_, query) = expanded.split_once('?').expect("query");
        assert_eq!(
            form_decode_query(query),
            vec![
                ("call".to_string(), call_id.to_string()),
                ("leg".to_string(), "1".to_string()),
            ]
        );
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
