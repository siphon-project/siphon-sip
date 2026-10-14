//! Headers a script adds to a response siphon sends itself as the caller's UAS:
//! `call.progress()`, `call.answer()`, `call.reject()` and the control plane's
//! `progress` / `answer` / `reject` verbs.
//!
//! There is no B-leg response for a header policy to act on here, so a header
//! the script names is precedence 1 and goes out as written, the way a script's
//! `reply.set_header()` does on a relayed response. What it cannot touch is the
//! set siphon owns on such a response: the dialog and transaction identity
//! (RFC 3261 §8.2.6.2), the Contact and Record-Route that build the caller's
//! route set (§12.1.1), the body framing, the `100rel` machinery (RFC 3262 §3:
//! `RSeq`, and the `Require` / `Supported` siphon writes when it sends a
//! provisional reliably) and the session timer it negotiates on the 2xx (RFC
//! 4028 §9). A script value for any of those would either be overwritten after
//! it ran or break the dialog it was meant to shape, so it is refused with an
//! error that says which header and why, never dropped quietly.

/// The headers siphon owns on a response it sends as the caller's UAS, and why.
///
/// Compared with [`crate::sip::headers::same_header_name`], so a compact form
/// (`k` for `Supported`, `l` for `Content-Length`) is refused like its long
/// name.
const FRAMEWORK_OWNED: &[(&str, &str)] = &[
    ("Via", "copied from the request (RFC 3261 §8.2.6.2)"),
    ("From", "copied from the request (RFC 3261 §8.2.6.2)"),
    ("To", "carries the dialog's UAS tag (RFC 3261 §8.2.6.2)"),
    ("Call-ID", "copied from the request (RFC 3261 §8.2.6.2)"),
    ("CSeq", "copied from the request (RFC 3261 §8.2.6.2)"),
    ("Max-Forwards", "is a request header siphon manages"),
    (
        "Contact",
        "is the dialog's remote target siphon advertises (RFC 3261 §12.1.1)",
    ),
    (
        "Record-Route",
        "is copied from the request into the dialog-forming response (RFC 3261 §12.1.1)",
    ),
    ("Route", "is per-hop routing siphon manages"),
    ("Content-Length", "is computed from the body"),
    (
        "Content-Type",
        "goes with the body: pass content_type= instead",
    ),
    (
        "RSeq",
        "is numbered by siphon for a reliable provisional (RFC 3262 §3)",
    ),
    ("RAck", "is a PRACK request header (RFC 3262 §7.2)"),
    (
        "Require",
        "carries the 100rel and timer tags siphon negotiates (RFC 3262 §3, RFC 4028 §9)",
    ),
    (
        "Supported",
        "carries the option tags siphon negotiates (RFC 3262 §3, RFC 4028 §9)",
    ),
    (
        "Session-Expires",
        "is the session timer siphon negotiates (RFC 4028 §9)",
    ),
    (
        "Min-SE",
        "is the session timer siphon negotiates (RFC 4028 §9)",
    ),
];

/// Why siphon refuses `name` on a response it sends as the caller's UAS, or
/// `None` when a script may set it.
pub fn framework_owned_reason(name: &str) -> Option<&'static str> {
    FRAMEWORK_OWNED
        .iter()
        .find(|(owned, _)| crate::sip::headers::same_header_name(owned, name))
        .map(|(_, reason)| *reason)
}

/// An RFC 3261 §25.1 `token`: what a header field name is made of.
fn is_token(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'-' | b'.' | b'!' | b'%' | b'*' | b'_' | b'+' | b'`' | b'\'' | b'~'
                )
        })
}

/// Check the headers a script asked to add to a UAS response.
///
/// `Err` names the first header refused and why: a framework-owned one, a name
/// that is not a header field name, or a value carrying a line break or NUL,
/// which would let one header's value start another (RFC 3261 §7.3.1 allows
/// folding only as whitespace, and siphon serializes values verbatim).
pub fn validate(headers: &[(String, String)]) -> Result<(), String> {
    for (name, value) in headers {
        if !is_token(name) {
            return Err(format!("'{name}' is not a SIP header name"));
        }
        if let Some(reason) = framework_owned_reason(name) {
            return Err(format!(
                "{name} cannot be set by a script on a response siphon sends: it {reason}"
            ));
        }
        if value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
            return Err(format!(
                "the value of {name} contains a line break or NUL, which would end the header early"
            ));
        }
    }
    Ok(())
}

/// Put the script's `headers` on `response`, each replacing any header of the
/// same name the framework put there first (`Server`, say). Run after
/// [`validate`], on a response siphon has otherwise finished building.
pub fn apply(response: &mut crate::sip::message::SipMessage, headers: &[(String, String)]) {
    for (name, value) in headers {
        response.headers.set(name, value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn a_header_siphon_does_not_own_is_accepted() {
        assert_eq!(
            validate(&headers(&[
                ("P-Early-Media", "sendrecv"),
                ("Allow", "INVITE, ACK, BYE, CANCEL, PRACK, UPDATE"),
                ("Server", "announcement-service"),
                ("Reason", "SIP;cause=480;text=\"Temporarily Unavailable\""),
                ("X-Lab-Tag", "a"),
            ])),
            Ok(())
        );
    }

    #[test]
    fn no_headers_is_accepted() {
        assert_eq!(validate(&[]), Ok(()));
    }

    #[test]
    fn every_framework_owned_header_is_refused_whatever_its_case() {
        for (name, _) in FRAMEWORK_OWNED {
            for spelling in [name.to_string(), name.to_ascii_lowercase()] {
                let refusal = validate(&headers(&[(&spelling, "x")]))
                    .expect_err("a framework-owned header must be refused");
                assert!(
                    refusal.starts_with(&spelling),
                    "the refusal names the header: {refusal}"
                );
            }
        }
    }

    #[test]
    fn a_compact_form_is_refused_like_its_long_name() {
        for compact in ["v", "f", "t", "i", "m", "l", "c", "k"] {
            assert!(
                validate(&headers(&[(compact, "x")])).is_err(),
                "compact {compact} must be refused"
            );
        }
    }

    #[test]
    fn content_type_points_at_the_content_type_argument() {
        let refusal = validate(&headers(&[("Content-Type", "application/sdp")]))
            .expect_err("Content-Type is the body's");
        assert!(refusal.contains("content_type="), "{refusal}");
    }

    #[test]
    fn the_100rel_and_session_timer_headers_are_refused() {
        for name in [
            "RSeq",
            "RAck",
            "Require",
            "Supported",
            "Session-Expires",
            "Min-SE",
        ] {
            assert!(framework_owned_reason(name).is_some(), "{name}");
        }
    }

    #[test]
    fn a_name_that_is_not_a_token_is_refused() {
        for name in ["", "Bad Name", "Bad:Name", "X-\r\nVia"] {
            assert!(
                validate(&headers(&[(name, "x")])).is_err(),
                "{name:?} is not a header name"
            );
        }
    }

    #[test]
    fn a_value_that_would_start_another_header_is_refused() {
        for value in ["sendrecv\r\nContact: <sip:x@192.0.2.1>", "a\nb", "a\0b"] {
            let refusal = validate(&headers(&[("P-Early-Media", value)]))
                .expect_err("a line break in a value is an injection");
            assert!(refusal.contains("P-Early-Media"), "{refusal}");
        }
    }

    #[test]
    fn the_first_refused_header_is_the_one_named() {
        let refusal = validate(&headers(&[
            ("P-Early-Media", "sendrecv"),
            ("Contact", "<sip:x@192.0.2.1>"),
            ("Via", "SIP/2.0/UDP 192.0.2.1"),
        ]))
        .expect_err("Contact is siphon's");
        assert!(refusal.starts_with("Contact"), "{refusal}");
    }

    #[test]
    fn apply_replaces_a_header_the_framework_put_there() {
        let mut response = crate::sip::builder::SipMessageBuilder::new()
            .response(183, "Session Progress".to_string())
            .header("Server", "siphon".to_string())
            .content_length(0)
            .build()
            .expect("a response builds");
        apply(
            &mut response,
            &headers(&[("Server", "announcer"), ("P-Early-Media", "sendrecv")]),
        );
        assert_eq!(
            response.headers.get_all("Server").map(Vec::len),
            Some(1),
            "one Server, the script's"
        );
        assert_eq!(
            response.headers.get("Server").map(String::as_str),
            Some("announcer")
        );
        assert_eq!(
            response.headers.get("P-Early-Media").map(String::as_str),
            Some("sendrecv")
        );
    }
}
