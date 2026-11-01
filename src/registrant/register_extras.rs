//! What a script or the YAML config adds to every REGISTER of one entry: extra
//! headers and a MIME body (`registration.add(register_headers=,
//! register_body=)`, `registrant.entries[].register`).
//!
//! The MCPTT client is the user: it carries its service authorisation in an
//! `application/vnd.3gpp.mcptt-info+xml` body of the REGISTER (3GPP TS 24.379
//! clause 7.2.1), and a deployment may need further headers beside it.
//!
//! Which REGISTERs carry it: every one that registers (`Expires` above zero):
//! the initial, the refresh, the answer to a digest or AKA challenge and the
//! protected (sec-agree) re-REGISTER, and the REGISTER of a registration that
//! moved address or was re-registered after a network de-registration (they
//! are all built by the four builders in [`super::messages`] and
//! [`super::protected`]). A de-REGISTER (`Expires: 0`) carries neither: TS
//! 24.379 clause 7.2.1 asks for the body to authorise a service binding, and
//! says nothing of one on removing it, so the de-REGISTER stays the plain
//! RFC 3261 §10.2.2 request.

use crate::sip::builder::SipMessageBuilder;

/// Headers siphon builds itself on a REGISTER, and why a script may not set
/// them. Compared with [`crate::sip::headers::same_header_name`], so a compact
/// form is refused like its long name.
const REGISTER_OWNED: &[(&str, &str)] = &[
    ("Via", "is built per request (RFC 3261 §8.1.1.7)"),
    ("From", "names the registration's AoR (RFC 3261 §10.2)"),
    ("To", "names the registration's AoR (RFC 3261 §10.2)"),
    ("Call-ID", "is one per registration (RFC 3261 §10.2)"),
    ("CSeq", "is numbered by siphon (RFC 3261 §10.2)"),
    (
        "Contact",
        "is the binding siphon registers (RFC 3261 §10.2.1)",
    ),
    (
        "Expires",
        "carries the registration interval (RFC 3261 §10.2.1.1)",
    ),
    ("Max-Forwards", "is a request header siphon manages"),
    ("Route", "is per-hop routing siphon manages"),
    ("Record-Route", "is per-hop routing siphon manages"),
    ("Content-Length", "is computed from the body"),
    (
        "Content-Type",
        "goes with the body: pass it in register_body",
    ),
    (
        "Authorization",
        "answers the registrar's challenge (RFC 3261 §22.4)",
    ),
    (
        "Proxy-Authorization",
        "answers the registrar's challenge (RFC 3261 §22.3)",
    ),
    (
        "Security-Client",
        "is the IPsec offer siphon builds (RFC 3329 §2.3)",
    ),
    (
        "Security-Verify",
        "echoes the P-CSCF's Security-Server (RFC 3329 §2.3)",
    ),
    ("Security-Server", "is a response header (RFC 3329 §2.3)"),
    (
        "Require",
        "carries the option tags siphon negotiates (RFC 3329)",
    ),
    (
        "Proxy-Require",
        "carries the option tags siphon negotiates (RFC 3329)",
    ),
    (
        "Supported",
        "carries the option tags siphon negotiates (RFC 3329)",
    ),
    (
        "Allow",
        "is the method set siphon advertises (RFC 3261 §20.5)",
    ),
    ("User-Agent", "is set by the identity block"),
];

/// Extra headers and a body for every registering REGISTER of an entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterExtras {
    /// `(Content-Type, body bytes)`.
    pub body: Option<(String, Vec<u8>)>,
    /// Extra headers, in the order given.
    pub headers: Vec<(String, String)>,
}

impl RegisterExtras {
    /// Check and build. `Err` names the first problem: a header siphon owns on
    /// a REGISTER, a malformed name or value, or a content type that is not
    /// one.
    pub fn new(
        body: Option<(String, Vec<u8>)>,
        headers: Vec<(String, String)>,
    ) -> Result<Self, String> {
        for (name, value) in &headers {
            crate::b2bua::uas_headers::check_syntax(name, value)?;
            if let Some((_, reason)) = REGISTER_OWNED
                .iter()
                .find(|(owned, _)| crate::sip::headers::same_header_name(owned, name))
            {
                return Err(format!(
                    "{name} cannot be set by register_headers: siphon owns it on a REGISTER, it {reason}"
                ));
            }
        }
        if let Some((content_type, _)) = &body {
            crate::b2bua::uas_headers::check_syntax("Content-Type", content_type)?;
            if !content_type.contains('/') || content_type.trim() != content_type {
                return Err(format!(
                    "register_body content type {content_type:?} is not a MIME type like \"application/vnd.3gpp.mcptt-info+xml\""
                ));
            }
        }
        Ok(Self { body, headers })
    }

    /// Put `extras` on `builder` when the REGISTER registers (`expires` above
    /// zero); see the module docs for why a de-REGISTER is left alone. Run
    /// last, so the body sets the final Content-Length.
    pub fn apply(
        extras: Option<&Self>,
        mut builder: SipMessageBuilder,
        expires: u32,
    ) -> SipMessageBuilder {
        let Some(extras) = extras.filter(|_| expires > 0) else {
            return builder;
        };
        for (name, value) in &extras.headers {
            builder = builder.header(name, value.clone());
        }
        if let Some((content_type, body)) = &extras.body {
            builder = builder
                .content_type(content_type.clone())
                .body(body.clone());
        }
        builder
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
        let extras = RegisterExtras::new(
            Some((
                "application/vnd.3gpp.mcptt-info+xml".into(),
                b"<x/>".to_vec(),
            )),
            headers(&[("P-Preferred-Service", "x")]),
        );
        assert!(extras.is_ok());
    }

    #[test]
    fn every_owned_header_is_refused_whatever_its_case() {
        for (name, _) in REGISTER_OWNED {
            for spelling in [name.to_string(), name.to_ascii_lowercase()] {
                let refused = RegisterExtras::new(None, headers(&[(&spelling, "x")]));
                assert!(refused.is_err(), "{spelling} must be refused");
            }
        }
        for compact in ["v", "f", "t", "i", "m", "l", "c", "k"] {
            assert!(
                RegisterExtras::new(None, headers(&[(compact, "x")])).is_err(),
                "{compact}"
            );
        }
    }

    #[test]
    fn a_line_break_or_a_bad_name_is_refused() {
        assert!(RegisterExtras::new(None, headers(&[("X-A", "a\r\nVia: b")])).is_err());
        assert!(RegisterExtras::new(None, headers(&[("X A", "a")])).is_err());
    }

    #[test]
    fn a_content_type_that_is_not_a_mime_type_is_refused() {
        assert!(RegisterExtras::new(Some(("xml".into(), vec![])), vec![]).is_err());
        assert!(RegisterExtras::new(Some(("text/plain\r\nX: y".into(), vec![])), vec![]).is_err());
    }
}

#[cfg(test)]
#[path = "register_extras_tests.rs"]
mod register_tests;
