//! Typed Name-Addr header for From, To, and Contact per RFC 3261 §20.10, §20.20, §20.39.
//!
//! Wire formats:
//! - `"Alice" <sip:alice@example.com>;tag=1928301774`
//! - `sip:bob@biloxi.com`
//! - `<sip:carol@chicago.com>;q=0.7;expires=3600`

use std::fmt;

use crate::sip::parser::parse_uri_standalone;
use crate::sip::uri::SipUri;

/// A parsed From, To, or Contact header value.
#[derive(Debug, Clone, PartialEq)]
pub struct NameAddr {
    /// Display name (the quoted part before angle brackets). May be empty.
    pub display_name: Option<String>,
    /// The SIP URI.
    pub uri: SipUri,
    /// `tag` parameter (From/To).
    pub tag: Option<String>,
    /// `q` parameter (Contact). Quality value 0.0–1.0.
    pub q: Option<f32>,
    /// `expires` parameter (Contact). Seconds.
    pub expires: Option<u32>,
    /// Additional header-level parameters we don't specifically parse.
    pub other_params: Vec<(String, Option<String>)>,
}

impl NameAddr {
    /// Parse a single From/To/Contact value.
    ///
    /// Handles both `"Display" <uri>;params` and bare `uri;params` forms.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();

        let (display_name, uri_str, params_str) = if let Some(lt_pos) = input.find('<') {
            // Angle-bracket form: optional display name before '<'
            let display = input[..lt_pos].trim();
            let display_name = if display.is_empty() {
                None
            } else {
                // Strip surrounding quotes if present
                Some(strip_quotes(display).to_string())
            };

            // Search for the closing '>' AFTER the '<'. Searching from offset 0
            // would find a '>' that precedes the '<' (e.g. inside a quoted display
            // name, or a malicious `From: ><sip:a@b>`), giving a reversed range
            // that panics the slice below. (Live-confirmed unauthenticated DoS.)
            let gt_pos = input[lt_pos + 1..]
                .find('>')
                .map(|offset| lt_pos + 1 + offset)
                .ok_or_else(|| format!("NameAddr missing '>': {input}"))?;
            let uri_str = &input[lt_pos + 1..gt_pos];
            let params_str = input[gt_pos + 1..].trim();
            (display_name, uri_str, params_str)
        } else {
            // Bare URI form: sip:user@host;tag=xxx
            // URI params use ';' and header params also use ';' — we need to separate them.
            // The trick: URI params are part of the URI (before any header-level params like tag/q/expires).
            // For bare URIs, tag/q/expires are header params, not URI params.
            // We parse the entire thing as a URI first, then pull out header params from the URI params.
            (None, input, "")
        };

        // Parse the URI
        let uri = parse_uri_standalone(uri_str)
            .map_err(|error| format!("NameAddr bad URI '{uri_str}': {error}"))?;

        // Parse header-level parameters
        let mut tag = None;
        let mut q = None;
        let mut expires = None;
        let mut other_params = Vec::new();

        // If we had angle brackets, params_str contains header params.
        // If bare URI, we need to check if the URI's own params contain tag/q/expires
        // and pull them out as header params.
        if params_str.is_empty() && display_name.is_none() {
            // Bare URI form — move tag/q/expires from URI params to header params
            let mut uri_clean = uri.clone();
            let mut kept_params = Vec::new();
            for (name, value) in &uri.params {
                match name.to_lowercase().as_str() {
                    "tag" => tag = value.clone(),
                    "q" => {
                        q = value.as_ref().and_then(|v| v.parse::<f32>().ok());
                    }
                    "expires" => {
                        expires = value.as_ref().and_then(|v| v.parse::<u32>().ok());
                    }
                    _ => kept_params.push((name.clone(), value.clone())),
                }
            }
            uri_clean.params = kept_params;
            return Ok(NameAddr {
                display_name: None,
                uri: uri_clean,
                tag,
                q,
                expires,
                other_params,
            });
        }

        // Parse semicolon-separated params from params_str
        for param in params_str.split(';').filter(|s| !s.trim().is_empty()) {
            let (name, value) = match param.split_once('=') {
                Some((n, v)) => (n.trim().to_lowercase(), Some(v.trim().to_string())),
                None => (param.trim().to_lowercase(), None),
            };
            match name.as_str() {
                "tag" => tag = value,
                "q" => {
                    q = value.as_ref().and_then(|v| v.parse::<f32>().ok());
                }
                "expires" => {
                    expires = value.as_ref().and_then(|v| v.parse::<u32>().ok());
                }
                _ => other_params.push((name, value)),
            }
        }

        Ok(NameAddr {
            display_name,
            uri,
            tag,
            q,
            expires,
            other_params,
        })
    }

    /// Parse a header value that may contain multiple comma-separated name-addr values.
    /// Used for Contact headers that list multiple bindings.
    pub fn parse_multi(input: &str) -> Result<Vec<NameAddr>, String> {
        // Handle wildcard Contact: *
        if input.trim() == "*" {
            return Ok(Vec::new());
        }

        let mut result = Vec::new();
        for part in split_comma_respecting_angles(input) {
            result.push(NameAddr::parse(part)?);
        }
        Ok(result)
    }
}

impl fmt::Display for NameAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref display_name) = self.display_name {
            write!(f, "\"{display_name}\" ")?;
        }
        write!(f, "<{}>", self.uri)?;
        if let Some(ref tag) = self.tag {
            write!(f, ";tag={tag}")?;
        }
        if let Some(q) = self.q {
            write!(f, ";q={q}")?;
        }
        if let Some(expires) = self.expires {
            write!(f, ";expires={expires}")?;
        }
        for (name, value) in &self.other_params {
            match value {
                Some(v) => write!(f, ";{name}={v}")?,
                None => write!(f, ";{name}")?,
            }
        }
        Ok(())
    }
}

/// Strip surrounding double-quotes from a string.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(s)
}

/// Split comma-separated values while respecting angle brackets.
/// `"A" <sip:a@x>;tag=1, "B" <sip:b@y>;tag=2` → two parts.
fn split_comma_respecting_angles(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;

    for (i, c) in input.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let part = input[start..i].trim();
                if !part.is_empty() {
                    parts.push(part);
                }
                start = i + 1;
            }
            _ => {}
        }
    }

    let last = input[start..].trim();
    if !last.is_empty() {
        parts.push(last);
    }

    parts
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_display_name_and_tag() {
        let na = NameAddr::parse("\"Alice\" <sip:alice@atlanta.com>;tag=1928301774").unwrap();
        assert_eq!(na.display_name.as_deref(), Some("Alice"));
        assert_eq!(na.uri.user.as_deref(), Some("alice"));
        assert_eq!(na.uri.host, "atlanta.com");
        assert_eq!(na.tag.as_deref(), Some("1928301774"));
    }

    #[test]
    fn parse_no_display_name() {
        let na = NameAddr::parse("<sip:bob@biloxi.com>;tag=a6c85cf").unwrap();
        assert_eq!(na.display_name, None);
        assert_eq!(na.uri.user.as_deref(), Some("bob"));
        assert_eq!(na.tag.as_deref(), Some("a6c85cf"));
    }

    #[test]
    fn parse_bare_uri_with_tag() {
        let na = NameAddr::parse("sip:carol@chicago.com;tag=xyz").unwrap();
        assert_eq!(na.display_name, None);
        assert_eq!(na.uri.user.as_deref(), Some("carol"));
        assert_eq!(na.uri.host, "chicago.com");
        assert_eq!(na.tag.as_deref(), Some("xyz"));
        // tag should NOT be in URI params
        assert!(na.uri.params.is_empty());
    }

    #[test]
    fn parse_contact_with_q_and_expires() {
        let na = NameAddr::parse("<sip:alice@10.0.0.1:5060>;q=0.7;expires=3600").unwrap();
        assert_eq!(na.q, Some(0.7));
        assert_eq!(na.expires, Some(3600));
        assert_eq!(na.uri.port, Some(5060));
    }

    #[test]
    fn parse_contact_bare_uri_q_expires() {
        let na = NameAddr::parse("sip:alice@10.0.0.1:5060;q=0.8;expires=1800").unwrap();
        assert_eq!(na.q, Some(0.8));
        assert_eq!(na.expires, Some(1800));
    }

    #[test]
    fn parse_uri_with_transport_param() {
        let na = NameAddr::parse("<sip:alice@example.com;transport=tcp>;tag=abc").unwrap();
        assert_eq!(na.uri.get_param("transport"), Some("tcp"));
        assert_eq!(na.tag.as_deref(), Some("abc"));
    }

    #[test]
    fn parse_multi_contacts() {
        let input = "\"Alice\" <sip:alice@a.com>;q=0.9, <sip:bob@b.com>;q=0.5;expires=600";
        let contacts = NameAddr::parse_multi(input).unwrap();
        assert_eq!(contacts.len(), 2);
        assert_eq!(contacts[0].display_name.as_deref(), Some("Alice"));
        assert_eq!(contacts[0].q, Some(0.9));
        assert_eq!(contacts[1].uri.user.as_deref(), Some("bob"));
        assert_eq!(contacts[1].q, Some(0.5));
        assert_eq!(contacts[1].expires, Some(600));
    }

    #[test]
    fn parse_wildcard_contact() {
        let contacts = NameAddr::parse_multi("*").unwrap();
        assert!(contacts.is_empty());
    }

    #[test]
    fn display_round_trip_angle_bracket() {
        let input = "\"Alice\" <sip:alice@atlanta.com>;tag=1928301774";
        let na = NameAddr::parse(input).unwrap();
        let serialized = na.to_string();
        let reparsed = NameAddr::parse(&serialized).unwrap();
        assert_eq!(na.display_name, reparsed.display_name);
        assert_eq!(na.uri.user, reparsed.uri.user);
        assert_eq!(na.uri.host, reparsed.uri.host);
        assert_eq!(na.tag, reparsed.tag);
    }

    #[test]
    fn display_contact_with_params() {
        let na = NameAddr::parse("<sip:alice@10.0.0.1:5060>;q=0.7;expires=3600").unwrap();
        let s = na.to_string();
        assert!(s.contains(";q=0.7"));
        assert!(s.contains(";expires=3600"));
    }

    #[test]
    fn missing_angle_bracket_close() {
        assert!(NameAddr::parse("\"Alice\" <sip:alice@x.com").is_err());
    }

    #[test]
    fn unquoted_display_name() {
        let na = NameAddr::parse("Bob Smith <sip:bob@biloxi.com>;tag=abc").unwrap();
        assert_eq!(na.display_name.as_deref(), Some("Bob Smith"));
    }

    #[test]
    fn tel_uri_with_tag() {
        let na = NameAddr::parse(
            "<tel:8367;phone-context=ims.mnc001.mcc001.3gppnetwork.org>;tag=0TleWIZ",
        )
        .unwrap();
        assert_eq!(na.uri.scheme, "tel");
        assert_eq!(na.uri.user.as_deref(), Some("8367"));
        assert_eq!(na.tag.as_deref(), Some("0TleWIZ"));
    }

    #[test]
    fn tel_uri_global_with_tag() {
        let na = NameAddr::parse("<tel:+15551234567>;tag=abc123").unwrap();
        assert_eq!(na.uri.scheme, "tel");
        assert_eq!(na.uri.user.as_deref(), Some("+15551234567"));
        assert_eq!(na.tag.as_deref(), Some("abc123"));
    }

    #[test]
    fn reversed_angle_brackets_do_not_panic() {
        // Regression: a '>' appearing before the first '<' must NOT panic the
        // `&input[lt_pos+1..gt_pos]` slice (reversed range). Live-confirmed DoS:
        // `From: ><sip:a@b>` panicked at nameaddr.rs:50
        // ("byte range starts at 2 but ends at 0") and dropped the request.
        // Post-fix the parser is lenient: the stray leading '>' is swallowed and
        // the bracketed URI still parses — the point is it does NOT panic.
        let poisoned = NameAddr::parse("><sip:audit@example.com>;tag=poc1").unwrap();
        assert_eq!(poisoned.uri.user.as_deref(), Some("audit"));
        assert_eq!(poisoned.tag.as_deref(), Some("poc1"));
        assert!(NameAddr::parse("><sip:alice@atlanta.com>").is_ok());
        // Lone '>' with no '<' at all → bare-URI form → rejected as a bad URI
        // (a graceful Err, never a panic).
        assert!(NameAddr::parse(">").is_err());
    }

    #[test]
    fn reversed_angle_brackets_multi_do_not_panic() {
        // Same class via the Contact multi-value path used by registrar.save().
        assert!(NameAddr::parse_multi("><sip:a@b>").is_ok());
    }

    #[test]
    fn gt_inside_quoted_display_name_parses() {
        // A '>' inside the quoted display name (before the real '<') is legal and
        // must resolve to the actual closing bracket, not the inner '>'.
        let na = NameAddr::parse("\"a>b\" <sip:alice@atlanta.com>;tag=1").unwrap();
        assert_eq!(na.uri.user.as_deref(), Some("alice"));
        assert_eq!(na.tag.as_deref(), Some("1"));
    }
}
