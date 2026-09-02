//! Refer-To (RFC 3515) and Replaces (RFC 3891) header parsing.
//!
//! Refer-To contains a URI (possibly with an embedded Replaces parameter):
//!   `Refer-To: <sip:bob@example.com?Replaces=call-id%3Bfrom-tag%3Dabc%3Bto-tag%3Dxyz>`
//!
//! Replaces is a standalone header:
//!   `Replaces: call-id;from-tag=abc;to-tag=xyz`

use std::fmt;

/// Parsed Refer-To header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferTo {
    /// The target URI for the transfer.
    pub uri: String,
    /// Embedded Replaces information (for attended transfer).
    pub replaces: Option<Replaces>,
}

/// Parsed Replaces header value (RFC 3891).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaces {
    /// Call-ID of the dialog to replace.
    pub call_id: String,
    /// From-tag of the dialog to replace.
    pub from_tag: String,
    /// To-tag of the dialog to replace.
    pub to_tag: String,
    /// Whether early dialogs should be matched (early-only parameter).
    pub early_only: bool,
}

impl fmt::Display for Replaces {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{};from-tag={};to-tag={}",
            self.call_id, self.from_tag, self.to_tag
        )?;
        if self.early_only {
            write!(formatter, ";early-only")?;
        }
        Ok(())
    }
}

impl fmt::Display for ReferTo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(replaces) = &self.replaces {
            let encoded_replaces = url_encode_replaces(replaces);
            write!(formatter, "<{}?Replaces={}>", self.uri, encoded_replaces)
        } else {
            write!(formatter, "<{}>", self.uri)
        }
    }
}

/// Parse a Refer-To header value.
///
/// Handles both bare URIs and angle-bracket-quoted URIs:
///   `<sip:bob@example.com>`
///   `sip:bob@example.com`
///   `<sip:bob@example.com?Replaces=...>`
pub fn parse_refer_to(input: &str) -> Result<ReferTo, String> {
    let input = input.trim();

    // Extract URI from angle brackets if present
    let uri_str = if input.starts_with('<') {
        let end = input
            .find('>')
            .ok_or_else(|| "Refer-To: missing closing '>'".to_string())?;
        &input[1..end]
    } else {
        // Bare URI — take until whitespace or end
        input.split_whitespace().next().unwrap_or(input)
    };

    // Check for embedded Replaces in URI headers (after ?)
    if let Some(query_start) = uri_str.find('?') {
        let base_uri = &uri_str[..query_start];
        let query = &uri_str[query_start + 1..];

        // Look for Replaces= in the URI headers
        let mut replaces = None;
        for param in query.split('&') {
            if let Some(value) = param
                .strip_prefix("Replaces=")
                .or_else(|| param.strip_prefix("replaces="))
            {
                let decoded = url_decode(value);
                replaces = Some(parse_replaces_value(&decoded)?);
            }
        }

        Ok(ReferTo {
            uri: base_uri.to_string(),
            replaces,
        })
    } else {
        Ok(ReferTo {
            uri: uri_str.to_string(),
            replaces: None,
        })
    }
}

/// Parse a standalone Replaces header value.
///
/// Format: `call-id;from-tag=abc;to-tag=xyz[;early-only]`
pub fn parse_replaces(input: &str) -> Result<Replaces, String> {
    parse_replaces_value(input.trim())
}

/// Internal parser for Replaces value (used by both standalone and embedded).
fn parse_replaces_value(input: &str) -> Result<Replaces, String> {
    let input = input.trim();

    // Split on ';' — first part is call-id, rest are parameters
    let mut parts = input.split(';');
    let call_id = parts
        .next()
        .ok_or_else(|| "Replaces: empty value".to_string())?
        .trim()
        .to_string();

    if call_id.is_empty() {
        return Err("Replaces: empty call-id".to_string());
    }

    let mut from_tag = None;
    let mut to_tag = None;
    let mut early_only = false;

    for param in parts {
        let param = param.trim();
        if let Some(value) = param.strip_prefix("from-tag=") {
            from_tag = Some(value.to_string());
        } else if let Some(value) = param.strip_prefix("to-tag=") {
            to_tag = Some(value.to_string());
        } else if param == "early-only" {
            early_only = true;
        }
    }

    Ok(Replaces {
        call_id,
        from_tag: from_tag.ok_or_else(|| "Replaces: missing from-tag".to_string())?,
        to_tag: to_tag.ok_or_else(|| "Replaces: missing to-tag".to_string())?,
        early_only,
    })
}

/// URL-decode a string (percent-decoding).
fn url_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(character) = chars.next() {
        if character == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if hex.len() == 2 {
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else {
            result.push(character);
        }
    }
    result
}

/// URL-encode a Replaces value for embedding in a Refer-To URI.
fn url_encode_replaces(replaces: &Replaces) -> String {
    let raw = replaces.to_string();
    raw.replace(';', "%3B").replace('=', "%3D")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Refer-To parsing ----

    #[test]
    fn parse_simple_refer_to() {
        let result = parse_refer_to("<sip:bob@example.com>").unwrap();
        assert_eq!(result.uri, "sip:bob@example.com");
        assert!(result.replaces.is_none());
    }

    #[test]
    fn parse_refer_to_bare_uri() {
        let result = parse_refer_to("sip:bob@example.com").unwrap();
        assert_eq!(result.uri, "sip:bob@example.com");
        assert!(result.replaces.is_none());
    }

    #[test]
    fn parse_refer_to_with_port() {
        let result = parse_refer_to("<sip:bob@example.com:5060>").unwrap();
        assert_eq!(result.uri, "sip:bob@example.com:5060");
        assert!(result.replaces.is_none());
    }

    #[test]
    fn parse_refer_to_sips() {
        let result = parse_refer_to("<sips:alice@secure.example.com>").unwrap();
        assert_eq!(result.uri, "sips:alice@secure.example.com");
    }

    #[test]
    fn parse_refer_to_with_replaces() {
        let input = "<sip:bob@example.com?Replaces=call-123%3Bfrom-tag%3Dabc%3Bto-tag%3Dxyz>";
        let result = parse_refer_to(input).unwrap();
        assert_eq!(result.uri, "sip:bob@example.com");
        let replaces = result.replaces.unwrap();
        assert_eq!(replaces.call_id, "call-123");
        assert_eq!(replaces.from_tag, "abc");
        assert_eq!(replaces.to_tag, "xyz");
        assert!(!replaces.early_only);
    }

    #[test]
    fn parse_refer_to_with_replaces_at_sign() {
        // Call-IDs often contain @ signs
        let input =
            "<sip:bob@example.com?Replaces=call-123%40host.com%3Bfrom-tag%3Dabc%3Bto-tag%3Dxyz>";
        let result = parse_refer_to(input).unwrap();
        let replaces = result.replaces.unwrap();
        assert_eq!(replaces.call_id, "call-123@host.com");
        assert_eq!(replaces.from_tag, "abc");
        assert_eq!(replaces.to_tag, "xyz");
    }

    #[test]
    fn parse_refer_to_with_replaces_early_only() {
        let input =
            "<sip:bob@example.com?Replaces=call-1%3Bfrom-tag%3Da%3Bto-tag%3Db%3Bearly-only>";
        let result = parse_refer_to(input).unwrap();
        let replaces = result.replaces.unwrap();
        assert!(replaces.early_only);
    }

    #[test]
    fn parse_refer_to_missing_closing_bracket() {
        assert!(parse_refer_to("<sip:bob@example.com").is_err());
    }

    #[test]
    fn parse_refer_to_with_whitespace() {
        let result = parse_refer_to("  <sip:bob@example.com>  ").unwrap();
        assert_eq!(result.uri, "sip:bob@example.com");
    }

    #[test]
    fn parse_refer_to_with_other_uri_headers() {
        // Replaces not present, other URI headers should be ignored
        let input = "<sip:bob@example.com?Subject=hello>";
        let result = parse_refer_to(input).unwrap();
        assert_eq!(result.uri, "sip:bob@example.com");
        assert!(result.replaces.is_none());
    }

    #[test]
    fn parse_refer_to_case_insensitive_replaces() {
        let input = "<sip:bob@example.com?replaces=call-1%3Bfrom-tag%3Da%3Bto-tag%3Db>";
        let result = parse_refer_to(input).unwrap();
        assert!(result.replaces.is_some());
    }

    // ---- Replaces header parsing ----

    #[test]
    fn parse_replaces_basic() {
        let result = parse_replaces("call-id-123;from-tag=abc;to-tag=xyz").unwrap();
        assert_eq!(result.call_id, "call-id-123");
        assert_eq!(result.from_tag, "abc");
        assert_eq!(result.to_tag, "xyz");
        assert!(!result.early_only);
    }

    #[test]
    fn parse_replaces_with_at_sign() {
        let result = parse_replaces("12345@192.168.1.1;from-tag=tag-a;to-tag=tag-b").unwrap();
        assert_eq!(result.call_id, "12345@192.168.1.1");
        assert_eq!(result.from_tag, "tag-a");
        assert_eq!(result.to_tag, "tag-b");
    }

    #[test]
    fn parse_replaces_with_early_only() {
        let result = parse_replaces("callid;from-tag=f;to-tag=t;early-only").unwrap();
        assert!(result.early_only);
    }

    #[test]
    fn parse_replaces_extra_whitespace() {
        let result = parse_replaces("  callid ; from-tag=f ; to-tag=t  ").unwrap();
        assert_eq!(result.call_id, "callid");
        assert_eq!(result.from_tag, "f");
        assert_eq!(result.to_tag, "t");
    }

    #[test]
    fn parse_replaces_missing_from_tag() {
        assert!(parse_replaces("callid;to-tag=t").is_err());
    }

    #[test]
    fn parse_replaces_missing_to_tag() {
        assert!(parse_replaces("callid;from-tag=f").is_err());
    }

    #[test]
    fn parse_replaces_empty() {
        assert!(parse_replaces("").is_err());
    }

    #[test]
    fn parse_replaces_only_semicolons() {
        assert!(parse_replaces(";;;").is_err());
    }

    // ---- Display / round-trip ----

    #[test]
    fn replaces_display() {
        let replaces = Replaces {
            call_id: "abc@host".to_string(),
            from_tag: "ftag".to_string(),
            to_tag: "ttag".to_string(),
            early_only: false,
        };
        assert_eq!(replaces.to_string(), "abc@host;from-tag=ftag;to-tag=ttag");
    }

    #[test]
    fn replaces_display_early_only() {
        let replaces = Replaces {
            call_id: "abc".to_string(),
            from_tag: "f".to_string(),
            to_tag: "t".to_string(),
            early_only: true,
        };
        assert_eq!(replaces.to_string(), "abc;from-tag=f;to-tag=t;early-only");
    }

    #[test]
    fn replaces_round_trip() {
        let original = Replaces {
            call_id: "call-99@sip.example.com".to_string(),
            from_tag: "alpha".to_string(),
            to_tag: "beta".to_string(),
            early_only: false,
        };
        let serialized = original.to_string();
        let parsed = parse_replaces(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn refer_to_display_without_replaces() {
        let refer_to = ReferTo {
            uri: "sip:bob@example.com".to_string(),
            replaces: None,
        };
        assert_eq!(refer_to.to_string(), "<sip:bob@example.com>");
    }

    #[test]
    fn refer_to_display_with_replaces() {
        let refer_to = ReferTo {
            uri: "sip:bob@example.com".to_string(),
            replaces: Some(Replaces {
                call_id: "call-1".to_string(),
                from_tag: "a".to_string(),
                to_tag: "b".to_string(),
                early_only: false,
            }),
        };
        let display = refer_to.to_string();
        assert!(display.starts_with("<sip:bob@example.com?Replaces="));
        assert!(display.ends_with('>'));
        // URL-encoded semicolons and equals
        assert!(display.contains("%3B"));
        assert!(display.contains("%3D"));
    }

    #[test]
    fn refer_to_round_trip_with_replaces() {
        let original = ReferTo {
            uri: "sip:bob@example.com".to_string(),
            replaces: Some(Replaces {
                call_id: "call-42@host.com".to_string(),
                from_tag: "sender".to_string(),
                to_tag: "receiver".to_string(),
                early_only: false,
            }),
        };
        let serialized = original.to_string();
        let parsed = parse_refer_to(&serialized).unwrap();
        assert_eq!(original, parsed);
    }

    // ---- URL encoding/decoding ----

    #[test]
    fn url_decode_basic() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("a%3Bb%3Dc"), "a;b=c");
        assert_eq!(url_decode("no-encoding"), "no-encoding");
    }

    #[test]
    fn url_decode_at_sign() {
        assert_eq!(url_decode("user%40host"), "user@host");
    }

    #[test]
    fn url_decode_incomplete_percent() {
        // Graceful handling of truncated percent encoding
        assert_eq!(url_decode("test%2"), "test%2");
        assert_eq!(url_decode("test%"), "test%");
    }

    #[test]
    fn url_encode_replaces_round_trip() {
        let replaces = Replaces {
            call_id: "abc@host".to_string(),
            from_tag: "f1".to_string(),
            to_tag: "t1".to_string(),
            early_only: false,
        };
        let encoded = url_encode_replaces(&replaces);
        let decoded = url_decode(&encoded);
        let parsed = parse_replaces_value(&decoded).unwrap();
        assert_eq!(replaces, parsed);
    }
}
