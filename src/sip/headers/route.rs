//! Typed Route and Record-Route headers per RFC 3261 §20.30, §20.34.
//!
//! Wire format: `<sip:proxy1.example.com;lr>, <sip:proxy2.example.com;lr>`
//!
//! Both Route and Record-Route use the same structure: a list of name-addr values.
//! The `lr` (loose-routing) parameter on the URI is significant per RFC 3261 §16.12.

use std::fmt;

use crate::sip::parser::parse_uri_standalone;
use crate::sip::uri::SipUri;

/// A single entry in a Route or Record-Route header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// The SIP URI for this hop.
    pub uri: SipUri,
    /// Additional header-level parameters (after the `>`).
    pub params: Vec<(String, Option<String>)>,
}

impl RouteEntry {
    /// Parse a single route entry: `<sip:proxy.example.com;lr>` or with params.
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();

        let lt_pos = input
            .find('<')
            .ok_or_else(|| format!("Route entry missing '<': {input}"))?;
        // Search for the closing '>' AFTER the '<'. Searching from offset 0 would
        // accept a '>' that precedes the '<', giving a reversed range that panics
        // the slice below (same bug class as the live-confirmed NameAddr DoS).
        let gt_pos = input[lt_pos + 1..]
            .find('>')
            .map(|offset| lt_pos + 1 + offset)
            .ok_or_else(|| format!("Route entry missing '>': {input}"))?;

        let uri_str = &input[lt_pos + 1..gt_pos];
        let uri = parse_uri_standalone(uri_str)?;

        // Parse header-level params after '>'
        let after = input[gt_pos + 1..].trim();
        let mut params = Vec::new();
        if !after.is_empty() {
            for param in after.split(';').filter(|s| !s.trim().is_empty()) {
                let (name, value) = match param.split_once('=') {
                    Some((n, v)) => (n.trim().to_string(), Some(v.trim().to_string())),
                    None => (param.trim().to_string(), None),
                };
                params.push((name, value));
            }
        }

        Ok(RouteEntry { uri, params })
    }

    /// Parse a Route/Record-Route header value containing comma-separated entries.
    pub fn parse_multi(input: &str) -> Result<Vec<RouteEntry>, String> {
        let mut result = Vec::new();
        for part in split_comma_respecting_angles(input) {
            result.push(RouteEntry::parse(part)?);
        }
        Ok(result)
    }

    /// Check if this route entry has the `lr` (loose-routing) URI parameter.
    pub fn is_loose_route(&self) -> bool {
        self.uri.params.iter().any(|(name, _)| name == "lr")
    }
}

impl fmt::Display for RouteEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{}>", self.uri)?;
        for (name, value) in &self.params {
            match value {
                Some(v) => write!(f, ";{name}={v}")?,
                None => write!(f, ";{name}")?,
            }
        }
        Ok(())
    }
}

/// Format a list of route entries as a single header value.
pub fn format_route_header(entries: &[RouteEntry]) -> String {
    entries
        .iter()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Split comma-separated values while respecting angle brackets.
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
    fn parse_single_loose_route() {
        let entry = RouteEntry::parse("<sip:proxy.example.com;lr>").unwrap();
        assert_eq!(entry.uri.host, "proxy.example.com");
        assert!(entry.is_loose_route());
        assert!(entry.params.is_empty());
    }

    #[test]
    fn parse_strict_route() {
        let entry = RouteEntry::parse("<sip:proxy.example.com>").unwrap();
        assert_eq!(entry.uri.host, "proxy.example.com");
        assert!(!entry.is_loose_route());
    }

    #[test]
    fn parse_route_with_port() {
        let entry = RouteEntry::parse("<sip:proxy.example.com:5060;lr>").unwrap();
        assert_eq!(entry.uri.port, Some(5060));
        assert!(entry.is_loose_route());
    }

    #[test]
    fn parse_route_with_transport() {
        let entry = RouteEntry::parse("<sip:proxy.example.com;transport=tcp;lr>").unwrap();
        assert_eq!(entry.uri.get_param("transport"), Some("tcp"));
        assert!(entry.is_loose_route());
    }

    #[test]
    fn parse_multi_route() {
        let input = "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>";
        let entries = RouteEntry::parse_multi(input).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uri.host, "p1.example.com");
        assert_eq!(entries[1].uri.host, "p2.example.com");
        assert!(entries[0].is_loose_route());
        assert!(entries[1].is_loose_route());
    }

    #[test]
    fn parse_multi_three_hops() {
        let input = "<sip:a.com;lr>, <sip:b.com;lr>, <sip:c.com;lr>";
        let entries = RouteEntry::parse_multi(input).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn display_round_trip() {
        let input = "<sip:proxy.example.com:5060;lr>";
        let entry = RouteEntry::parse(input).unwrap();
        let serialized = entry.to_string();
        let reparsed = RouteEntry::parse(&serialized).unwrap();
        assert_eq!(entry.uri.host, reparsed.uri.host);
        assert_eq!(entry.uri.port, reparsed.uri.port);
        assert_eq!(entry.is_loose_route(), reparsed.is_loose_route());
    }

    #[test]
    fn format_route_header_multi() {
        let entries =
            RouteEntry::parse_multi("<sip:p1.example.com;lr>, <sip:p2.example.com;lr>").unwrap();
        let formatted = format_route_header(&entries);
        assert!(formatted.contains("p1.example.com"));
        assert!(formatted.contains("p2.example.com"));
        assert!(formatted.contains(", "));
    }

    #[test]
    fn missing_angle_brackets() {
        assert!(RouteEntry::parse("sip:proxy.example.com;lr").is_err());
    }

    #[test]
    fn route_entry_with_header_params() {
        let entry = RouteEntry::parse("<sip:proxy.example.com;lr>;custom=value").unwrap();
        assert_eq!(entry.params.len(), 1);
        assert_eq!(entry.params[0].0, "custom");
        assert_eq!(entry.params[0].1.as_deref(), Some("value"));
    }

    #[test]
    fn reversed_angle_brackets_do_not_panic() {
        // Regression: a '>' before '<' must NOT panic the `&input[lt_pos+1..gt_pos]`
        // slice. Same bug class as the live-confirmed NameAddr panic, reachable
        // via in-dialog Route/Record-Route (loose_route()). Post-fix the parser is
        // lenient (stray leading '>' swallowed) — the point is it does NOT panic.
        assert!(RouteEntry::parse("><sip:proxy@x.com>").is_ok());
        assert!(RouteEntry::parse_multi("><sip:proxy@x.com>").is_ok());
        // Lone '>' with no '<' → graceful Err, never a panic.
        assert!(RouteEntry::parse(">").is_err());
    }
}
