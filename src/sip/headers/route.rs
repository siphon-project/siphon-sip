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

/// One route entry as its parts, each a slice of the text it was written in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParts<'a> {
    /// The display name ahead of the `<`, quoted or not, as written. Empty
    /// when there is none.
    pub display_name: &'a str,
    /// The URI, without angle brackets.
    pub uri: &'a str,
    /// What follows the `>`: the header parameters with their leading `;`, as
    /// written. Empty when there are none.
    pub parameters: &'a str,
}

impl RouteParts<'_> {
    /// The entry as a `name-addr` with its header parameters: the form RFC 3261
    /// §20.34 gives a `Route` value, and §20.30 a `Record-Route` and RFC 3327
    /// §4 a `Path`.
    pub fn to_name_addr(&self) -> String {
        self.with_uri(self.uri)
    }

    /// The same entry around another URI, which the caller has derived from
    /// [`uri`](Self::uri).
    pub fn with_uri(&self, uri: &str) -> String {
        if self.display_name.is_empty() {
            format!("<{uri}>{}", self.parameters)
        } else {
            format!("{} <{uri}>{}", self.display_name, self.parameters)
        }
    }
}

/// Take apart the route entries a script supplied as one string: a bare URI, a
/// URI in angle brackets, a full `name-addr` with or without a display name and
/// header parameters, or several bracketed entries separated by commas, as a
/// received `Route` or `Service-Route` value has them.
///
/// RFC 3261 §20: "If the URI is not enclosed in angle brackets, any
/// semicolon-delimited parameters are header-parameters, not URI parameters."
/// A script that hands over a URI means its parameters to be the URI's, `lr`
/// first among them, so a value with no angle brackets is read whole as one
/// URI, commas and semicolons included. Nothing is re-serialized: every part is
/// a slice of `value`, so a parameter siphon does not know keeps its place and
/// spelling.
///
/// Each URI has to be a complete SIP or SIPS URI (RFC 3261 §19.1.1), the only
/// kind a request can be routed to (§8.1.2). The error names the entry and what
/// is wrong with it.
pub fn route_parts(value: &str) -> Result<Vec<RouteParts<'_>>, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("a route entry is empty".to_string());
    }
    if !value.contains('<') {
        return Ok(vec![RouteParts {
            display_name: "",
            uri: route_uri(value, value)?,
            parameters: "",
        }]);
    }
    split_route_entries(value)
        .into_iter()
        .map(|entry| {
            let malformed = |why: &str| format!("route entry {entry:?} {why}");
            let open = find_unquoted(entry, '<')
                .ok_or_else(|| malformed("has no '<' outside its display name"))?;
            let close = entry[open..]
                .find('>')
                .map(|offset| open + offset)
                .ok_or_else(|| malformed("has no '>' closing its URI"))?;
            let parameters = entry[close + 1..].trim();
            if !parameters.is_empty() && !parameters.starts_with(';') {
                return Err(malformed(
                    "has text after '>' that is not a ';'-separated parameter",
                ));
            }
            Ok(RouteParts {
                display_name: entry[..open].trim(),
                uri: route_uri(entry[open + 1..close].trim(), entry)?,
                parameters,
            })
        })
        .collect()
}

/// The route entries of `value` ([`route_parts`]), each written as a
/// `name-addr`.
pub fn route_name_addrs(value: &str) -> Result<Vec<String>, String> {
    Ok(route_parts(value)?
        .iter()
        .map(RouteParts::to_name_addr)
        .collect())
}

/// `uri` when it is a complete SIP or SIPS URI, as the URI of `entry`.
fn route_uri<'a>(uri: &'a str, entry: &str) -> Result<&'a str, String> {
    let parsed = crate::sip::parser::parse_uri_complete(uri)
        .map_err(|error| format!("route entry {entry:?} is not a URI: {error}"))?;
    if !parsed.scheme.is_sip_family() || parsed.host.is_empty() {
        return Err(format!(
            "route entry {entry:?} is not a SIP or SIPS URI with a host, which is all a request can be routed to"
        ));
    }
    Ok(uri)
}

/// The byte offset of the first `needle` in `input` that is not inside a quoted
/// string (RFC 3261 §25.1 `quoted-string`, where a backslash escapes the next
/// character).
fn find_unquoted(input: &str, needle: char) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in input.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == needle {
            return Some(offset);
        }
    }
    None
}

/// Split a `Route` value at the commas between its entries: those outside angle
/// brackets and outside a quoted display name.
fn split_route_entries(input: &str) -> Vec<&str> {
    let mut entries = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut bracketed = false;
    let mut start = 0;
    for (offset, character) in input.char_indices() {
        match character {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' if !bracketed => quoted = !quoted,
            _ if quoted => {}
            '<' => bracketed = true,
            '>' => bracketed = false,
            ',' if !bracketed => {
                entries.push(input[start..offset].trim());
                start = offset + 1;
            }
            _ => {}
        }
    }
    entries.push(input[start..].trim());
    entries.retain(|entry| !entry.is_empty());
    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_uri_is_one_entry_with_every_parameter_on_the_uri() {
        assert_eq!(
            route_name_addrs("sip:orig@198.51.100.7:5060;lr;odi=abc"),
            Ok(vec!["<sip:orig@198.51.100.7:5060;lr;odi=abc>".to_string()])
        );
        // No angle brackets: a comma is the URI's own (RFC 3261 §25.1 allows
        // one in the user part), not a separator.
        let parts = route_parts(" sips:a,b@edge.example.com;lr ").expect("a URI");
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].uri, "sips:a,b@edge.example.com;lr");
        assert_eq!(parts[0].display_name, "");
        assert_eq!(parts[0].parameters, "");
    }

    #[test]
    fn a_bracketed_uri_and_a_name_addr_are_kept_as_written() {
        assert_eq!(
            route_name_addrs("<sip:198.51.100.7:5060;lr>"),
            Ok(vec!["<sip:198.51.100.7:5060;lr>".to_string()])
        );
        assert_eq!(
            route_name_addrs("\"First, hop <1>\" <sip:198.51.100.7;lr>;hop=1;flag"),
            Ok(vec![
                "\"First, hop <1>\" <sip:198.51.100.7;lr>;hop=1;flag".to_string()
            ])
        );
        assert_eq!(
            route_name_addrs(
                "<sips:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org:6060;transport=tcp;lr>"
            ),
            Ok(vec![
                "<sips:orig@scscf.ims.mnc001.mcc001.3gppnetwork.org:6060;transport=tcp;lr>"
                    .to_string()
            ])
        );
        assert_eq!(
            route_name_addrs("Edge  <sip:[2001:db8::7]:5060;lr>"),
            Ok(vec!["Edge <sip:[2001:db8::7]:5060;lr>".to_string()])
        );
        let parts = route_parts("\"A \\\" quote\" <sip:a.example.com>;x=1").expect("a name-addr");
        assert_eq!(parts[0].display_name, "\"A \\\" quote\"");
        assert_eq!(parts[0].uri, "sip:a.example.com");
        assert_eq!(parts[0].parameters, ";x=1");
    }

    #[test]
    fn a_received_route_value_is_taken_apart_at_its_commas() {
        assert_eq!(
            route_name_addrs(
                "<sip:a.example.com;lr>, \"B, two\" <sip:1,2@b.example.com;lr>;p=q ,<sip:c.example.com>"
            ),
            Ok(vec![
                "<sip:a.example.com;lr>".to_string(),
                "\"B, two\" <sip:1,2@b.example.com;lr>;p=q".to_string(),
                "<sip:c.example.com>".to_string(),
            ])
        );
    }

    #[test]
    fn an_entry_can_be_rebuilt_around_a_derived_uri() {
        let parts = route_parts("Edge <sip:a.example.com>;x=1").expect("a name-addr");
        assert_eq!(
            parts[0].with_uri("sip:a.example.com;lr"),
            "Edge <sip:a.example.com;lr>;x=1"
        );
    }

    #[test]
    fn what_is_not_a_sip_uri_is_refused_with_the_entry_named() {
        for (value, expected) in [
            ("", "is empty"),
            ("   ", "is empty"),
            ("198.51.100.7:5060;lr", "is not a URI"),
            ("sip:", "is not a URI"),
            ("sip:a.example.com garbage", "is not a URI"),
            ("tel:+15550100", "is not a SIP or SIPS URI"),
            ("<urn:service:sos>", "is not a SIP or SIPS URI"),
            ("<sip:a.example.com;lr", "has no '>'"),
            (
                "<sip:a.example.com;lr> trailing",
                "that is not a ';'-separated parameter",
            ),
            ("\"only <a> name\"", "has no '<' outside its display name"),
            ("<sip:a.example.com;lr>, <not a uri>", "is not a URI"),
        ] {
            let error = route_parts(value).expect_err(value);
            assert!(error.contains(expected), "{value:?}: {error}");
        }
        let error = route_parts("<sip:a.example.com;lr>, <not a uri>").expect_err("refused");
        assert!(error.contains("\"<not a uri>\""), "{error}");
    }

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
