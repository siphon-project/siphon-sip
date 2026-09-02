//! RFC 5626 Outbound flow token encoding/decoding.
//!
//! A flow token encodes a connection identifier into the user part of a Route URI
//! so that requests can be routed back to the correct transport connection.
//!
//! Format: `<connection_id>~<transport>` encoded as hex in the Route URI user part.
//! Example Route: `<sip:466c6f7731~tcp@proxy.example.com;lr;ob>`

use std::fmt;
use std::net::SocketAddr;

/// Hex-encode bytes (no external crate needed).
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex-decode a string to bytes.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// A decoded flow token identifying a specific transport connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowToken {
    /// The remote socket address of the connection.
    pub remote_addr: SocketAddr,
    /// The transport protocol.
    pub transport: String,
}

impl FlowToken {
    pub fn new(remote_addr: SocketAddr, transport: &str) -> Self {
        Self {
            remote_addr,
            transport: transport.to_lowercase(),
        }
    }

    /// Encode the flow token as a hex string for use in a Route URI user part.
    pub fn encode(&self) -> String {
        let raw = format!("{}~{}", self.remote_addr, self.transport);
        hex_encode(raw.as_bytes())
    }

    /// Decode a flow token from a hex-encoded string.
    pub fn decode(encoded: &str) -> Option<Self> {
        let bytes = hex_decode(encoded)?;
        let raw = String::from_utf8(bytes).ok()?;
        let (addr_str, transport) = raw.rsplit_once('~')?;
        let remote_addr = addr_str.parse::<SocketAddr>().ok()?;
        Some(FlowToken {
            remote_addr,
            transport: transport.to_lowercase(),
        })
    }

    /// Build a Route URI containing this flow token.
    ///
    /// Example: `sip:<encoded>@proxy.example.com;lr;ob`
    pub fn to_route_uri(&self, proxy_host: &str) -> String {
        format!("sip:{}@{};lr;ob", self.encode(), proxy_host)
    }

    /// Extract a flow token from a Route URI user part.
    ///
    /// Given `sip:466c6f7731~746370@proxy.example.com;lr;ob`, extracts and decodes
    /// the user part.
    pub fn from_route_uri(uri: &str) -> Option<Self> {
        // Strip sip: prefix
        let rest = uri
            .strip_prefix("sip:")
            .or_else(|| uri.strip_prefix("sips:"))?;
        // Get user part (before @)
        let user = rest.split('@').next()?;
        Self::decode(user)
    }
}

impl fmt::Display for FlowToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "flow[{}~{}]", self.remote_addr, self.transport)
    }
}

/// Check if a SIP message supports RFC 5626 Outbound.
/// Returns true if `Supported` or `Require` contains `outbound`.
pub fn supports_outbound(supported: Option<&str>, require: Option<&str>) -> bool {
    for header_value in [supported, require].iter().flatten() {
        for token in header_value.split(',') {
            if token.trim().eq_ignore_ascii_case("outbound") {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        let addr: SocketAddr = "192.168.1.100:50000".parse().unwrap();
        let token = FlowToken::new(addr, "tcp");
        let encoded = token.encode();
        let decoded = FlowToken::decode(&encoded).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn encode_decode_ipv6() {
        let addr: SocketAddr = "[::1]:5060".parse().unwrap();
        let token = FlowToken::new(addr, "tls");
        let encoded = token.encode();
        let decoded = FlowToken::decode(&encoded).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn decode_invalid_hex() {
        assert!(FlowToken::decode("not-hex!").is_none());
    }

    #[test]
    fn decode_invalid_format() {
        // Valid hex but not a valid flow token
        let encoded = hex_encode(b"just-garbage");
        assert!(FlowToken::decode(&encoded).is_none());
    }

    #[test]
    fn to_route_uri_format() {
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let token = FlowToken::new(addr, "tcp");
        let uri = token.to_route_uri("proxy.example.com");
        assert!(uri.starts_with("sip:"));
        assert!(uri.contains("@proxy.example.com;lr;ob"));
    }

    #[test]
    fn from_route_uri_roundtrip() {
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let token = FlowToken::new(addr, "tcp");
        let uri = token.to_route_uri("proxy.example.com");
        let decoded = FlowToken::from_route_uri(&uri).unwrap();
        assert_eq!(decoded, token);
    }

    #[test]
    fn from_route_uri_invalid() {
        assert!(FlowToken::from_route_uri("sip:normal-user@example.com").is_none());
    }

    #[test]
    fn display_format() {
        let addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let token = FlowToken::new(addr, "tcp");
        assert_eq!(token.to_string(), "flow[10.0.0.1:5060~tcp]");
    }

    #[test]
    fn supports_outbound_detection() {
        assert!(supports_outbound(Some("outbound, path"), None));
        assert!(supports_outbound(None, Some("outbound")));
        assert!(supports_outbound(Some("Outbound"), None));
        assert!(!supports_outbound(Some("path, replaces"), None));
        assert!(!supports_outbound(None, None));
    }
}
