//! Typed Via header per RFC 3261 §20.42.
//!
//! Wire format: `SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-xyz;rport;received=10.0.0.1`

use std::fmt;

/// A single Via header value (one hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    /// Transport protocol: "UDP", "TCP", "TLS", "WS", "WSS", "SCTP".
    pub transport: String,
    /// Sent-by host (domain or IP).
    pub host: String,
    /// Sent-by port (None = protocol default).
    pub port: Option<u16>,
    /// Branch parameter (transaction ID). Must start with `z9hG4bK` per RFC 3261.
    pub branch: Option<String>,
    /// `received` parameter — real source IP inserted by next hop.
    pub received: Option<String>,
    /// `rport` parameter — real source port. `Some(None)` = rport present without value,
    /// `Some(Some(port))` = rport with value, `None` = absent.
    pub rport: Option<Option<u16>>,
    /// Additional parameters we don't specifically parse.
    pub other_params: Vec<(String, Option<String>)>,
}

impl Via {
    /// Parse a single Via header value string.
    ///
    /// Example: `SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-abc`
    pub fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();

        // Parse "SIP/2.0/<transport>"
        let rest = input
            .strip_prefix("SIP/2.0/")
            .ok_or_else(|| format!("Via missing SIP/2.0/ prefix: {input}"))?;

        // Transport ends at first whitespace
        let (transport, rest) = rest
            .split_once(|c: char| c.is_ascii_whitespace())
            .ok_or_else(|| format!("Via missing sent-by after transport: {input}"))?;
        let transport = transport.to_uppercase();
        let rest = rest.trim_start();

        // Parse sent-by host[:port] — stops at ';' or end
        let (sent_by, params_str) = match rest.find(';') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => (rest, ""),
        };
        let sent_by = sent_by.trim();

        // Split host:port — careful with IPv6 brackets
        let (host, port) = if sent_by.starts_with('[') {
            // IPv6: [::1]:5060
            match sent_by.find(']') {
                Some(bracket_end) => {
                    let host = &sent_by[..=bracket_end];
                    let after = &sent_by[bracket_end + 1..];
                    let port = if let Some(port_str) = after.strip_prefix(':') {
                        Some(
                            port_str
                                .parse::<u16>()
                                .map_err(|error| format!("Via bad port: {error}"))?,
                        )
                    } else {
                        None
                    };
                    (host.to_string(), port)
                }
                None => return Err(format!("Via unterminated IPv6 bracket: {sent_by}")),
            }
        } else {
            match sent_by.rsplit_once(':') {
                Some((host, port_str)) => {
                    if let Ok(port) = port_str.parse::<u16>() {
                        (host.to_string(), Some(port))
                    } else {
                        // Not a valid port — treat entire thing as host
                        (sent_by.to_string(), None)
                    }
                }
                None => (sent_by.to_string(), None),
            }
        };

        // Parse parameters
        let mut branch = None;
        let mut received = None;
        let mut rport = None;
        let mut other_params = Vec::new();

        if !params_str.is_empty() {
            for param in split_params(params_str) {
                let (name, value) = match param.split_once('=') {
                    Some((name, value)) => {
                        (name.trim().to_lowercase(), Some(value.trim().to_string()))
                    }
                    None => (param.trim().to_lowercase(), None),
                };

                match name.as_str() {
                    "branch" => branch = value,
                    "received" => received = value,
                    "rport" => {
                        rport = Some(match value {
                            Some(v) => Some(
                                v.parse::<u16>()
                                    .map_err(|error| format!("Via bad rport: {error}"))?,
                            ),
                            None => None,
                        });
                    }
                    _ => other_params.push((name, value)),
                }
            }
        }

        Ok(Via {
            transport,
            host,
            port,
            branch,
            received,
            rport,
            other_params,
        })
    }

    /// Parse a Via header that may contain multiple comma-separated values.
    ///
    /// RFC 3261 allows: `Via: SIP/2.0/UDP a.example.com, SIP/2.0/TCP b.example.com`
    pub fn parse_multi(input: &str) -> Result<Vec<Via>, String> {
        let mut result = Vec::new();
        for part in split_comma_values(input) {
            result.push(Via::parse(part)?);
        }
        if result.is_empty() {
            return Err("Via header is empty".to_string());
        }
        Ok(result)
    }
}

impl fmt::Display for Via {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/2.0/{} {}", self.transport, self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(ref branch) = self.branch {
            write!(f, ";branch={branch}")?;
        }
        if let Some(ref received) = self.received {
            write!(f, ";received={received}")?;
        }
        match self.rport {
            Some(Some(port)) => write!(f, ";rport={port}")?,
            Some(None) => write!(f, ";rport")?,
            None => {}
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

/// Split semicolon-delimited params, skipping the leading ';'.
fn split_params(input: &str) -> Vec<&str> {
    input.split(';').filter(|s| !s.trim().is_empty()).collect()
}

/// Split comma-separated Via values, respecting that params use ';' not ','.
fn split_comma_values(input: &str) -> Vec<&str> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_udp_via() {
        let via = Via::parse("SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-abc123").unwrap();
        assert_eq!(via.transport, "UDP");
        assert_eq!(via.host, "192.168.1.1");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK-abc123"));
        assert_eq!(via.received, None);
        assert_eq!(via.rport, None);
    }

    #[test]
    fn parse_tcp_with_domain() {
        let via = Via::parse("SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bKnashds8").unwrap();
        assert_eq!(via.transport, "TCP");
        assert_eq!(via.host, "proxy.example.com");
        assert_eq!(via.port, Some(5060));
        assert_eq!(via.branch.as_deref(), Some("z9hG4bKnashds8"));
    }

    #[test]
    fn parse_tls_no_port() {
        let via = Via::parse("SIP/2.0/TLS sip.example.com;branch=z9hG4bK776asdhds").unwrap();
        assert_eq!(via.transport, "TLS");
        assert_eq!(via.host, "sip.example.com");
        assert_eq!(via.port, None);
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK776asdhds"));
    }

    #[test]
    fn parse_received_and_rport() {
        let via = Via::parse(
            "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc;received=203.0.113.5;rport=12345",
        )
        .unwrap();
        assert_eq!(via.received.as_deref(), Some("203.0.113.5"));
        assert_eq!(via.rport, Some(Some(12345)));
    }

    #[test]
    fn parse_rport_without_value() {
        let via = Via::parse("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc;rport").unwrap();
        assert_eq!(via.rport, Some(None));
    }

    #[test]
    fn parse_ipv6() {
        let via = Via::parse("SIP/2.0/UDP [::1]:5060;branch=z9hG4bK-v6").unwrap();
        assert_eq!(via.host, "[::1]");
        assert_eq!(via.port, Some(5060));
    }

    #[test]
    fn parse_ws_transport() {
        let via = Via::parse("SIP/2.0/WS ws.example.com;branch=z9hG4bKws1").unwrap();
        assert_eq!(via.transport, "WS");
        assert_eq!(via.host, "ws.example.com");
        assert_eq!(via.port, None);
    }

    #[test]
    fn parse_extra_params() {
        let via = Via::parse("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc;maddr=224.0.1.75;ttl=1")
            .unwrap();
        assert_eq!(via.other_params.len(), 2);
        assert_eq!(
            via.other_params[0],
            ("maddr".to_string(), Some("224.0.1.75".to_string()))
        );
        assert_eq!(
            via.other_params[1],
            ("ttl".to_string(), Some("1".to_string()))
        );
    }

    #[test]
    fn parse_multi_comma_separated() {
        let input = "SIP/2.0/UDP first.example.com;branch=z9hG4bK-1, SIP/2.0/TCP second.example.com:5060;branch=z9hG4bK-2";
        let vias = Via::parse_multi(input).unwrap();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0].host, "first.example.com");
        assert_eq!(vias[0].transport, "UDP");
        assert_eq!(vias[1].host, "second.example.com");
        assert_eq!(vias[1].transport, "TCP");
        assert_eq!(vias[1].port, Some(5060));
    }

    #[test]
    fn display_round_trip() {
        let input = "SIP/2.0/UDP 192.168.1.1:5060;branch=z9hG4bK-abc;received=10.0.0.1;rport=12345";
        let via = Via::parse(input).unwrap();
        let serialized = via.to_string();
        let reparsed = Via::parse(&serialized).unwrap();
        assert_eq!(via, reparsed);
    }

    #[test]
    fn display_rport_no_value() {
        let via = Via::parse("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-abc;rport").unwrap();
        let s = via.to_string();
        assert!(s.contains(";rport"));
        assert!(!s.contains(";rport="));
    }

    #[test]
    fn reject_missing_prefix() {
        assert!(Via::parse("HTTP/1.1 example.com").is_err());
    }

    #[test]
    fn case_insensitive_transport() {
        let via = Via::parse("SIP/2.0/udp 10.0.0.1:5060;branch=z9hG4bK-lc").unwrap();
        assert_eq!(via.transport, "UDP");
    }

    #[test]
    fn case_insensitive_params() {
        let via =
            Via::parse("SIP/2.0/UDP 10.0.0.1:5060;Branch=z9hG4bK-ci;Received=1.2.3.4").unwrap();
        assert_eq!(via.branch.as_deref(), Some("z9hG4bK-ci"));
        assert_eq!(via.received.as_deref(), Some("1.2.3.4"));
    }
}
