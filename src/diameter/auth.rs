//! Accept-time peer authentication for the server mode Diameter path.
//!
//! Two Rust-only gates, both enforced **before** any Python callback runs, so a
//! script bug cannot let an unauthenticated peer reach `@diameter.on_request`:
//!
//! 1. **Source-IP ACL** ([`SourceIpAcl`]) — at TCP/SCTP accept, the peer's
//!    source address must fall in a configured CIDR; a miss closes the socket
//!    before a single CER byte is read.
//! 2. **Origin-Host validation** ([`OriginHostPolicy`]) — after the CER is
//!    decoded, the asserted `Origin-Host` must match the value configured for
//!    the matched peer (when one is configured). A mismatch is answered with
//!    `DIAMETER_UNKNOWN_PEER` (3010) and the connection is closed (RFC 6733
//!    §5.2 / §7.1.3.4).

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// Which tenant + peer a source address resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclMatch {
    pub tenant: String,
    pub peer: String,
}

/// Failure parsing an ACL entry from config.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid allowed_ips entry: {0:?}")]
pub struct AclParseError(pub String);

/// Source-IP ACL: an ordered list of `(CIDR, tenant, peer)` scanned
/// first-match. Built from `diameter.tenants.<name>.clients[].allowed_ips`.
///
/// A `HashMap<IpAddr,_>` cannot express CIDR membership, and CER frequency is
/// per-connection (not per-message), so a linear scan over even hundreds of
/// prefixes is negligible.
#[derive(Debug, Default, Clone)]
pub struct SourceIpAcl {
    entries: Vec<(IpNet, String, String)>,
}

impl SourceIpAcl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a parsed CIDR mapping.
    pub fn add(&mut self, net: IpNet, tenant: impl Into<String>, peer: impl Into<String>) {
        self.entries.push((net, tenant.into(), peer.into()));
    }

    /// Add an entry from a config string — either a CIDR (`10.0.0.0/24`) or a
    /// bare address (`172.16.0.1`, treated as a /32 or /128 host route).
    pub fn add_str(&mut self, cidr: &str, tenant: &str, peer: &str) -> Result<(), AclParseError> {
        self.add(parse_cidr(cidr)?, tenant, peer);
        Ok(())
    }

    /// First matching `(tenant, peer)` for `addr`, or `None` if no CIDR
    /// contains it (→ drop the connection).
    pub fn lookup(&self, addr: IpAddr) -> Option<AclMatch> {
        self.entries
            .iter()
            .find(|(net, _, _)| net.contains(&addr))
            .map(|(_, tenant, peer)| AclMatch {
                tenant: tenant.clone(),
                peer: peer.clone(),
            })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Parse a CIDR or bare IP into an [`IpNet`]. A bare address becomes a host
/// route (/32 or /128).
pub fn parse_cidr(value: &str) -> Result<IpNet, AclParseError> {
    if let Ok(net) = value.parse::<IpNet>() {
        return Ok(net);
    }
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Ipv4Net::new(v4, 32)
            .map(IpNet::V4)
            .map_err(|_| AclParseError(value.to_string())),
        Ok(IpAddr::V6(v6)) => Ipv6Net::new(v6, 128)
            .map(IpNet::V6)
            .map_err(|_| AclParseError(value.to_string())),
        Err(_) => Err(AclParseError(value.to_string())),
    }
}

/// Per-peer expected `Origin-Host`. Built from
/// `diameter.tenants.<name>.clients[].expected_origin_host`. Peers without an
/// entry accept whatever they assert (exact match is the security default).
#[derive(Debug, Default, Clone)]
pub struct OriginHostPolicy {
    expected: HashMap<String, String>,
}

impl OriginHostPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, peer: impl Into<String>, expected: impl Into<String>) {
        self.expected.insert(peer.into(), expected.into());
    }

    /// Whether `asserted` is acceptable for `peer`. Unconstrained peers (no
    /// configured expectation) accept any value.
    pub fn validate(&self, peer: &str, asserted: &str) -> bool {
        match self.expected.get(peer) {
            Some(expected) => expected == asserted,
            None => true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.expected.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acl_matches_bare_ip_and_cidr() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("172.16.0.150", "default", "ip-sm-gw").unwrap();
        acl.add_str("10.0.0.0/24", "default", "mme-pool").unwrap();

        assert_eq!(
            acl.lookup("172.16.0.150".parse().unwrap()),
            Some(AclMatch {
                tenant: "default".into(),
                peer: "ip-sm-gw".into()
            })
        );
        assert_eq!(
            acl.lookup("10.0.0.42".parse().unwrap()).unwrap().peer,
            "mme-pool"
        );
        // Outside any prefix → no match (connection dropped).
        assert!(acl.lookup("192.0.2.1".parse().unwrap()).is_none());
        // Just outside the /24.
        assert!(acl.lookup("10.0.1.1".parse().unwrap()).is_none());
    }

    #[test]
    fn acl_matches_ipv6_cidr() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("2001:db8::/32", "v6tenant", "v6peer").unwrap();
        assert_eq!(
            acl.lookup("2001:db8:1234::1".parse().unwrap()).unwrap().tenant,
            "v6tenant"
        );
        assert!(acl.lookup("2001:dead::1".parse().unwrap()).is_none());
    }

    #[test]
    fn acl_first_match_wins() {
        let mut acl = SourceIpAcl::new();
        acl.add_str("10.0.0.0/8", "broad", "broad-peer").unwrap();
        acl.add_str("10.1.0.0/16", "narrow", "narrow-peer").unwrap();
        // 10.1.0.5 falls in both; first entry wins.
        assert_eq!(acl.lookup("10.1.0.5".parse().unwrap()).unwrap().peer, "broad-peer");
    }

    #[test]
    fn acl_rejects_garbage() {
        let mut acl = SourceIpAcl::new();
        assert!(acl.add_str("not-an-ip", "t", "p").is_err());
        assert!(acl.is_empty());
    }

    #[test]
    fn origin_host_exact_match() {
        let mut policy = OriginHostPolicy::new();
        policy.set("mme", "mme.epc.example.org");
        assert!(policy.validate("mme", "mme.epc.example.org"));
        assert!(!policy.validate("mme", "spoofed.example.org"));
        // Unconstrained peer accepts anything.
        assert!(policy.validate("unknown-peer", "whatever.example.org"));
    }
}
