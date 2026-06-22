//! IP-based Access Control List for transport-level filtering.
//!
//! Checks source IPs against deny and allow CIDR lists before any SIP parsing.
//! Applied at UDP recv and TCP/TLS accept.

use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashSet;
use ipnet::IpNet;

/// Transport-level ACL.
///
/// If `deny_cidrs` is non-empty, any source matching a deny CIDR is blocked.
/// If `allow_cidrs` is non-empty, only sources matching an allow CIDR are permitted.
/// If both are empty (and no APIBAN set), all traffic is allowed.
///
/// When an APIBAN deny set is attached, IPs in that set are blocked before
/// static deny/allow checks.
pub struct TransportAcl {
    deny: Vec<IpNet>,
    allow: Vec<IpNet>,
    apiban_deny: Option<Arc<DashSet<IpAddr>>>,
}

impl TransportAcl {
    pub fn new(deny_cidrs: Vec<String>, allow_cidrs: Vec<String>) -> Self {
        let deny = deny_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();
        let allow = allow_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();
        Self {
            deny,
            allow,
            apiban_deny: None,
        }
    }

    /// Create an ACL with an APIBAN deny set attached.
    pub fn with_apiban(
        deny_cidrs: Vec<String>,
        allow_cidrs: Vec<String>,
        apiban_deny: Arc<DashSet<IpAddr>>,
    ) -> Self {
        let mut acl = Self::new(deny_cidrs, allow_cidrs);
        acl.apiban_deny = Some(apiban_deny);
        acl
    }

    /// Returns `true` if the source IP is permitted.
    pub fn is_allowed(&self, source: IpAddr) -> bool {
        // Runtime auto-ban (failed_auth_ban scanner protection) — O(1) lookup,
        // checked before the static lists like APIBAN. The store exempts
        // trusted_cidrs internally. Process-global (mirrors metrics) rather than an
        // injected field, so this is a no-op until the feature is configured.
        if let Some(ban) = crate::security::auto_ban() {
            if ban.is_banned(source) {
                return false;
            }
        }

        // Check APIBAN blocklist first (O(1) hash lookup)
        if let Some(apiban) = &self.apiban_deny {
            if apiban.contains(&source) {
                return false;
            }
        }

        // Check static deny list
        for cidr in &self.deny {
            if cidr.contains(&source) {
                return false;
            }
        }

        // If allow list is configured, source must match at least one entry
        if !self.allow.is_empty() {
            return self.allow.iter().any(|cidr| cidr.contains(&source));
        }

        true
    }

    /// Whether this ACL has any rules (deny, allow, or APIBAN).
    pub fn has_rules(&self) -> bool {
        !self.deny.is_empty()
            || !self.allow.is_empty()
            || self.apiban_deny.as_ref().is_some_and(|set| !set.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acl_allows_all() {
        let acl = TransportAcl::new(vec![], vec![]);
        assert!(acl.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(acl.is_allowed("::1".parse().unwrap()));
        assert!(!acl.has_rules());
    }

    #[test]
    fn deny_blocks_matching() {
        let acl = TransportAcl::new(
            vec!["10.0.0.0/8".to_string(), "192.168.1.100/32".to_string()],
            vec![],
        );

        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!acl.is_allowed("10.255.255.255".parse().unwrap()));
        assert!(!acl.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(acl.is_allowed("192.168.1.101".parse().unwrap()));
        assert!(acl.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(acl.has_rules());
    }

    #[test]
    fn allow_only_permits_matching() {
        let acl = TransportAcl::new(
            vec![],
            vec!["172.16.0.0/12".to_string()],
        );

        assert!(acl.is_allowed("172.16.0.1".parse().unwrap()));
        assert!(acl.is_allowed("172.31.255.255".parse().unwrap()));
        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!acl.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let acl = TransportAcl::new(
            vec!["10.0.0.1/32".to_string()],
            vec!["10.0.0.0/8".to_string()],
        );

        // 10.0.0.1 is in both deny and allow — deny wins
        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        // 10.0.0.2 is only in allow
        assert!(acl.is_allowed("10.0.0.2".parse().unwrap()));
        // 8.8.8.8 is in neither — blocked by allow list
        assert!(!acl.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ipv6_support() {
        let acl = TransportAcl::new(
            vec!["fd00::/8".to_string()],
            vec![],
        );

        assert!(!acl.is_allowed("fd00::1".parse().unwrap()));
        assert!(acl.is_allowed("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn invalid_cidr_ignored() {
        let acl = TransportAcl::new(
            vec!["not-a-cidr".to_string(), "10.0.0.0/8".to_string()],
            vec![],
        );

        // Invalid CIDR is silently ignored, valid one still works
        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(acl.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn apiban_blocks_listed_ips() {
        let apiban_set = Arc::new(DashSet::new());
        apiban_set.insert("1.2.3.4".parse::<IpAddr>().unwrap());
        apiban_set.insert("5.6.7.8".parse::<IpAddr>().unwrap());

        let acl = TransportAcl::with_apiban(vec![], vec![], apiban_set);

        assert!(!acl.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(!acl.is_allowed("5.6.7.8".parse().unwrap()));
        assert!(acl.is_allowed("9.9.9.9".parse().unwrap()));
        assert!(acl.has_rules());
    }

    #[test]
    fn apiban_empty_set_allows_all() {
        let apiban_set = Arc::new(DashSet::new());
        let acl = TransportAcl::with_apiban(vec![], vec![], apiban_set);

        assert!(acl.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(!acl.has_rules()); // empty set means no active rules
    }

    #[test]
    fn apiban_combined_with_static_deny() {
        let apiban_set = Arc::new(DashSet::new());
        apiban_set.insert("1.2.3.4".parse::<IpAddr>().unwrap());

        let acl = TransportAcl::with_apiban(
            vec!["10.0.0.0/8".to_string()],
            vec![],
            apiban_set,
        );

        // Blocked by APIBAN
        assert!(!acl.is_allowed("1.2.3.4".parse().unwrap()));
        // Blocked by static deny
        assert!(!acl.is_allowed("10.0.0.1".parse().unwrap()));
        // Allowed (neither list)
        assert!(acl.is_allowed("8.8.8.8".parse().unwrap()));
    }
}
