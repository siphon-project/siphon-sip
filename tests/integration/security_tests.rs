//! Integration tests for the request-level security filter
//! (`security.rate_limit` + `security.scanner_block` + `security.trusted_cidrs`).
//!
//! These exercise the full path the dispatcher uses: deserialize the YAML
//! `security:` block into [`siphon::config::SecurityConfig`], build a
//! [`siphon::security::SecurityFilter`] from it, parse real SIP requests with
//! [`siphon::sip::parse_sip_message`], extract the `User-Agent` exactly as
//! [`dispatcher::handle_request`] does, and assert the verdict the dispatcher
//! would act on (silent drop vs. allow).

use std::net::IpAddr;

use siphon::config::SecurityConfig;
use siphon::security::{SecurityFilter, SecurityVerdict};
use siphon::sip::parse_sip_message;

/// The `security:` block from the deployment template, as a standalone
/// `SecurityConfig` document (rate_limit + scanner_block + trusted_cidrs +
/// failed_auth_ban + apiban).
const SECURITY_YAML: &str = concat!(
    "rate_limit:\n",
    "  window_secs: 10\n",
    "  max_requests: 30\n",
    "  ban_duration_secs: 3600\n",
    "scanner_block:\n",
    "  user_agents:\n",
    "    - \"sipvicious\"\n",
    "    - \"friendly-scanner\"\n",
    "    - \"VaxSip\"\n",
    "    - \"sipcli\"\n",
    "trusted_cidrs:\n",
    "  - \"10.0.0.0/8\"\n",
    "failed_auth_ban:\n",
    "  threshold: 5\n",
    "  ban_duration_secs: 3600\n",
    "apiban:\n",
    "  api_key: \"test-key-not-a-real-key\"\n",
    "  interval_secs: 900\n",
);

fn deployment_filter() -> std::sync::Arc<SecurityFilter> {
    let config: SecurityConfig =
        siphon::config::yaml::from_str(SECURITY_YAML).expect("security block should deserialize");
    SecurityFilter::from_config(&config).expect("rate_limit + scanner_block => filter installed")
}

/// Build a minimal but well-formed INVITE carrying a given `User-Agent`.
fn invite_with_user_agent(user_agent: &str) -> String {
    format!(
        concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK776asdhds\r\n",
            "Max-Forwards: 70\r\n",
            "From: Alice <sip:alice@example.com>;tag=1928301774\r\n",
            "To: Bob <sip:bob@example.com>\r\n",
            "Call-ID: a84b4c76e66710@host.example.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:alice@host.example.com>\r\n",
            "User-Agent: {}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        user_agent
    )
}

/// INVITE with no `User-Agent` header at all (scanners frequently omit it; a
/// legit endpoint usually sends one but RFC 3261 doesn't require it).
const INVITE_NO_USER_AGENT: &str = concat!(
    "INVITE sip:bob@example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK776asdhds\r\n",
    "Max-Forwards: 70\r\n",
    "From: Alice <sip:alice@example.com>;tag=1928301774\r\n",
    "To: Bob <sip:bob@example.com>\r\n",
    "Call-ID: a84b4c76e66710@host.example.com\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:alice@host.example.com>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// Extract the `User-Agent` exactly as `dispatcher::handle_request` does.
fn user_agent_of(raw: &str) -> Option<String> {
    let (_, message) = parse_sip_message(raw).expect("test SIP message should parse");
    message.headers.get("User-Agent").cloned()
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("valid IP")
}

#[test]
fn scanner_user_agents_from_yaml_are_blocked() {
    let filter = deployment_filter();
    let attacker = ip("203.0.113.50");

    for raw_ua in ["sipvicious", "friendly-scanner", "sipcli/1.8"] {
        let raw = invite_with_user_agent(raw_ua);
        let user_agent = user_agent_of(&raw);
        assert_eq!(
            filter.evaluate(attacker, user_agent.as_deref()),
            SecurityVerdict::Scanner,
            "User-Agent {raw_ua:?} should be blocked",
        );
    }
}

#[test]
fn scanner_match_is_case_insensitive_and_substring() {
    let filter = deployment_filter();
    let attacker = ip("203.0.113.51");

    // "VaxSip" configured; real-world UA is "VaxSIPUserAgent/3.1" — substring,
    // different case. And sipvicious embedded in a spoofed Mozilla UA.
    for raw_ua in ["VaxSIPUserAgent/3.1", "Mozilla/5.0 sipvicious"] {
        let raw = invite_with_user_agent(raw_ua);
        assert_eq!(
            filter.evaluate(attacker, user_agent_of(&raw).as_deref()),
            SecurityVerdict::Scanner,
            "User-Agent {raw_ua:?} should match a scanner signature",
        );
    }
}

#[test]
fn legitimate_user_agent_passes() {
    let filter = deployment_filter();
    let caller = ip("198.51.100.10");
    let raw = invite_with_user_agent("PolycomVVX-VVX_411-UA/5.9.0.0000");
    assert_eq!(
        filter.evaluate(caller, user_agent_of(&raw).as_deref()),
        SecurityVerdict::Allow,
    );
}

#[test]
fn missing_user_agent_is_not_a_scanner() {
    let filter = deployment_filter();
    let caller = ip("198.51.100.11");
    let user_agent = user_agent_of(INVITE_NO_USER_AGENT);
    assert!(user_agent.is_none());
    assert_eq!(
        filter.evaluate(caller, user_agent.as_deref()),
        SecurityVerdict::Allow,
    );
}

#[test]
fn rate_limit_bans_after_max_requests() {
    let filter = deployment_filter();
    let flooder = ip("203.0.113.60");
    // No scanner UA, so only the rate limiter is in play.
    let raw = invite_with_user_agent("Acme-SIP/1.0");
    let user_agent = user_agent_of(&raw);

    // The YAML allows 30 requests per 10s window; 30 quick calls stay inside it.
    for index in 0..30 {
        assert_eq!(
            filter.evaluate(flooder, user_agent.as_deref()),
            SecurityVerdict::Allow,
            "request {index} should be within the limit",
        );
    }
    // The 31st trips the limit and bans the source.
    assert_eq!(
        filter.evaluate(flooder, user_agent.as_deref()),
        SecurityVerdict::RateLimited,
    );
    assert_eq!(filter.rate_limit_bans(), 1);
    // Subsequent requests stay dropped while the ban holds.
    assert_eq!(
        filter.evaluate(flooder, user_agent.as_deref()),
        SecurityVerdict::RateLimited,
    );
}

#[test]
fn trusted_cidr_bypasses_rate_limit_and_scanner() {
    let filter = deployment_filter();
    // 10.0.0.0/8 is in trusted_cidrs (internal AS / monitoring).
    let trusted = ip("10.20.30.40");

    // A scanner UA from a trusted source is still allowed.
    let scanner = invite_with_user_agent("friendly-scanner");
    assert_eq!(
        filter.evaluate(trusted, user_agent_of(&scanner).as_deref()),
        SecurityVerdict::Allow,
    );

    // And it never accrues a rate-limit ban, even well past max_requests.
    let normal = invite_with_user_agent("Acme-SIP/1.0");
    let user_agent = user_agent_of(&normal);
    for _ in 0..100 {
        assert_eq!(
            filter.evaluate(trusted, user_agent.as_deref()),
            SecurityVerdict::Allow,
        );
    }
    assert_eq!(filter.rate_limit_bans(), 0);
}

#[test]
fn filter_is_opt_in_when_neither_rate_limit_nor_scanner_block_set() {
    // Only failed_auth_ban + apiban + trusted_cidrs configured — the request
    // filter must stay off (those are handled by the transport ACL / auto-ban
    // store, not this filter).
    let yaml = concat!(
        "trusted_cidrs:\n",
        "  - \"10.0.0.0/8\"\n",
        "failed_auth_ban:\n",
        "  threshold: 5\n",
        "  ban_duration_secs: 3600\n",
        "apiban:\n",
        "  api_key: \"test-key-not-a-real-key\"\n",
        "  interval_secs: 900\n",
    );
    let config: SecurityConfig = siphon::config::yaml::from_str(yaml).expect("should deserialize");
    assert!(SecurityFilter::from_config(&config).is_none());
}

#[test]
fn scanner_block_only_still_installs_filter() {
    // Just scanner_block, no rate_limit — filter installs, rate limiting is off.
    let yaml = concat!(
        "scanner_block:\n",
        "  user_agents:\n",
        "    - \"sipvicious\"\n",
    );
    let config: SecurityConfig = siphon::config::yaml::from_str(yaml).expect("should deserialize");
    let filter = SecurityFilter::from_config(&config).expect("scanner_block installs the filter");

    let attacker = ip("203.0.113.70");
    let raw = invite_with_user_agent("sipvicious");
    assert_eq!(
        filter.evaluate(attacker, user_agent_of(&raw).as_deref()),
        SecurityVerdict::Scanner,
    );
    // Rate limiting is off, so a flood of non-scanner traffic is allowed.
    let normal = invite_with_user_agent("Acme-SIP/1.0");
    let user_agent = user_agent_of(&normal);
    for _ in 0..1000 {
        assert_eq!(
            filter.evaluate(attacker, user_agent.as_deref()),
            SecurityVerdict::Allow,
        );
    }
    assert_eq!(filter.rate_limit_bans(), 0);
}
