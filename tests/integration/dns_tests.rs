//! Integration tests for DNS resolution (RFC 3263).
//!
//! Focus on the numeric IP fast path and port defaulting logic which do not
//! require real network DNS lookups. The `SipResolver` wraps hickory-resolver
//! and is constructed via `from_system()`.

use std::net::SocketAddr;

use siphon::dns::SipResolver;

#[tokio::test]
async fn numeric_ipv4_with_explicit_port() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("1.2.3.4", Some(5060), "sip", None).await;

    assert_eq!(results.len(), 1);
    let expected: SocketAddr = "1.2.3.4:5060".parse().unwrap();
    assert_eq!(results[0].address, expected);
}

#[tokio::test]
async fn numeric_ipv6_with_explicit_port() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("[::1]", Some(5060), "sip", None).await;

    assert_eq!(results.len(), 1);
    let expected: SocketAddr = "[::1]:5060".parse().unwrap();
    assert_eq!(results[0].address, expected);
}

#[tokio::test]
async fn numeric_ipv6_without_brackets() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("::1", Some(5060), "sip", None).await;

    assert_eq!(results.len(), 1);
    let expected: SocketAddr = "[::1]:5060".parse().unwrap();
    assert_eq!(results[0].address, expected);
}

#[tokio::test]
async fn sip_scheme_defaults_to_port_5060() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("10.0.0.1", None, "sip", None).await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].address.port(), 5060);
    assert_eq!(
        results[0].address,
        "10.0.0.1:5060".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test]
async fn sips_scheme_defaults_to_port_5061() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("10.0.0.1", None, "sips", None).await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].address.port(), 5061);
    assert_eq!(
        results[0].address,
        "10.0.0.1:5061".parse::<SocketAddr>().unwrap()
    );
}

#[tokio::test]
async fn explicit_port_overrides_scheme_default() {
    let resolver = SipResolver::from_system().unwrap();

    // Even with sips scheme (default 5061), explicit port wins
    let results = resolver.resolve("10.0.0.1", Some(9090), "sips", None).await;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].address.port(), 9090);
}

#[tokio::test]
async fn transport_hint_preserved_in_result() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver
        .resolve("192.168.1.1", Some(5060), "sip", Some("tcp"))
        .await;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].transport.as_deref(), Some("tcp"));
}

#[tokio::test]
async fn transport_hint_none_when_not_provided() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("192.168.1.1", Some(5060), "sip", None).await;

    assert_eq!(results.len(), 1);
    assert!(
        results[0].transport.is_none(),
        "transport should be None when no hint is given"
    );
}

#[tokio::test]
async fn bracketed_ipv6_full_address() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver
        .resolve("[2001:db8::1]", Some(5080), "sip", None)
        .await;

    assert_eq!(results.len(), 1);
    let expected: SocketAddr = "[2001:db8::1]:5080".parse().unwrap();
    assert_eq!(results[0].address, expected);
}

#[tokio::test]
async fn nonexistent_domain_returns_empty() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver
        .resolve(
            "this-domain-should-not-exist-xyzzy.invalid",
            None,
            "sip",
            None,
        )
        .await;

    assert!(
        results.is_empty(),
        "unresolvable domain should return empty results"
    );
}

#[tokio::test]
async fn localhost_resolves_to_loopback() {
    let resolver = SipResolver::from_system().unwrap();
    let results = resolver.resolve("localhost", Some(5090), "sip", None).await;

    assert!(!results.is_empty(), "localhost should resolve to at least one address");
    assert_eq!(results[0].address.port(), 5090);
    assert!(
        results[0].address.ip().is_loopback(),
        "localhost should resolve to a loopback address, got {}",
        results[0].address.ip()
    );
}

#[tokio::test]
async fn host_with_explicit_port_skips_srv() {
    // When an explicit port is provided, RFC 3263 says skip SRV and go
    // straight to A/AAAA. For a numeric IP this is the fast path.
    let resolver = SipResolver::from_system().unwrap();

    let results = resolver
        .resolve("192.0.2.1", Some(5070), "sip", Some("udp"))
        .await;

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].address,
        "192.0.2.1:5070".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(results[0].transport.as_deref(), Some("udp"));
}

#[tokio::test]
async fn multiple_resolves_same_resolver() {
    // Verify the resolver can be reused across multiple calls
    let resolver = SipResolver::from_system().unwrap();

    let results1 = resolver.resolve("1.1.1.1", Some(5060), "sip", None).await;
    let results2 = resolver.resolve("2.2.2.2", Some(5061), "sips", None).await;
    let results3 = resolver.resolve("3.3.3.3", None, "sip", Some("tcp")).await;

    assert_eq!(results1.len(), 1);
    assert_eq!(results1[0].address, "1.1.1.1:5060".parse::<SocketAddr>().unwrap());

    assert_eq!(results2.len(), 1);
    assert_eq!(results2[0].address, "2.2.2.2:5061".parse::<SocketAddr>().unwrap());

    assert_eq!(results3.len(), 1);
    assert_eq!(results3[0].address, "3.3.3.3:5060".parse::<SocketAddr>().unwrap());
    assert_eq!(results3[0].transport.as_deref(), Some("tcp"));
}
