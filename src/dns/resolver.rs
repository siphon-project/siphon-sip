//! SIP-aware DNS resolver implementing RFC 3263 server location.

use std::net::{IpAddr, SocketAddr};
use hickory_resolver::TokioResolver;
use tracing::{debug, warn};

use crate::sip::uri::strip_ipv6_brackets;

/// A resolved SIP target: address + transport hint from SRV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTarget {
    pub address: SocketAddr,
    pub transport: Option<String>,
}

/// SIP DNS resolver (RFC 3263).
///
/// Wraps a `hickory-resolver` async resolver. Constructed once at startup and
/// shared across the dispatcher via `Arc`.
#[derive(Clone)]
pub struct SipResolver {
    resolver: TokioResolver,
}

impl SipResolver {
    /// Create a resolver using system DNS configuration.
    pub fn from_system() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = TokioResolver::builder_tokio()?.build();
        Ok(Self { resolver })
    }

    /// Resolve a SIP target to one or more socket addresses.
    ///
    /// Follows RFC 3263 procedure:
    /// - Numeric IP → direct use
    /// - Explicit port → A/AAAA lookup only (SRV records define their own port)
    /// - No port → SRV lookup first, fallback to A/AAAA on default port 5060/5061
    pub async fn resolve(
        &self,
        host: &str,
        port: Option<u16>,
        scheme: &str,
        transport_hint: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        // Strip brackets from IPv6 addresses (SIP URIs store as [::1])
        let host = strip_ipv6_brackets(host);

        // Default port: 5061 for sips: or transport=tls, 5060 otherwise
        let is_tls = scheme == "sips"
            || transport_hint.is_some_and(|t| t.eq_ignore_ascii_case("tls"));
        let default_port = if is_tls { 5061 } else { 5060 };

        // 1. Numeric IP — no DNS needed
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ResolvedTarget {
                address: SocketAddr::new(ip, port.unwrap_or(default_port)),
                transport: transport_hint.map(|s| s.to_string()),
            }];
        }

        // 2. Explicit port provided — skip SRV, go straight to A/AAAA
        if let Some(port) = port {
            return self.resolve_a_aaaa(host, port, transport_hint).await;
        }

        // 3. No port — try SRV lookup first (RFC 3263 §4)
        let srv_results = self.resolve_srv(host, scheme, transport_hint).await;
        if !srv_results.is_empty() {
            return srv_results;
        }

        // 4. No SRV records — fall back to A/AAAA with default port
        debug!(host = %host, port = default_port, "no SRV records, falling back to A/AAAA");
        self.resolve_a_aaaa(host, default_port, transport_hint).await
    }

    /// Perform SRV lookup for a SIP domain.
    ///
    /// Tries service names based on scheme and transport hint:
    /// - `sips` scheme → `_sips._tcp.host`
    /// - `sip` + UDP → `_sip._udp.host`
    /// - `sip` + TCP → `_sip._tcp.host`
    /// - No hint → try UDP first, then TCP
    ///
    /// Records are ordered per RFC 2782: ascending priority, with weighted
    /// random selection within each priority group. The selection is fresh
    /// on every call, so callers that pick `.next()` will hit different
    /// equal-cost targets across resolutions.
    async fn resolve_srv(
        &self,
        host: &str,
        scheme: &str,
        transport_hint: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        let service_names: Vec<(String, &str)> = match (scheme, transport_hint) {
            ("sips", _) => vec![("_sips._tcp".to_string(), "tls")],
            (_, Some(transport)) => {
                let proto = match transport.to_lowercase().as_str() {
                    "udp" => "_udp",
                    "tcp" => "_tcp",
                    "tls" => "_tcp",
                    "sctp" => "_sctp",
                    _ => "_udp",
                };
                vec![(format!("_sip.{proto}"), transport)]
            }
            _ => vec![
                ("_sip._udp".to_string(), "udp"),
                ("_sip._tcp".to_string(), "tcp"),
            ],
        };

        let mut results = Vec::new();

        for (service_prefix, transport) in &service_names {
            let srv_name = format!("{service_prefix}.{host}.");
            match self.resolver.srv_lookup(&srv_name).await {
                Ok(lookup) => {
                    let entries: Vec<SrvEntry> = lookup
                        .iter()
                        .map(|record| SrvEntry {
                            priority: record.priority(),
                            weight: record.weight(),
                            port: record.port(),
                            target: record
                                .target()
                                .to_string()
                                .trim_end_matches('.')
                                .to_string(),
                        })
                        .collect();

                    let ordered = order_srv_entries(entries);

                    for entry in ordered {
                        let addresses = self
                            .resolve_a_aaaa(&entry.target, entry.port, Some(transport))
                            .await;
                        results.extend(addresses);
                    }

                    if !results.is_empty() {
                        debug!(
                            host = %host,
                            srv = %srv_name,
                            count = results.len(),
                            "SRV lookup succeeded"
                        );
                        return results;
                    }
                }
                Err(error) => {
                    debug!(
                        host = %host,
                        srv = %srv_name,
                        %error,
                        "SRV lookup failed"
                    );
                }
            }
        }

        results
    }

    /// Perform a NAPTR lookup and return the first matching SIP URI replacement.
    ///
    /// Used for ENUM (e164.arpa) lookups. Returns the URI from the first
    /// NAPTR record whose service field contains "E2U+sip".
    pub async fn naptr_lookup(&self, query_name: &str) -> Option<String> {
        use hickory_resolver::proto::rr::RecordType;
        use hickory_resolver::proto::rr::record_data::RData;

        match self.resolver.lookup(query_name, RecordType::NAPTR).await {
            Ok(lookup) => {
                for rdata in lookup.iter() {
                    if let RData::NAPTR(naptr) = rdata {
                        let services = String::from_utf8_lossy(naptr.services());
                        if services.contains("E2U+sip") || services.contains("e2u+sip") {
                            let replacement = naptr.replacement().to_string();
                            if !replacement.is_empty() && replacement != "." {
                                return Some(replacement.trim_end_matches('.').to_string());
                            }
                            // Check regexp field for URI extraction
                            let regexp = String::from_utf8_lossy(naptr.regexp());
                            if !regexp.is_empty() {
                                // NAPTR regexp format: "!pattern!replacement!"
                                let parts: Vec<&str> = regexp.split('!').collect();
                                if parts.len() >= 3 && !parts[2].is_empty() {
                                    return Some(parts[2].to_string());
                                }
                            }
                        }
                    }
                }
                None
            }
            Err(error) => {
                debug!(query = %query_name, %error, "NAPTR lookup failed");
                None
            }
        }
    }

    /// Resolve a hostname to IP addresses via A/AAAA lookup.
    ///
    /// Records are returned in a fresh random order on every call. RFC 3263
    /// §4.2 mandates that when an explicit port skips SRV, the client tries
    /// multiple A/AAAA records — but if the consumer always picks `.next()`,
    /// any deterministic order pins traffic to a single IP. Shuffling here
    /// guarantees uniform distribution regardless of upstream ordering or
    /// resolver-cache stickiness.
    async fn resolve_a_aaaa(
        &self,
        host: &str,
        port: u16,
        transport: Option<&str>,
    ) -> Vec<ResolvedTarget> {
        match self.resolver.lookup_ip(host).await {
            Ok(lookup) => {
                let mut results: Vec<ResolvedTarget> = lookup
                    .iter()
                    .map(|ip| ResolvedTarget {
                        address: SocketAddr::new(ip, port),
                        transport: transport.map(|s| s.to_string()),
                    })
                    .collect();
                shuffle_targets(&mut results, random_u32_inclusive);
                results
            }
            Err(error) => {
                warn!(host = %host, %error, "DNS A/AAAA lookup failed");
                Vec::new()
            }
        }
    }
}

/// Fisher-Yates shuffle over the resolved A/AAAA list.
///
/// `random_inclusive(max)` must return a uniform integer in `[0, max]`.
/// Factored as a parameter so tests can pump in deterministic draws.
fn shuffle_targets<F>(targets: &mut [ResolvedTarget], mut random_inclusive: F)
where
    F: FnMut(u32) -> u32,
{
    for index in (1..targets.len()).rev() {
        let pick = random_inclusive(index as u32) as usize;
        targets.swap(index, pick);
    }
}

/// Extracted SRV record fields for RFC 2782 selection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SrvEntry {
    priority: u16,
    weight: u16,
    port: u16,
    target: String,
}

/// Order SRV records per RFC 2782.
///
/// Records are grouped by priority (ascending). Within a priority group,
/// records are ordered by weighted random selection: a record's chance of
/// being placed at any given position is proportional to its weight relative
/// to the remaining unordered records. Weight-0 records are placed at the
/// front of the candidate list and only get picked when the random draw is 0
/// or when they are all that remain.
///
/// The randomness is fresh on every call, so consecutive resolutions of the
/// same SRV name produce different orderings — that is the whole point of
/// RFC 2782.
fn order_srv_entries(mut entries: Vec<SrvEntry>) -> Vec<SrvEntry> {
    entries.sort_by_key(|entry| entry.priority);

    let mut ordered = Vec::with_capacity(entries.len());
    let mut group_start = 0usize;
    while group_start < entries.len() {
        let mut group_end = group_start + 1;
        while group_end < entries.len()
            && entries[group_end].priority == entries[group_start].priority
        {
            group_end += 1;
        }
        let group: Vec<SrvEntry> = entries[group_start..group_end].to_vec();
        ordered.extend(rfc2782_select(group, random_u32_inclusive));
        group_start = group_end;
    }
    ordered
}

/// RFC 2782 weighted random selection for one priority group.
///
/// `random_inclusive(max)` must return a uniform integer in `[0, max]`.
/// Factored as a parameter so tests can pump in deterministic draws.
fn rfc2782_select<F>(items: Vec<SrvEntry>, mut random_inclusive: F) -> Vec<SrvEntry>
where
    F: FnMut(u32) -> u32,
{
    // RFC 2782: "all those with weight 0 are placed at the beginning of the
    // list". sort_by_key is stable, so the relative order of zero-weight and
    // non-zero-weight subgroups is preserved from the input.
    let mut remaining = items;
    remaining.sort_by_key(|entry| u8::from(entry.weight != 0));

    let mut ordered = Vec::with_capacity(remaining.len());
    while !remaining.is_empty() {
        let total: u32 = remaining.iter().map(|entry| u32::from(entry.weight)).sum();
        let pick = random_inclusive(total);

        let mut cumulative: u32 = 0;
        let mut chosen_index = remaining.len() - 1;
        for (index, entry) in remaining.iter().enumerate() {
            cumulative += u32::from(entry.weight);
            if cumulative >= pick {
                chosen_index = index;
                break;
            }
        }
        ordered.push(remaining.remove(chosen_index));
    }
    ordered
}

/// Uniform `u32` in `[0, max]` (inclusive on both ends) using `getrandom`.
///
/// On the (vanishingly rare) event that the OS RNG fails, falls back to 0,
/// which simply biases that single draw toward the head of the candidate
/// list — still RFC-compliant, just unbiased over the next call.
fn random_u32_inclusive(max: u32) -> u32 {
    if max == 0 {
        return 0;
    }
    let range = u64::from(max) + 1;
    let mut buf = [0u8; 8];
    if getrandom::fill(&mut buf).is_err() {
        return 0;
    }
    let value = u64::from_le_bytes(buf);
    (value % range) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[tokio::test]
    async fn resolve_numeric_ipv4() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("192.168.1.100", Some(5080), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "192.168.1.100:5080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv4_default_port() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("10.0.0.1", None, "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv4_sips_default_port() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("10.0.0.1", None, "sips", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "10.0.0.1:5061".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_numeric_ipv6() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("::1", Some(5060), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "[::1]:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_bracketed_ipv6() {
        let resolver = SipResolver::from_system().unwrap();
        // SIP URIs store IPv6 with brackets — resolver should strip them
        let results = resolver.resolve("[::1]", Some(5060), "sip", None).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].address, "[::1]:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test]
    async fn resolve_bracketed_ipv6_full() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("[2001:db8::1]", Some(5080), "sip", None).await;
        assert_eq!(results.len(), 1);
        let expected: SocketAddr = "[2001:db8::1]:5080".parse().unwrap();
        assert_eq!(results[0].address, expected);
    }

    #[tokio::test]
    async fn resolve_localhost() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver.resolve("localhost", Some(5090), "sip", None).await;
        assert!(!results.is_empty(), "localhost should resolve");
        assert_eq!(results[0].address.port(), 5090);
        assert!(
            results[0].address.ip().is_loopback(),
            "localhost should resolve to loopback"
        );
    }

    #[tokio::test]
    async fn resolve_transport_hint_preserved() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver
            .resolve("192.168.1.1", Some(5060), "sip", Some("tcp"))
            .await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].transport.as_deref(), Some("tcp"));
    }

    #[tokio::test]
    async fn resolve_nonexistent_domain_returns_empty() {
        let resolver = SipResolver::from_system().unwrap();
        let results = resolver
            .resolve("this-domain-should-not-exist-xyzzy.invalid", None, "sip", None)
            .await;
        assert!(results.is_empty());
    }

    fn entry(priority: u16, weight: u16, target: &str) -> SrvEntry {
        SrvEntry { priority, weight, port: 5060, target: target.to_string() }
    }

    fn scripted_random(values: Vec<u32>) -> impl FnMut(u32) -> u32 {
        let cell = RefCell::new(values.into_iter());
        move |max| {
            let drawn = cell.borrow_mut().next().unwrap_or(0);
            assert!(drawn <= max, "scripted draw {drawn} > max {max}");
            drawn
        }
    }

    #[test]
    fn rfc2782_priority_groups_processed_in_ascending_order() {
        let entries = vec![
            entry(20, 100, "low-prio"),
            entry(10, 100, "high-prio-a"),
            entry(10, 100, "high-prio-b"),
        ];
        let ordered = order_srv_entries(entries);
        // Priority 10 entries come first regardless of which one wins the
        // weight draw between them.
        assert_eq!(ordered[2].target, "low-prio");
        assert_eq!(ordered[0].priority, 10);
        assert_eq!(ordered[1].priority, 10);
    }

    #[test]
    fn rfc2782_equal_weights_pick_first_when_random_at_lower_bound() {
        // Two equal records, weights 50+50, total=100. Draw=0 must hit the
        // first entry's running sum (50). The remaining record then has
        // total=50, draw=0 hits that one.
        let group = vec![entry(10, 50, "a"), entry(10, 50, "b")];
        let ordered = rfc2782_select(group, scripted_random(vec![0, 0]));
        assert_eq!(ordered[0].target, "a");
        assert_eq!(ordered[1].target, "b");
    }

    #[test]
    fn rfc2782_equal_weights_pick_second_when_random_in_upper_half() {
        // Draw=51 falls past the first running sum (50), so the second
        // record wins. Then the second draw on the remaining record (total
        // = 50) must be ≤ 50; use 50 to keep the assert_le invariant.
        let group = vec![entry(10, 50, "a"), entry(10, 50, "b")];
        let ordered = rfc2782_select(group, scripted_random(vec![51, 50]));
        assert_eq!(ordered[0].target, "b");
        assert_eq!(ordered[1].target, "a");
    }

    #[test]
    fn rfc2782_weight_zero_only_picked_on_zero_draw() {
        // weight-0 placed first; draw=0 picks it; second pass has only the
        // weighted record left, draw any.
        let group = vec![entry(10, 100, "weighted"), entry(10, 0, "zero")];
        let ordered = rfc2782_select(group, scripted_random(vec![0, 50]));
        assert_eq!(ordered[0].target, "zero");
        assert_eq!(ordered[1].target, "weighted");

        // Any non-zero draw skips the zero-weight prefix and lands on the
        // weighted record.
        let group = vec![entry(10, 100, "weighted"), entry(10, 0, "zero")];
        let ordered = rfc2782_select(group, scripted_random(vec![1, 0]));
        assert_eq!(ordered[0].target, "weighted");
        assert_eq!(ordered[1].target, "zero");
    }

    #[test]
    fn rfc2782_all_weight_zero_falls_back_to_input_order() {
        let group = vec![entry(10, 0, "first"), entry(10, 0, "second")];
        let ordered = rfc2782_select(group, scripted_random(vec![0, 0]));
        assert_eq!(ordered[0].target, "first");
        assert_eq!(ordered[1].target, "second");
    }

    #[test]
    fn rfc2782_distribution_roughly_proportional_to_weight() {
        // Real RNG, large sample. With weights 90/10, the high-weight target
        // should win the first slot the overwhelming majority of the time.
        let mut wins_a = 0u32;
        let trials = 2000u32;
        for _ in 0..trials {
            let group = vec![entry(10, 90, "a"), entry(10, 10, "b")];
            let ordered = order_srv_entries(group);
            if ordered[0].target == "a" {
                wins_a += 1;
            }
        }
        // Expected ~90% (1800/2000). Allow generous slack for RNG variance.
        assert!(
            wins_a > 1500 && wins_a < 1950,
            "weighted distribution looks broken: a won {wins_a}/{trials}"
        );
    }

    fn target(ip: &str, port: u16) -> ResolvedTarget {
        ResolvedTarget {
            address: format!("{ip}:{port}").parse::<SocketAddr>().unwrap(),
            transport: None,
        }
    }

    #[test]
    fn shuffle_targets_empty_is_noop() {
        let mut targets: Vec<ResolvedTarget> = vec![];
        shuffle_targets(&mut targets, scripted_random(vec![]));
        assert!(targets.is_empty());
    }

    #[test]
    fn shuffle_targets_single_is_noop() {
        let mut targets = vec![target("10.0.0.1", 5060)];
        shuffle_targets(&mut targets, scripted_random(vec![]));
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].address.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn shuffle_targets_two_elements_swap_with_zero_draw() {
        // Fisher-Yates with i=1 picks j in [0,1]; draw=0 swaps targets[1] with
        // targets[0], reversing the pair.
        let mut targets = vec![target("10.0.0.1", 5060), target("10.0.0.2", 5060)];
        shuffle_targets(&mut targets, scripted_random(vec![0]));
        assert_eq!(targets[0].address.ip().to_string(), "10.0.0.2");
        assert_eq!(targets[1].address.ip().to_string(), "10.0.0.1");
    }

    #[test]
    fn shuffle_targets_two_elements_keep_with_max_draw() {
        // draw=1 swaps targets[1] with itself — order preserved.
        let mut targets = vec![target("10.0.0.1", 5060), target("10.0.0.2", 5060)];
        shuffle_targets(&mut targets, scripted_random(vec![1]));
        assert_eq!(targets[0].address.ip().to_string(), "10.0.0.1");
        assert_eq!(targets[1].address.ip().to_string(), "10.0.0.2");
    }

    #[test]
    fn shuffle_targets_three_elements_deterministic_with_scripted_rng() {
        // i=2: draw=1 swaps [2] with [1] → ["a","c","b"]
        // i=1: draw=0 swaps [1] with [0] → ["c","a","b"]
        let mut targets = vec![
            target("10.0.0.1", 5060),
            target("10.0.0.2", 5060),
            target("10.0.0.3", 5060),
        ];
        shuffle_targets(&mut targets, scripted_random(vec![1, 0]));
        assert_eq!(targets[0].address.ip().to_string(), "10.0.0.3");
        assert_eq!(targets[1].address.ip().to_string(), "10.0.0.1");
        assert_eq!(targets[2].address.ip().to_string(), "10.0.0.2");
    }

    #[test]
    fn shuffle_targets_real_rng_eventually_picks_both_orderings() {
        // Pin the bug: A-only resolver path was returning records in
        // deterministic DNS order. After the fix, two equal-cost records
        // must each appear at index 0 across repeated shuffles.
        let mut a_first = false;
        let mut b_first = false;
        for _ in 0..200 {
            let mut targets = vec![target("10.0.0.1", 5060), target("10.0.0.2", 5060)];
            shuffle_targets(&mut targets, random_u32_inclusive);
            match targets[0].address.ip().to_string().as_str() {
                "10.0.0.1" => a_first = true,
                "10.0.0.2" => b_first = true,
                _ => unreachable!(),
            }
            if a_first && b_first {
                return;
            }
        }
        panic!("A/AAAA shuffle is sticky: a_first={a_first} b_first={b_first}");
    }

    #[test]
    fn shuffle_targets_real_rng_distribution_roughly_uniform() {
        // With two equal records, each should win the first slot ~50% of
        // the time. Generous slack for RNG variance over a 2000-trial run.
        let mut wins_a = 0u32;
        let trials = 2000u32;
        for _ in 0..trials {
            let mut targets = vec![target("10.0.0.1", 5060), target("10.0.0.2", 5060)];
            shuffle_targets(&mut targets, random_u32_inclusive);
            if targets[0].address.ip().to_string() == "10.0.0.1" {
                wins_a += 1;
            }
        }
        assert!(
            wins_a > 800 && wins_a < 1200,
            "shuffle distribution looks broken: a won {wins_a}/{trials}"
        );
    }

    #[test]
    fn rfc2782_real_rng_eventually_picks_both_equal_targets() {
        // The bug this test pins: equal-priority equal-weight records must
        // not be sticky across resolutions. Run order_srv_entries many
        // times; both targets must appear at index 0 at least once.
        let mut a_first = false;
        let mut b_first = false;
        for _ in 0..200 {
            let group = vec![entry(10, 50, "a"), entry(10, 50, "b")];
            let ordered = order_srv_entries(group);
            match ordered[0].target.as_str() {
                "a" => a_first = true,
                "b" => b_first = true,
                _ => unreachable!(),
            }
            if a_first && b_first {
                return;
            }
        }
        panic!("RFC 2782 random selection is sticky: a_first={a_first} b_first={b_first}");
    }
}
