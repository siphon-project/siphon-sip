//! General-purpose destination dispatcher with health probing.
//!
//! Manages named groups of SIP destinations with configurable load-balancing
//! algorithms and per-group OPTIONS health probing.
//!
//! Python scripts use:
//! ```python
//! from siphon import dispatcher
//! gw = dispatcher.select("carriers")
//! if gw:
//!     request.relay(gw.uri)
//! ```

use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use tracing::{debug, info, warn};

use crate::sip::uri::SipUri;
use crate::transport::Transport;
use crate::uac::UacSender;

// ---------------------------------------------------------------------------
// Algorithm
// ---------------------------------------------------------------------------

/// Load-balancing algorithm for a dispatcher group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Simple rotation through healthy destinations.
    RoundRobin,
    /// Weighted round-robin respecting the `weight` field.
    Weighted,
    /// Consistent hash on a caller-provided key (e.g. Call-ID for sticky sessions).
    Hash,
}

impl Algorithm {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "round_robin" => Some(Self::RoundRobin),
            "weighted" => Some(Self::Weighted),
            "hash" | "call_id_hash" | "from_uri_hash" | "to_uri_hash" => Some(Self::Hash),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RoundRobin => "round_robin",
            Self::Weighted => "weighted",
            Self::Hash => "hash",
        }
    }
}

// ---------------------------------------------------------------------------
// Destination
// ---------------------------------------------------------------------------

/// A single destination in a dispatcher group.
#[derive(Debug)]
pub struct Destination {
    /// SIP URI to route to (e.g. "sip:gw1.carrier.com:5060").
    pub uri: String,
    /// Original address string for DNS re-resolution (e.g. "gw1.carrier.com:5060").
    pub address_str: Option<String>,
    /// Resolved socket address for sending (updated on DNS re-resolution).
    address: std::sync::Mutex<SocketAddr>,
    /// Transport protocol.
    pub transport: Transport,
    /// Weight for weighted round-robin (higher = more traffic).
    pub weight: u32,
    /// Priority group (lower number = higher priority, for failover tiers).
    pub priority: u32,
    /// User-defined attributes (e.g. {"region": "us-east", "type": "pstn"}).
    pub attrs: HashMap<String, String>,
    /// Whether this destination is currently healthy.
    healthy: AtomicBool,
    /// Consecutive failure count.
    failures: AtomicU32,
}

impl Destination {
    pub fn new(
        uri: String,
        address: SocketAddr,
        transport: Transport,
        weight: u32,
        priority: u32,
    ) -> Self {
        Self {
            uri,
            address_str: None,
            address: std::sync::Mutex::new(address),
            transport,
            weight,
            priority,
            attrs: HashMap::new(),
            healthy: AtomicBool::new(true),
            failures: AtomicU32::new(0),
        }
    }

    /// Get the current resolved address.
    pub fn address(&self) -> SocketAddr {
        *self.address.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Update the resolved address (after DNS re-resolution).
    pub fn set_address(&self, address: SocketAddr) {
        *self.address.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = address;
    }

    pub fn with_address_str(mut self, address_str: String) -> Self {
        self.address_str = Some(address_str);
        self
    }

    pub fn with_attrs(mut self, attrs: HashMap<String, String>) -> Self {
        self.attrs = attrs;
        self
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn mark_up(&self) {
        self.healthy.store(true, Ordering::Relaxed);
        self.failures.store(0, Ordering::Relaxed);
    }

    pub fn mark_down(&self) {
        self.healthy.store(false, Ordering::Relaxed);
    }

    fn record_failure(&self) -> u32 {
        self.failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.healthy.store(true, Ordering::Relaxed);
    }

    /// Check if this destination matches all the given attr filters.
    pub fn matches_attrs(&self, filters: &HashMap<String, String>) -> bool {
        filters
            .iter()
            .all(|(key, value)| self.attrs.get(key).is_some_and(|v| v == value))
    }
}


// ---------------------------------------------------------------------------
// Probe config (per-group)
// ---------------------------------------------------------------------------

/// Per-group health probe configuration.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub enabled: bool,
    pub interval: Duration,
    pub failure_threshold: u32,
    /// User part for the From URI in OPTIONS probes (default: "siphon").
    pub from_user: Option<String>,
    /// Host part for the From URI in OPTIONS probes (default: local IP).
    pub from_domain: Option<String>,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: Duration::from_secs(30),
            failure_threshold: 3,
            from_user: None,
            from_domain: None,
        }
    }
}

// ---------------------------------------------------------------------------
// DispatcherGroup
// ---------------------------------------------------------------------------

/// A named group of destinations with its own algorithm and probe config.
pub struct DispatcherGroup {
    /// Group name (e.g. "carriers", "sbc-pool").
    pub name: String,
    /// Load-balancing algorithm.
    pub algorithm: Algorithm,
    /// Health probe configuration.
    pub probe_config: ProbeConfig,
    /// Destinations in this group.
    destinations: Vec<Arc<Destination>>,
    /// Round-robin counter per priority level.
    counters: DashMap<u32, AtomicU32>,
    /// Lock-free cache of every resolved source IP across all destinations.
    ///
    /// Read on the request hot path by `contains_source` (the backing store
    /// for `request.from_gateway` / `call.from_gateway`); rebuilt off the
    /// hot path by `refresh_member_ips` (startup + each probe cycle). The
    /// `ArcSwap` gives an atomic swap with no empty window during refresh.
    member_ips: ArcSwap<HashSet<IpAddr>>,
}

impl DispatcherGroup {
    pub fn new(name: String, algorithm: Algorithm, destinations: Vec<Destination>) -> Self {
        let destinations: Vec<Arc<Destination>> =
            destinations.into_iter().map(Arc::new).collect();
        let group = Self {
            name,
            algorithm,
            probe_config: ProbeConfig::default(),
            destinations,
            counters: DashMap::new(),
            member_ips: ArcSwap::from_pointee(HashSet::new()),
        };
        // Startup resolution — sync context, `to_socket_addrs` is fine here.
        group.refresh_member_ips();
        group
    }

    pub fn with_probe_config(mut self, config: ProbeConfig) -> Self {
        self.probe_config = config;
        self
    }

    /// Select a destination using the group's algorithm.
    ///
    /// `key` is used by hash-based algorithms (e.g. Call-ID). Ignored for round-robin.
    /// `attr_filter` narrows candidates to those matching all given attrs.
    pub fn select(
        &self,
        key: Option<&str>,
        attr_filter: Option<&HashMap<String, String>>,
    ) -> Option<Arc<Destination>> {
        // Collect unique priority levels, sorted ascending (lowest = highest priority)
        let mut priorities: Vec<u32> = self.destinations.iter().map(|d| d.priority).collect();
        priorities.sort_unstable();
        priorities.dedup();

        for priority in priorities {
            let candidates: Vec<&Arc<Destination>> = self
                .destinations
                .iter()
                .filter(|d| {
                    d.priority == priority
                        && d.is_healthy()
                        && attr_filter
                            .map_or(true, |f| d.matches_attrs(f))
                })
                .collect();

            if candidates.is_empty() {
                continue;
            }

            return Some(match self.algorithm {
                Algorithm::RoundRobin => self.select_round_robin(&candidates, priority),
                Algorithm::Weighted => self.select_weighted(&candidates, priority),
                Algorithm::Hash => self.select_hash(&candidates, key),
            });
        }

        None
    }

    /// Simple round-robin (ignoring weights).
    fn select_round_robin(
        &self,
        candidates: &[&Arc<Destination>],
        priority: u32,
    ) -> Arc<Destination> {
        let counter = self
            .counters
            .entry(priority)
            .or_insert_with(|| AtomicU32::new(0));
        let index = counter.value().fetch_add(1, Ordering::Relaxed) as usize % candidates.len();
        Arc::clone(candidates[index])
    }

    /// Weighted round-robin.
    fn select_weighted(
        &self,
        candidates: &[&Arc<Destination>],
        priority: u32,
    ) -> Arc<Destination> {
        let total_weight: u32 = candidates.iter().map(|d| d.weight).sum();
        if total_weight == 0 {
            return Arc::clone(candidates[0]);
        }

        let counter = self
            .counters
            .entry(priority)
            .or_insert_with(|| AtomicU32::new(0));
        let index = counter.value().fetch_add(1, Ordering::Relaxed) % total_weight;

        let mut cumulative = 0u32;
        for dest in candidates {
            cumulative += dest.weight;
            if index < cumulative {
                return Arc::clone(dest);
            }
        }

        Arc::clone(candidates[0])
    }

    /// Hash-based selection for sticky sessions.
    fn select_hash(
        &self,
        candidates: &[&Arc<Destination>],
        key: Option<&str>,
    ) -> Arc<Destination> {
        let hash_value = match key {
            Some(k) => {
                let mut hasher = DefaultHasher::new();
                k.hash(&mut hasher);
                hasher.finish()
            }
            None => 0,
        };
        let index = (hash_value as usize) % candidates.len();
        Arc::clone(candidates[index])
    }

    /// Get all destinations with their current status.
    pub fn status(&self) -> Vec<(String, bool)> {
        self.destinations
            .iter()
            .map(|d| (d.uri.clone(), d.is_healthy()))
            .collect()
    }

    /// List all destinations (for Python API).
    pub fn list_destinations(&self) -> Vec<Arc<Destination>> {
        self.destinations.iter().map(Arc::clone).collect()
    }

    /// Find a destination by URI and mark it down.
    pub fn mark_down(&self, uri: &str) -> bool {
        if let Some(dest) = self.destinations.iter().find(|d| d.uri == uri) {
            dest.mark_down();
            true
        } else {
            false
        }
    }

    /// Find a destination by URI and mark it up.
    pub fn mark_up(&self, uri: &str) -> bool {
        if let Some(dest) = self.destinations.iter().find(|d| d.uri == uri) {
            dest.mark_up();
            true
        } else {
            false
        }
    }

    /// Return all destinations (for health probing).
    pub fn all_destinations(&self) -> &[Arc<Destination>] {
        &self.destinations
    }

    /// Rebuild the cached set of member source IPs.
    ///
    /// For every destination: if `address_str` is set, resolve it and insert
    /// each resolved candidate IP (so a round-robin hostname, and Teams'
    /// `sip`/`sip2`/`sip3.pstnhub.microsoft.com`, all match, not just the
    /// currently-selected address). The currently-resolved `address().ip()`
    /// is ALWAYS also inserted as a floor — this covers static-IP
    /// destinations and survives a transient resolver hiccup. The new set is
    /// swapped in atomically, so readers never observe an empty window.
    ///
    /// Uses blocking `to_socket_addrs`, so it must never run on the request
    /// hot path — it is called once at construction (startup) and once per
    /// probe cycle. Groups with probing disabled get only the startup
    /// refresh, so a DNS change on such a group is not picked up until
    /// restart; static-IP and probed groups are always correct.
    pub fn refresh_member_ips(&self) {
        use std::net::ToSocketAddrs;

        let mut set: HashSet<IpAddr> = HashSet::new();
        for dest in &self.destinations {
            if let Some(ref address_str) = dest.address_str {
                if let Ok(addrs) = address_str.to_socket_addrs() {
                    for addr in addrs {
                        set.insert(addr.ip());
                    }
                }
            }
            // Floor: the currently-resolved address always counts as a member.
            set.insert(dest.address().ip());
        }
        self.member_ips.store(Arc::new(set));
    }

    /// True when `ip` is a member of this group's cached resolved-address set.
    ///
    /// Matches on IP only (source port is ignored — gateways answer from
    /// varied ports). Reads the lock-free cache; never resolves DNS.
    pub fn contains_source(&self, ip: IpAddr) -> bool {
        self.member_ips.load().contains(&ip)
    }
}


// ---------------------------------------------------------------------------
// DispatcherManager
// ---------------------------------------------------------------------------

/// Manager for multiple dispatcher groups.
pub struct DispatcherManager {
    groups: DashMap<String, Arc<DispatcherGroup>>,
}

impl DispatcherManager {
    pub fn new() -> Self {
        Self {
            groups: DashMap::new(),
        }
    }

    pub fn add_group(&self, group: DispatcherGroup) {
        let name = group.name.clone();
        self.groups.insert(name, Arc::new(group));
    }

    pub fn get_group(&self, name: &str) -> Option<Arc<DispatcherGroup>> {
        self.groups.get(name).map(|entry| Arc::clone(entry.value()))
    }

    /// Remove a group by name.
    pub fn remove_group(&self, name: &str) -> bool {
        self.groups.remove(name).is_some()
    }

    /// List all group names.
    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|e| e.key().clone()).collect()
    }

    /// Select a destination from a named group.
    pub fn select(
        &self,
        group_name: &str,
        key: Option<&str>,
        attr_filter: Option<&HashMap<String, String>>,
    ) -> Option<Arc<Destination>> {
        self.get_group(group_name)
            .and_then(|group| group.select(key, attr_filter))
    }

    /// True when `ip` is a resolved member of the named group.
    ///
    /// Backs `request.from_gateway` / `call.from_gateway` — a routing-direction
    /// / trust predicate (the siphon equivalent of Kamailio `ds_is_from_list()`
    /// / OpenSIPS `ds_is_in_list()`). Returns `false` when the group does not
    /// exist, so callers can stay infallible.
    pub fn source_in_group(&self, group_name: &str, ip: IpAddr) -> bool {
        self.get_group(group_name)
            .map(|group| group.contains_source(ip))
            .unwrap_or(false)
    }
}

impl Default for DispatcherManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Health probing
// ---------------------------------------------------------------------------

/// Spawn background health probers for all groups that have probing enabled.
///
/// Each group gets its own probe task with its own interval and threshold.
pub fn spawn_health_probers(
    manager: Arc<DispatcherManager>,
    uac_sender: Arc<UacSender>,
) {
    for entry in manager.groups.iter() {
        let group = Arc::clone(entry.value());
        if !group.probe_config.enabled {
            continue;
        }

        let uac = Arc::clone(&uac_sender);
        let interval = group.probe_config.interval;
        let threshold = group.probe_config.failure_threshold;
        let from_user = group.probe_config.from_user.clone();
        let from_domain = group.probe_config.from_domain.clone();

        info!(
            group = %group.name,
            interval_secs = interval.as_secs(),
            threshold = threshold,
            "dispatcher health prober started"
        );

        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            loop {
                tick.tick().await;
                probe_group(&group, &uac, threshold, from_user.as_deref(), from_domain.as_deref()).await;
            }
        });
    }
}

async fn probe_group(
    group: &Arc<DispatcherGroup>,
    uac_sender: &UacSender,
    failure_threshold: u32,
    from_user: Option<&str>,
    from_domain: Option<&str>,
) {
    // Refresh the cached member-IP set so `from_gateway` tracks DNS changes on
    // the probe interval. `refresh_member_ips` does blocking DNS, so run it off
    // the tokio worker; the request hot path only ever reads the cached set.
    let group_for_refresh = Arc::clone(group);
    if let Err(error) = tokio::task::spawn_blocking(move || {
        group_for_refresh.refresh_member_ips();
    })
    .await
    {
        warn!(group = %group.name, %error, "member-IP refresh task failed");
    }

    for dest in group.all_destinations() {
        probe_destination(dest, uac_sender, failure_threshold, from_user, from_domain).await;
    }
}

async fn probe_destination(
    dest: &Destination,
    uac_sender: &UacSender,
    failure_threshold: u32,
    from_user: Option<&str>,
    from_domain: Option<&str>,
) {
    // Build R-URI from the gateway's configured URI hostname (not the resolved IP).
    let host_part = dest.uri
        .strip_prefix("sip:")
        .or_else(|| dest.uri.strip_prefix("sips:"))
        .unwrap_or(&dest.uri);
    let current_addr = dest.address();
    let (host, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(current_addr.port()))
    } else {
        (host_part.to_string(), current_addr.port())
    };
    // Keep the configured hostname for TLS SNI — the probe addresses the
    // resolved IP (`current_addr`), but a hostname-vhost peer routes the TLS
    // handshake on SNI, so a new outbound TLS connection must present it.
    let server_name = host.clone();
    let mut request_uri = SipUri::new(host).with_port(port);
    if dest.transport != Transport::Udp {
        request_uri = request_uri.with_param(
            "transport".to_string(),
            Some(dest.transport.to_string().to_lowercase()),
        );
    }

    let receiver = uac_sender.send_options_with_identity(
        current_addr,
        dest.transport,
        request_uri,
        from_user,
        from_domain,
        if dest.transport == Transport::Tls {
            Some(server_name.as_str())
        } else {
            None
        },
    );

    let result = tokio::time::timeout(Duration::from_secs(5), receiver).await;

    match result {
        Ok(Ok(crate::uac::UacResult::Response(_))) => {
            if !dest.is_healthy() {
                info!(uri = %dest.uri, "destination recovered");
            }
            dest.record_success();
        }
        _ => {
            let count = dest.record_failure();
            debug!(
                uri = %dest.uri,
                failures = count,
                "destination probe failed"
            );
            if count >= failure_threshold {
                if dest.is_healthy() {
                    warn!(uri = %dest.uri, "marking destination down after {count} failures");
                }
                dest.mark_down();

                // Re-resolve DNS to try a different IP on next probe
                if let Some(ref address_str) = dest.address_str {
                    use std::net::ToSocketAddrs;
                    if let Ok(mut addrs) = address_str.to_socket_addrs() {
                        let old = dest.address();
                        // Pick a different address than the current one if available
                        let new_addr = addrs.find(|a| *a != old)
                            .or_else(|| address_str.to_socket_addrs().ok()?.next());
                        if let Some(new_addr) = new_addr {
                            if new_addr != old {
                                info!(
                                    uri = %dest.uri,
                                    old = %old,
                                    new = %new_addr,
                                    "re-resolved destination to different IP"
                                );
                                dest.set_address(new_addr);
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// URI utilities (shared by server init + Python gateway API)
// ---------------------------------------------------------------------------

/// Extract a `host:port` address string from a SIP URI (best-effort).
///
/// Strips the scheme prefix, `user@`, and any URI parameters (`;transport=tls`,
/// etc.) before extracting `host:port`. Falls back to port 5060 (or 5061 for
/// `sips:`).
pub fn extract_address_from_uri(uri: &str) -> String {
    let is_sips = uri.starts_with("sips:");
    let host_part = uri
        .strip_prefix("sip:")
        .or_else(|| uri.strip_prefix("sips:"))
        .unwrap_or(uri);

    // Strip user@ if present
    let host_part = host_part.split('@').next_back().unwrap_or(host_part);

    // Strip URI parameters (;transport=tls, ;lr, etc.)
    let host_port = host_part.split(';').next().unwrap_or(host_part);

    let default_port = if is_sips { 5061 } else { 5060 };

    if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:{default_port}")
    }
}

/// Resolve an address string (`IP:port` or `hostname:port`) to a `SocketAddr`.
pub fn resolve_address(address: &str) -> Result<SocketAddr, String> {
    // Fast path: raw IP:port
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Slow path: DNS resolution (hostname:port)
    use std::net::ToSocketAddrs;
    address
        .to_socket_addrs()
        .map_err(|e| format!("{e}"))?
        .next()
        .ok_or_else(|| "DNS returned no addresses".to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{OutboundRouter};

    fn make_dest(uri: &str, port: u16, weight: u32, priority: u32) -> Destination {
        Destination::new(
            uri.to_string(),
            format!("10.0.0.1:{port}").parse().unwrap(),
            Transport::Udp,
            weight,
            priority,
        )
    }

    fn make_dest_with_attrs(
        uri: &str,
        port: u16,
        weight: u32,
        priority: u32,
        attrs: HashMap<String, String>,
    ) -> Destination {
        Destination::new(
            uri.to_string(),
            format!("10.0.0.1:{port}").parse().unwrap(),
            Transport::Udp,
            weight,
            priority,
        )
        .with_attrs(attrs)
    }

    // --- Algorithm: Weighted (default behavior) ---

    #[test]
    fn weighted_select_returns_healthy() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.carrier.com", 5060, 1, 1),
                make_dest("sip:gw2.carrier.com", 5061, 1, 1),
            ],
        );

        let selected = group.select(None, None);
        assert!(selected.is_some());
    }

    #[test]
    fn weighted_skips_unhealthy() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.carrier.com", 5060, 1, 1),
                make_dest("sip:gw2.carrier.com", 5061, 1, 1),
            ],
        );

        group.mark_down("sip:gw1.carrier.com");

        for _ in 0..5 {
            let selected = group.select(None, None).unwrap();
            assert_eq!(selected.uri, "sip:gw2.carrier.com");
        }
    }

    #[test]
    fn weighted_returns_none_when_all_down() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.carrier.com", 5060, 1, 1)],
        );

        group.mark_down("sip:gw1.carrier.com");
        assert!(group.select(None, None).is_none());
    }

    #[test]
    fn weighted_falls_back_to_lower_priority() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:primary.carrier.com", 5060, 1, 1),
                make_dest("sip:backup.carrier.com", 5061, 1, 2),
            ],
        );

        group.mark_down("sip:primary.carrier.com");

        let selected = group.select(None, None).unwrap();
        assert_eq!(selected.uri, "sip:backup.carrier.com");
    }

    #[test]
    fn weighted_distributes_by_weight() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:heavy.carrier.com", 5060, 3, 1),
                make_dest("sip:light.carrier.com", 5061, 1, 1),
            ],
        );

        let mut heavy_count = 0;
        let mut light_count = 0;

        for _ in 0..100 {
            let selected = group.select(None, None).unwrap();
            if selected.uri == "sip:heavy.carrier.com" {
                heavy_count += 1;
            } else {
                light_count += 1;
            }
        }

        assert!(heavy_count > light_count, "heavy={heavy_count} light={light_count}");
        assert!(heavy_count >= 60, "heavy={heavy_count} should be >= 60");
    }

    // --- Algorithm: RoundRobin ---

    #[test]
    fn round_robin_cycles_evenly() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::RoundRobin,
            vec![
                make_dest("sip:gw1.example.com", 5060, 10, 1), // weight ignored
                make_dest("sip:gw2.example.com", 5061, 1, 1),
            ],
        );

        let mut gw1_count = 0;
        let mut gw2_count = 0;

        for _ in 0..100 {
            let selected = group.select(None, None).unwrap();
            if selected.uri == "sip:gw1.example.com" {
                gw1_count += 1;
            } else {
                gw2_count += 1;
            }
        }

        // Round-robin should be 50/50 regardless of weight
        assert_eq!(gw1_count, 50);
        assert_eq!(gw2_count, 50);
    }

    // --- Algorithm: Hash ---

    #[test]
    fn hash_same_key_same_destination() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:gw1.example.com", 5060, 1, 1),
                make_dest("sip:gw2.example.com", 5061, 1, 1),
                make_dest("sip:gw3.example.com", 5062, 1, 1),
            ],
        );

        let key = "call-id-abc-123";
        let first = group.select(Some(key), None).unwrap();

        // Same key should always return the same destination
        for _ in 0..20 {
            let selected = group.select(Some(key), None).unwrap();
            assert_eq!(selected.uri, first.uri);
        }
    }

    #[test]
    fn hash_different_keys_distribute() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:gw1.example.com", 5060, 1, 1),
                make_dest("sip:gw2.example.com", 5061, 1, 1),
            ],
        );

        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let key = format!("call-id-{i}");
            let selected = group.select(Some(&key), None).unwrap();
            seen.insert(selected.uri.clone());
        }

        // With 100 different keys and 2 destinations, both should be hit
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn hash_falls_back_on_unhealthy() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:primary.example.com", 5060, 1, 1),
                make_dest("sip:backup.example.com", 5061, 1, 2),
            ],
        );

        group.mark_down("sip:primary.example.com");

        let selected = group.select(Some("any-key"), None).unwrap();
        assert_eq!(selected.uri, "sip:backup.example.com");
    }

    // --- Attrs filtering ---

    #[test]
    fn select_with_attr_filter() {
        let mut attrs_east = HashMap::new();
        attrs_east.insert("region".to_string(), "us-east".to_string());
        let mut attrs_west = HashMap::new();
        attrs_west.insert("region".to_string(), "us-west".to_string());

        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::RoundRobin,
            vec![
                make_dest_with_attrs("sip:east.example.com", 5060, 1, 1, attrs_east.clone()),
                make_dest_with_attrs("sip:west.example.com", 5061, 1, 1, attrs_west.clone()),
            ],
        );

        let filter = HashMap::from([("region".to_string(), "us-east".to_string())]);

        // Should only return the east gateway
        for _ in 0..10 {
            let selected = group.select(None, Some(&filter)).unwrap();
            assert_eq!(selected.uri, "sip:east.example.com");
        }
    }

    #[test]
    fn select_with_no_matching_attrs_returns_none() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::RoundRobin,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        );

        let filter = HashMap::from([("region".to_string(), "eu-west".to_string())]);
        assert!(group.select(None, Some(&filter)).is_none());
    }

    // --- Mark up/down ---

    #[test]
    fn mark_up_restores_destination() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.carrier.com", 5060, 1, 1)],
        );

        group.mark_down("sip:gw1.carrier.com");
        assert!(group.select(None, None).is_none());

        group.mark_up("sip:gw1.carrier.com");
        assert!(group.select(None, None).is_some());
    }

    #[test]
    fn mark_nonexistent_returns_false() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.carrier.com", 5060, 1, 1)],
        );

        assert!(!group.mark_down("sip:nonexistent.com"));
        assert!(!group.mark_up("sip:nonexistent.com"));
    }

    // --- Status and listing ---

    #[test]
    fn status_shows_all_destinations() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.carrier.com", 5060, 1, 1),
                make_dest("sip:gw2.carrier.com", 5061, 1, 1),
            ],
        );

        group.mark_down("sip:gw2.carrier.com");

        let status = group.status();
        assert_eq!(status.len(), 2);
        assert_eq!(status[0], ("sip:gw1.carrier.com".to_string(), true));
        assert_eq!(status[1], ("sip:gw2.carrier.com".to_string(), false));
    }

    #[test]
    fn list_destinations_returns_all() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.carrier.com", 5060, 1, 1),
                make_dest("sip:gw2.carrier.com", 5061, 1, 1),
            ],
        );

        let dests = group.list_destinations();
        assert_eq!(dests.len(), 2);
    }

    // --- DispatcherManager ---

    #[test]
    fn manager_multiple_groups() {
        let manager = DispatcherManager::new();

        manager.add_group(DispatcherGroup::new(
            "carriers".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.pstn.com", 5060, 1, 1)],
        ));
        manager.add_group(DispatcherGroup::new(
            "sbc-pool".to_string(),
            Algorithm::Hash,
            vec![make_dest("sip:sbc1.example.com", 5060, 1, 1)],
        ));

        let carrier = manager.select("carriers", None, None).unwrap();
        assert_eq!(carrier.uri, "sip:gw1.pstn.com");

        let sbc = manager.select("sbc-pool", Some("call-123"), None).unwrap();
        assert_eq!(sbc.uri, "sip:sbc1.example.com");

        assert!(manager.select("nonexistent", None, None).is_none());
    }

    #[test]
    fn manager_remove_group() {
        let manager = DispatcherManager::new();
        manager.add_group(DispatcherGroup::new(
            "test".to_string(),
            Algorithm::RoundRobin,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        ));

        assert!(manager.remove_group("test"));
        assert!(!manager.remove_group("test")); // already removed
        assert!(manager.select("test", None, None).is_none());
    }

    #[test]
    fn manager_group_names() {
        let manager = DispatcherManager::new();
        manager.add_group(DispatcherGroup::new(
            "alpha".to_string(),
            Algorithm::RoundRobin,
            vec![make_dest("sip:a.example.com", 5060, 1, 1)],
        ));
        manager.add_group(DispatcherGroup::new(
            "beta".to_string(),
            Algorithm::Hash,
            vec![make_dest("sip:b.example.com", 5060, 1, 1)],
        ));

        let mut names = manager.group_names();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    // --- Probe config ---

    #[test]
    fn probe_config_per_group() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        )
        .with_probe_config(ProbeConfig {
            enabled: true,
            interval: Duration::from_secs(10),
            failure_threshold: 5,
            from_user: Some("bgcf".to_string()),
            from_domain: Some("example.com".to_string()),
        });

        assert!(group.probe_config.enabled);
        assert_eq!(group.probe_config.interval, Duration::from_secs(10));
        assert_eq!(group.probe_config.failure_threshold, 5);
        assert_eq!(group.probe_config.from_user.as_deref(), Some("bgcf"));
        assert_eq!(group.probe_config.from_domain.as_deref(), Some("example.com"));
    }

    #[test]
    fn probe_config_disabled() {
        let group = DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        )
        .with_probe_config(ProbeConfig {
            enabled: false,
            ..ProbeConfig::default()
        });

        assert!(!group.probe_config.enabled);
    }

    // --- Destination attrs ---

    #[test]
    fn destination_matches_attrs() {
        let attrs = HashMap::from([
            ("region".to_string(), "us-east".to_string()),
            ("type".to_string(), "pstn".to_string()),
        ]);
        let dest = make_dest_with_attrs("sip:gw.example.com", 5060, 1, 1, attrs);

        // Exact match
        let filter = HashMap::from([("region".to_string(), "us-east".to_string())]);
        assert!(dest.matches_attrs(&filter));

        // Multi-key match
        let filter = HashMap::from([
            ("region".to_string(), "us-east".to_string()),
            ("type".to_string(), "pstn".to_string()),
        ]);
        assert!(dest.matches_attrs(&filter));

        // No match
        let filter = HashMap::from([("region".to_string(), "eu-west".to_string())]);
        assert!(!dest.matches_attrs(&filter));

        // Missing key
        let filter = HashMap::from([("tier".to_string(), "premium".to_string())]);
        assert!(!dest.matches_attrs(&filter));

        // Empty filter matches everything
        assert!(dest.matches_attrs(&HashMap::new()));
    }

    // --- Health prober (async) ---

    #[tokio::test]
    async fn health_prober_marks_destination_down() {
        let (udp_tx, _udp_rx) = flume::unbounded();
        let (tcp_tx, _tcp_rx) = flume::unbounded();
        let (tls_tx, _tls_rx) = flume::unbounded();
        let (ws_tx, _ws_rx) = flume::unbounded();
        let (wss_tx, _wss_rx) = flume::unbounded();
        let (sctp_tx, _sctp_rx) = flume::unbounded();

        let router = Arc::new(OutboundRouter {
            udp: udp_tx,
            udp_by_local: std::collections::HashMap::new(),
            tcp: tcp_tx,
            tls: tls_tx,
            ws: ws_tx,
            wss: wss_tx,
            sctp: sctp_tx,
        });

        let uac_sender = Arc::new(UacSender::new(router, "127.0.0.1:5060".parse().unwrap(), std::collections::HashMap::new(), std::collections::HashMap::new(), None, None, None));
        let manager = Arc::new(DispatcherManager::new());

        manager.add_group(DispatcherGroup::new(
            "test".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.test.com", 5060, 1, 1)],
        ));

        // Probe with threshold=1 — first failure should mark down
        let group = manager.get_group("test").unwrap();
        probe_group(&group, &uac_sender, 1, None, None).await;

        let status = group.status();
        assert!(!status[0].1);
    }

    // --- Algorithm parsing ---

    #[test]
    fn algorithm_from_str() {
        assert_eq!(Algorithm::from_str("round_robin"), Some(Algorithm::RoundRobin));
        assert_eq!(Algorithm::from_str("weighted"), Some(Algorithm::Weighted));
        assert_eq!(Algorithm::from_str("hash"), Some(Algorithm::Hash));
        assert_eq!(Algorithm::from_str("call_id_hash"), Some(Algorithm::Hash));
        assert_eq!(Algorithm::from_str("from_uri_hash"), Some(Algorithm::Hash));
        assert_eq!(Algorithm::from_str("to_uri_hash"), Some(Algorithm::Hash));
        assert_eq!(Algorithm::from_str("invalid"), None);
    }

    #[test]
    fn algorithm_as_str() {
        assert_eq!(Algorithm::RoundRobin.as_str(), "round_robin");
        assert_eq!(Algorithm::Weighted.as_str(), "weighted");
        assert_eq!(Algorithm::Hash.as_str(), "hash");
    }

    // --- DispatcherManager end-to-end ---

    #[test]
    fn manager_select_end_to_end() {
        let manager = DispatcherManager::new();
        manager.add_group(DispatcherGroup::new(
            "carriers".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.carrier.com", 5060, 3, 1),
                make_dest("sip:gw2.carrier.com", 5061, 1, 1),
            ],
        ));
        manager.add_group(DispatcherGroup::new(
            "sbc-pool".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:sbc1.example.com", 5060, 1, 1),
                make_dest("sip:sbc2.example.com", 5061, 1, 1),
            ],
        ));

        // Weighted select returns a destination
        let destination = manager.select("carriers", None, None).unwrap();
        assert!(destination.uri.starts_with("sip:gw"));

        // Hash select with key is sticky
        let first = manager.select("sbc-pool", Some("call-abc"), None).unwrap();
        for _ in 0..10 {
            let again = manager.select("sbc-pool", Some("call-abc"), None).unwrap();
            assert_eq!(again.uri, first.uri);
        }

        // Nonexistent group returns None
        assert!(manager.select("nonexistent", None, None).is_none());
    }

    #[test]
    fn dynamic_group_creation_then_select() {
        let manager = DispatcherManager::new();

        // No groups yet
        assert!(manager.select("overflow", None, None).is_none());

        // Add group dynamically
        manager.add_group(DispatcherGroup::new(
            "overflow".to_string(),
            Algorithm::RoundRobin,
            vec![
                make_dest("sip:overflow1.example.com", 5060, 1, 1),
                make_dest("sip:overflow2.example.com", 5061, 1, 1),
            ],
        ));

        let destination = manager.select("overflow", None, None);
        assert!(destination.is_some());

        // Replace with a new group (same name, different destinations)
        manager.add_group(DispatcherGroup::new(
            "overflow".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:replacement.example.com", 5070, 1, 1)],
        ));

        let destination = manager.select("overflow", None, None).unwrap();
        assert_eq!(destination.uri, "sip:replacement.example.com");
    }

    #[test]
    fn concurrent_select_with_mark_down_mark_up() {
        let manager = Arc::new(DispatcherManager::new());
        manager.add_group(DispatcherGroup::new(
            "concurrent".to_string(),
            Algorithm::RoundRobin,
            vec![
                make_dest("sip:gw1.concurrent.com", 5060, 1, 1),
                make_dest("sip:gw2.concurrent.com", 5061, 1, 1),
                make_dest("sip:gw3.concurrent.com", 5062, 1, 1),
            ],
        ));

        let mut handles = Vec::new();

        // Spawn 4 threads doing selects
        for _ in 0..4 {
            let manager_clone = Arc::clone(&manager);
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = manager_clone.select("concurrent", None, None);
                }
            }));
        }

        // Spawn 2 threads toggling health
        for uri in ["sip:gw1.concurrent.com", "sip:gw2.concurrent.com"] {
            let manager_clone = Arc::clone(&manager);
            let uri_owned = uri.to_string();
            handles.push(std::thread::spawn(move || {
                for iteration in 0..500 {
                    let group = manager_clone.get_group("concurrent").unwrap();
                    if iteration % 2 == 0 {
                        group.mark_down(&uri_owned);
                    } else {
                        group.mark_up(&uri_owned);
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked during concurrent test");
        }

        // Verify system is still functional after contention
        let group = manager.get_group("concurrent").unwrap();
        group.mark_up("sip:gw1.concurrent.com");
        group.mark_up("sip:gw2.concurrent.com");
        let result = manager.select("concurrent", None, None);
        assert!(result.is_some());
    }

    // --- Hash algorithm ---

    #[test]
    fn hash_determinism_across_iterations() {
        let group = DispatcherGroup::new(
            "hash-det".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:a.example.com", 5060, 1, 1),
                make_dest("sip:b.example.com", 5061, 1, 1),
                make_dest("sip:c.example.com", 5062, 1, 1),
                make_dest("sip:d.example.com", 5063, 1, 1),
            ],
        );

        let keys = ["call-id-alpha", "call-id-beta", "call-id-gamma", "call-id-delta"];
        let expected: Vec<String> = keys
            .iter()
            .map(|key| group.select(Some(key), None).unwrap().uri.clone())
            .collect();

        // Interleave many calls and verify determinism
        for _ in 0..50 {
            for (index, key) in keys.iter().enumerate() {
                let selected = group.select(Some(key), None).unwrap();
                assert_eq!(
                    selected.uri, expected[index],
                    "hash not deterministic for key '{key}'"
                );
            }
        }
    }

    #[test]
    fn hash_distribution_across_destinations() {
        let group = DispatcherGroup::new(
            "hash-dist".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:node1.example.com", 5060, 1, 1),
                make_dest("sip:node2.example.com", 5061, 1, 1),
                make_dest("sip:node3.example.com", 5062, 1, 1),
            ],
        );

        let mut counts = HashMap::new();
        for index in 0..300 {
            let key = format!("unique-call-id-{index}");
            let selected = group.select(Some(&key), None).unwrap();
            *counts.entry(selected.uri.clone()).or_insert(0u32) += 1;
        }

        // All 3 destinations should receive at least some traffic
        assert_eq!(
            counts.len(),
            3,
            "not all destinations received traffic: {counts:?}"
        );
        for (uri, count) in &counts {
            assert!(*count >= 10, "{uri} only got {count} selections out of 300");
        }
    }

    #[test]
    fn hash_priority_failover() {
        let group = DispatcherGroup::new(
            "hash-failover".to_string(),
            Algorithm::Hash,
            vec![
                make_dest("sip:primary1.example.com", 5060, 1, 1),
                make_dest("sip:primary2.example.com", 5061, 1, 1),
                make_dest("sip:backup1.example.com", 5062, 1, 2),
                make_dest("sip:backup2.example.com", 5063, 1, 2),
            ],
        );

        let key = "sticky-call-id";

        // With primaries up, select from priority 1
        let primary_result = group.select(Some(key), None).unwrap();
        assert!(
            primary_result.uri.contains("primary"),
            "expected primary, got {}",
            primary_result.uri
        );

        // Mark all primaries down
        group.mark_down("sip:primary1.example.com");
        group.mark_down("sip:primary2.example.com");

        // Should failover to priority 2
        let backup_result = group.select(Some(key), None).unwrap();
        assert!(
            backup_result.uri.contains("backup"),
            "expected backup, got {}",
            backup_result.uri
        );

        // Hash should still be deterministic within the backup tier
        for _ in 0..10 {
            let again = group.select(Some(key), None).unwrap();
            assert_eq!(again.uri, backup_result.uri);
        }
    }

    // --- Round robin priority failover ---

    #[test]
    fn round_robin_priority_failover() {
        let group = DispatcherGroup::new(
            "rr-failover".to_string(),
            Algorithm::RoundRobin,
            vec![
                make_dest("sip:primary.example.com", 5060, 1, 1),
                make_dest("sip:backup1.example.com", 5061, 1, 2),
                make_dest("sip:backup2.example.com", 5062, 1, 2),
            ],
        );

        // Primary is up: should always select it (only one at priority 1)
        for _ in 0..5 {
            let selected = group.select(None, None).unwrap();
            assert_eq!(selected.uri, "sip:primary.example.com");
        }

        // Mark primary down
        group.mark_down("sip:primary.example.com");

        // Now should round-robin through backups
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10 {
            let selected = group.select(None, None).unwrap();
            assert!(selected.uri.contains("backup"), "got {}", selected.uri);
            seen.insert(selected.uri.clone());
        }
        assert_eq!(seen.len(), 2, "should cycle through both backups");
    }

    // --- Edge cases ---

    #[test]
    fn select_with_empty_group() {
        let group = DispatcherGroup::new("empty".to_string(), Algorithm::Weighted, vec![]);

        assert!(group.select(None, None).is_none());
        assert!(group.select(Some("any-key"), None).is_none());

        // Also verify through manager
        let manager = DispatcherManager::new();
        manager.add_group(group);
        assert!(manager.select("empty", None, None).is_none());
    }

    // --- Failure tracking ---

    #[test]
    fn record_failure_threshold_behavior() {
        let destination = Destination::new(
            "sip:fragile.example.com".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            1,
            1,
        );

        assert!(destination.is_healthy());

        // Accumulate failures — destination stays healthy (prober decides when to mark down)
        let count1 = destination.record_failure();
        assert_eq!(count1, 1);
        assert!(destination.is_healthy());

        let count2 = destination.record_failure();
        assert_eq!(count2, 2);

        let count3 = destination.record_failure();
        assert_eq!(count3, 3);

        // Simulate what the prober does: mark down after threshold
        let threshold = 3;
        if count3 >= threshold {
            destination.mark_down();
        }
        assert!(!destination.is_healthy());
    }

    #[test]
    fn record_success_resets_failures() {
        let destination = Destination::new(
            "sip:recoverable.example.com".to_string(),
            "10.0.0.1:5060".parse().unwrap(),
            Transport::Udp,
            1,
            1,
        );

        // Accumulate some failures
        destination.record_failure();
        destination.record_failure();
        assert_eq!(destination.failures.load(Ordering::Relaxed), 2);

        // Mark down explicitly (as prober would)
        destination.mark_down();
        assert!(!destination.is_healthy());

        // record_success resets everything
        destination.record_success();
        assert!(destination.is_healthy());
        assert_eq!(destination.failures.load(Ordering::Relaxed), 0);

        // Further failures start from 0
        let count = destination.record_failure();
        assert_eq!(count, 1);
    }

    // --- extract_address_from_uri ---

    #[test]
    fn extract_address_strips_sip_scheme() {
        assert_eq!(
            extract_address_from_uri("sip:gw.example.com:5060"),
            "gw.example.com:5060"
        );
    }

    #[test]
    fn extract_address_strips_uri_params() {
        assert_eq!(
            extract_address_from_uri("sip:gw.example.com:5061;transport=tls"),
            "gw.example.com:5061"
        );
    }

    #[test]
    fn extract_address_strips_multiple_params() {
        assert_eq!(
            extract_address_from_uri("sip:gw.example.com:5060;transport=tcp;lr"),
            "gw.example.com:5060"
        );
    }

    #[test]
    fn extract_address_strips_user_part() {
        assert_eq!(
            extract_address_from_uri("sip:trunk@gw.example.com:5060"),
            "gw.example.com:5060"
        );
    }

    #[test]
    fn extract_address_default_port_sip() {
        assert_eq!(
            extract_address_from_uri("sip:gw.example.com"),
            "gw.example.com:5060"
        );
    }

    #[test]
    fn extract_address_default_port_sips() {
        assert_eq!(
            extract_address_from_uri("sips:gw.example.com"),
            "gw.example.com:5061"
        );
    }

    #[test]
    fn extract_address_sips_with_params() {
        assert_eq!(
            extract_address_from_uri("sips:gw.example.com;transport=tls"),
            "gw.example.com:5061"
        );
    }

    #[test]
    fn extract_address_bare_ip_port() {
        assert_eq!(
            extract_address_from_uri("10.0.0.1:5060"),
            "10.0.0.1:5060"
        );
    }

    // --- resolve_address ---

    #[test]
    fn resolve_address_parses_ip_port() {
        let addr = resolve_address("127.0.0.1:5060").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1:5060");
    }

    #[test]
    fn resolve_address_rejects_garbage() {
        assert!(resolve_address("not_valid").is_err());
    }

    // --- Member-IP set / source membership (from_gateway backing store) ---

    #[test]
    fn member_ips_populated_from_static_ip_destinations() {
        // make_dest builds destinations at 10.0.0.1:<port> with no
        // address_str, so the floor (address().ip()) is the only source.
        let group = DispatcherGroup::new(
            "static".to_string(),
            Algorithm::Weighted,
            vec![
                make_dest("sip:gw1.example.com", 5060, 1, 1),
                make_dest("sip:gw2.example.com", 5061, 1, 1),
            ],
        );
        // Constructor already called refresh_member_ips().
        assert!(group.contains_source("10.0.0.1".parse().unwrap()));
        // RFC 5737 TEST-NET-1 — never a member here.
        assert!(!group.contains_source("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn member_ips_resolve_hostname_candidates() {
        // Floor is RFC 5737 TEST-NET-2; the hostname resolves to loopback.
        // Seeing 127.0.0.1 in the set proves resolution ran (not the floor).
        let dest = Destination::new(
            "sip:local.example.com".to_string(),
            "198.51.100.1:5060".parse().unwrap(),
            Transport::Udp,
            1,
            1,
        )
        .with_address_str("localhost:5060".to_string());
        let group =
            DispatcherGroup::new("local".to_string(), Algorithm::Weighted, vec![dest]);

        assert!(
            group.contains_source("127.0.0.1".parse().unwrap()),
            "localhost should resolve to 127.0.0.1"
        );
        // Floor is always present too.
        assert!(group.contains_source("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn contains_source_ignores_port() {
        // Membership is IP-only; the source port never enters the set.
        let group = DispatcherGroup::new(
            "static".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 12345, 1, 1)],
        );
        assert!(group.contains_source("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn source_in_group_matches_and_rejects() {
        let manager = DispatcherManager::new();
        manager.add_group(DispatcherGroup::new(
            "trunks".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        ));

        assert!(manager.source_in_group("trunks", "10.0.0.1".parse().unwrap()));
        assert!(!manager.source_in_group("trunks", "192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn source_in_group_unknown_group_is_false() {
        let manager = DispatcherManager::new();
        manager.add_group(DispatcherGroup::new(
            "trunks".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        ));
        // Unknown group must never raise — it returns false.
        assert!(!manager.source_in_group("nonexistent", "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn refresh_member_ips_tracks_address_change() {
        let group = DispatcherGroup::new(
            "static".to_string(),
            Algorithm::Weighted,
            vec![make_dest("sip:gw1.example.com", 5060, 1, 1)],
        );
        assert!(group.contains_source("10.0.0.1".parse().unwrap()));

        // Simulate a DNS re-resolution to a new IP (as probe_destination does),
        // then re-run the refresh the probe cycle would trigger.
        group.all_destinations()[0].set_address("203.0.113.7:5060".parse().unwrap());
        group.refresh_member_ips();
        assert!(group.contains_source("203.0.113.7".parse().unwrap()));
    }
}
