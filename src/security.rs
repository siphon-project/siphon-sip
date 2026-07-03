//! Auto-ban store — per-source-IP failure tracking with TTL bans.
//!
//! Feeds the transport ACL ([`crate::transport::acl::TransportAcl::is_allowed`])
//! so a banned source is dropped at accept/recv, before any SIP parsing. Two
//! failure signals increment the same per-IP counter:
//!   * an auth challenge issued without valid credentials ([`crate::script::api`]
//!     auth path), and
//!   * a non-ACK INVITE **server**-transaction timeout (dispatcher) — the peer
//!     sent an INVITE, got a final response, and never ACKed it.
//!
//! A successful authentication resets the counter, so a legitimate client that
//! challenges-then-succeeds never accumulates. Sources matching `trusted_cidrs`
//! are never counted and never banned (own infrastructure: BGCF, trunks,
//! monitoring).
//!
//! The whole feature is opt-in: it is only constructed when
//! `security.failed_auth_ban` is configured.

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ipnet::IpNet;

/// Process-wide auto-ban store. `None` until installed at startup (only when
/// `security.failed_auth_ban` is configured), so the whole feature is opt-in and
/// every hot-path check is a cheap `OnceLock` read. Mirrors
/// [`crate::metrics::try_metrics`].
static AUTO_BAN: OnceLock<Arc<AutoBanStore>> = OnceLock::new();

/// Install the process-wide auto-ban store (idempotent — a second call is a
/// no-op). Called once at server startup before any traffic is accepted.
pub fn set_auto_ban(store: Arc<AutoBanStore>) {
    let _ = AUTO_BAN.set(store);
}

/// The process-wide auto-ban store, or `None` when `security.failed_auth_ban`
/// is not configured. Read on the accept/recv path (ACL), the auth path, and the
/// transaction-timeout path.
pub fn auto_ban() -> Option<&'static Arc<AutoBanStore>> {
    AUTO_BAN.get()
}

/// Process-wide request-level security filter (PIKE-style per-source rate
/// limiting + scanner User-Agent blocking). `None` until installed at startup,
/// and only installed when `security.rate_limit` or `security.scanner_block` is
/// configured — so the dispatcher hot-path check is a cheap `OnceLock` read that
/// no-ops until the feature is turned on. Mirrors [`AUTO_BAN`].
static SECURITY_FILTER: OnceLock<Arc<SecurityFilter>> = OnceLock::new();

/// Install the process-wide request security filter (idempotent — a second call
/// is a no-op). Called once at server startup before any traffic is accepted.
pub fn set_security_filter(filter: Arc<SecurityFilter>) {
    let _ = SECURITY_FILTER.set(filter);
}

/// The process-wide request security filter, or `None` when neither
/// `security.rate_limit` nor `security.scanner_block` is configured. Read on the
/// dispatcher's inbound-request path before transaction/dialog processing.
pub fn security_filter() -> Option<&'static Arc<SecurityFilter>> {
    SECURITY_FILTER.get()
}

/// Record one failed/timed-out transport handshake (TLS / WSS TLS / WS upgrade)
/// from `source` as an auto-ban signal, and bump the handshake-failure metric.
///
/// Called from the TLS/WSS/WS accept paths when a handshake never completes.
/// Because all three run over TCP, `source` is validated by the TCP three-way
/// handshake (no UDP-style spoofing), making a failed handshake one of the
/// highest-confidence ban signals available — a legitimate SIP client never
/// fails the handshake this way (it sends sig-algs, a usable cipher suite, a
/// well-formed `Sec-WebSocket-Protocol`). The metric is always counted (so
/// scanner volume is visible even before bans are turned on); the ban itself is
/// a no-op until `security.failed_auth_ban` is configured, and `trusted_cidrs`
/// are exempt inside the store. `transport` only labels the ban-transition log.
pub fn record_handshake_failure(source: IpAddr, transport: &str) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.handshake_failures_total.inc();
    }
    if let Some(ban) = auto_ban() {
        if ban.record_failure(source) {
            tracing::warn!(
                source = %source,
                transport,
                "auto-ban: source banned (repeated handshake failures)"
            );
        }
    }
}

/// Record one non-SIP / unparseable message from `source` on a stream transport
/// (`transport` = "TCP" / "TLS") as a high-confidence auto-ban signal, and bump
/// the malformed-message metric.
///
/// Called from the TCP/TLS read loop only when the accumulated bytes are a
/// *definite* non-SIP attempt — never for an incomplete-but-plausible SIP frame
/// still arriving, never for an empty connection (an AWS NLB / load-balancer TCP
/// health check opens and closes without data), and never for a CRLF keepalive
/// (RFC 5626 §4.4.1), all of which are drained/filtered before this is reached.
/// Because the bytes arrived over a completed TCP handshake the source IP is
/// validated (no UDP-style spoofing), so this is weighted as a strong signal.
pub fn record_malformed_message(source: IpAddr, transport: &str) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.malformed_messages_total.inc();
    }
    if let Some(ban) = auto_ban() {
        if ban.record_strong_failure(source) {
            tracing::warn!(
                source = %source,
                transport,
                "auto-ban: source banned (non-SIP bytes on stream)"
            );
        }
    }
}

/// Fixed-window failure counter for one source IP.
#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    count: u32,
    window_start: Instant,
}

/// Per-source-IP auto-ban store. Cheap, lock-free reads (DashMap), `Send + Sync`,
/// shared as an `Arc` between the transport ACL, the auth path, and the dispatcher.
pub struct AutoBanStore {
    /// IP → current failure window.
    failures: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    /// Sources that are never counted and never banned.
    trusted: Vec<IpNet>,
    threshold: u32,
    window: Duration,
    ban_duration: Duration,
    /// Failure weight applied by [`Self::record_strong_failure`] — how many
    /// counts a single high-confidence abuse signal (present-but-invalid
    /// credentials, forged/stale/replayed nonce, non-SIP garbage on a stream,
    /// scanner User-Agent) contributes toward `threshold`. A weight > 1 bans
    /// these unambiguous signals faster than a bare scanning probe (weight 1)
    /// while reusing the single per-IP window. Always ≥ 1.
    strong_weight: u32,
    /// Optional kernel-firewall handle. When wired, every new ban is also
    /// pushed to the nf_tables set so the source is dropped pre-userspace.
    firewall: OnceLock<crate::firewall::KernelFirewall>,
}

impl AutoBanStore {
    /// Build a store from the `failed_auth_ban` policy and `trusted_cidrs`.
    /// Invalid CIDRs in `trusted_cidrs` are ignored (logged by the caller).
    pub fn new(
        threshold: u32,
        window_secs: u32,
        ban_duration_secs: u32,
        trusted_cidrs: &[String],
        strong_weight: u32,
    ) -> Self {
        let trusted = trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            trusted,
            // Guard against a zero policy disabling the feature by accident.
            threshold: threshold.max(1),
            window: Duration::from_secs(u64::from(window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(ban_duration_secs.max(1))),
            strong_weight: strong_weight.max(1),
            firewall: OnceLock::new(),
        }
    }

    /// Attach a kernel-firewall handle so new bans are also programmed into the
    /// nf_tables set. Called once at startup; a second call is a no-op.
    pub fn set_firewall(&self, firewall: crate::firewall::KernelFirewall) {
        let _ = self.firewall.set(firewall);
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Record one low-confidence failure for `source` (weight 1) — a signal that
    /// could occasionally fire for a benign peer: an auth challenge without
    /// credentials (the legitimate first leg of challenge-response), a non-ACK
    /// INVITE server-transaction timeout, a failed transport handshake. Returns
    /// `true` if this call newly banned the IP (so the caller can log/metric the
    /// transition once).
    pub fn record_failure(&self, source: IpAddr) -> bool {
        self.record_failure_weighted_at(source, 1, Instant::now())
    }

    /// Record one high-confidence abuse signal for `source`, weighted by
    /// `strong_weight` so it bans faster than a bare probe: present-but-invalid
    /// credentials (wrong password), a forged/stale/replayed digest nonce,
    /// non-SIP garbage on a stream transport, or a scanner User-Agent. A
    /// legitimate client never produces these (a stale-nonce retry is reset by
    /// the subsequent [`Self::record_success`]). Returns `true` if this call
    /// newly banned the IP.
    pub fn record_strong_failure(&self, source: IpAddr) -> bool {
        self.record_failure_weighted_at(source, self.strong_weight, Instant::now())
    }

    fn record_failure_weighted_at(&self, source: IpAddr, weight: u32, now: Instant) -> bool {
        if self.is_trusted(source) {
            return false;
        }
        if self.is_banned_at(source, now) {
            // Already banned — nothing to escalate.
            return false;
        }

        let newly_banned = {
            let mut entry = self
                .failures
                .entry(source)
                .or_insert(FailureWindow { count: 0, window_start: now });
            // Roll the window if it has elapsed.
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count = entry.count.saturating_add(weight);
            entry.count >= self.threshold
            // `entry` (shard write guard) dropped here, before we touch `bans`
            // or `failures` again — never hold a DashMap guard across another
            // op on the same map.
        };

        if newly_banned {
            self.failures.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
            // Mirror the ban into the kernel firewall (nf_tables) if wired, so
            // the source is dropped before it reaches siphon's socket. The
            // kernel element carries the same TTL as the in-memory ban, so both
            // expire in lockstep. Non-blocking (drops silently if the actor
            // queue is full — the userspace ACL still enforces the ban).
            if let Some(firewall) = self.firewall.get() {
                firewall.ban(source, self.ban_duration);
            }
        }
        newly_banned
    }

    /// Test-only weight-1 shim preserving the pre-weighting call shape.
    #[cfg(test)]
    fn record_failure_at(&self, source: IpAddr, now: Instant) -> bool {
        self.record_failure_weighted_at(source, 1, now)
    }

    /// A successful authentication from `source` clears its failure count.
    pub fn record_success(&self, source: IpAddr) {
        self.failures.remove(&source);
    }

    /// Whether `source` is currently banned. Trusted sources are never banned.
    /// Expired bans are lazily removed.
    pub fn is_banned(&self, source: IpAddr) -> bool {
        self.is_banned_at(source, Instant::now())
    }

    fn is_banned_at(&self, source: IpAddr, now: Instant) -> bool {
        if self.is_trusted(source) {
            return false;
        }
        // Copy the expiry out so we never hold the shard read guard across the
        // `remove()` below (would deadlock on the same shard).
        let expiry = self.bans.get(&source).map(|entry| *entry.value());
        match expiry {
            Some(exp) if exp > now => true,
            Some(_) => {
                self.bans.remove(&source);
                false
            }
            None => false,
        }
    }

    /// Number of currently-tracked bans (may include not-yet-pruned expired
    /// entries; published as a metric and pruned periodically).
    pub fn active_bans(&self) -> usize {
        self.bans.len()
    }

    /// Drop expired bans and stale failure windows. Call periodically to keep
    /// memory bounded under scanner churn.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.failures
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Verdict for one inbound request, returned by [`SecurityFilter::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerdict {
    /// Source is permitted — proceed to transaction/dialog/script processing.
    Allow,
    /// Source's `User-Agent` matched a `security.scanner_block` signature —
    /// drop silently (no response) so the server is not fingerprinted.
    Scanner,
    /// Source exceeded `security.rate_limit.max_requests` within the window (or
    /// is inside the resulting ban) — drop silently.
    RateLimited,
}

/// Fixed-window per-source-IP rate limiter with TTL bans. Replaces the Kamailio
/// PIKE module: once a source sends more than `max_requests` within `window`, it
/// is banned for `ban_duration` and every further request is dropped until the
/// ban expires.
struct RateLimitState {
    /// IP → current request-count window.
    windows: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    max_requests: u32,
    window: Duration,
    ban_duration: Duration,
}

impl RateLimitState {
    /// Count one request from `source`. Returns `true` when the request is
    /// within the limit, `false` when the source is over the limit (and now
    /// banned) or already inside an active ban.
    fn check_at(&self, source: IpAddr, now: Instant) -> bool {
        // Active ban? (Copy the expiry out before any mutation so we never hold
        // a DashMap shard guard across a second op on the same map.)
        let ban_expiry = self.bans.get(&source).map(|entry| *entry.value());
        match ban_expiry {
            Some(expiry) if expiry > now => return false,
            Some(_) => {
                self.bans.remove(&source);
            }
            None => {}
        }

        let over_limit = {
            let mut entry = self
                .windows
                .entry(source)
                .or_insert(FailureWindow { count: 0, window_start: now });
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            entry.count > self.max_requests
            // shard write guard dropped here, before touching `bans`/`windows`.
        };

        if over_limit {
            self.windows.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
            return false;
        }
        true
    }

    fn active_bans(&self) -> usize {
        self.bans.len()
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.windows
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Request-level security filter: per-source rate limiting (`rate_limit`) plus
/// scanner User-Agent blocking (`scanner_block`), both bypassed for
/// `trusted_cidrs`. Consulted by the dispatcher before any request processing.
///
/// The whole feature is opt-in: [`SecurityFilter::from_config`] returns `None`
/// unless at least one of `rate_limit` / `scanner_block` is configured.
pub struct SecurityFilter {
    /// Per-source rate limiter — `None` when `rate_limit` is not configured.
    rate_limit: Option<RateLimitState>,
    /// Lower-cased `User-Agent` substrings to block. Empty = scanner blocking off.
    scanner_user_agents: Vec<String>,
    /// Sources exempt from both rate limiting and scanner blocking (own
    /// infrastructure: AS, trunks, monitoring).
    trusted: Vec<IpNet>,
}

impl SecurityFilter {
    /// Build a filter from the `security` config block. Returns `None` when
    /// neither `rate_limit` nor `scanner_block` is set (feature is opt-in, so
    /// the dispatcher check is a no-op). Invalid `trusted_cidrs` are ignored.
    pub fn from_config(config: &crate::config::SecurityConfig) -> Option<Arc<Self>> {
        let rate_limit = config.rate_limit.as_ref().map(|policy| RateLimitState {
            windows: DashMap::new(),
            bans: DashMap::new(),
            // Guard against a zero policy permitting nothing / dividing by zero.
            max_requests: policy.max_requests.max(1),
            window: Duration::from_secs(u64::from(policy.window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(policy.ban_duration_secs.max(1))),
        });

        let scanner_user_agents: Vec<String> = config
            .scanner_block
            .as_ref()
            .map(|block| {
                block
                    .user_agents
                    .iter()
                    .map(|agent| agent.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        if rate_limit.is_none() && scanner_user_agents.is_empty() {
            return None;
        }

        let trusted = config
            .trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();

        Some(Arc::new(Self {
            rate_limit,
            scanner_user_agents,
            trusted,
        }))
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Whether `user_agent` matches a configured scanner signature
    /// (case-insensitive substring — sipvicious advertises `friendly-scanner`).
    fn is_scanner(&self, user_agent: Option<&str>) -> bool {
        if self.scanner_user_agents.is_empty() {
            return false;
        }
        match user_agent {
            Some(agent) => {
                let agent = agent.to_lowercase();
                self.scanner_user_agents
                    .iter()
                    .any(|needle| agent.contains(needle))
            }
            None => false,
        }
    }

    /// Evaluate one inbound request from `source` carrying `user_agent`. Trusted
    /// sources always pass. Scanner blocking is checked before the rate limit so
    /// a flood of scanner traffic doesn't burn a rate-limit ban slot it doesn't
    /// need.
    pub fn evaluate(&self, source: IpAddr, user_agent: Option<&str>) -> SecurityVerdict {
        self.evaluate_at(source, user_agent, Instant::now())
    }

    fn evaluate_at(
        &self,
        source: IpAddr,
        user_agent: Option<&str>,
        now: Instant,
    ) -> SecurityVerdict {
        if self.is_trusted(source) {
            return SecurityVerdict::Allow;
        }
        if self.is_scanner(user_agent) {
            return SecurityVerdict::Scanner;
        }
        if let Some(ref rate) = self.rate_limit {
            if !rate.check_at(source, now) {
                return SecurityVerdict::RateLimited;
            }
        }
        SecurityVerdict::Allow
    }

    /// Drop expired rate-limit bans and stale windows. Call periodically to keep
    /// memory bounded under scanner churn. No-op when rate limiting is off.
    pub fn prune(&self) {
        if let Some(ref rate) = self.rate_limit {
            rate.prune_at(Instant::now());
        }
    }

    /// Number of currently-tracked rate-limit bans (0 when rate limiting is off).
    pub fn rate_limit_bans(&self) -> usize {
        self.rate_limit.as_ref().map_or(0, RateLimitState::active_bans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_failures() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1);
        let source = ip("203.0.113.7");
        assert!(!store.record_failure(source)); // 1
        assert!(!store.record_failure(source)); // 2
        assert!(!store.is_banned(source));
        assert!(store.record_failure(source)); // 3 -> ban, returns true
        assert!(store.is_banned(source));
        assert_eq!(store.active_bans(), 1);
    }

    #[test]
    fn success_resets_the_counter() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1);
        let source = ip("203.0.113.8");
        store.record_failure(source);
        store.record_failure(source);
        store.record_success(source); // legit auth — wipe the count
        store.record_failure(source);
        store.record_failure(source);
        assert!(!store.is_banned(source)); // only 2 since reset
        assert!(store.record_failure(source)); // now 3 -> ban
    }

    #[test]
    fn trusted_cidr_never_banned() {
        let store = AutoBanStore::new(2, 600, 3600, &["10.0.0.0/8".to_string()], 1);
        let source = ip("10.1.2.3");
        for _ in 0..10 {
            assert!(!store.record_failure(source));
        }
        assert!(!store.is_banned(source));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn window_rolls_so_slow_failures_do_not_ban() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1);
        let source = ip("203.0.113.9");
        let t0 = Instant::now();
        assert!(!store.record_failure_at(source, t0));
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(10)));
        // Past the window — counter rolls, so this is "1" again, not "3".
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(700)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(700)));
    }

    #[test]
    fn ban_expires_after_ttl() {
        let store = AutoBanStore::new(1, 600, 60, &[], 1);
        let source = ip("203.0.113.10");
        let t0 = Instant::now();
        assert!(store.record_failure_at(source, t0)); // threshold 1 -> immediate ban
        assert!(store.is_banned_at(source, t0 + Duration::from_secs(30)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(61))); // expired
    }

    #[test]
    fn prune_drops_expired_entries() {
        let store = AutoBanStore::new(1, 600, 60, &[], 1);
        let source = ip("203.0.113.11");
        let t0 = Instant::now();
        store.record_failure_at(source, t0);
        assert_eq!(store.active_bans(), 1);
        store.prune_at(t0 + Duration::from_secs(61));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn already_banned_failure_is_noop() {
        let store = AutoBanStore::new(1, 600, 3600, &[], 1);
        let source = ip("203.0.113.12");
        assert!(store.record_failure(source)); // ban
        assert!(!store.record_failure(source)); // already banned -> not "newly banned"
        assert!(store.is_banned(source));
    }

    #[test]
    fn strong_failures_ban_faster_than_plain_probes() {
        // threshold 6, strong weight 3: two high-confidence signals (3+3=6) ban,
        // while a plain probe (weight 1) needs the full six hits.
        let store = AutoBanStore::new(6, 600, 3600, &[], 3);

        let abuser = ip("203.0.113.30");
        assert!(!store.record_strong_failure(abuser)); // 3 < 6
        assert!(store.record_strong_failure(abuser)); // 6 -> ban
        assert!(store.is_banned(abuser));

        let prober = ip("203.0.113.31");
        for _ in 0..5 {
            assert!(!store.record_failure(prober)); // 1..=5 < 6
        }
        assert!(store.record_failure(prober)); // 6 -> ban
        assert!(store.is_banned(prober));
    }

    #[test]
    fn strong_weight_is_clamped_to_at_least_one() {
        // A misconfigured weight of 0 must not make strong signals free.
        let store = AutoBanStore::new(2, 600, 3600, &[], 0);
        let source = ip("203.0.113.32");
        assert!(!store.record_strong_failure(source)); // 1
        assert!(store.record_strong_failure(source)); // 2 -> ban
    }

    // --- record_handshake_failure (TLS/WSS/WS auto-ban signal) -------------
    //
    // This test owns the process-global AUTO_BAN OnceLock: no other test (and no
    // code outside server.rs startup) installs a store, so the install here is
    // deterministic within the lib test binary. It uses TEST-NET-2 addresses
    // (RFC 5737, 198.51.100.0/24) that no other test touches, so the lingering
    // global store cannot perturb the ACL/auth tests that share the binary.
    #[test]
    fn handshake_failures_feed_the_auto_ban_store_and_acl() {
        // Before any store is installed, the helper must be a cheap no-op and
        // never panic — the whole feature is off until failed_auth_ban is set.
        let never = ip("198.51.100.78");
        crate::security::record_handshake_failure(never, "TLS");

        // Install a low-threshold store (3 failures / 600 s window / 1 h ban).
        let store = Arc::new(AutoBanStore::new(3, 600, 3600, &[], 1));
        set_auto_ban(Arc::clone(&store));

        // Handshake failures accumulate per-IP across transports and ban at the
        // threshold — exactly like the auth / INVITE-timeout signals.
        let scanner = ip("198.51.100.77");
        crate::security::record_handshake_failure(scanner, "TLS");
        crate::security::record_handshake_failure(scanner, "TLS");
        assert!(!store.is_banned(scanner)); // 2 < threshold
        crate::security::record_handshake_failure(scanner, "WSS"); // 3rd -> ban
        assert!(store.is_banned(scanner));

        // The pre-install no-op IP never accrued a count.
        assert!(!store.is_banned(never));

        // End-to-end: the banned scanner is now dropped at transport accept by
        // the ACL (which consults the same global store), while an IP that never
        // failed a handshake still passes.
        let acl = crate::transport::acl::TransportAcl::new(vec![], vec![]);
        assert!(!acl.is_allowed(scanner));
        assert!(acl.is_allowed(never));
    }

    // --- SecurityFilter (rate_limit + scanner_block) -----------------------

    use crate::config::{RateLimitConfig, ScannerBlockConfig, SecurityConfig};

    fn security_config(
        rate_limit: Option<RateLimitConfig>,
        user_agents: Vec<&str>,
        trusted_cidrs: Vec<&str>,
    ) -> SecurityConfig {
        SecurityConfig {
            rate_limit,
            scanner_block: if user_agents.is_empty() {
                None
            } else {
                Some(ScannerBlockConfig {
                    user_agents: user_agents.into_iter().map(String::from).collect(),
                })
            },
            trusted_cidrs: trusted_cidrs.into_iter().map(String::from).collect(),
            failed_auth_ban: None,
            apiban: None,
            firewall: None,
        }
    }

    #[test]
    fn filter_opt_in_none_when_unconfigured() {
        // No rate_limit, no scanner_block -> feature stays off.
        let config = security_config(None, vec![], vec!["10.0.0.0/8"]);
        assert!(SecurityFilter::from_config(&config).is_none());
    }

    #[test]
    fn scanner_block_matches_case_insensitive_substring() {
        let config = security_config(None, vec!["sipvicious", "friendly-scanner"], vec![]);
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.20");

        // Exact, mixed-case, and substring-within-larger-UA all match.
        assert_eq!(
            filter.evaluate(source, Some("friendly-scanner")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("SIPVICIOUS")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("Mozilla sipvicious/0.3.0")),
            SecurityVerdict::Scanner
        );
        // A legit UA and a missing UA both pass.
        assert_eq!(
            filter.evaluate(source, Some("Acme-SIP/1.0")),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.evaluate(source, None), SecurityVerdict::Allow);
    }

    #[test]
    fn rate_limit_bans_after_max_requests() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.21");
        let t0 = Instant::now();

        // First 3 within the window pass.
        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // 4th trips the limit -> banned.
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        assert_eq!(filter.rate_limit_bans(), 1);
        // Still banned a moment later (well inside ban_duration).
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(5)),
            SecurityVerdict::RateLimited
        );
    }

    #[test]
    fn rate_limit_window_rolls() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.22");
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // Past the window — counter rolls, so this is request #1 again, not #4.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(11)),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn rate_limit_ban_expires() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.23");
        let t0 = Instant::now();

        assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        // After the ban TTL the source is allowed again.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(61)),
            SecurityVerdict::Allow
        );
    }

    #[test]
    fn trusted_cidr_bypasses_both_checks() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 3600,
            }),
            vec!["sipvicious"],
            vec!["10.0.0.0/8"],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let trusted = ip("10.1.2.3");
        let t0 = Instant::now();

        // Scanner UA from a trusted source is still allowed.
        assert_eq!(
            filter.evaluate_at(trusted, Some("sipvicious"), t0),
            SecurityVerdict::Allow
        );
        // And it never accrues a rate-limit ban no matter how many it sends.
        for _ in 0..50 {
            assert_eq!(
                filter.evaluate_at(trusted, None, t0),
                SecurityVerdict::Allow
            );
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn prune_drops_expired_rate_limit_bans() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.24");
        let now = Instant::now();
        filter.evaluate_at(source, None, now);
        filter.evaluate_at(source, None, now); // ban
        assert_eq!(filter.rate_limit_bans(), 1);
        if let Some(ref rate) = filter.rate_limit {
            rate.prune_at(now + Duration::from_secs(61));
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }
}
