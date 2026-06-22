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
}

impl AutoBanStore {
    /// Build a store from the `failed_auth_ban` policy and `trusted_cidrs`.
    /// Invalid CIDRs in `trusted_cidrs` are ignored (logged by the caller).
    pub fn new(
        threshold: u32,
        window_secs: u32,
        ban_duration_secs: u32,
        trusted_cidrs: &[String],
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
        }
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Record one failure for `source`. Returns `true` if this call newly banned
    /// the IP (so the caller can log/metric the transition once).
    pub fn record_failure(&self, source: IpAddr) -> bool {
        self.record_failure_at(source, Instant::now())
    }

    fn record_failure_at(&self, source: IpAddr, now: Instant) -> bool {
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
            entry.count += 1;
            entry.count >= self.threshold
            // `entry` (shard write guard) dropped here, before we touch `bans`
            // or `failures` again — never hold a DashMap guard across another
            // op on the same map.
        };

        if newly_banned {
            self.failures.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
        }
        newly_banned
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

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_failures() {
        let store = AutoBanStore::new(3, 600, 3600, &[]);
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
        let store = AutoBanStore::new(3, 600, 3600, &[]);
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
        let store = AutoBanStore::new(2, 600, 3600, &["10.0.0.0/8".to_string()]);
        let source = ip("10.1.2.3");
        for _ in 0..10 {
            assert!(!store.record_failure(source));
        }
        assert!(!store.is_banned(source));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn window_rolls_so_slow_failures_do_not_ban() {
        let store = AutoBanStore::new(3, 600, 3600, &[]);
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
        let store = AutoBanStore::new(1, 600, 60, &[]);
        let source = ip("203.0.113.10");
        let t0 = Instant::now();
        assert!(store.record_failure_at(source, t0)); // threshold 1 -> immediate ban
        assert!(store.is_banned_at(source, t0 + Duration::from_secs(30)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(61))); // expired
    }

    #[test]
    fn prune_drops_expired_entries() {
        let store = AutoBanStore::new(1, 600, 60, &[]);
        let source = ip("203.0.113.11");
        let t0 = Instant::now();
        store.record_failure_at(source, t0);
        assert_eq!(store.active_bans(), 1);
        store.prune_at(t0 + Duration::from_secs(61));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn already_banned_failure_is_noop() {
        let store = AutoBanStore::new(1, 600, 3600, &[]);
        let source = ip("203.0.113.12");
        assert!(store.record_failure(source)); // ban
        assert!(!store.record_failure(source)); // already banned -> not "newly banned"
        assert!(store.is_banned(source));
    }
}
