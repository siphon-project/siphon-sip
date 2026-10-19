//! The request filter: per-source rate limiting (`rate_limit`) and scanner
//! `User-Agent` blocking (`scanner_block`), with a policy a config reload
//! swaps.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::trust::SourceTrust;
use super::{FailureWindow, SecurityVerdict};

/// The `rate_limit` policy: a source sending more than `max_requests` within
/// `window` is banned for `ban_duration`. Replaces the Kamailio PIKE module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitPolicy {
    max_requests: u32,
    window: Duration,
    ban_duration: Duration,
}

impl RateLimitPolicy {
    fn from_config(config: &crate::config::RateLimitConfig) -> Self {
        Self {
            // Guard against a zero policy permitting nothing / dividing by zero.
            max_requests: config.max_requests.max(1),
            window: Duration::from_secs(u64::from(config.window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(config.ban_duration_secs.max(1))),
        }
    }
}

/// What [`SecurityFilter`] enforces, swapped whole by a config reload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct FilterPolicy {
    /// `None` when `rate_limit` is not configured.
    rate_limit: Option<RateLimitPolicy>,
    /// Lower-cased `User-Agent` substrings to block. Empty = scanner blocking off.
    scanner_user_agents: Vec<String>,
    /// The shared `trusted_cidrs` list as of this snapshot, carried here so a
    /// request costs one load, not one for the policy and one for the list.
    /// Derived: [`SecurityFilter::refresh_trusted`] re-stores the snapshot
    /// whenever the shared [`super::trust::TrustedCidrs`] is swapped.
    trusted: Arc<Vec<ipnet::IpNet>>,
}

impl FilterPolicy {
    fn from_config(
        config: &crate::config::SecurityConfig,
        trusted: Arc<Vec<ipnet::IpNet>>,
    ) -> Self {
        Self {
            trusted,
            rate_limit: config.rate_limit.as_ref().map(RateLimitPolicy::from_config),
            scanner_user_agents: config
                .scanner_block
                .as_ref()
                .map(|block| {
                    block
                        .user_agents
                        .iter()
                        .map(|agent| agent.to_lowercase())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn is_off(&self) -> bool {
        self.rate_limit.is_none() && self.scanner_user_agents.is_empty()
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
}

/// The per-source tables behind `rate_limit`. Kept across a policy change, so
/// a new threshold applies from the next request and a ban keeps its expiry.
#[derive(Default)]
pub(super) struct RateLimitState {
    /// IP → current request-count window.
    windows: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    /// IP → request-count window for gateway sources exempted by
    /// `trust_gateways`. Counted apart from `windows` so the only thing it can
    /// do is say, once per window, that a carrier went over the limit it is
    /// exempt from — and so a carrier removed from the source starts back
    /// under the policy at zero rather than with the count it ran up while
    /// trusted. Pruned with the rest; one row per busy gateway at most.
    exempt_windows: DashMap<IpAddr, FailureWindow>,
}

impl RateLimitState {
    /// Count one request from `source`. Returns `true` when the request is
    /// within the limit, `false` when the source is over the limit (and now
    /// banned) or already inside an active ban.
    fn check_at(&self, policy: &RateLimitPolicy, source: IpAddr, now: Instant) -> bool {
        // Active ban? (Copy the expiry out before any mutation so we never hold
        // a DashMap shard guard across a second op on the same map.)
        //
        // Deliberately NOT the sliding expiry [`AutoBanStore`] uses, and the
        // asymmetry is the design, not an oversight. A rate-limit ban is a
        // capacity verdict — "this source is asking for more than its share" —
        // where the auto-ban's is an abuse verdict. Extending on every request
        // during the ban would mean a legitimate client that retries on a timer
        // (and behind CGNAT, one client speaking for a whole NAT) could never
        // serve out its ban. Fixed duration here; sliding only where the signal
        // is evidence of intent.
        let ban_expiry = self.bans.get(&source).map(|entry| *entry.value());
        match ban_expiry {
            Some(expiry) if expiry > now => return false,
            Some(_) => {
                self.bans.remove(&source);
            }
            None => {}
        }

        let over_limit = {
            let mut entry = self.windows.entry(source).or_insert(FailureWindow {
                count: 0,
                window_start: now,
            });
            if now.duration_since(entry.window_start) > policy.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            entry.count > policy.max_requests
            // shard write guard dropped here, before touching `bans`/`windows`.
        };

        if over_limit {
            self.windows.remove(&source);
            self.bans.insert(source, now + policy.ban_duration);
            return false;
        }
        true
    }

    /// Count one request from an exempt gateway source. Returns `true` exactly
    /// once per window: on the request that takes it past the limit. Never
    /// bans and never drops.
    fn count_exempt_at(&self, policy: &RateLimitPolicy, source: IpAddr, now: Instant) -> bool {
        let mut entry = self.exempt_windows.entry(source).or_insert(FailureWindow {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) > policy.window {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count = entry.count.saturating_add(1);
        entry.count == policy.max_requests.saturating_add(1)
    }

    fn prune_at(&self, window: Duration, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.windows
            .retain(|_, entry| now.duration_since(entry.window_start) <= window);
        self.exempt_windows
            .retain(|_, entry| now.duration_since(entry.window_start) <= window);
    }

    fn clear(&self) {
        self.bans.clear();
        self.windows.clear();
        self.exempt_windows.clear();
    }

    /// Lift bans and windows on every source inside `trusted`.
    fn lift_trusted(&self, trusted: &[ipnet::IpNet]) {
        let outside = |source: &IpAddr| !trusted.iter().any(|network| network.contains(source));
        self.bans.retain(|source, _| outside(source));
        self.windows.retain(|source, _| outside(source));
    }

    /// Rows held across the three maps. Test-only: each is keyed by a live
    /// source, so all three must drain once their windows lapse.
    #[cfg(test)]
    pub(super) fn tracked_sources(&self) -> (usize, usize, usize) {
        (
            self.windows.len(),
            self.bans.len(),
            self.exempt_windows.len(),
        )
    }
}

/// Request-level security filter: per-source rate limiting (`rate_limit`) plus
/// scanner User-Agent blocking (`scanner_block`), both bypassed for
/// `trusted_cidrs`. Consulted by the dispatcher before any request processing.
///
/// The whole feature is opt-in: [`SecurityFilter::from_config`] returns `None`
/// unless at least one of `rate_limit` / `scanner_block` is configured. Once
/// installed it stays installed; a reload that removes both leaves it with a
/// policy that allows everything.
pub struct SecurityFilter {
    /// Thresholds, window, ban length and scanner list, swapped by
    /// `POST /admin/config/reload`. Loaded once per request.
    pub(super) policy: arc_swap::ArcSwap<FilterPolicy>,
    /// Per-source rate-limit tables, empty while `rate_limit` is off.
    pub(super) rate: RateLimitState,
    /// Sources exempt from both rate limiting and scanner blocking (own
    /// infrastructure: AS, trunks, monitoring — and gateways, under
    /// `trust_gateways`).
    trust: SourceTrust,
}

impl SecurityFilter {
    /// Build a filter from the `security` config block. Returns `None` when
    /// neither `rate_limit` nor `scanner_block` is set (feature is opt-in, so
    /// the dispatcher check is a no-op). Invalid `trusted_cidrs` are ignored.
    pub fn from_config(config: &crate::config::SecurityConfig) -> Option<Arc<Self>> {
        Self::from_config_with_gateways(config, None)
    }

    /// [`Self::from_config`], also exempting every source `gateways` admits —
    /// what start-up passes when `security.trust_gateways` is on.
    pub fn from_config_with_gateways(
        config: &crate::config::SecurityConfig,
        gateways: Option<Arc<crate::gateway::view::GatewayView>>,
    ) -> Option<Arc<Self>> {
        Self::from_config_with_trust(
            config,
            SourceTrust::from_cidrs(&config.trusted_cidrs).with_gateways(gateways),
        )
    }

    /// [`Self::from_config`], exempting what `trust` exempts.
    pub fn from_config_with_trust(
        config: &crate::config::SecurityConfig,
        trust: SourceTrust,
    ) -> Option<Arc<Self>> {
        let policy = FilterPolicy::from_config(config, trust.configured_snapshot());
        if policy.is_off() {
            return None;
        }
        Some(Arc::new(Self {
            policy: arc_swap::ArcSwap::from_pointee(policy),
            rate: RateLimitState::default(),
            trust,
        }))
    }

    /// Enforce what `config` says from the next request on. The rate-limit
    /// tables are kept (a ban keeps its expiry) unless `rate_limit` is gone,
    /// which clears them.
    pub fn set_policy(&self, config: &crate::config::SecurityConfig) {
        let policy = FilterPolicy::from_config(config, self.trust.configured_snapshot());
        let clear = policy.rate_limit.is_none();
        self.policy.store(Arc::new(policy));
        if clear {
            self.rate.clear();
        }
    }

    /// Stop both checks and drop the rate-limit tables: what removing
    /// `rate_limit` and `scanner_block` means.
    pub fn disable(&self) {
        self.policy.store(Arc::new(FilterPolicy {
            trusted: self.trust.configured_snapshot(),
            ..FilterPolicy::default()
        }));
        self.rate.clear();
    }

    /// Re-read the shared `trusted_cidrs` list into the policy snapshot.
    /// Called after the list is swapped, so the next request sees it.
    pub fn refresh_trusted(&self) {
        let current = self.policy.load_full();
        self.policy.store(Arc::new(FilterPolicy {
            trusted: self.trust.configured_snapshot(),
            ..(*current).clone()
        }));
    }

    /// Whether either check is in force.
    pub fn is_enabled(&self) -> bool {
        !self.policy.load().is_off()
    }

    /// Lift rate-limit bans and windows on every source `trusted` now holds.
    pub fn lift_trusted(&self, trusted: &[ipnet::IpNet]) {
        self.rate.lift_trusted(trusted);
    }

    /// Evaluate one inbound request from `source` carrying `user_agent`. Trusted
    /// sources always pass. Scanner blocking is checked before the rate limit so
    /// a flood of scanner traffic doesn't burn a rate-limit ban slot it doesn't
    /// need.
    pub fn evaluate(&self, source: IpAddr, user_agent: Option<&str>) -> SecurityVerdict {
        self.evaluate_at(source, user_agent, Instant::now())
    }

    pub(super) fn evaluate_at(
        &self,
        source: IpAddr,
        user_agent: Option<&str>,
        now: Instant,
    ) -> SecurityVerdict {
        let policy = self.policy.load();
        if policy.is_off() {
            return SecurityVerdict::Allow;
        }
        if policy
            .trusted
            .iter()
            .any(|network| network.contains(&source))
        {
            return SecurityVerdict::Allow;
        }
        if self.trust.is_gateway(source) {
            self.note_exempt_gateway(&policy, source, now);
            return SecurityVerdict::Allow;
        }
        if policy.is_scanner(user_agent) {
            return SecurityVerdict::Scanner;
        }
        if let Some(ref rate) = policy.rate_limit {
            if !self.rate.check_at(rate, source, now) {
                return SecurityVerdict::RateLimited;
            }
        }
        SecurityVerdict::Allow
    }

    /// Count a request from a gateway that `trust_gateways` exempts, and say so
    /// once per window when it goes over the limit that would otherwise have
    /// dropped it and banned it. Nothing else: the request is allowed.
    fn note_exempt_gateway(&self, policy: &FilterPolicy, source: IpAddr, now: Instant) {
        let Some(ref rate) = policy.rate_limit else {
            return;
        };
        if self.rate.count_exempt_at(rate, source, now) {
            let group = self.trust.gateways().and_then(|view| view.group_of(source));
            tracing::warn!(
                source = %source,
                gateway_group = %group.as_deref().unwrap_or("-"),
                max_requests = rate.max_requests,
                window_secs = rate.window.as_secs(),
                "rate_limit: gateway source is over the limit and not dropped (security.trust_gateways)"
            );
        }
    }

    /// Drop expired rate-limit bans and stale windows. Call periodically to keep
    /// memory bounded under scanner churn.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    pub(super) fn prune_at(&self, now: Instant) {
        match self.policy.load().rate_limit {
            Some(rate) => self.rate.prune_at(rate.window, now),
            None => self.rate.clear(),
        }
    }

    /// Number of currently-tracked rate-limit bans (0 when rate limiting is off).
    pub fn rate_limit_bans(&self) -> usize {
        self.rate.bans.len()
    }
}
