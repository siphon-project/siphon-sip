//! The request filter: per-source rate limiting (`rate_limit`) and scanner
//! `User-Agent` blocking (`scanner_block`), with a policy a config reload
//! swaps.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
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
    /// Budget for the WARN raised with each ban.
    installed_log: BanLog,
    /// Budget for the INFO raised when a ban ends.
    lifted_log: BanLog,
}

/// Lines of each kind ([`BanLog`]) logged per [`BAN_LOG_WINDOW`] before the
/// rest are only counted.
pub(super) const BAN_LOG_BUDGET: u32 = 20;
/// The window [`BAN_LOG_BUDGET`] applies to.
pub(super) const BAN_LOG_WINDOW: Duration = Duration::from_secs(60);

/// A budget for one kind of ban log line.
///
/// One line per ban is right for the case this exists for, a peer the operator
/// forgot to trust going over the limit; a scanner fleet tripping it from
/// thousands of addresses at once is the case it must not turn into a log
/// flood. Past the budget a line is counted instead, and the count is said
/// with the next line logged, or at the prune once the window rolls, so a
/// wave shows as its size rather than as silence.
#[derive(Default)]
struct BanLog(Mutex<BanLogWindow>);

#[derive(Default)]
struct BanLogWindow {
    started: Option<Instant>,
    logged: u32,
    unlogged: u32,
}

impl BanLog {
    /// Whether to log one more line at `now`, and how many went unlogged
    /// since the last one that was.
    fn admit(&self, now: Instant) -> Option<u32> {
        let mut window = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if window
            .started
            .is_none_or(|started| now.duration_since(started) >= BAN_LOG_WINDOW)
        {
            window.started = Some(now);
            window.logged = 0;
        }
        if window.logged < BAN_LOG_BUDGET {
            window.logged += 1;
            Some(std::mem::take(&mut window.unlogged))
        } else {
            window.unlogged = window.unlogged.saturating_add(1);
            None
        }
    }

    /// The lines counted but not logged, once the window they fell in is
    /// over; `0` otherwise, or when there were none.
    fn take_unlogged(&self, now: Instant) -> u32 {
        let mut window = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match window.started {
            Some(started) if now.duration_since(started) >= BAN_LOG_WINDOW => {
                std::mem::take(&mut window.unlogged)
            }
            _ => 0,
        }
    }
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
            // `remove` can find nothing: the prune lifted it meanwhile, and
            // logged it there.
            Some(_) if self.bans.remove(&source).is_some() => self.ban_lifted(source, now),
            Some(_) | None => {}
        }

        let (over_limit, count) = {
            let mut entry = self.windows.entry(source).or_insert(FailureWindow {
                count: 0,
                window_start: now,
            });
            if now.duration_since(entry.window_start) > policy.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            (entry.count > policy.max_requests, entry.count)
            // shard write guard dropped here, before touching `bans`/`windows`.
        };

        if over_limit {
            self.windows.remove(&source);
            self.bans.insert(source, now + policy.ban_duration);
            self.ban_installed(policy, source, count, now);
            return false;
        }
        true
    }

    /// Say that `source` is banned, once per ban: every request it sends from
    /// here to the end of the ban is dropped without a word, so this line is
    /// the only place the operator learns which peer went quiet and why.
    fn ban_installed(&self, policy: &RateLimitPolicy, source: IpAddr, count: u32, now: Instant) {
        crate::metrics::rate_limit::record_ban();
        self.publish_bans();
        let Some(unlogged) = self.installed_log.admit(now) else {
            return;
        };
        tracing::warn!(
            source = %source,
            requests = count,
            max_requests = policy.max_requests,
            window_secs = policy.window.as_secs(),
            ban_secs = policy.ban_duration.as_secs(),
            unlogged_bans = unlogged,
            "rate_limit: source banned, its requests are dropped unanswered until the ban ends \
             (list: GET /admin/rate-limit/bans; exempt a peer with security.trusted_cidrs)"
        );
    }

    /// Say that the ban on `source` is over.
    fn ban_lifted(&self, source: IpAddr, now: Instant) {
        self.publish_bans();
        if let Some(unlogged) = self.lifted_log.admit(now) {
            tracing::info!(
                source = %source,
                unlogged_lifts = unlogged,
                "rate_limit: ban lifted"
            );
        }
    }

    fn publish_bans(&self) {
        crate::metrics::rate_limit::publish_banned_sources(self.bans.len());
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
        let mut expired = Vec::new();
        self.bans.retain(|source, expiry| {
            let live = *expiry > now;
            if !live {
                expired.push(*source);
            }
            live
        });
        for source in expired {
            self.ban_lifted(source, now);
        }
        let unlogged = self.installed_log.take_unlogged(now);
        if unlogged > 0 {
            tracing::warn!(
                unlogged,
                banned_now = self.bans.len(),
                "rate_limit: further rate-limit bans went unlogged (budget per minute spent)"
            );
        }
        let unlogged = self.lifted_log.take_unlogged(now);
        if unlogged > 0 {
            tracing::info!(
                unlogged,
                "rate_limit: further rate-limit ban lifts went unlogged"
            );
        }
        self.publish_bans();
        self.windows
            .retain(|_, entry| now.duration_since(entry.window_start) <= window);
        self.exempt_windows
            .retain(|_, entry| now.duration_since(entry.window_start) <= window);
    }

    fn clear(&self) {
        let lifted = self.bans.len();
        self.bans.clear();
        self.windows.clear();
        self.exempt_windows.clear();
        if lifted > 0 {
            tracing::info!(lifted, "rate_limit: off, every rate-limit ban lifted");
        }
        self.publish_bans();
    }

    /// Lift bans and windows on every source inside `trusted`.
    fn lift_trusted(&self, trusted: &[ipnet::IpNet]) {
        let outside = |source: &IpAddr| !trusted.iter().any(|network| network.contains(source));
        let mut lifted = Vec::new();
        self.bans.retain(|source, _| {
            let keep = outside(source);
            if !keep {
                lifted.push(*source);
            }
            keep
        });
        self.windows.retain(|source, _| outside(source));
        let now = Instant::now();
        for source in lifted {
            self.ban_lifted(source, now);
        }
    }

    /// Banned sources with the whole seconds left on each ban at `now`; a
    /// ban already past its expiry is left out, pruned or not.
    fn banned_sources_at(&self, now: Instant) -> Vec<(IpAddr, u64)> {
        let mut banned: Vec<(IpAddr, u64)> = self
            .bans
            .iter()
            .filter_map(|entry| {
                let remaining = entry.value().saturating_duration_since(now);
                (!remaining.is_zero()).then(|| (*entry.key(), remaining.as_secs()))
            })
            .collect();
        banned.sort_unstable();
        banned
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

    /// Whether `rate_limit` is in force, so a list of its bans means something.
    pub fn rate_limit_enabled(&self) -> bool {
        self.policy.load().rate_limit.is_some()
    }

    /// Sources banned by `rate_limit` now, each with the seconds left on its
    /// ban, ordered by address. For `GET /admin/rate-limit/bans`.
    pub fn rate_limit_banned_sources(&self) -> Vec<(IpAddr, u64)> {
        self.rate_limit_banned_sources_at(Instant::now())
    }

    pub(super) fn rate_limit_banned_sources_at(&self, now: Instant) -> Vec<(IpAddr, u64)> {
        self.rate.banned_sources_at(now)
    }
}

#[cfg(test)]
#[path = "filter_tests.rs"]
mod tests;
