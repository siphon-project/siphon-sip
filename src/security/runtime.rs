//! Installing, and re-applying at run time, the abuse controls a config reload
//! can change: `trusted_cidrs`, `rate_limit` / `scanner_block` (the request
//! filter) and `failed_auth_ban` (the auto-ban store).
//!
//! Start-up and `POST /admin/config/reload` go through the same functions, so a
//! control first enabled by a reload is built exactly as one configured at
//! start-up would have been: same shared trusted list, same gateway view, same
//! kernel handle, and its prune task spawned once. A control is installed into
//! its process-wide slot at most once; turning it off later leaves it installed
//! with a policy that does nothing, and turning it back on swaps the policy in.
//! The gateway-view subscription a store takes at install is therefore taken
//! once per process too, never per reload.

use std::sync::{Arc, OnceLock};

use ipnet::IpNet;
use tracing::{info, warn};

use super::trust::{SourceTrust, TrustedCidrs};
use super::{AutoBanStore, BanPolicy, SecurityFilter};
use crate::apiban::InstalledBlocklist;
use crate::config::SecurityConfig;
use crate::gateway::view::GatewayView;

/// Interval of the prune task each installed control runs.
const PRUNE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The handles every runtime-changeable abuse control is built from.
pub struct SecurityRuntime {
    trusted: TrustedCidrs,
    gateways: Option<Arc<GatewayView>>,
    firewall: Option<crate::firewall::KernelFirewall>,
    auto_ban_slot: &'static OnceLock<Arc<AutoBanStore>>,
    filter_slot: &'static OnceLock<Arc<SecurityFilter>>,
    apiban: fn() -> Option<&'static InstalledBlocklist>,
    publish_allow_set: fn(),
}

impl SecurityRuntime {
    /// The runtime start-up builds: the process-wide slots, the shared
    /// `trusted_cidrs` list parsed from `trusted_entries`, the gateway view
    /// under `trust_gateways`, and the kernel handle when one is up.
    ///
    /// An entry that is neither a CIDR nor an address is skipped and logged at
    /// warn, not refused: a config that started before keeps starting.
    pub fn new(
        trusted_entries: &[String],
        gateways: Option<Arc<GatewayView>>,
        firewall: Option<crate::firewall::KernelFirewall>,
    ) -> Self {
        let (networks, invalid) = TrustedCidrs::parse(trusted_entries);
        for entry in &invalid {
            warn!(
                entry = %entry,
                "security.trusted_cidrs entry is neither a CIDR nor an address — skipped"
            );
        }
        Self {
            trusted: TrustedCidrs::new(networks),
            gateways,
            firewall,
            auto_ban_slot: super::auto_ban_slot(),
            filter_slot: super::security_filter_slot(),
            apiban: crate::apiban::installed,
            publish_allow_set: crate::firewall::gateways::request_publish,
        }
    }

    /// A runtime over slots of its own, for a test that must not touch the
    /// process-wide ones.
    #[cfg(test)]
    pub(crate) fn detached(
        trusted_entries: &[String],
        gateways: Option<Arc<GatewayView>>,
        firewall: Option<crate::firewall::KernelFirewall>,
        apiban: fn() -> Option<&'static InstalledBlocklist>,
    ) -> Self {
        Self {
            trusted: TrustedCidrs::from_entries(trusted_entries),
            gateways,
            firewall,
            auto_ban_slot: Box::leak(Box::new(OnceLock::new())),
            filter_slot: Box::leak(Box::new(OnceLock::new())),
            apiban,
            publish_allow_set: || {},
        }
    }

    /// The shared `trusted_cidrs` list.
    pub fn trusted(&self) -> TrustedCidrs {
        self.trusted.clone()
    }

    /// What every control built here exempts: the shared list, and the gateway
    /// view under `trust_gateways`.
    pub fn trust(&self) -> SourceTrust {
        SourceTrust::default()
            .with_trusted(self.trusted.clone())
            .with_gateways(self.gateways.clone())
    }

    /// The auto-ban store this runtime installed, if any.
    pub fn auto_ban(&self) -> Option<&Arc<AutoBanStore>> {
        self.auto_ban_slot.get()
    }

    /// The request filter this runtime installed, if any.
    pub fn security_filter(&self) -> Option<&Arc<SecurityFilter>> {
        self.filter_slot.get()
    }

    /// Bring `failed_auth_ban` to `policy` (`None`: off).
    ///
    /// Already installed: the policy is swapped (bans keep their expiry), or
    /// on `None` every ban and failure window is lifted, kernel included. Not
    /// installed and `Some`: the store is built, installed, wired to the kernel
    /// and the gateway view, and its prune task spawned. Must run on a Tokio
    /// runtime.
    pub fn apply_auto_ban(&self, policy: Option<BanPolicy>) {
        match (self.auto_ban_slot.get(), policy) {
            (Some(store), Some(policy)) => store.set_policy(policy),
            (Some(store), None) => {
                if store.is_enabled() {
                    store.disable();
                    if let Some(metrics) = crate::metrics::try_metrics() {
                        metrics.banned_ips.set(0);
                    }
                    info!("failed_auth_ban off: every auto-ban lifted");
                }
            }
            (None, Some(policy)) => self.install_auto_ban(policy),
            (None, None) => {}
        }
    }

    fn install_auto_ban(&self, policy: BanPolicy) {
        let store = Arc::new(AutoBanStore::with_policy(policy, self.trust()));
        if let Some(firewall) = &self.firewall {
            store.set_firewall(firewall.clone());
        }
        if self.auto_ban_slot.set(Arc::clone(&store)).is_err() {
            return;
        }
        // Once per process: the store is installed once.
        store.follow_gateway_view();
        info!(
            policy = ?policy,
            trusted_cidrs = self.trusted.load().len(),
            "failed_auth_ban scanner protection enabled"
        );
        // Periodic prune (bounds memory under scanner churn) + publish the
        // banned_ips gauge authoritatively each tick.
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(PRUNE_INTERVAL);
            loop {
                ticker.tick().await;
                store.prune();
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.banned_ips.set(store.active_bans() as i64);
                }
            }
        });
    }

    /// Bring `rate_limit` / `scanner_block` to what `security` says (`None`:
    /// no `security:` section, both off). The same install-once rule as
    /// [`Self::apply_auto_ban`]. Must run on a Tokio runtime.
    pub fn apply_filter(&self, security: Option<&SecurityConfig>) {
        match (self.filter_slot.get(), security) {
            (Some(filter), Some(security)) => filter.set_policy(security),
            (Some(filter), None) => filter.disable(),
            (None, Some(security)) => self.install_filter(security),
            (None, None) => {}
        }
    }

    fn install_filter(&self, security: &SecurityConfig) {
        let Some(filter) = SecurityFilter::from_config_with_trust(security, self.trust()) else {
            return;
        };
        if self.filter_slot.set(Arc::clone(&filter)).is_err() {
            return;
        }
        info!(
            rate_limit = security.rate_limit.is_some(),
            scanner_user_agents = security
                .scanner_block
                .as_ref()
                .map_or(0, |block| block.user_agents.len()),
            trusted_cidrs = self.trusted.load().len(),
            "request security filter enabled (rate_limit / scanner_block)"
        );
        // Periodic prune to bound the rate-limiter maps under scanner churn.
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(PRUNE_INTERVAL);
            loop {
                ticker.tick().await;
                filter.prune();
            }
        });
    }

    /// Make `networks` the trusted list for every control at once, lift what
    /// each one holds against a source it now trusts (kernel elements
    /// included), and ask for the kernel gateway allow set to be republished.
    /// A source no longer trusted is counted from zero from its next signal.
    pub fn apply_trusted(&self, networks: Vec<IpNet>) {
        self.trusted.store(networks);
        let trusted = self.trusted.load();
        if let Some(store) = self.auto_ban_slot.get() {
            store.lift_trusted(&trusted);
        }
        if let Some(filter) = self.filter_slot.get() {
            // The filter carries the list in its policy snapshot (one load per
            // request); re-store it from the list just swapped.
            filter.refresh_trusted();
            filter.lift_trusted(&trusted);
        }
        if let Some(blocklist) = (self.apiban)() {
            blocklist.lift_trusted(&trusted);
        }
        (self.publish_allow_set)();
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
