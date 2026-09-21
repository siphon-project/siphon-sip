//! The kernel gateway allow set.
//!
//! An estate whose carriers authenticate by source address has no registration
//! and no outbound digest, so the address list *is* the authentication, and it
//! is enforced by the operator's own nftables ruleset. A carrier added in a
//! controller and picked up by `gateway.backend`'s reconcile is therefore one
//! siphon will dial and whose answers the kernel drops: the outbound half
//! appears to work while the inbound half is dead, which is the worst shape of
//! failure to debug.
//!
//! This publishes the live gateway view into the two interval sets
//! [`super::nftables::ensure_firewall`] declares, so the kernel admits a
//! carrier in the same tick it becomes dialable. siphon owns the sets and
//! writes no rule for them — the operator references them from their own
//! ruleset:
//!
//! ```text
//! ip saddr @gateways4 udp dport 5060 accept
//! ip saddr @gateways6 udp dport 5060 accept
//! ```
//!
//! An `accept` inside siphon's own chain would also make a gateway immune to
//! the ban drops, and that is the operator's policy call, not a side effect of
//! keeping a set current.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ipnet::IpNet;
use tokio::sync::Notify;

use crate::gateway::DispatcherManager;

/// Floor between republishes. Covers a change nothing else notifies about: a
/// destination re-resolved by the health prober, and — via
/// [`DispatcherManager::refresh_member_ips_for_unprobed`] — a change of A
/// record on a group that is not probed at all.
const FLOOR_TICK: Duration = Duration::from_secs(60);

/// The process-wide publisher, so a gateway source reconcile and
/// `POST /admin/gateways/refresh` can poke it without threading a handle
/// through either. Absent when the kernel firewall is not configured, or when
/// it failed to start.
static ALLOW_SET: OnceLock<Arc<GatewayAllowSet>> = OnceLock::new();

/// Publish the gateway allow set into the kernel, and keep it current.
pub struct GatewayAllowSet {
    table: String,
    set_v4: String,
    set_v6: String,
    dispatcher: Arc<DispatcherManager>,
    /// `security.trusted_cidrs`, already parsed. Present in the allow set
    /// because it is already the estate's "not an abuser" list: own trunks,
    /// monitoring, management.
    trusted: Vec<IpNet>,
    /// What the kernel was last told, so an unchanged view issues no netlink
    /// transaction at all. Stored only after the kernel acked, so a failed
    /// publish is retried on the next tick rather than remembered as done.
    published: Mutex<Option<(Vec<IpNet>, Vec<IpNet>)>>,
    notify: Notify,
}

impl GatewayAllowSet {
    pub fn new(
        config: &crate::config::FirewallConfig,
        trusted_cidrs: &[String],
        dispatcher: Arc<DispatcherManager>,
    ) -> Self {
        let mut trusted = Vec::new();
        for entry in trusted_cidrs {
            match crate::gateway::parse_source_network(entry) {
                Some(network) => trusted.push(network),
                // Skipped, not fatal — every other `trusted_cidrs` consumer
                // drops an unparseable entry the same way, and failing start-up
                // here would make the firewall stricter about the list than the
                // userspace ACL that also reads it.
                None => tracing::warn!(
                    entry = %entry,
                    "kernel firewall: security.trusted_cidrs entry is neither a CIDR nor an address — skipped"
                ),
            }
        }
        Self {
            table: config.table.clone(),
            set_v4: config.set_gateways_v4.clone(),
            set_v6: config.set_gateways_v6.clone(),
            dispatcher,
            trusted,
            published: Mutex::new(None),
            notify: Notify::new(),
        }
    }

    /// The ranges the kernel should hold right now, v4 and v6, normalised.
    fn desired(&self) -> (Vec<IpNet>, Vec<IpNet>) {
        let mut sources = self.dispatcher.admitted_sources();
        sources.extend_from_slice(&self.trusted);
        let (v4, v6): (Vec<IpNet>, Vec<IpNet>) = sources
            .into_iter()
            .partition(|network| network.addr().is_ipv4());
        (normalise(v4), normalise(v6))
    }

    /// Publish if the view changed. Returns whether a netlink transaction was
    /// issued.
    pub async fn publish(&self) -> std::io::Result<bool> {
        let (v4, v6) = self.desired();
        {
            let published = self
                .published
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if published
                .as_ref()
                .is_some_and(|(last_v4, last_v6)| last_v4 == &v4 && last_v6 == &v6)
            {
                return Ok(false);
            }
        }
        self.replace(&v4, &v6).await?;
        let ranges = v4.len() + v6.len();
        *self
            .published
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((v4, v6));
        tracing::info!(
            table = %self.table,
            set_v4 = %self.set_v4,
            set_v6 = %self.set_v6,
            ranges,
            "kernel firewall: gateway allow set published"
        );
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    async fn replace(&self, v4: &[IpNet], v6: &[IpNet]) -> std::io::Result<()> {
        super::nftables::replace_gateways(&self.table, &self.set_v4, &self.set_v6, v4, v6).await
    }

    #[cfg(not(target_os = "linux"))]
    async fn replace(&self, _v4: &[IpNet], _v6: &[IpNet]) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "firewall: the nf_tables backend is Linux-only",
        ))
    }

    /// Ask for a publish on the next wake-up. Cheap and lossless: a poke while
    /// one is already pending collapses into it, which is what a reconcile that
    /// touches twenty groups should cost.
    pub fn request_publish(&self) {
        self.notify.notify_one();
    }

    /// Republish on a poke, and on a floor tick so a change nothing announces
    /// is still followed.
    pub async fn run(self: Arc<Self>) {
        let mut floor = tokio::time::interval(FLOOR_TICK);
        floor.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; the bootstrap publish already
        // covered it, and `publish` is a no-op when nothing changed.
        floor.tick().await;
        loop {
            tokio::select! {
                _ = self.notify.notified() => {}
                _ = floor.tick() => {
                    // Only the floor tick re-resolves: a poke follows a
                    // reconcile that has already refreshed what it changed.
                    let dispatcher = Arc::clone(&self.dispatcher);
                    let _ = tokio::task::spawn_blocking(move || {
                        dispatcher.refresh_member_ips_for_unprobed();
                    })
                    .await;
                }
            }
            if let Err(error) = self.publish().await {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.firewall_command_failures_total.inc();
                }
                tracing::warn!(%error, "kernel firewall: gateway allow set publish failed");
            }
        }
    }
}

/// Install the process-wide publisher. Idempotent; a second call is ignored.
pub fn install(allow_set: Arc<GatewayAllowSet>) {
    let _ = ALLOW_SET.set(allow_set);
}

/// Poke the publisher because the live gateway set may have changed — a
/// `gateway.backend` reconcile, or `POST /admin/gateways/refresh`. A no-op when
/// the kernel firewall is not running, so callers need no configuration check.
pub fn request_publish() {
    if let Some(allow_set) = ALLOW_SET.get() {
        allow_set.request_publish();
    }
}

/// Sort, deduplicate, and drop any range another already contains.
///
/// An nf_tables interval set rejects an element overlapping one already in it,
/// and the same address reaches here from several places: two groups naming one
/// carrier, a gateway inside a `trusted_cidrs` range, the same host in
/// `source_networks` and in the resolved members. CIDR ranges are either
/// disjoint or nested — a partial overlap is not expressible — so dropping the
/// contained one is exact, not an approximation, and needs no range arithmetic.
///
/// The result is sorted so an unchanged view compares equal to the last
/// published one and issues no transaction.
fn normalise(mut networks: Vec<IpNet>) -> Vec<IpNet> {
    // Broadest first, so a container is always seen before what it contains.
    networks.sort_by(|left, right| {
        left.prefix_len()
            .cmp(&right.prefix_len())
            .then_with(|| left.network().cmp(&right.network()))
    });
    let mut kept: Vec<IpNet> = Vec::with_capacity(networks.len());
    for network in networks {
        if kept.iter().any(|held| held.contains(&network)) {
            continue;
        }
        kept.push(network);
    }
    kept.sort_by(|left, right| {
        left.network()
            .cmp(&right.network())
            .then_with(|| left.prefix_len().cmp(&right.prefix_len()))
    });
    kept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(spec: &str) -> IpNet {
        spec.parse().expect("test CIDR")
    }

    #[test]
    fn normalise_drops_a_host_inside_a_configured_range() {
        let kept = normalise(vec![net("192.0.2.7/32"), net("192.0.2.0/24")]);
        assert_eq!(kept, vec![net("192.0.2.0/24")]);
    }

    #[test]
    fn normalise_keeps_adjacent_hosts() {
        // Adjacent is not overlapping, and an interval set takes both.
        let kept = normalise(vec![net("192.0.2.2/32"), net("192.0.2.1/32")]);
        assert_eq!(kept, vec![net("192.0.2.1/32"), net("192.0.2.2/32")]);
    }

    #[test]
    fn normalise_deduplicates_the_same_range_twice() {
        let kept = normalise(vec![net("198.51.100.0/24"), net("198.51.100.0/24")]);
        assert_eq!(kept, vec![net("198.51.100.0/24")]);
    }

    #[test]
    fn normalise_drops_a_nested_prefix_not_only_a_host() {
        let kept = normalise(vec![net("203.0.113.0/28"), net("203.0.113.0/24")]);
        assert_eq!(kept, vec![net("203.0.113.0/24")]);
    }

    #[test]
    fn normalise_is_order_independent() {
        let forward = normalise(vec![
            net("192.0.2.1/32"),
            net("198.51.100.0/24"),
            net("203.0.113.9/32"),
        ]);
        let reverse = normalise(vec![
            net("203.0.113.9/32"),
            net("198.51.100.0/24"),
            net("192.0.2.1/32"),
        ]);
        assert_eq!(forward, reverse);
    }

    #[test]
    fn normalise_handles_v6_nesting() {
        let kept = normalise(vec![
            net("2001:db8::1/128"),
            net("2001:db8::/32"),
            net("2001:db8:1::/48"),
        ]);
        assert_eq!(kept, vec![net("2001:db8::/32")]);
    }

    #[test]
    fn normalise_keeps_disjoint_v6_ranges() {
        let kept = normalise(vec![net("2001:db8:2::/48"), net("2001:db8:1::/48")]);
        assert_eq!(kept, vec![net("2001:db8:1::/48"), net("2001:db8:2::/48")]);
    }

    #[test]
    fn normalise_of_nothing_is_nothing() {
        assert!(normalise(Vec::new()).is_empty());
    }
}
