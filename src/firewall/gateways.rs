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
//!
//! Referencing the sets means naming the table that holds them — an nf_tables
//! set is scoped to its table — so an operator using this puts siphon's sets in
//! a table they own, and reloads that table by deleting and redefining it. Each
//! wake-up therefore checks that siphon's objects are still the ones it
//! declared, and re-declares and republishes when they are not. Without that,
//! a reload leaves siphon dialling carriers whose answers the kernel drops,
//! with the cache below reporting everything published.

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
    ///
    /// Only true of the sets it was written into: cleared whenever
    /// [`Self::reassert`] finds those sets replaced.
    published: Mutex<Option<(Vec<IpNet>, Vec<IpNet>)>>,
    /// The whole firewall section, so [`Self::reassert`] re-declares exactly
    /// what start-up declared — ban sets and managed chain included, since a
    /// reload of the table that holds them deletes those too.
    firewall: crate::config::FirewallConfig,
    /// The kernel handles of the declared objects when last checked. A
    /// different fingerprint means someone deleted or recreated them.
    fingerprint: Mutex<Option<Vec<u64>>>,
    notify: Notify,
}

/// What a check found when it compared the declared objects against the
/// last fingerprint.
#[derive(Debug, PartialEq, Eq)]
enum Declaration {
    /// The same objects siphon last saw. Nothing to do.
    Unchanged,
    /// Nothing seen yet, and everything is present: the start-up declaration.
    FirstSeen,
    /// Something is missing, or was recreated underneath siphon.
    Replaced,
}

fn compare_declaration(known: Option<&[u64]>, current: Option<&[u64]>) -> Declaration {
    match (known, current) {
        (_, None) => Declaration::Replaced,
        (None, Some(_)) => Declaration::FirstSeen,
        (Some(known), Some(current)) if known == current => Declaration::Unchanged,
        (Some(_), Some(_)) => Declaration::Replaced,
    }
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
            firewall: config.clone(),
            fingerprint: Mutex::new(None),
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
        if self.is_published(&v4, &v6) {
            return Ok(false);
        }
        self.replace(&v4, &v6).await?;
        let ranges = v4.len() + v6.len();
        *self.lock_published() = Some((v4, v6));
        tracing::info!(
            table = %self.table,
            set_v4 = %self.set_v4,
            set_v6 = %self.set_v6,
            ranges,
            "kernel firewall: gateway allow set published"
        );
        Ok(true)
    }

    fn lock_published(&self) -> std::sync::MutexGuard<'_, Option<(Vec<IpNet>, Vec<IpNet>)>> {
        self.published
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    /// Whether the kernel was last told exactly this view.
    fn is_published(&self, v4: &[IpNet], v6: &[IpNet]) -> bool {
        self.lock_published()
            .as_ref()
            .is_some_and(|(last_v4, last_v6)| last_v4 == v4 && last_v6 == v6)
    }

    /// Stop trusting the cache, so the next [`Self::publish`] writes the sets
    /// whatever the view is.
    fn forget_published(&self) {
        *self.lock_published() = None;
    }

    /// Make sure siphon's objects are still the ones it declared, and put them
    /// back when they are not. Returns whether it had to.
    ///
    /// A check that finds everything as it was reads a few handles and issues
    /// no transaction. One that finds a set missing, or recreated — an operator
    /// reloading the table that holds it — re-runs the start-up declaration and
    /// drops the publish cache, because the view it remembers was written into
    /// sets that no longer exist.
    pub async fn reassert(&self) -> std::io::Result<bool> {
        let current = self.kernel_fingerprint().await?;
        let known = self
            .fingerprint
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        match compare_declaration(known.as_deref(), current.as_deref()) {
            Declaration::Unchanged => return Ok(false),
            Declaration::FirstSeen => {
                *self
                    .fingerprint
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = current;
                return Ok(false);
            }
            Declaration::Replaced => {}
        }
        self.declare().await?;
        let declared = self.kernel_fingerprint().await?.ok_or_else(|| {
            std::io::Error::other(
                "kernel firewall: objects still missing straight after declaring them",
            )
        })?;
        *self
            .fingerprint
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(declared);
        self.forget_published();
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.firewall_redeclared_total.inc();
        }
        tracing::warn!(
            table = %self.table,
            missing = current.is_none(),
            "kernel firewall: siphon's sets were deleted or recreated underneath it (a ruleset \
             reload?) — re-declared them; the gateway allow set is republished now; bans placed \
             before the reload are enforced in userspace only"
        );
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    async fn kernel_fingerprint(&self) -> std::io::Result<Option<Vec<u64>>> {
        super::fingerprint(&self.firewall).await
    }

    #[cfg(not(target_os = "linux"))]
    async fn kernel_fingerprint(&self) -> std::io::Result<Option<Vec<u64>>> {
        Err(std::io::Error::other(
            "firewall: the nf_tables backend is Linux-only",
        ))
    }

    #[cfg(target_os = "linux")]
    async fn declare(&self) -> std::io::Result<()> {
        super::declare(&self.firewall).await
    }

    #[cfg(not(target_os = "linux"))]
    async fn declare(&self) -> std::io::Result<()> {
        Err(std::io::Error::other(
            "firewall: the nf_tables backend is Linux-only",
        ))
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
            // On every wake-up, not only the floor tick: a few lookups, and it
            // lets `POST /admin/gateways/refresh` after a ruleset reload close
            // the window at once instead of leaving it open until the tick.
            if let Err(error) = self.reassert().await {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.firewall_command_failures_total.inc();
                }
                tracing::warn!(%error, "kernel firewall: could not check or re-declare siphon's sets");
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

    // --- Declaration fingerprint ---

    #[test]
    fn the_same_handles_are_unchanged() {
        assert_eq!(
            compare_declaration(Some(&[4, 1, 2, 3, 4]), Some(&[4, 1, 2, 3, 4])),
            Declaration::Unchanged
        );
    }

    #[test]
    fn the_first_look_records_rather_than_redeclares() {
        assert_eq!(
            compare_declaration(None, Some(&[1, 1, 2])),
            Declaration::FirstSeen
        );
    }

    #[test]
    fn a_missing_object_is_replaced_whatever_was_known() {
        assert_eq!(
            compare_declaration(Some(&[1, 1, 2]), None),
            Declaration::Replaced
        );
        // Missing on the very first look too: start-up declared it, so
        // something removed it since.
        assert_eq!(compare_declaration(None, None), Declaration::Replaced);
    }

    #[test]
    fn a_recreated_table_is_replaced_even_with_the_same_object_handles() {
        // What a reload of an operator's table looks like: object handles
        // restart inside the new table, only the table's own handle moves.
        assert_eq!(
            compare_declaration(Some(&[1, 1, 2, 3, 4]), Some(&[2, 1, 2, 3, 4])),
            Declaration::Replaced
        );
    }

    // --- Publish cache ---

    fn allow_set() -> GatewayAllowSet {
        let config: crate::config::FirewallConfig =
            serde_yaml_ng::from_str("{}").expect("an empty firewall section parses");
        GatewayAllowSet::new(&config, &[], Arc::new(DispatcherManager::new()))
    }

    #[test]
    fn an_unchanged_view_is_published() {
        let allow_set = allow_set();
        let v4 = vec![net("192.0.2.0/24")];
        assert!(!allow_set.is_published(&v4, &[]), "nothing published yet");
        *allow_set.lock_published() = Some((v4.clone(), Vec::new()));
        assert!(allow_set.is_published(&v4, &[]));
        assert!(!allow_set.is_published(&[net("198.51.100.0/24")], &[]));
    }

    #[test]
    fn forgetting_the_cache_forces_the_next_publish() {
        // The cache describes sets a reload has deleted; the view has not
        // changed, and publish must still write it.
        let allow_set = allow_set();
        let v4 = vec![net("192.0.2.0/24")];
        *allow_set.lock_published() = Some((v4.clone(), Vec::new()));
        allow_set.forget_published();
        assert!(!allow_set.is_published(&v4, &[]));
    }

    /// The whole recovery against a real kernel: siphon's sets live in a table
    /// the operator owns, the operator reloads it the way a deploy does, and
    /// the next floor tick puts the sets back and refills them.
    ///   `unshare -rn cargo test -- --ignored allow_set_survives --nocapture`
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires CAP_NET_ADMIN (run under `unshare -rn`)"]
    async fn allow_set_survives_the_operator_reloading_its_table() {
        let config: crate::config::FirewallConfig =
            serde_yaml_ng::from_str("table: edge\nmanage_rule: false\n").expect("firewall section");
        super::super::declare(&config)
            .await
            .expect("start-up declaration");
        let allow_set = GatewayAllowSet::new(
            &config,
            &["192.0.2.0/24".to_string()],
            Arc::new(DispatcherManager::new()),
        );
        assert!(!allow_set.reassert().await.expect("first look"));
        assert!(allow_set.publish().await.expect("first publish"));

        // Nothing deleted, nothing changed: no transaction either way.
        assert!(!allow_set.reassert().await.expect("unchanged look"));
        assert!(!allow_set.publish().await.expect("unchanged publish"));

        // The operator's deploy: delete the table and redefine it. It has to
        // declare the set its own rule references, because nothing else would;
        // this one declares every set siphon owns, in siphon's own order, so
        // all of them are present afterwards under the very handles they had
        // before, and only the table's handle shows that they are new.
        let ruleset = concat!(
            "table inet edge\n",
            "delete table inet edge\n",
            "table inet edge {\n",
            "  set banned4 { type ipv4_addr; flags timeout; }\n",
            "  set banned6 { type ipv6_addr; flags timeout; }\n",
            "  set gateways4 { type ipv4_addr; flags interval; }\n",
            "  set gateways6 { type ipv6_addr; flags interval; }\n",
            "}\n",
            // After the block, not inside it: `nft` allocates a block's chains
            // before its sets, which would shift the set handles and hide
            // whether the table's handle alone is enough.
            "add chain inet edge input { type filter hook input priority 0; policy accept; }\n",
            "add rule inet edge input ip saddr @gateways4 udp dport 5060 accept\n",
        );
        let path = std::env::temp_dir().join(format!("siphon-reload-{}.nft", std::process::id()));
        std::fs::write(&path, ruleset).expect("write ruleset");
        let status = std::process::Command::new("nft")
            .arg("-f")
            .arg(&path)
            .status()
            .expect("run nft");
        let _ = std::fs::remove_file(&path);
        assert!(status.success(), "the operator's ruleset did not load");
        assert!(
            !nft_list().contains("192.0.2.0/24"),
            "the reload was meant to empty the set"
        );

        // Every set is present again, and the publish cache still believes the
        // view is in them: only the fingerprint can tell.
        assert!(
            allow_set.reassert().await.expect("look after reload"),
            "a reload that left every set present but empty went unnoticed"
        );
        assert!(
            allow_set.publish().await.expect("publish after reload"),
            "publish short-circuited on a view written into a deleted set"
        );
        let listed = nft_list();
        assert!(listed.contains("192.0.2.0/24"), "not refilled:\n{listed}");
        assert!(
            listed.contains("gateways6"),
            "v6 set not re-declared:\n{listed}"
        );
        assert!(
            listed.contains("banned4"),
            "ban set not re-declared:\n{listed}"
        );
        assert!(
            listed.contains("@gateways4 udp dport 5060 accept"),
            "the operator's own rule must survive the re-declaration:\n{listed}"
        );

        // And settles again.
        assert!(!allow_set.reassert().await.expect("settled look"));
        assert!(!allow_set.publish().await.expect("settled publish"));
    }

    #[cfg(target_os = "linux")]
    fn nft_list() -> String {
        let output = std::process::Command::new("nft")
            .args(["list", "table", "inet", "edge"])
            .output()
            .expect("run nft");
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}
