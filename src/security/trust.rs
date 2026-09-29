//! Who the abuse controls leave alone.
//!
//! Every abuse control — the request filter (`rate_limit`, `scanner_block`),
//! the auto-ban store (`failed_auth_ban`), the connection ceilings and the
//! APIBAN ingest — exempts the same sources, and this is the one place that
//! says which:
//!
//! - `security.trusted_cidrs`, always; and
//! - with `security.trust_gateways: true`, every source a gateway group admits
//!   — the published [`GatewayView`], which is exactly what
//!   `request.from_gateway()` answers from and what the kernel allow set holds:
//!   resolved destination addresses plus `source_networks`, across siphon.yaml,
//!   script and `gateway.backend` groups.
//!
//! A carrier provisioned through a gateway source is therefore trusted the
//! moment the reconcile that adds it publishes the view, and back under every
//! policy at the reconcile that removes it — counted again from zero, never
//! retroactively banned. Without `trust_gateways` no view is attached, and each
//! check is exactly the `trusted_cidrs` scan it always was.

use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::gateway::view::GatewayView;

/// Why a source is exempt, for a log line that has to say so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exemption {
    /// Inside `security.trusted_cidrs`.
    Configured,
    /// Admitted by this gateway group, and `security.trust_gateways` is on.
    Gateway(Arc<str>),
}

/// The exemption list one abuse control consults. Cheap to clone.
#[derive(Clone, Default)]
pub struct SourceTrust {
    configured: Vec<IpNet>,
    gateways: Option<Arc<GatewayView>>,
}

impl SourceTrust {
    /// Trust `trusted_cidrs` only. Unparseable entries are skipped, as every
    /// consumer of the list always has (the caller logs them).
    pub fn from_cidrs(trusted_cidrs: &[String]) -> Self {
        Self {
            configured: trusted_cidrs
                .iter()
                .filter_map(|cidr| cidr.parse::<IpNet>().ok())
                .collect(),
            gateways: None,
        }
    }

    /// Also trust every source `gateways` admits. `None` leaves the list as
    /// it is — what `trust_gateways: false` passes.
    pub fn with_gateways(mut self, gateways: Option<Arc<GatewayView>>) -> Self {
        self.gateways = gateways;
        self
    }

    /// Whether `source` is exempt, either way.
    #[inline]
    pub fn is_trusted(&self, source: IpAddr) -> bool {
        self.is_configured(source) || self.is_gateway(source)
    }

    /// Whether `source` is inside `trusted_cidrs`.
    #[inline]
    pub fn is_configured(&self, source: IpAddr) -> bool {
        self.configured
            .iter()
            .any(|network| network.contains(&source))
    }

    /// Whether `source` is exempt only because a gateway admits it. `false`
    /// whenever `trust_gateways` is off.
    #[inline]
    pub fn is_gateway(&self, source: IpAddr) -> bool {
        self.gateways
            .as_ref()
            .is_some_and(|gateways| gateways.contains(source))
    }

    /// Why `source` is exempt, or `None` when it is not. For log lines; the
    /// checks themselves use [`Self::is_trusted`].
    pub fn exemption(&self, source: IpAddr) -> Option<Exemption> {
        if self.is_configured(source) {
            return Some(Exemption::Configured);
        }
        self.gateways
            .as_ref()
            .and_then(|gateways| gateways.group_of(source))
            .map(Exemption::Gateway)
    }

    /// The gateway view consulted, when `trust_gateways` is on.
    pub fn gateways(&self) -> Option<&Arc<GatewayView>> {
        self.gateways.as_ref()
    }

    /// Number of parsed `trusted_cidrs` entries, for start-up logging.
    pub fn configured_len(&self) -> usize {
        self.configured.len()
    }
}

/// The gateway view the abuse controls should consult: the dispatcher's, when
/// `security.trust_gateways` is on; `None` otherwise.
///
/// On with no `gateway:` section there is nothing to trust, which is almost
/// certainly a configuration slip rather than a policy, so it is said loudly
/// once rather than silently ignored.
pub fn gateway_view_for(
    config: &crate::config::Config,
    gateways: Option<&Arc<crate::gateway::DispatcherManager>>,
) -> Option<Arc<GatewayView>> {
    let enabled = config
        .security
        .as_ref()
        .is_some_and(|security| security.trust_gateways);
    if !enabled {
        return None;
    }
    match gateways {
        Some(manager) => {
            tracing::info!(
                "security.trust_gateways: sources admitted by a gateway group are exempt from \
                 rate_limit, scanner_block, failed_auth_ban, the connection ceilings and APIBAN"
            );
            Some(manager.gateway_view())
        }
        None => {
            tracing::warn!(
                "security.trust_gateways is set but no gateway: section is configured — no \
                 source is trusted by it"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::view::AdmittedRange;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test address")
    }

    fn view_with(spec: &str, group: &str) -> Arc<GatewayView> {
        let view = Arc::new(GatewayView::new());
        view.publish(|| {
            vec![AdmittedRange {
                network: spec.parse().expect("test CIDR"),
                group: Arc::from(group),
            }]
        });
        view
    }

    #[test]
    fn configured_cidrs_alone_behave_as_before() {
        let trust =
            SourceTrust::from_cidrs(&["198.51.100.0/24".to_string(), "not-a-cidr".to_string()]);
        assert_eq!(trust.configured_len(), 1);
        assert!(trust.is_trusted(ip("198.51.100.3")));
        assert!(!trust.is_trusted(ip("192.0.2.1")));
        assert!(!trust.is_gateway(ip("198.51.100.3")));
    }

    #[test]
    fn a_gateway_is_trusted_only_when_the_view_is_attached() {
        let view = view_with("192.0.2.10/32", "carriers");
        let off = SourceTrust::from_cidrs(&[]);
        let on = SourceTrust::from_cidrs(&[]).with_gateways(Some(Arc::clone(&view)));
        assert!(!off.is_trusted(ip("192.0.2.10")));
        assert!(on.is_trusted(ip("192.0.2.10")));
        assert!(!on.is_trusted(ip("192.0.2.11")));
    }

    #[test]
    fn exemption_names_the_reason() {
        let view = view_with("192.0.2.10/32", "carriers");
        let trust =
            SourceTrust::from_cidrs(&["203.0.113.0/24".to_string()]).with_gateways(Some(view));
        assert_eq!(
            trust.exemption(ip("203.0.113.5")),
            Some(Exemption::Configured)
        );
        assert_eq!(
            trust.exemption(ip("192.0.2.10")),
            Some(Exemption::Gateway(Arc::from("carriers")))
        );
        assert_eq!(trust.exemption(ip("198.51.100.1")), None);
    }

    #[test]
    fn a_later_publish_is_seen_without_rebuilding_the_trust() {
        // The trust holds the view, not a copy: a reconcile that provisions or
        // removes a carrier is seen on the next check.
        let view = Arc::new(GatewayView::new());
        let trust = SourceTrust::from_cidrs(&[]).with_gateways(Some(Arc::clone(&view)));
        assert!(!trust.is_trusted(ip("192.0.2.10")));
        view.publish(|| {
            vec![AdmittedRange {
                network: "192.0.2.10/32".parse().expect("cidr"),
                group: Arc::from("carriers"),
            }]
        });
        assert!(trust.is_trusted(ip("192.0.2.10")));
        view.publish(Vec::new);
        assert!(!trust.is_trusted(ip("192.0.2.10")));
    }

    // --- Every abuse control, with and without trust_gateways ---

    use super::super::{
        AutoBanStore, ConnectionLimiter, ConnectionLimits, RefusedReason, SecurityFilter,
        SecurityVerdict,
    };
    use crate::config::{RateLimitConfig, ScannerBlockConfig, SecurityConfig};
    use std::time::{Duration, Instant};

    const GATEWAY: &str = "192.0.2.10";
    const STRANGER: &str = "203.0.113.50";

    fn security_config(max_requests: u32) -> SecurityConfig {
        SecurityConfig {
            max_message_bytes: None,
            rate_limit: Some(RateLimitConfig {
                window_secs: 60,
                max_requests,
                ban_duration_secs: 600,
            }),
            scanner_block: Some(ScannerBlockConfig {
                user_agents: vec!["friendly-scanner".to_string()],
            }),
            trusted_cidrs: Vec::new(),
            trust_gateways: true,
            failed_auth_ban: None,
            apiban: None,
            firewall: None,
            connection_limits: Default::default(),
        }
    }

    /// Drive `requests` requests from `source` through `filter` at one
    /// instant, returning the last verdict.
    fn flood(
        filter: &SecurityFilter,
        source: &str,
        requests: u32,
        now: Instant,
    ) -> SecurityVerdict {
        let mut verdict = SecurityVerdict::Allow;
        for _ in 0..requests {
            verdict = filter.evaluate_at(ip(source), Some("carrier-sbc/1.0"), now);
        }
        verdict
    }

    #[test]
    fn a_gateway_over_the_rate_limit_is_neither_dropped_nor_banned() {
        let view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let filter =
            SecurityFilter::from_config_with_gateways(&security_config(5), Some(view)).unwrap();
        let now = Instant::now();

        assert_eq!(flood(&filter, GATEWAY, 50, now), SecurityVerdict::Allow);
        assert_eq!(filter.rate_limit_bans(), 0, "a gateway was banned");
        // Positive control: the same flood from a stranger is dropped and banned.
        assert_eq!(
            flood(&filter, STRANGER, 50, now),
            SecurityVerdict::RateLimited
        );
        assert_eq!(filter.rate_limit_bans(), 1);
    }

    #[test]
    fn a_gateway_is_rate_limited_when_trust_gateways_is_off() {
        // The view knows the carrier; with the key off nothing consults it.
        let _view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let mut config = security_config(5);
        config.trust_gateways = false;
        let filter = SecurityFilter::from_config(&config).unwrap();
        assert_eq!(
            flood(&filter, GATEWAY, 50, Instant::now()),
            SecurityVerdict::RateLimited
        );
        assert_eq!(filter.rate_limit_bans(), 1);
    }

    #[test]
    fn a_gateway_with_a_scanner_user_agent_is_let_through() {
        // The same exemption trusted_cidrs has had all along.
        let view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let filter =
            SecurityFilter::from_config_with_gateways(&security_config(5), Some(view)).unwrap();
        assert_eq!(
            filter.evaluate(ip(GATEWAY), Some("friendly-scanner")),
            SecurityVerdict::Allow
        );
        assert_eq!(
            filter.evaluate(ip(STRANGER), Some("friendly-scanner")),
            SecurityVerdict::Scanner
        );
    }

    #[test]
    fn an_exempt_gateway_over_the_limit_is_warned_about_once_per_window() {
        let view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let filter =
            SecurityFilter::from_config_with_gateways(&security_config(5), Some(view)).unwrap();
        let log = crate::log_capture::LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(log.clone())
            .finish();
        let now = Instant::now();
        tracing::subscriber::with_default(subscriber, || {
            flood(&filter, GATEWAY, 5, now);
            assert!(log.rendered().is_empty(), "warned inside the limit");
            flood(&filter, GATEWAY, 100, now);
            // The next window says it again, once.
            flood(&filter, GATEWAY, 100, now + Duration::from_secs(61));
        });
        let rendered = log.rendered();
        let warnings: Vec<&str> = rendered
            .lines()
            .filter(|line| line.contains("over the limit and not dropped"))
            .collect();
        assert_eq!(warnings.len(), 2, "{rendered}");
        assert!(warnings[0].contains("gateway_group=carriers"), "{rendered}");
    }

    #[test]
    fn exempt_gateway_windows_drain_on_prune() {
        // Per-module leak rule: the counting kept for the warning is one row
        // per gateway and must go once its window lapses.
        let view = view_with("192.0.2.0/24", "carriers");
        let filter =
            SecurityFilter::from_config_with_gateways(&security_config(5), Some(view)).unwrap();
        let now = Instant::now();
        for host in 1..=200u32 {
            flood(&filter, &format!("192.0.2.{}", host % 250), 3, now);
        }
        let rate = filter.rate_limit.as_ref().unwrap();
        assert_eq!(rate.tracked_sources(), (0, 0, 200));
        rate.prune_at(now + Duration::from_secs(61));
        assert_eq!(rate.tracked_sources(), (0, 0, 0));
    }

    #[test]
    fn a_removed_gateway_is_counted_again_from_zero() {
        // Removed from the source: back under the policy at once, but it is
        // not retroactively banned for what it sent while trusted.
        let view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let filter =
            SecurityFilter::from_config_with_gateways(&security_config(5), Some(Arc::clone(&view)))
                .unwrap();
        let now = Instant::now();
        assert_eq!(flood(&filter, GATEWAY, 50, now), SecurityVerdict::Allow);
        view.publish(Vec::new);
        assert_eq!(flood(&filter, GATEWAY, 5, now), SecurityVerdict::Allow);
        assert_eq!(
            flood(&filter, GATEWAY, 1, now),
            SecurityVerdict::RateLimited
        );
    }

    fn auto_ban(view: Option<Arc<GatewayView>>) -> Arc<AutoBanStore> {
        Arc::new(AutoBanStore::new(3, 600, 3600, &[], 3, 0, 86_400).with_gateway_trust(view))
    }

    #[test]
    fn a_gateway_is_never_auto_banned() {
        let store = auto_ban(Some(view_with(&format!("{GATEWAY}/32"), "carriers")));
        for _ in 0..10 {
            assert!(!store.record_strong_failure(ip(GATEWAY)));
        }
        assert!(!store.is_banned(ip(GATEWAY)));
        // Positive control.
        assert!(store.record_strong_failure(ip(STRANGER)));
        assert!(store.is_banned(ip(STRANGER)));
    }

    #[test]
    fn a_gateway_is_auto_banned_when_trust_gateways_is_off() {
        let _view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let store = auto_ban(None);
        assert!(store.record_strong_failure(ip(GATEWAY)));
        assert!(store.is_banned(ip(GATEWAY)));
    }

    #[tokio::test]
    async fn an_auto_ban_is_lifted_in_userspace_and_the_kernel_when_the_source_becomes_a_gateway() {
        let view = Arc::new(GatewayView::new());
        let store = auto_ban(Some(Arc::clone(&view)));
        let (firewall, mut commands) = crate::firewall::KernelFirewall::capturing();
        store.set_firewall(firewall);
        store.follow_gateway_view();

        assert!(store.record_strong_failure(ip(GATEWAY)));
        assert!(store.record_strong_failure(ip(STRANGER)));
        // Drain the two ban commands.
        assert!(commands.try_recv().is_ok());
        assert!(commands.try_recv().is_ok());

        view.publish(|| {
            vec![AdmittedRange {
                network: format!("{GATEWAY}/32").parse().expect("cidr"),
                group: Arc::from("carriers"),
            }]
        });

        assert!(!store.is_banned(ip(GATEWAY)));
        assert_eq!(store.active_bans(), 1, "only the gateway's ban goes");
        assert!(store.is_banned(ip(STRANGER)), "the stranger stays banned");
        assert_eq!(
            commands.try_recv().ok(),
            Some(crate::firewall::Command::Unban { ip: ip(GATEWAY) })
        );
        assert!(commands.try_recv().is_err(), "nothing else was unbanned");
    }

    #[test]
    fn live_bans_leave_out_lapsed_and_trusted_sources() {
        let view = Arc::new(GatewayView::new());
        let store = auto_ban(Some(Arc::clone(&view)));
        let now = Instant::now();
        assert!(store.record_failure_weighted_at(ip(STRANGER), 3, now, "test"));
        assert!(store.record_failure_weighted_at(ip(GATEWAY), 3, now, "test"));
        // Trusted since it was banned, without the lift having run.
        view.publish(|| {
            vec![AdmittedRange {
                network: format!("{GATEWAY}/32").parse().expect("cidr"),
                group: Arc::from("carriers"),
            }]
        });

        let later = now + Duration::from_secs(600);
        assert_eq!(
            store.live_bans_at(later),
            vec![(ip(STRANGER), Duration::from_secs(3000))]
        );
        assert!(store
            .live_bans_at(now + Duration::from_secs(3600))
            .is_empty());
    }

    #[test]
    fn a_gateway_is_never_refused_a_connection() {
        let ceilings = ConnectionLimits {
            max_handshakes_per_source: 0,
            max_handshakes: 0,
            max_connections_per_source: 1,
            max_connections: 0,
        };
        let view = view_with(&format!("{GATEWAY}/32"), "carriers");
        let on = Arc::new(ConnectionLimiter::new(ceilings, &[]).with_gateway_trust(Some(view)));
        let off = Arc::new(ConnectionLimiter::new(ceilings, &[]));

        let held: Vec<_> = (0..10)
            .map(|_| on.try_accept(ip(GATEWAY)).expect("a gateway is unmetered"))
            .collect();
        assert_eq!(on.tracked_sources(), (0, 0));
        drop(held);
        // Positive control: a stranger on the same limiter, and the gateway on
        // one without trust_gateways, hit the ceiling.
        let _stranger = on.try_accept(ip(STRANGER)).expect("first");
        assert_eq!(
            on.try_accept(ip(STRANGER)).unwrap_err(),
            RefusedReason::ConnectionsPerSource
        );
        let _gateway = off.try_accept(ip(GATEWAY)).expect("first");
        assert_eq!(
            off.try_accept(ip(GATEWAY)).unwrap_err(),
            RefusedReason::ConnectionsPerSource
        );
    }
}
