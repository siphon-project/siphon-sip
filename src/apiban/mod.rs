//! APIBAN community blocklist integration.
//!
//! Periodically polls the APIBAN REST API to fetch IPs known for SIP abuse
//! (scanners, brute-forcers, toll fraud) and feeds them into the transport ACL.
//!
//! Two properties the feed itself dictates, and which the store below
//! implements:
//!
//! - **Trusted sources are never blocked.** A carrier trunk or a management
//!   address that lands on a community feed would otherwise lose its trunk (or
//!   its ssh, since the kernel drop is port-agnostic) with no config able to
//!   save it. `security.trusted_cidrs` is applied at insert, so neither the
//!   userspace set nor the kernel set ever receives a trusted address. With
//!   `security.trust_gateways`, so is every source a gateway group admits, and
//!   an address the feed listed before its carrier was provisioned is evicted
//!   from both sets at the reconcile that provisions it.
//! - **Entries expire.** APIBAN releases an address after 7 days; siphon used
//!   to insert permanently, so a false positive stayed blocked for the life of
//!   the process and the only levers were a restart (which drops every
//!   registration) or lifting one address at a time. Entries now carry a TTL.
//!
//! Known limit: the poll only fetches *forward* from `last_id`, so an address
//! whose TTL expired while it is still abusive returns to the set only when the
//! feed re-lists it under a new id. That matches how the feed publishes; it is
//! not a full re-synchronisation.
//!
//! API docs: <https://apiban.org/doc.html>

use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::config::ApiBanConfig;
use crate::gateway::view::{AdmittedRange, GatewaySnapshot};
use crate::security::trust::{Exemption, SourceTrust};

/// Batch size returned by APIBAN per request.
const APIBAN_BATCH_SIZE: usize = 250;

/// Sentinel ID for the first full fetch.
const INITIAL_ID: &str = "100";

/// Base URL for the APIBAN API.
const APIBAN_BASE_URL: &str = "https://apiban.org/api";

/// Blocklist entries fetched from the feed, each with an expiry deadline.
///
/// `None` as a deadline means the entry never expires — reachable only by
/// configuring `ban_ttl_secs: 0`, which restores the pre-TTL behaviour for an
/// operator who wants it.
///
/// Expiry is enforced on read as well as by the periodic sweep, so an entry is
/// never honoured past its deadline just because no sweep has run yet.
#[derive(Debug, Default)]
pub struct ApiBanStore {
    entries: DashMap<IpAddr, Option<Instant>>,
}

impl ApiBanStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Whether `source` is currently blocked. An entry past its deadline
    /// reports `false` even before the sweep removes it.
    pub fn contains(&self, source: &IpAddr) -> bool {
        self.contains_at(source, Instant::now())
    }

    fn contains_at(&self, source: &IpAddr, now: Instant) -> bool {
        match self.entries.get(source) {
            Some(entry) => match *entry {
                Some(deadline) => deadline > now,
                None => true,
            },
            None => false,
        }
    }

    /// Insert `source` with `ttl` (`None` = never expires). Returns `true` when
    /// the address was not already present, so the caller can count genuinely
    /// new entries and program the kernel set once.
    pub(crate) fn insert(&self, source: IpAddr, ttl: Option<Duration>) -> bool {
        let deadline = ttl.map(|ttl| Instant::now() + ttl);
        self.entries.insert(source, deadline).is_none()
    }

    /// Drop every entry past its deadline. Returns how many were removed.
    fn sweep(&self) -> usize {
        self.sweep_at(Instant::now())
    }

    fn sweep_at(&self, now: Instant) -> usize {
        let before = self.entries.len();
        // Explicit match rather than `is_none_or`, which is newer than the
        // crate's MSRV.
        self.entries.retain(|_, deadline| match deadline {
            Some(deadline) => *deadline > now,
            None => true,
        });
        before - self.entries.len()
    }

    /// Number of entries held, including any past their deadline but not yet
    /// swept. Used only for logging and the ACL's cheap "any rules at all"
    /// check, both of which tolerate the imprecision.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove every entry `admitted` holds, returning each with the gateway
    /// group that admits it.
    fn evict_admitted(&self, admitted: &GatewaySnapshot) -> Vec<(IpAddr, Arc<str>)> {
        let listed: Vec<(IpAddr, Arc<str>)> = self
            .entries
            .iter()
            .filter_map(|entry| {
                admitted
                    .group_of(*entry.key())
                    .map(|group| (*entry.key(), Arc::clone(group)))
            })
            .collect();
        listed
            .into_iter()
            .filter(|(source, _)| self.entries.remove(source).is_some())
            .collect()
    }

    /// Every entry still in force, with the time it has left (`None` =
    /// permanent). Lapsed entries not yet swept are skipped.
    fn live_at(&self, now: Instant) -> Vec<(IpAddr, Option<Duration>)> {
        self.entries
            .iter()
            .filter_map(|entry| match *entry.value() {
                None => Some((*entry.key(), None)),
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(now);
                    (!remaining.is_zero()).then_some((*entry.key(), Some(remaining)))
                }
            })
            .collect()
    }
}

/// The running blocklist, for the kernel firewall to refill its ban sets from
/// after a ruleset reload recreated them empty. Set once, by
/// [`ApiBanClient::start`].
static INSTALLED: OnceLock<InstalledBlocklist> = OnceLock::new();

/// The running blocklist, or `None` when APIBAN is not configured.
pub(crate) fn installed() -> Option<&'static InstalledBlocklist> {
    INSTALLED.get()
}

/// The blocklist together with the trust it was filtered by.
pub(crate) struct InstalledBlocklist {
    store: Arc<ApiBanStore>,
    trust: SourceTrust,
}

impl InstalledBlocklist {
    /// A blocklist that is not the process-wide one, for a test driving the
    /// replay without starting a poller.
    #[cfg(test)]
    pub(crate) fn for_test(store: Arc<ApiBanStore>, trust: SourceTrust) -> Self {
        Self { store, trust }
    }

    /// Every entry in force at `now` with its remaining lifetime (`None` =
    /// permanent), leaving out any source trusted since it was listed.
    pub(crate) fn live_bans_at(&self, now: Instant) -> Vec<(IpAddr, Option<Duration>)> {
        live_untrusted(&self.store, &self.trust, now)
    }
}

fn live_untrusted(
    store: &ApiBanStore,
    trust: &SourceTrust,
    now: Instant,
) -> Vec<(IpAddr, Option<Duration>)> {
    store
        .live_at(now)
        .into_iter()
        .filter(|(source, _)| !trust.is_trusted(*source))
        .collect()
}

/// JSON response from the APIBAN `/banned` endpoint.
#[derive(Debug, Deserialize)]
struct ApiBanResponse {
    #[serde(rename = "ID")]
    id: String,
    ipaddress: Option<Vec<String>>,
}

/// Client that polls APIBAN and maintains a shared set of banned IPs.
pub struct ApiBanClient {
    api_key: String,
    interval: Duration,
    /// How long a fetched entry stays blocked. `None` = never expires.
    ban_ttl: Option<Duration>,
    /// Sources that must never be blocked no matter what the feed says
    /// (`security.trusted_cidrs`, and gateways under `trust_gateways`): own
    /// trunks, monitoring, management.
    trust: SourceTrust,
    banned: Arc<ApiBanStore>,
    client: reqwest::Client,
    /// Optional kernel-firewall handle — fetched IPs are also pushed to the
    /// nf_tables set, with the same TTL so the kernel expires them in lockstep.
    firewall: Option<crate::firewall::KernelFirewall>,
}

impl ApiBanClient {
    /// Create a new client from config. The banned set is empty until `start()`
    /// is called. `trusted_cidrs` comes from the enclosing `security` block;
    /// unparseable entries are ignored (the caller logs them).
    pub fn new(config: &ApiBanConfig, trusted_cidrs: &[String]) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            api_key: config.api_key.clone(),
            interval: Duration::from_secs(config.interval_secs),
            // 0 means "never expire" — the pre-TTL behaviour, kept reachable.
            ban_ttl: match config.ban_ttl_secs {
                0 => None,
                secs => Some(Duration::from_secs(secs)),
            },
            trust: SourceTrust::from_cidrs(trusted_cidrs),
            banned: Arc::new(ApiBanStore::new()),
            client,
            firewall: None,
        })
    }

    /// Returns the shared banned IP store for ACL integration.
    pub fn banned(&self) -> Arc<ApiBanStore> {
        Arc::clone(&self.banned)
    }

    /// Attach a kernel-firewall handle so fetched IPs are also programmed into
    /// the nf_tables set, on top of the userspace ACL set.
    pub fn with_firewall(mut self, firewall: Option<crate::firewall::KernelFirewall>) -> Self {
        self.firewall = firewall;
        self
    }

    /// Also exempt every source a gateway group admits
    /// (`security.trust_gateways`). `None` changes nothing.
    pub fn with_gateway_trust(
        mut self,
        gateways: Option<Arc<crate::gateway::view::GatewayView>>,
    ) -> Self {
        self.trust = self.trust.with_gateways(gateways);
        self
    }

    /// Whether `source` is exempt from the feed.
    #[cfg(test)]
    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trust.is_trusted(source)
    }

    /// Evict, at every publish of the gateway view, each listed address the
    /// view has just started admitting — from the store and from the kernel
    /// set. A no-op without `trust_gateways`.
    ///
    /// Ingest keeps a gateway out; this is the other order, a carrier
    /// provisioned after the feed listed its address. Without it the address
    /// stays blackholed in the kernel, on every port, for the entry's TTL.
    pub(crate) fn follow_gateway_view(&self) {
        let Some(gateways) = self.trust.gateways() else {
            return;
        };
        let store = Arc::downgrade(&self.banned);
        let firewall = self.firewall.clone();
        gateways.subscribe(Arc::new(move |_snapshot, added: &[AdmittedRange]| {
            let Some(store) = store.upgrade() else {
                return;
            };
            if added.is_empty() || store.is_empty() {
                return;
            }
            let admitted = GatewaySnapshot::build(added.to_vec());
            for (source, group) in store.evict_admitted(&admitted) {
                if let Some(firewall) = &firewall {
                    firewall.unban(source);
                }
                warn!(
                    ip = %source,
                    gateway_group = %group,
                    "APIBAN: listed address is now a gateway (security.trust_gateways), evicted"
                );
            }
        }));
    }

    /// Spawn the background polling task. Returns a `JoinHandle` for the poll loop.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        self.follow_gateway_view();
        let _ = INSTALLED.set(InstalledBlocklist {
            store: Arc::clone(&self.banned),
            trust: self.trust.clone(),
        });
        tokio::spawn(async move {
            self.poll_loop().await;
        })
    }

    async fn poll_loop(self) {
        let mut last_id = INITIAL_ID.to_string();

        info!(
            interval_secs = self.interval.as_secs(),
            ban_ttl_secs = self.ban_ttl.map(|ttl| ttl.as_secs()).unwrap_or(0),
            trusted_cidrs = self.trust.configured_len(),
            trust_gateways = self.trust.gateways().is_some(),
            "APIBAN client started"
        );

        loop {
            match self.fetch_all(&mut last_id).await {
                Ok(count) => {
                    if count > 0 {
                        info!(
                            new_entries = count,
                            total = self.banned.len(),
                            "APIBAN blocklist updated"
                        );
                    } else {
                        debug!("APIBAN: no new bans");
                    }
                }
                Err(error) => {
                    error!(%error, "APIBAN fetch failed, will retry next interval");
                }
            }

            // Drop entries past their TTL. The kernel set expires its own
            // elements, so this only keeps the userspace store in step.
            let expired = self.banned.sweep();
            if expired > 0 {
                info!(expired, total = self.banned.len(), "APIBAN entries expired");
            }

            tokio::time::sleep(self.interval).await;
        }
    }

    /// Add one batch of feed addresses to the store, dropping trusted and
    /// unparseable ones, and program each newly-added address into the kernel
    /// set with the same TTL. Returns how many were genuinely new.
    ///
    /// Split out of [`Self::fetch_all`] so the trusted filter and the TTL are
    /// exercised on the path that actually runs, not on a re-creation of it.
    pub(crate) fn ingest(&self, addresses: &[String]) -> usize {
        let mut added = 0;

        for ip_str in addresses {
            let Ok(ip_address) = ip_str.parse::<IpAddr>() else {
                warn!(ip = %ip_str, "APIBAN: skipping invalid IP address");
                continue;
            };

            // Trusted sources are dropped here, before both the userspace store
            // and the kernel set, so a listed trunk or management address is
            // never dropped anywhere. Doing it at the ACL alone would still
            // leave the kernel set blackholing the address on every port.
            match self.trust.exemption(ip_address) {
                Some(Exemption::Configured) => {
                    warn!(
                        ip = %ip_address,
                        "APIBAN: listed address is in trusted_cidrs, not banning"
                    );
                    continue;
                }
                Some(Exemption::Gateway(group)) => {
                    warn!(
                        ip = %ip_address,
                        gateway_group = %group,
                        "APIBAN: listed address is a gateway (security.trust_gateways), not banning"
                    );
                    continue;
                }
                None => {}
            }

            if self.banned.insert(ip_address, self.ban_ttl) {
                added += 1;
                if let Some(firewall) = &self.firewall {
                    match self.ban_ttl {
                        Some(ttl) => firewall.ban(ip_address, ttl),
                        None => firewall.ban_permanent(ip_address),
                    }
                }
            }
        }

        added
    }

    /// Fetch all new entries since `last_id`, paginating in batches of 250.
    /// Updates `last_id` to the most recent ID returned.
    /// Returns the number of new IPs added.
    async fn fetch_all(&self, last_id: &mut String) -> Result<usize, ApiBanError> {
        let mut total_added = 0;

        loop {
            let url = format!("{}/{}/banned/{}", APIBAN_BASE_URL, self.api_key, last_id);

            let response = self
                .client
                .get(&url)
                .send()
                .await
                .map_err(ApiBanError::Http)?;

            let status = response.status();
            if status == reqwest::StatusCode::UNAUTHORIZED {
                return Err(ApiBanError::InvalidApiKey);
            }

            let body = response.text().await.map_err(ApiBanError::Http)?;

            // APIBAN returns a plain text message when there are no new bans
            if body.contains("no new bans") {
                break;
            }

            if !status.is_success() {
                return Err(ApiBanError::BadStatus(status.as_u16(), body));
            }

            let parsed: ApiBanResponse = serde_json::from_str(&body).map_err(ApiBanError::Json)?;

            let addresses = parsed.ipaddress.unwrap_or_default();
            let batch_size = addresses.len();

            total_added += self.ingest(&addresses);

            *last_id = parsed.id;

            // If fewer than BATCH_SIZE returned, we have all entries
            if batch_size < APIBAN_BATCH_SIZE {
                break;
            }
        }

        Ok(total_added)
    }
}

/// Errors from the APIBAN client.
#[derive(Debug, thiserror::Error)]
pub enum ApiBanError {
    #[error("HTTP request failed: {0}")]
    Http(reqwest::Error),
    #[error("invalid API key (401 Unauthorized)")]
    InvalidApiKey,
    #[error("unexpected status {0}: {1}")]
    BadStatus(u16, String),
    #[error("JSON parse error: {0}")]
    Json(serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().expect("test IP literal")
    }

    fn client_with(trusted: &[&str], ban_ttl_secs: u64) -> ApiBanClient {
        let config = ApiBanConfig {
            api_key: "test-key".to_string(),
            interval_secs: 300,
            ban_ttl_secs,
        };
        let trusted: Vec<String> = trusted.iter().map(|cidr| (*cidr).to_string()).collect();
        ApiBanClient::new(&config, &trusted).expect("client builds")
    }

    #[test]
    fn parse_valid_response() {
        let json = r#"{"ID":"12345","ipaddress":["1.2.3.4","5.6.7.8","2001:db8::1"]}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "12345");
        let addresses = response.ipaddress.unwrap();
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], "1.2.3.4");
        assert_eq!(addresses[1], "5.6.7.8");
        assert_eq!(addresses[2], "2001:db8::1");
    }

    #[test]
    fn parse_empty_ipaddress_list() {
        let json = r#"{"ID":"99999","ipaddress":[]}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "99999");
        assert!(response.ipaddress.unwrap().is_empty());
    }

    #[test]
    fn parse_null_ipaddress() {
        let json = r#"{"ID":"100"}"#;
        let response: ApiBanResponse = serde_json::from_str(json).unwrap();

        assert_eq!(response.id, "100");
        assert!(response.ipaddress.is_none());
    }

    #[test]
    fn no_new_bans_detection() {
        // The actual APIBAN response when there are no new bans
        let body = r#"{"ID":"none","ipaddress":"no new bans"}"#;
        assert!(body.contains("no new bans"));

        // Normal response with IPs should not trigger the check
        let body = r#"{"ID":"12345","ipaddress":["1.2.3.4"]}"#;
        assert!(!body.contains("no new bans"));
    }

    #[test]
    fn store_reports_inserted_address_as_banned() {
        let store = ApiBanStore::new();
        assert!(store.insert(ip("192.0.2.10"), Some(Duration::from_secs(60))));
        assert!(store.contains(&ip("192.0.2.10")));
        assert!(!store.contains(&ip("192.0.2.11")));
    }

    #[test]
    fn store_duplicate_insert_reports_not_new() {
        let store = ApiBanStore::new();
        let ttl = Some(Duration::from_secs(60));
        assert!(store.insert(ip("192.0.2.10"), ttl));
        assert!(!store.insert(ip("192.0.2.10"), ttl));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_entry_stops_matching_once_past_its_deadline() {
        // Expiry is enforced on read, so a false positive stops being blocked
        // at its deadline rather than at the next sweep.
        let store = ApiBanStore::new();
        let now = Instant::now();
        store.insert(ip("192.0.2.10"), Some(Duration::from_millis(1)));

        assert!(store.contains_at(&ip("192.0.2.10"), now));
        assert!(!store.contains_at(&ip("192.0.2.10"), now + Duration::from_secs(1)));
    }

    #[test]
    fn store_sweep_drops_only_expired_entries() {
        let store = ApiBanStore::new();
        let now = Instant::now();
        store.insert(ip("192.0.2.10"), Some(Duration::from_secs(1)));
        store.insert(ip("192.0.2.11"), Some(Duration::from_secs(3600)));
        assert_eq!(store.len(), 2);

        assert_eq!(store.sweep_at(now + Duration::from_secs(60)), 1);
        assert_eq!(store.len(), 1);
        assert!(!store.contains_at(&ip("192.0.2.10"), now));
        assert!(store.contains_at(&ip("192.0.2.11"), now));
    }

    #[test]
    fn store_sweep_leaves_the_store_empty_after_every_entry_expires() {
        // The store grew without bound before entries carried a TTL; a batch of
        // entries whose TTL has passed must drain it back to zero.
        let store = ApiBanStore::new();
        let now = Instant::now();
        for octet in 0..50u8 {
            store.insert(
                ip(&format!("192.0.2.{octet}")),
                Some(Duration::from_secs(60)),
            );
        }
        assert_eq!(store.len(), 50);

        assert_eq!(store.sweep_at(now + Duration::from_secs(120)), 50);
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }

    #[test]
    fn store_permanent_entry_never_expires() {
        // ban_ttl_secs: 0 restores the pre-TTL behaviour.
        let store = ApiBanStore::new();
        let now = Instant::now();
        store.insert(ip("192.0.2.10"), None);

        assert!(store.contains_at(&ip("192.0.2.10"), now + Duration::from_secs(86_400 * 365)));
        assert_eq!(store.sweep_at(now + Duration::from_secs(86_400 * 365)), 0);
    }

    #[test]
    fn trusted_cidr_matches_v4_and_v6_sources() {
        let client = client_with(&["203.0.113.0/24", "2001:db8::/32"], 604_800);

        assert!(client.is_trusted(ip("203.0.113.7")));
        assert!(client.is_trusted(ip("2001:db8::1")));
        assert!(!client.is_trusted(ip("198.51.100.7")));
    }

    #[test]
    fn untrusted_client_treats_every_source_as_bannable() {
        let client = client_with(&[], 604_800);
        assert!(!client.is_trusted(ip("203.0.113.7")));
    }

    #[test]
    fn invalid_trusted_cidr_is_ignored_and_the_rest_still_apply() {
        let client = client_with(&["not-a-cidr", "203.0.113.0/24"], 604_800);

        assert!(client.is_trusted(ip("203.0.113.7")));
        assert!(!client.is_trusted(ip("198.51.100.7")));
    }

    #[test]
    fn ban_ttl_secs_zero_means_permanent() {
        assert_eq!(client_with(&[], 0).ban_ttl, None);
        assert_eq!(
            client_with(&[], 604_800).ban_ttl,
            Some(Duration::from_secs(604_800))
        );
    }

    fn feed(addresses: &[&str]) -> Vec<String> {
        addresses.iter().map(|a| (*a).to_string()).collect()
    }

    #[test]
    fn ingest_bans_an_untrusted_listed_address() {
        let client = client_with(&["203.0.113.0/24"], 604_800);

        assert_eq!(client.ingest(&feed(&["198.51.100.7"])), 1);
        assert!(client.banned.contains(&ip("198.51.100.7")));
    }

    #[test]
    fn ingest_never_bans_a_trusted_address() {
        // The regression this closes: a carrier trunk or a management address
        // that lands on the feed used to lose its trunk (and, because the
        // kernel drop is port-agnostic, its ssh) with no config able to save it.
        let client = client_with(&["203.0.113.0/24"], 604_800);

        assert_eq!(client.ingest(&feed(&["203.0.113.7"])), 0);
        assert!(!client.banned.contains(&ip("203.0.113.7")));
        assert!(client.banned.is_empty());
    }

    #[test]
    fn ingest_bans_the_untrusted_addresses_of_a_mixed_batch() {
        let client = client_with(&["203.0.113.0/24"], 604_800);

        let added = client.ingest(&feed(&[
            "198.51.100.7", // untrusted -> banned
            "203.0.113.7",  // trusted -> skipped
            "not-an-ip",    // unparseable -> skipped
            "198.51.100.8", // untrusted -> banned
            "198.51.100.7", // duplicate -> not counted again
        ]));

        assert_eq!(added, 2);
        assert!(client.banned.contains(&ip("198.51.100.7")));
        assert!(client.banned.contains(&ip("198.51.100.8")));
        assert!(!client.banned.contains(&ip("203.0.113.7")));
        assert_eq!(client.banned.len(), 2);
    }

    #[test]
    fn ingest_applies_the_configured_ttl_so_entries_do_not_accumulate() {
        // Entries used to be inserted permanently, so the store grew for the
        // life of the process. Ingest a batch, then step past the TTL.
        let client = client_with(&[], 1);
        let now = Instant::now();

        assert_eq!(client.ingest(&feed(&["198.51.100.7", "198.51.100.8"])), 2);
        assert!(client.banned.contains_at(&ip("198.51.100.7"), now));

        assert_eq!(client.banned.sweep_at(now + Duration::from_secs(60)), 2);
        assert!(client.banned.is_empty());
    }

    #[test]
    fn ingest_with_ttl_disabled_keeps_entries_forever() {
        let client = client_with(&[], 0);
        let now = Instant::now();

        client.ingest(&feed(&["198.51.100.7"]));

        let far_future = now + Duration::from_secs(86_400 * 365);
        assert!(client.banned.contains_at(&ip("198.51.100.7"), far_future));
        assert_eq!(client.banned.sweep_at(far_future), 0);
    }

    // --- security.trust_gateways ---

    fn gateway_view(spec: &str) -> Arc<crate::gateway::view::GatewayView> {
        let view = Arc::new(crate::gateway::view::GatewayView::new());
        publish(&view, spec);
        view
    }

    fn publish(view: &crate::gateway::view::GatewayView, spec: &str) {
        view.publish(|| {
            vec![AdmittedRange {
                network: spec.parse().expect("test CIDR"),
                group: Arc::from("carriers"),
            }]
        });
    }

    #[tokio::test]
    async fn ingest_never_bans_a_gateway_and_says_so() {
        let (firewall, mut commands) = crate::firewall::KernelFirewall::capturing();
        let client = client_with(&[], 604_800)
            .with_firewall(Some(firewall))
            .with_gateway_trust(Some(gateway_view("192.0.2.10/32")));

        let log = crate::log_capture::LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(log.clone())
            .finish();
        let added = tracing::subscriber::with_default(subscriber, || {
            client.ingest(&feed(&["192.0.2.10", "198.51.100.7"]))
        });

        assert_eq!(added, 1);
        assert!(!client.banned.contains(&ip("192.0.2.10")));
        // Positive control: the stranger in the same batch is banned, in
        // userspace and in the kernel — and only it reaches the kernel.
        assert!(client.banned.contains(&ip("198.51.100.7")));
        assert_eq!(
            commands.try_recv().ok(),
            Some(crate::firewall::Command::Ban {
                ip: ip("198.51.100.7"),
                ttl_ms: 604_800_000
            })
        );
        assert!(commands.try_recv().is_err());
        let rendered = log.rendered();
        assert!(
            rendered.contains("listed address is a gateway")
                && rendered.contains("ip=192.0.2.10")
                && rendered.contains("gateway_group=carriers"),
            "{rendered}"
        );
    }

    #[tokio::test]
    async fn ingest_bans_a_gateway_when_trust_gateways_is_off() {
        let _view = gateway_view("192.0.2.10/32");
        let client = client_with(&[], 604_800);
        assert_eq!(client.ingest(&feed(&["192.0.2.10"])), 1);
        assert!(client.banned.contains(&ip("192.0.2.10")));
    }

    #[tokio::test]
    async fn a_listed_address_is_evicted_when_it_becomes_a_gateway() {
        let (firewall, mut commands) = crate::firewall::KernelFirewall::capturing();
        let view = Arc::new(crate::gateway::view::GatewayView::new());
        let client = client_with(&[], 604_800)
            .with_firewall(Some(firewall))
            .with_gateway_trust(Some(Arc::clone(&view)));
        client.follow_gateway_view();

        assert_eq!(client.ingest(&feed(&["192.0.2.10", "198.51.100.7"])), 2);
        assert!(commands.try_recv().is_ok());
        assert!(commands.try_recv().is_ok());

        publish(&view, "192.0.2.10/32");

        assert!(!client.banned.contains(&ip("192.0.2.10")));
        assert!(client.banned.contains(&ip("198.51.100.7")), "stranger kept");
        assert_eq!(
            commands.try_recv().ok(),
            Some(crate::firewall::Command::Unban {
                ip: ip("192.0.2.10")
            })
        );
        assert!(commands.try_recv().is_err());
    }

    #[test]
    fn live_bans_leave_out_lapsed_permanent_aside_and_trusted_entries() {
        let view = Arc::new(crate::gateway::view::GatewayView::new());
        let store = ApiBanStore::new();
        let trust = SourceTrust::from_cidrs(&[]).with_gateways(Some(Arc::clone(&view)));
        let now = Instant::now();
        store.insert(ip("198.51.100.1"), Some(Duration::from_secs(3600)));
        store.insert(ip("198.51.100.2"), Some(Duration::from_millis(1)));
        store.insert(ip("198.51.100.3"), None);
        store.insert(ip("192.0.2.10"), Some(Duration::from_secs(3600)));
        publish(&view, "192.0.2.10/32");

        let mut live = live_untrusted(&store, &trust, now + Duration::from_secs(600));
        live.sort();
        assert_eq!(live.len(), 2, "{live:?}");
        assert_eq!(live[0].0, ip("198.51.100.1"));
        let remaining = live[0].1.expect("timed");
        assert!(
            remaining >= Duration::from_secs(3000) && remaining < Duration::from_secs(3010),
            "{remaining:?}"
        );
        assert_eq!(live[1], (ip("198.51.100.3"), None));
    }
}
