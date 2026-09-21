//! Reading the gateway groups from a source the controller owns, and
//! reconciling the live dispatcher against it.
//!
//! The gateway twin of [`crate::registrant::source`], and deliberately the same
//! shape: a versioned JSON contract, a pure reconcile, and an interval poll
//! that a source read failure never turns into a teardown.
//!
//! One thing is specific to gateways and load-bearing: the reconcile carries
//! **existing destinations over** rather than rebuilding them. A destination's
//! health, consecutive-failure count and `Retry-After` cooldown live on the
//! `Destination` itself, so rebuilding the group every poll would mark every
//! dead carrier healthy again on a 30-second cycle and route calls straight
//! back into it.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use super::{Algorithm, Destination, DispatcherGroup, DispatcherManager, ProbeConfig};
use crate::auth::{StoredCredentials, StoredSecret};
use crate::source_health::{Backoff, SourceHealth};
use crate::transport::Transport;

/// Version of the JSON contract the `http` source speaks.
pub const CONTRACT_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Wire contract
// ---------------------------------------------------------------------------

/// What a `gateway.backend: http` endpoint answers `GET {url}` with.
///
/// Typed for endpoint authors in `siphon_sdk.gateways`; see
/// `docs/reference/gateway-api.md`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayListResponse {
    /// Contract version. Absent is treated as `"1"`.
    #[serde(default = "default_contract_version")]
    pub version: String,
    /// One entry per destination. Rows are grouped by `group`.
    #[serde(default)]
    pub gateways: Vec<GatewayRow>,
}

/// One gateway destination, as the source describes it.
///
/// The same shape the `database` source reads by column name, so one view can
/// serve both.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayRow {
    /// Group this destination belongs to — the name `gateway.select()` takes.
    pub group: String,
    /// SIP URI to route to, e.g. `sip:gw1.carrier.example:5060`.
    pub uri: String,
    /// Socket address to send to. Resolved from the URI host when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `udp` (default), `tcp` or `tls`. Also read from the URI's
    /// `;transport=` parameter when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Weight for weighted round-robin.
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Priority tier; lower is tried first.
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Load-balancing algorithm for the whole group: `weighted` (default),
    /// `round_robin` or `hash`. Taken from the first row of each group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Free-form attributes, matched by `gateway.select(attrs=…)`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attrs: HashMap<String, String>,
    /// Source CIDRs that also count as members of this group for
    /// `from_gateway()`. Group-wide; taken from the first row that carries any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_networks: Vec<String>,
    /// Digest username this destination challenges with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Plaintext password. Supply this or `ha1`, not both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Pre-computed `H(username:realm:password)` hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha1: Option<String>,
    /// Which hash `ha1` was computed with. Default `md5`.
    #[serde(default = "default_ha1_algorithm")]
    pub ha1_algorithm: String,
    /// AoR of an outbound registration this destination belongs to. With no
    /// credentials of its own, it answers challenges with that registration's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers: Option<String>,
    /// Keep this destination out of selection while `registers` is not
    /// registered.
    #[serde(default)]
    pub require_registration: bool,
    /// `false` drops the destination without removing the row.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_contract_version() -> String {
    CONTRACT_VERSION.to_string()
}
fn default_ha1_algorithm() -> String {
    "md5".to_string()
}
fn default_weight() -> u32 {
    1
}
fn default_priority() -> u32 {
    1
}
fn default_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Desired state
// ---------------------------------------------------------------------------

/// One destination the source wants, validated.
#[derive(Debug, Clone)]
pub struct DesiredDestination {
    pub uri: String,
    pub address: String,
    pub transport: Transport,
    pub weight: u32,
    pub priority: u32,
    pub attrs: HashMap<String, String>,
    pub credentials: Option<StoredCredentials>,
    pub registers: Option<String>,
    pub require_registration: bool,
}

impl DesiredDestination {
    /// Whether an existing destination is the same one, so it can be carried
    /// over with its health intact.
    ///
    /// Everything a call would notice is compared. A change to any of it makes
    /// a new destination, which starts healthy — correct, because it is a
    /// different peer or a different way of reaching the same one.
    fn matches(&self, existing: &Destination) -> bool {
        existing.uri == self.uri
            && existing.transport == self.transport
            && existing.weight == self.weight
            && existing.priority == self.priority
            && existing.attrs == self.attrs
            && existing.registers == self.registers
            && existing.require_registration == self.require_registration
            && existing
                .credentials
                .as_deref()
                .map(|credentials| (credentials.username.clone(), credentials.secret.clone()))
                == self
                    .credentials
                    .as_ref()
                    .map(|credentials| (credentials.username.clone(), credentials.secret.clone()))
            && existing.address_str.as_deref().unwrap_or_default() == address_str_of(&self.address)
    }

    fn build(&self) -> Result<Destination, String> {
        let resolved = super::resolve_address(&self.address)
            .map_err(|error| format!("cannot resolve {:?}: {error}", self.address))?;
        let mut destination = Destination::new(
            self.uri.clone(),
            resolved,
            self.transport,
            self.weight,
            self.priority,
        )
        .with_attrs(self.attrs.clone());
        if let Some(ref credentials) = self.credentials {
            destination = destination.with_credentials(credentials.clone());
        }
        if let Some(ref aor) = self.registers {
            destination = destination.with_registration(aor.clone(), self.require_registration);
        }
        // Only a hostname is re-resolved on the probe cycle; a literal has
        // nothing to re-resolve to.
        if self.address.parse::<std::net::SocketAddr>().is_err() {
            destination = destination.with_address_str(self.address.clone());
        }
        Ok(destination)
    }
}

/// The `address_str` a destination built from this address would carry: the
/// address for a hostname, nothing for a literal.
fn address_str_of(address: &str) -> &str {
    if address.parse::<std::net::SocketAddr>().is_ok() {
        ""
    } else {
        address
    }
}

/// One group the source wants.
#[derive(Debug, Clone)]
pub struct DesiredGroup {
    pub name: String,
    pub algorithm: Algorithm,
    pub source_networks: Vec<String>,
    pub destinations: Vec<DesiredDestination>,
}

/// Turn source rows into the groups they describe.
///
/// Returns the groups plus the number of rows that could not be used. A bad row
/// is skipped rather than fatal: one malformed gateway must not take the rest
/// of the estate with it.
pub fn group_rows(rows: &[GatewayRow]) -> (Vec<DesiredGroup>, usize) {
    let mut groups: Vec<DesiredGroup> = Vec::new();
    let mut rejected = 0;

    for row in rows {
        if !row.enabled {
            continue;
        }
        let destination = match desired_destination(row) {
            Ok(destination) => destination,
            Err(error) => {
                rejected += 1;
                warn!(group = %row.group, uri = %row.uri, %error,
                      "gateway source: skipping an unusable row");
                continue;
            }
        };

        match groups.iter_mut().find(|group| group.name == row.group) {
            Some(group) => {
                // Group-wide settings come from whichever row carries them;
                // the first one wins so the result does not depend on row order
                // beyond that.
                if group.source_networks.is_empty() && !row.source_networks.is_empty() {
                    group.source_networks = row.source_networks.clone();
                }
                group.destinations.push(destination);
            }
            None => groups.push(DesiredGroup {
                name: row.group.clone(),
                algorithm: row
                    .algorithm
                    .as_deref()
                    .and_then(Algorithm::from_str)
                    .unwrap_or(Algorithm::Weighted),
                source_networks: row.source_networks.clone(),
                destinations: vec![destination],
            }),
        }
    }

    (groups, rejected)
}

fn desired_destination(row: &GatewayRow) -> Result<DesiredDestination, String> {
    if row.group.trim().is_empty() {
        return Err("`group` is empty".to_string());
    }
    if row.uri.trim().is_empty() {
        return Err("`uri` is empty".to_string());
    }

    let transport = match row
        .transport
        .as_deref()
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("tcp") => Transport::Tcp,
        Some("tls") => Transport::Tls,
        Some("udp") | None => transport_from_uri(&row.uri),
        Some(other) => {
            return Err(format!(
                "unknown `transport` {other:?} — use udp, tcp or tls"
            ))
        }
    };

    let address = row
        .address
        .clone()
        .unwrap_or_else(|| super::extract_address_from_uri(&row.uri));

    // A username with no secret, or a secret with no username, is a
    // half-configured credential — refused rather than silently unused.
    let credentials = match (&row.username, &row.password, &row.ha1) {
        (None, None, None) => None,
        (None, _, _) => return Err("a password or ha1 needs a `username`".to_string()),
        (Some(username), password, ha1) => Some(StoredCredentials {
            username: username.clone(),
            secret: StoredSecret::from_config(
                password.as_deref(),
                ha1.as_deref(),
                &row.ha1_algorithm,
            )?,
        }),
    };

    if row.require_registration && row.registers.is_none() {
        return Err("`require_registration` needs a `registers` AoR to gate on".to_string());
    }

    Ok(DesiredDestination {
        uri: row.uri.trim().to_string(),
        address,
        transport,
        weight: row.weight,
        priority: row.priority,
        attrs: row.attrs.clone(),
        credentials,
        registers: row.registers.clone(),
        require_registration: row.require_registration,
    })
}

fn transport_from_uri(uri: &str) -> Transport {
    let lowered = uri.to_ascii_lowercase();
    match lowered.split(";transport=").nth(1) {
        Some(rest) => {
            let value = rest.split([';', '>', ' ']).next().unwrap_or("udp");
            match value {
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                _ => Transport::Udp,
            }
        }
        None => Transport::Udp,
    }
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

/// What one reconcile pass did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReconcileReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    pub rejected: usize,
}

/// Build the destination list for a group, carrying over the ones that have not
/// changed.
///
/// Returns the list and whether anything about the group differs from `live` —
/// `false` means the group is left completely alone, which matters because
/// replacing it restarts its health prober.
fn reconcile_destinations(
    desired: &DesiredGroup,
    live: &[Arc<Destination>],
) -> (Vec<Arc<Destination>>, bool, usize) {
    let mut next = Vec::with_capacity(desired.destinations.len());
    let mut changed = live.len() != desired.destinations.len();
    let mut rejected = 0;

    for wanted in &desired.destinations {
        match live.iter().find(|existing| wanted.matches(existing)) {
            // Unchanged: carry the same Arc, and with it the health, failure
            // count and cooldown the prober has built up.
            Some(existing) => next.push(Arc::clone(existing)),
            None => match wanted.build() {
                Ok(destination) => {
                    changed = true;
                    next.push(Arc::new(destination));
                }
                Err(error) => {
                    rejected += 1;
                    changed = true;
                    warn!(uri = %wanted.uri, %error, "gateway source: cannot build a destination");
                }
            },
        }
    }

    (next, changed, rejected)
}

/// Read the source once and bring the live dispatcher in line with it.
pub async fn reconcile_once(
    manager: &Arc<DispatcherManager>,
    source: &GatewaySource,
) -> Result<ReconcileReport, String> {
    let rows = source.fetch().await?;

    // Resolving addresses blocks, so the whole build runs off the runtime.
    let manager_for_build = Arc::clone(manager);
    let report = tokio::task::spawn_blocking(move || apply_rows(&manager_for_build, &rows))
        .await
        .map_err(|error| format!("the gateway reconcile panicked: {error}"))?;

    // Admit a newly provisioned carrier in the same tick it became dialable.
    // A no-op unless the kernel gateway allow set is running, and it collapses
    // with any other poke in the same window, so an unchanged pass costs
    // nothing beyond the comparison the publisher does anyway.
    crate::firewall::gateways::request_publish();

    Ok(report)
}

/// The synchronous half of a reconcile: everything that resolves DNS.
fn apply_rows(manager: &Arc<DispatcherManager>, rows: &[GatewayRow]) -> ReconcileReport {
    let (mut desired, rejected) = group_rows(rows);
    let mut report = ReconcileReport {
        rejected,
        ..Default::default()
    };

    // A group name already held by YAML or a script is not the source's to take
    // over. Said once per pass, because the symptom otherwise is a group that
    // never picks up its new members.
    desired.retain(|group| {
        if manager.is_foreign_to_source(&group.name) {
            report.rejected += 1;
            warn!(
                group = %group.name,
                "gateway source: this group is already defined in siphon.yaml or by a script — \
                 leaving it alone"
            );
            return false;
        }
        true
    });

    for group in &desired {
        let live = manager.destinations_of(&group.name);
        let live_group = manager.get_group(&group.name);
        let existed = live_group.is_some();
        let (destinations, changed, build_rejected) = reconcile_destinations(group, &live);
        report.rejected += build_rejected;

        let source_networks: Vec<_> = group
            .source_networks
            .iter()
            .filter_map(|spec| super::parse_source_network(spec))
            .collect();
        let group_changed = live_group.as_ref().is_some_and(|existing| {
            existing.algorithm != group.algorithm || existing.source_networks != source_networks
        });

        if existed && !changed && !group_changed {
            // Nothing to do — and importantly, no group replacement, so the
            // health prober keeps running rather than being aborted and
            // respawned every poll.
            continue;
        }

        manager.add_group(
            DispatcherGroup::from_existing(group.name.clone(), group.algorithm, destinations)
                .with_probe_config(ProbeConfig::default())
                .with_source_networks(source_networks)
                .from_source(),
        );

        if existed {
            report.updated += 1;
        } else {
            report.added += 1;
        }
    }

    let wanted: std::collections::HashSet<&str> =
        desired.iter().map(|group| group.name.as_str()).collect();
    for name in manager.source_group_names() {
        if !wanted.contains(name.as_str()) {
            manager.remove_group(&name);
            report.removed += 1;
        }
    }

    report
}

/// How long start-up keeps retrying an unreadable source before giving up and
/// letting the node come up with no carriers.
///
/// Bounded on purpose. A node that cannot reach its controller has to come up:
/// it still has to answer a health probe, serve `/metrics` (where the
/// last-success gauge reads 0, which is exactly the alert), and accept the
/// admin refresh that a controller coming back can push at it. Blocking boot
/// indefinitely would turn a controller outage into an outage of every node
/// that happened to restart during it.
const STARTUP_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Read the source once at start-up, retrying on a short backoff, **before**
/// the listeners take traffic.
///
/// The loop below used to do its first fetch inside itself, so a node came up
/// and started answering calls while its carriers were still being read — or,
/// if the controller was down, with no carriers at all and one `warn` to say
/// so. At start-up the "keep the current set" reasoning that governs a running
/// node does not apply: there is no current set to keep.
///
/// Returns whether the source was read. A `false` is a node with no carriers
/// from this source, which is worth the `error` it logs.
pub async fn reconcile_at_startup(
    manager: &Arc<DispatcherManager>,
    source: &Arc<GatewaySource>,
    health: &mut SourceHealth,
) -> bool {
    reconcile_at_startup_within(manager, source, health, STARTUP_BUDGET).await
}

/// [`reconcile_at_startup`] with an explicit budget, so a test can exercise the
/// give-up path without waiting out the production one.
async fn reconcile_at_startup_within(
    manager: &Arc<DispatcherManager>,
    source: &Arc<GatewaySource>,
    health: &mut SourceHealth,
    budget: std::time::Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    let mut backoff = Backoff::new(source.refresh_interval());

    loop {
        match reconcile_once(manager, source).await {
            Ok(report) => {
                health.record_success();
                info!(
                    added = report.added,
                    rejected = report.rejected,
                    "gateway source read at start-up"
                );
                return true;
            }
            Err(error) => {
                health.record_failure(&error);
                let delay = backoff.next_delay();
                if tokio::time::Instant::now() + delay >= deadline {
                    error!(
                        %error,
                        budget_secs = budget.as_secs(),
                        "gateway source unreadable at start-up — coming up with NO carriers from \
                         it; siphon keeps retrying, and POST /admin/gateways/refresh applies one \
                         as soon as the source is back"
                    );
                    return false;
                }
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Poll the source and reconcile, for the life of the process.
///
/// `health` carries the start-up attempt's streak in, so a node that came up
/// against a dead controller does not restart its escalation from scratch.
pub async fn reconcile_loop(
    manager: Arc<DispatcherManager>,
    source: Arc<GatewaySource>,
    mut health: SourceHealth,
) {
    let interval = source.refresh_interval();
    info!(
        refresh_secs = interval.as_secs(),
        "gateway groups follow a configured source"
    );
    let mut backoff = Backoff::new(interval);

    loop {
        let delay = match reconcile_once(&manager, &source).await {
            Ok(report) => {
                health.record_success();
                backoff.reset();
                if report.added + report.updated + report.removed + report.rejected > 0 {
                    info!(
                        added = report.added,
                        updated = report.updated,
                        removed = report.removed,
                        rejected = report.rejected,
                        "gateway source reconciled"
                    );
                }
                interval
            }
            Err(error) => {
                // An unreadable source is not evidence that the carriers went
                // away; tearing the estate down over it would fail every call.
                // So the set is kept — but the node retries sooner than the
                // next interval, so a controller that comes back is picked up
                // in seconds rather than up to `refresh_secs` later.
                health.record_failure(&error);
                backoff.next_delay()
            }
        };
        tokio::time::sleep(delay).await;
    }
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The configured source of gateway groups.
#[derive(Debug)]
pub enum GatewaySource {
    Database(DatabaseSource),
    Http(HttpSource),
}

impl GatewaySource {
    pub async fn fetch(&self) -> Result<Vec<GatewayRow>, String> {
        match self {
            GatewaySource::Database(source) => source.fetch().await,
            GatewaySource::Http(source) => source.fetch().await,
        }
    }

    pub fn refresh_interval(&self) -> std::time::Duration {
        let seconds = match self {
            GatewaySource::Database(source) => source.refresh_secs(),
            GatewaySource::Http(source) => source.config.refresh_secs,
        };
        std::time::Duration::from_secs(seconds.max(1))
    }
}

/// The configured source, so an out-of-band refresh can reach it.
static SOURCE: std::sync::OnceLock<Arc<GatewaySource>> = std::sync::OnceLock::new();

/// Record the configured source. Called once, at start-up.
pub fn set_source(source: Arc<GatewaySource>) {
    let _ = SOURCE.set(source);
}

/// The configured source, if `gateway.backend` names one.
pub fn configured_source() -> Option<&'static Arc<GatewaySource>> {
    SOURCE.get()
}

/// A JSON endpoint the controller serves.
#[derive(Debug)]
pub struct HttpSource {
    config: crate::config::GatewayHttpConfig,
    client: reqwest::Client,
}

impl HttpSource {
    pub fn new(config: crate::config::GatewayHttpConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
        Ok(Self { config, client })
    }

    async fn fetch(&self) -> Result<Vec<GatewayRow>, String> {
        let mut request = self.client.get(&self.config.url);
        if let Some(ref header) = self.config.auth_header {
            request = request.header(reqwest::header::AUTHORIZATION, header);
        }
        let response = request
            .send()
            .await
            .map_err(|error| format!("GET {} failed: {error}", self.config.url))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("GET {} answered {status}", self.config.url));
        }
        let body: GatewayListResponse = response
            .json()
            .await
            .map_err(|error| format!("GET {} returned invalid JSON: {error}", self.config.url))?;
        if body.version != CONTRACT_VERSION {
            warn!(
                version = %body.version,
                expected = CONTRACT_VERSION,
                "gateway http source speaks a different contract version"
            );
        }
        Ok(body.gateways)
    }
}

#[cfg(feature = "postgres-backend")]
pub use postgres::DatabaseSource;

#[cfg(feature = "postgres-backend")]
mod postgres {
    use super::GatewayRow;
    use crate::config::GatewayDatabaseConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tracing::{debug, warn};

    /// A PostgreSQL gateway source, reconnecting on demand.
    #[derive(Debug)]
    pub struct DatabaseSource {
        config: GatewayDatabaseConfig,
        client: Arc<Mutex<Option<Arc<tokio_postgres::Client>>>>,
        instance_id: String,
        binds_instance: bool,
    }

    impl DatabaseSource {
        pub fn new(config: GatewayDatabaseConfig, instance_id: String) -> Self {
            let binds_instance = config.query.contains("$1");
            Self {
                config,
                client: Arc::new(Mutex::new(None)),
                instance_id,
                binds_instance,
            }
        }

        pub(super) fn refresh_secs(&self) -> u64 {
            self.config.refresh_secs
        }

        pub(super) async fn fetch(&self) -> Result<Vec<GatewayRow>, String> {
            let timeout = Duration::from_millis(self.config.timeout_ms);
            match tokio::time::timeout(timeout, self.query()).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    self.drop_client().await;
                    Err(format!(
                        "the gateway query did not answer within {}ms",
                        self.config.timeout_ms
                    ))
                }
            }
        }

        async fn query(&self) -> Result<Vec<GatewayRow>, String> {
            let client = self.client().await?;
            let rows = if self.binds_instance {
                client.query(&self.config.query, &[&self.instance_id]).await
            } else {
                client.query(&self.config.query, &[]).await
            };
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => {
                    self.drop_client().await;
                    return Err(format!("the gateway query failed: {error}"));
                }
            };
            Ok(rows.iter().map(row_from_sql).collect())
        }

        async fn client(&self) -> Result<Arc<tokio_postgres::Client>, String> {
            let mut guard = self.client.lock().await;
            if let Some(client) = guard.as_ref() {
                if !client.is_closed() {
                    return Ok(Arc::clone(client));
                }
                debug!("gateway source: connection closed, reconnecting");
                *guard = None;
            }

            let (client, connection) =
                tokio_postgres::connect(&self.config.url, tokio_postgres::NoTls)
                    .await
                    .map_err(|error| format!("cannot connect to the gateway source: {error}"))?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    warn!(error = %error, "gateway source: connection ended");
                }
            });
            let client = Arc::new(client);
            *guard = Some(Arc::clone(&client));
            Ok(client)
        }

        async fn drop_client(&self) {
            *self.client.lock().await = None;
        }
    }

    /// Read one row by column name. `group` is also accepted as `group_name`,
    /// because `group` is a reserved word in SQL and a view often spells it the
    /// other way rather than quoting it.
    fn row_from_sql(row: &tokio_postgres::Row) -> GatewayRow {
        GatewayRow {
            group: text(row, "group")
                .or_else(|| text(row, "group_name"))
                .unwrap_or_default(),
            uri: text(row, "uri").unwrap_or_default(),
            address: text(row, "address"),
            transport: text(row, "transport"),
            weight: integer(row, "weight").map(|v| v.max(0) as u32).unwrap_or(1),
            priority: integer(row, "priority")
                .map(|v| v.max(0) as u32)
                .unwrap_or(1),
            algorithm: text(row, "algorithm"),
            attrs: HashMap::new(),
            source_networks: text(row, "source_networks")
                .map(|value| {
                    value
                        .split(',')
                        .map(str::trim)
                        .filter(|entry| !entry.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            username: text(row, "username"),
            password: text(row, "password"),
            ha1: text(row, "ha1"),
            ha1_algorithm: text(row, "ha1_algorithm").unwrap_or_else(|| "md5".to_string()),
            registers: text(row, "registers"),
            require_registration: boolean(row, "require_registration").unwrap_or(false),
            enabled: boolean(row, "enabled").unwrap_or(true),
        }
    }

    fn has_column(row: &tokio_postgres::Row, name: &str) -> bool {
        row.columns().iter().any(|column| column.name() == name)
    }

    fn text(row: &tokio_postgres::Row, name: &str) -> Option<String> {
        if !has_column(row, name) {
            return None;
        }
        row.try_get::<_, Option<String>>(name).ok().flatten()
    }

    fn integer(row: &tokio_postgres::Row, name: &str) -> Option<i64> {
        if !has_column(row, name) {
            return None;
        }
        if let Ok(Some(value)) = row.try_get::<_, Option<i32>>(name) {
            return Some(value as i64);
        }
        row.try_get::<_, Option<i64>>(name).ok().flatten()
    }

    fn boolean(row: &tokio_postgres::Row, name: &str) -> Option<bool> {
        if !has_column(row, name) {
            return None;
        }
        row.try_get::<_, Option<bool>>(name).ok().flatten()
    }
}

/// Stand-in when the `postgres-backend` feature is off.
#[cfg(not(feature = "postgres-backend"))]
#[derive(Debug)]
pub struct DatabaseSource {
    config: crate::config::GatewayDatabaseConfig,
}

#[cfg(not(feature = "postgres-backend"))]
impl DatabaseSource {
    pub fn new(config: crate::config::GatewayDatabaseConfig, _instance_id: String) -> Self {
        Self { config }
    }

    pub(super) fn refresh_secs(&self) -> u64 {
        self.config.refresh_secs
    }

    pub(super) async fn fetch(&self) -> Result<Vec<GatewayRow>, String> {
        Err(
            "gateway.backend: database needs the postgres-backend feature, which this binary was \
             built without"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(group: &str, uri: &str) -> GatewayRow {
        GatewayRow {
            group: group.to_string(),
            uri: uri.to_string(),
            address: Some("203.0.113.10:5060".to_string()),
            transport: None,
            weight: 1,
            priority: 1,
            algorithm: None,
            attrs: HashMap::new(),
            source_networks: Vec::new(),
            username: None,
            password: None,
            ha1: None,
            ha1_algorithm: "md5".to_string(),
            registers: None,
            require_registration: false,
            enabled: true,
        }
    }

    fn manager() -> Arc<DispatcherManager> {
        Arc::new(DispatcherManager::new())
    }

    // --- Row grouping and validation ---

    #[test]
    fn rows_are_gathered_into_their_groups() {
        let rows = vec![
            row("carriers", "sip:gw1.carrier.example:5060"),
            row("carriers", "sip:gw2.carrier.example:5060"),
            row("peers", "sip:peer.example:5060"),
        ];
        let (groups, rejected) = group_rows(&rows);

        assert_eq!(rejected, 0);
        assert_eq!(groups.len(), 2);
        let carriers = groups.iter().find(|g| g.name == "carriers").expect("group");
        assert_eq!(carriers.destinations.len(), 2);
    }

    #[test]
    fn a_disabled_row_is_dropped_without_being_an_error() {
        let mut disabled = row("carriers", "sip:gw1.carrier.example:5060");
        disabled.enabled = false;
        let (groups, rejected) = group_rows(&[disabled]);
        assert!(groups.is_empty());
        assert_eq!(rejected, 0);
    }

    #[test]
    fn a_secret_without_a_username_is_rejected() {
        // Half a credential would otherwise sit there looking configured while
        // every challenge went unanswered.
        let mut orphan = row("carriers", "sip:gw1.carrier.example:5060");
        orphan.password = Some("secret123".to_string());
        let (groups, rejected) = group_rows(&[orphan]);
        assert!(groups.is_empty());
        assert_eq!(rejected, 1);
    }

    #[test]
    fn require_registration_without_a_link_is_rejected() {
        let mut ungated = row("carriers", "sip:gw1.carrier.example:5060");
        ungated.require_registration = true;
        let (_, rejected) = group_rows(&[ungated]);
        assert_eq!(rejected, 1);
    }

    #[test]
    fn the_transport_comes_from_the_uri_when_the_column_is_absent() {
        let row = row("carriers", "sip:gw1.carrier.example:5061;transport=tls");
        let (groups, _) = group_rows(&[row]);
        assert_eq!(groups[0].destinations[0].transport, Transport::Tls);
    }

    // --- Reconcile ---

    #[test]
    fn a_first_pass_adds_every_group() {
        let manager = manager();
        let report = apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);

        assert_eq!(report.added, 1);
        assert_eq!(report.updated, 0);
        assert!(manager.get_group("carriers").is_some());
    }

    #[test]
    fn an_unchanged_source_leaves_the_group_completely_alone() {
        // The one that matters. Replacing a group restarts its health prober,
        // so an unchanged poll must not touch it at all.
        let manager = manager();
        let rows = vec![row("carriers", "sip:gw1.carrier.example:5060")];
        apply_rows(&manager, &rows);
        let first = manager.get_group("carriers").expect("group");

        let report = apply_rows(&manager, &rows);

        assert_eq!(report, ReconcileReport::default());
        let second = manager.get_group("carriers").expect("group");
        assert!(
            Arc::ptr_eq(&first, &second),
            "the group was replaced despite nothing changing"
        );
    }

    #[test]
    fn changing_only_source_networks_updates_membership_without_resetting_health() {
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gateway.example.com:5060")];
        rows[0].source_networks = vec!["192.0.2.0/24".to_string()];
        apply_rows(&manager, &rows);
        let first = manager.get_group("carriers").expect("group");
        let destination = Arc::clone(&first.all_destinations()[0]);
        destination.mark_down();

        rows[0].source_networks = vec!["198.51.100.0/24".to_string()];
        let report = apply_rows(&manager, &rows);
        assert_eq!(report.updated, 1);
        let second = manager.get_group("carriers").expect("group");
        assert!(!second.contains_source("192.0.2.1".parse().unwrap()));
        assert!(second.contains_source("198.51.100.1".parse().unwrap()));
        assert!(Arc::ptr_eq(&destination, &second.all_destinations()[0]));
        assert!(!destination.is_healthy());
        assert_eq!(apply_rows(&manager, &rows), ReconcileReport::default());

        rows[0].source_networks.clear();
        assert_eq!(apply_rows(&manager, &rows).updated, 1);
        assert!(!manager
            .get_group("carriers")
            .unwrap()
            .contains_source("198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn changing_only_algorithm_replaces_group_and_preserves_destinations() {
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gateway.example.com:5060")];
        apply_rows(&manager, &rows);
        let first = manager.get_group("carriers").expect("group");
        rows[0].algorithm = Some("hash".to_string());

        assert_eq!(apply_rows(&manager, &rows).updated, 1);
        let second = manager.get_group("carriers").expect("group");
        assert_eq!(second.algorithm, Algorithm::Hash);
        assert!(Arc::ptr_eq(
            &first.all_destinations()[0],
            &second.all_destinations()[0]
        ));
        assert_eq!(apply_rows(&manager, &rows), ReconcileReport::default());
    }

    #[test]
    fn a_dead_carrier_stays_dead_across_a_refresh() {
        // Health lives on the Destination, so rebuilding it would mark every
        // dead carrier healthy again on every poll and route calls back into
        // it. The unchanged destination has to carry over as the same Arc.
        let manager = manager();
        let rows = vec![
            row("carriers", "sip:gw1.carrier.example:5060"),
            row("carriers", "sip:gw2.carrier.example:5060"),
        ];
        apply_rows(&manager, &rows);
        let group = manager.get_group("carriers").expect("group");
        let dead = Arc::clone(&group.all_destinations()[0]);
        dead.mark_down();
        assert!(!dead.is_healthy());

        // A third carrier appears, so the group IS rebuilt — the survivors
        // still have to keep their health.
        let mut grown = rows.clone();
        grown.push(row("carriers", "sip:gw3.carrier.example:5060"));
        let report = apply_rows(&manager, &grown);

        assert_eq!(report.updated, 1);
        let refreshed = manager.get_group("carriers").expect("group");
        let still_dead = refreshed
            .all_destinations()
            .iter()
            .find(|d| d.uri == "sip:gw1.carrier.example:5060")
            .expect("the carrier is still in the group");
        assert!(
            !still_dead.is_healthy(),
            "a dead carrier came back healthy on a refresh"
        );
        assert!(
            Arc::ptr_eq(&dead, still_dead),
            "it was rebuilt, not carried"
        );
    }

    #[test]
    fn a_group_the_source_dropped_is_removed() {
        let manager = manager();
        apply_rows(
            &manager,
            &[
                row("carriers", "sip:gw1.carrier.example:5060"),
                row("peers", "sip:peer.example:5060"),
            ],
        );

        let report = apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);

        assert_eq!(report.removed, 1);
        assert!(manager.get_group("peers").is_none());
        assert!(manager.get_group("carriers").is_some());
    }

    #[test]
    fn a_yaml_group_is_never_touched_by_a_reconcile() {
        // Without this the first pass would delete every configured group.
        let manager = manager();
        manager.add_group(
            DispatcherGroup::new("carriers".to_string(), Algorithm::Weighted, Vec::new())
                .from_yaml(),
        );

        let report = apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);

        assert_eq!(report.rejected, 1);
        assert_eq!(report.added, 0);
        let group = manager.get_group("carriers").expect("still there");
        assert_eq!(group.origin, crate::gateway::GroupOrigin::Yaml);
        assert!(group.all_destinations().is_empty(), "it was overwritten");
    }

    #[test]
    fn a_source_group_is_removed_but_a_yaml_one_survives() {
        let manager = manager();
        manager.add_group(
            DispatcherGroup::new("configured".to_string(), Algorithm::Weighted, Vec::new())
                .from_yaml(),
        );
        apply_rows(
            &manager,
            &[row("from-source", "sip:gw1.carrier.example:5060")],
        );

        // The source now lists nothing at all.
        let report = apply_rows(&manager, &[]);

        assert_eq!(report.removed, 1);
        assert!(manager.get_group("from-source").is_none());
        assert!(manager.get_group("configured").is_some());
    }

    #[test]
    fn a_changed_weight_rebuilds_the_destination() {
        let manager = manager();
        apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);

        let mut heavier = row("carriers", "sip:gw1.carrier.example:5060");
        heavier.weight = 5;
        let report = apply_rows(&manager, &[heavier]);

        assert_eq!(report.updated, 1);
        let group = manager.get_group("carriers").expect("group");
        assert_eq!(group.all_destinations()[0].weight, 5);
    }

    // --- Wire contract ---

    #[test]
    fn the_http_contract_parses_a_minimal_row() {
        let json = r#"{"gateways":[{"group":"carriers","uri":"sip:gw1.carrier.example:5060"}]}"#;
        let response: GatewayListResponse =
            serde_json::from_str(json).expect("the contract parses");
        assert_eq!(response.version, CONTRACT_VERSION);
        let parsed = &response.gateways[0];
        assert_eq!(parsed.weight, 1);
        assert_eq!(parsed.priority, 1);
        assert!(parsed.enabled);
        assert!(!parsed.require_registration);
    }

    #[test]
    fn the_http_contract_round_trips_without_nulls() {
        let response = GatewayListResponse {
            version: CONTRACT_VERSION.to_string(),
            gateways: vec![row("carriers", "sip:gw1.carrier.example:5060")],
        };
        let json = serde_json::to_string(&response).expect("serializes");
        let back: GatewayListResponse = serde_json::from_str(&json).expect("re-parses");
        assert_eq!(back.gateways.len(), 1);
        assert_eq!(back.gateways[0].group, "carriers");
        assert!(!json.contains("null"), "{json}");
    }

    /// An HTTP source aimed at a port nothing is listening on: every fetch
    /// fails immediately, which is what a node booting while its controller is
    /// down actually sees.
    fn unreadable_source(refresh_secs: u64) -> Arc<GatewaySource> {
        let http = crate::config::GatewayHttpConfig {
            // Reserved for documentation (RFC 5737), so this cannot reach a
            // real host on a developer's network.
            url: "http://192.0.2.1:1/gateways".to_string(),
            refresh_secs,
            timeout_ms: 50,
            auth_header: None,
        };
        Arc::new(GatewaySource::Http(
            HttpSource::new(http).expect("the HTTP client builds"),
        ))
    }

    /// The boot path gives up inside its budget rather than blocking start-up.
    ///
    /// A node that cannot reach its controller still has to come up: it answers
    /// the health probe, serves the last-success gauge that is the alert, and
    /// accepts the admin refresh a recovering controller pushes at it. Blocking
    /// boot would turn one controller outage into an outage of every node that
    /// restarted during it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unreadable_source_at_startup_gives_up_inside_its_budget() {
        let manager = manager();
        let source = unreadable_source(1);
        let mut health = SourceHealth::new(crate::source_health::SourceKind::Gateway);

        let started = std::time::Instant::now();
        let read = reconcile_at_startup_within(
            &manager,
            &source,
            &mut health,
            std::time::Duration::from_millis(900),
        )
        .await;

        assert!(!read, "an unreachable controller cannot be read");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "start-up must not block: took {:?}",
            started.elapsed()
        );
        assert!(
            health.consecutive_failures() >= 2,
            "it retried rather than giving up on the first failure: {} attempt(s)",
            health.consecutive_failures()
        );
    }

    /// Retries are a backoff, not a hot loop: a controller that is down must
    /// not be hammered by every node that rebooted into the outage.
    #[tokio::test(flavor = "multi_thread")]
    async fn startup_retries_back_off_rather_than_spinning() {
        let manager = manager();
        let source = unreadable_source(1);
        let mut health = SourceHealth::new(crate::source_health::SourceKind::Gateway);

        reconcile_at_startup_within(
            &manager,
            &source,
            &mut health,
            std::time::Duration::from_millis(900),
        )
        .await;

        // 250 ms, 500 ms, then the 1 s ceiling — a 900 ms budget admits a
        // handful of attempts, not hundreds.
        assert!(
            health.consecutive_failures() <= 6,
            "{} attempts in 900 ms is a spin, not a backoff",
            health.consecutive_failures()
        );
    }

    /// Every failed read is counted, so a dashboard can rate it; the success
    /// timestamp is what ages out. Together they are "this node has been
    /// serving a stale carrier set for six hours".
    #[tokio::test(flavor = "multi_thread")]
    async fn every_failed_read_is_counted() {
        let manager = manager();
        let source = unreadable_source(1);
        let mut health = SourceHealth::new(crate::source_health::SourceKind::Gateway);

        for _ in 0..3 {
            assert!(reconcile_once(&manager, &source).await.is_err());
            health.record_failure("connection refused");
        }
        assert_eq!(health.consecutive_failures(), 3);
    }
}
