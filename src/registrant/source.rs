//! Reading the registering trunks from a source the controller owns, and
//! reconciling siphon's live registrations against it.
//!
//! A controller holds trunks as data — created, edited and deleted in a UI,
//! across tenants — and renders no YAML by hand. `registrant.backend: database`
//! and `http` let siphon follow that data without a restart, the way
//! `auth.backend: database` already lets it follow a credential store.
//!
//! Two sources, because a credential store cannot always hold a reversible
//! secret. A trunk password has to be recoverable to register with, unlike the
//! H(A1) a credential view exposes. `database` therefore accepts an `ha1`
//! column as well as a `password`, and `http` exists for the deployment that
//! seals its secrets at rest: the controller unseals in-process and serves the
//! credential over a trusted local channel, so siphon never sees the sealed
//! form and no sealing construction has to enter siphon.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::auth::StoredSecret;
use crate::source_health::{Backoff, SourceHealth};

/// Version of the JSON contract the `http` source speaks.
pub const CONTRACT_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// Wire contract (the `http` source)
// ---------------------------------------------------------------------------

/// What a `registrant.backend: http` endpoint answers `GET {url}` with.
///
/// Typed for endpoint authors in `siphon_sdk.registrants`; see
/// `docs/reference/registrant-api.md`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrantListResponse {
    /// Contract version. Absent is treated as `"1"`.
    #[serde(default = "default_contract_version")]
    pub version: String,
    /// One entry per trunk that should be registered.
    #[serde(default)]
    pub registrants: Vec<RegistrantRow>,
}

/// One registering trunk, as the source describes it.
///
/// The same shape the `database` source reads by column name, so one view can
/// serve both.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RegistrantRow {
    /// Address of record to register, e.g. `sip:trunk1@carrier.example`.
    pub aor: String,
    /// Registrar to send the REGISTER to, e.g. `sip:carrier.example:5060`.
    pub registrar: String,
    /// Digest username.
    pub username: String,
    /// Plaintext password. Supply this or `ha1`, not both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Pre-computed `H(username:realm:password)` hex string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ha1: Option<String>,
    /// Which hash `ha1` was computed with. Default `md5`.
    #[serde(default = "default_ha1_algorithm")]
    pub ha1_algorithm: String,
    /// Realm hint. Derived from the registrar's challenge when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// Re-registration interval in seconds. `registrant.default_interval`
    /// when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u32>,
    /// Contact URI override. Generated from the local address when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// `udp` (default), `tcp` or `tls`.
    #[serde(default = "default_transport")]
    pub transport: String,
    /// `false` de-registers the trunk without removing the row, which is what
    /// a UI's "disable" switch wants. Default `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Optional `gateway:` group this trunk's calls egress through. Links the
    /// registration to a gateway destination so one row describes one trunk;
    /// see `gateway.backend`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

fn default_contract_version() -> String {
    CONTRACT_VERSION.to_string()
}

fn default_ha1_algorithm() -> String {
    "md5".to_string()
}

fn default_transport() -> String {
    "udp".to_string()
}

fn default_enabled() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Desired state
// ---------------------------------------------------------------------------

/// One trunk the source says should be registered, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredRegistrant {
    pub aor: String,
    pub registrar: String,
    pub username: String,
    pub secret: StoredSecret,
    pub realm: Option<String>,
    pub interval: Option<u32>,
    pub contact: Option<String>,
    pub transport: String,
    pub gateway: Option<String>,
}

impl DesiredRegistrant {
    /// Validate a source row. `Ok(None)` for a row that is present but
    /// disabled: the trunk should not be registered, which is different from
    /// the row being malformed.
    pub fn from_row(row: &RegistrantRow) -> Result<Option<Self>, String> {
        if !row.enabled {
            return Ok(None);
        }
        if row.aor.trim().is_empty() {
            return Err("`aor` is empty".to_string());
        }
        if row.registrar.trim().is_empty() {
            return Err("`registrar` is empty".to_string());
        }
        if row.username.trim().is_empty() {
            return Err("`username` is empty".to_string());
        }
        let secret = StoredSecret::from_config(
            row.password.as_deref(),
            row.ha1.as_deref(),
            &row.ha1_algorithm,
        )?;
        let transport = row.transport.to_ascii_lowercase();
        if !matches!(transport.as_str(), "udp" | "tcp" | "tls") {
            return Err(format!(
                "unknown `transport` {transport:?} — use udp, tcp or tls"
            ));
        }
        Ok(Some(Self {
            aor: row.aor.trim().to_string(),
            registrar: row.registrar.trim().to_string(),
            username: row.username.clone(),
            secret,
            realm: row.realm.clone(),
            interval: row.interval,
            contact: row.contact.clone(),
            transport,
            gateway: row.gateway.clone(),
        }))
    }

    /// A hash of everything that changes what siphon registers.
    ///
    /// This is what stops a poll from re-REGISTERing the whole estate every
    /// cycle: an entry whose fingerprint is unchanged is left completely
    /// alone, Call-ID, CSeq and refresh timer included.
    pub fn fingerprint(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.aor.hash(&mut hasher);
        self.registrar.hash(&mut hasher);
        self.username.hash(&mut hasher);
        match &self.secret {
            StoredSecret::Password(password) => {
                0u8.hash(&mut hasher);
                password.hash(&mut hasher);
            }
            StoredSecret::Ha1 { value, algorithm } => {
                1u8.hash(&mut hasher);
                value.hash(&mut hasher);
                algorithm.to_string().hash(&mut hasher);
            }
        }
        self.realm.hash(&mut hasher);
        self.interval.hash(&mut hasher);
        self.contact.hash(&mut hasher);
        self.transport.hash(&mut hasher);
        self.gateway.hash(&mut hasher);
        hasher.finish()
    }
}

// ---------------------------------------------------------------------------
// Reconcile
// ---------------------------------------------------------------------------

/// What reconciling the live set against the source calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// Not registered yet.
    Add(DesiredRegistrant),
    /// Registered, but something registration-visible changed.
    Update(DesiredRegistrant),
    /// Registered, and the source no longer lists it (deleted, or disabled).
    Remove(String),
}

/// The changes that bring `live` in line with `desired`.
///
/// `live` maps AoR to the fingerprint it was created from, and must contain
/// **only entries this source created** — a YAML entry or one a script added
/// with `registration.add` is not the source's to remove, and including it here
/// would have the poller delete it on its first pass.
///
/// Pure on purpose: the diff is the part worth testing, and it tests without a
/// database.
pub fn reconcile(
    desired: &[DesiredRegistrant],
    live: &HashMap<String, u64>,
) -> Vec<ReconcileAction> {
    let mut actions = Vec::new();
    let mut seen = std::collections::HashSet::with_capacity(desired.len());

    for entry in desired {
        seen.insert(entry.aor.as_str());
        match live.get(&entry.aor) {
            None => actions.push(ReconcileAction::Add(entry.clone())),
            Some(&fingerprint) if fingerprint != entry.fingerprint() => {
                actions.push(ReconcileAction::Update(entry.clone()))
            }
            Some(_) => {}
        }
    }

    for aor in live.keys() {
        if !seen.contains(aor.as_str()) {
            actions.push(ReconcileAction::Remove(aor.clone()));
        }
    }

    actions
}

/// Build a live registrant entry from a validated source row.
///
/// Resolves the registrar's address, which is blocking DNS, so the reconcile
/// task calls this inside `spawn_blocking`.
pub fn entry_from_desired(
    desired: &DesiredRegistrant,
    default_interval: u32,
) -> Result<super::RegistrantEntry, String> {
    let registrar_host = desired
        .registrar
        .strip_prefix("sip:")
        .or_else(|| desired.registrar.strip_prefix("sips:"))
        .unwrap_or(&desired.registrar);

    let transport = match desired.transport.as_str() {
        "tcp" => crate::transport::Transport::Tcp,
        "tls" => crate::transport::Transport::Tls,
        _ => crate::transport::Transport::Udp,
    };
    let default_port: u16 = if transport == crate::transport::Transport::Tls {
        5061
    } else {
        5060
    };
    let address_str = if registrar_host.contains(':') {
        registrar_host.to_string()
    } else {
        format!("{registrar_host}:{default_port}")
    };
    let destination = crate::gateway::resolve_address(&address_str)
        .map_err(|error| format!("cannot resolve registrar {registrar_host:?}: {error}"))?;

    let mut entry = super::RegistrantEntry::new(
        desired.aor.clone(),
        desired.registrar.clone(),
        destination,
        transport,
        super::RegistrantCredentials {
            username: desired.username.clone(),
            secret: desired.secret.clone(),
            realm: desired.realm.clone(),
        },
        desired.interval.unwrap_or(default_interval),
        desired.contact.clone(),
    )
    .from_source(desired.fingerprint());

    // Only a hostname gets re-resolved on failure; a literal has nothing to
    // re-resolve to.
    if address_str.parse::<std::net::SocketAddr>().is_err() {
        entry.address_str = Some(address_str);
    }
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

/// The configured source of registering trunks.
///
/// An enum rather than a trait object: an async method behind `dyn` needs a
/// boxing crate, and there are exactly two sources.
#[derive(Debug)]
pub enum RegistrantSource {
    Database(DatabaseSource),
    Http(HttpSource),
}

impl RegistrantSource {
    /// Read the current trunk list.
    ///
    /// An `Err` means the source could not be read, which is deliberately not
    /// the same as an empty list: reconciling an unreachable source to "no
    /// trunks" would de-register the whole estate because a database was
    /// briefly down.
    pub async fn fetch(&self) -> Result<Vec<RegistrantRow>, String> {
        match self {
            RegistrantSource::Database(source) => source.fetch().await,
            RegistrantSource::Http(source) => source.fetch().await,
        }
    }

    /// How often to re-read and reconcile.
    pub fn refresh_interval(&self) -> std::time::Duration {
        let seconds = match self {
            RegistrantSource::Database(source) => source.config.refresh_secs,
            RegistrantSource::Http(source) => source.config.refresh_secs,
        };
        std::time::Duration::from_secs(seconds.max(1))
    }
}

/// A JSON endpoint the controller serves.
#[derive(Debug)]
pub struct HttpSource {
    config: crate::config::RegistrantHttpConfig,
    client: reqwest::Client,
}

impl HttpSource {
    pub fn new(config: crate::config::RegistrantHttpConfig) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|error| format!("cannot build the HTTP client: {error}"))?;
        Ok(Self { config, client })
    }

    async fn fetch(&self) -> Result<Vec<RegistrantRow>, String> {
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
        let body: RegistrantListResponse = response
            .json()
            .await
            .map_err(|error| format!("GET {} returned invalid JSON: {error}", self.config.url))?;
        if body.version != CONTRACT_VERSION {
            // Not fatal: a newer minor contract still parses into what siphon
            // reads, and refusing the whole list would de-register the estate.
            tracing::warn!(
                version = %body.version,
                expected = CONTRACT_VERSION,
                "registrant http source speaks a different contract version"
            );
        }
        Ok(body.registrants)
    }
}

#[cfg(feature = "postgres-backend")]
pub use postgres::DatabaseSource;

#[cfg(feature = "postgres-backend")]
mod postgres {
    use super::RegistrantRow;
    use crate::config::RegistrantDatabaseConfig;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tracing::{debug, warn};

    /// A PostgreSQL trunk source, reconnecting on demand.
    ///
    /// Lazy and self-healing rather than established once at start-up, for the
    /// same reason as the credential source in [`crate::auth::server`]:
    /// `tokio_postgres` ends its connection task when the socket drops, and a
    /// client that outlives it fails every query afterwards.
    #[derive(Debug)]
    pub struct DatabaseSource {
        pub(super) config: RegistrantDatabaseConfig,
        /// `None` until the first read, and again after a connection dies.
        client: Arc<Mutex<Option<Arc<tokio_postgres::Client>>>>,
        /// Bound to `$1` when the statement references it, so a deployment can
        /// shard its trunks across nodes.
        instance_id: String,
        binds_instance: bool,
    }

    impl DatabaseSource {
        pub fn new(config: RegistrantDatabaseConfig, instance_id: String) -> Self {
            let binds_instance = config.query.contains("$1");
            Self {
                config,
                client: Arc::new(Mutex::new(None)),
                instance_id,
                binds_instance,
            }
        }

        pub(super) async fn fetch(&self) -> Result<Vec<RegistrantRow>, String> {
            let timeout = Duration::from_millis(self.config.timeout_ms);
            match tokio::time::timeout(timeout, self.query()).await {
                Ok(outcome) => outcome,
                Err(_) => {
                    self.drop_client().await;
                    Err(format!(
                        "the trunk query did not answer within {}ms",
                        self.config.timeout_ms
                    ))
                }
            }
        }

        async fn query(&self) -> Result<Vec<RegistrantRow>, String> {
            let client = self.client().await?;
            let rows = if self.binds_instance {
                client.query(&self.config.query, &[&self.instance_id]).await
            } else {
                client.query(&self.config.query, &[]).await
            };
            let rows = match rows {
                Ok(rows) => rows,
                Err(error) => {
                    // The socket may be gone rather than the statement bad;
                    // drop it so the next read reconnects.
                    self.drop_client().await;
                    return Err(format!("the trunk query failed: {error}"));
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
                debug!("registrant source: connection closed, reconnecting");
                *guard = None;
            }

            let (client, connection) =
                tokio_postgres::connect(&self.config.url, tokio_postgres::NoTls)
                    .await
                    .map_err(|error| format!("cannot connect to the trunk source: {error}"))?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    warn!(error = %error, "registrant source: connection ended");
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

    /// Read one row by column name.
    ///
    /// Columns are optional by design: the operator's view names what it has,
    /// and a missing one takes the contract's default rather than failing the
    /// whole read. `aor`, `registrar` and `username` are the required three,
    /// and a row missing one is returned empty so validation rejects it by
    /// name rather than this silently dropping it.
    fn row_from_sql(row: &tokio_postgres::Row) -> RegistrantRow {
        RegistrantRow {
            aor: text(row, "aor").unwrap_or_default(),
            registrar: text(row, "registrar").unwrap_or_default(),
            username: text(row, "username").unwrap_or_default(),
            password: text(row, "password"),
            ha1: text(row, "ha1"),
            ha1_algorithm: text(row, "ha1_algorithm").unwrap_or_else(|| "md5".to_string()),
            realm: text(row, "realm"),
            interval: integer(row, "interval").map(|value| value.max(0) as u32),
            contact: text(row, "contact"),
            transport: text(row, "transport").unwrap_or_else(|| "udp".to_string()),
            enabled: boolean(row, "enabled").unwrap_or(true),
            gateway: text(row, "gateway"),
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

// ---------------------------------------------------------------------------
// Applying a reconcile
// ---------------------------------------------------------------------------

/// What one reconcile pass did, for the log and the admin endpoint's reply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ReconcileReport {
    pub added: usize,
    pub updated: usize,
    pub removed: usize,
    /// Rows the source returned that siphon could not use. Counted rather than
    /// fatal: one malformed trunk must not stop the other nine hundred.
    pub rejected: usize,
}

/// Read the source once and bring the live registrations in line with it.
///
/// Errors only when the source itself could not be read. That is deliberately
/// distinct from an empty list: treating an outage as "no trunks" would
/// de-register the whole estate because a database was briefly down.
pub async fn reconcile_once(
    manager: &std::sync::Arc<super::RegistrantManager>,
    source: &RegistrantSource,
) -> Result<ReconcileReport, String> {
    let rows = source.fetch().await?;

    let mut desired = Vec::with_capacity(rows.len());
    let mut report = ReconcileReport::default();
    for row in &rows {
        match DesiredRegistrant::from_row(row) {
            Ok(Some(entry)) => desired.push(entry),
            // Disabled: not wanted, and not an error.
            Ok(None) => {}
            Err(error) => {
                report.rejected += 1;
                warn!(aor = %row.aor, %error, "registrant source: skipping an unusable row");
            }
        }
    }

    // A row whose AoR is already held by YAML or a script is not the source's
    // to take over. Said once per pass rather than silently, because the
    // symptom otherwise is a trunk that never picks up its new credentials.
    desired.retain(|entry| {
        if manager.is_foreign_to_source(&entry.aor) {
            report.rejected += 1;
            warn!(
                aor = %entry.aor,
                "registrant source: this AoR is already registered from siphon.yaml or a script — \
                 leaving it alone"
            );
            return false;
        }
        true
    });

    let live = manager.source_fingerprints();
    let actions = reconcile(&desired, &live);
    if actions.is_empty() {
        return Ok(report);
    }

    let default_interval = manager.default_interval;
    for action in actions {
        match action {
            ReconcileAction::Add(entry) => {
                match build_entry_off_thread(entry, default_interval).await {
                    Ok(built) => {
                        manager.add(built);
                        report.added += 1;
                    }
                    Err(error) => {
                        report.rejected += 1;
                        warn!(%error, "registrant source: cannot add a trunk");
                    }
                }
            }
            ReconcileAction::Update(entry) => {
                match build_entry_off_thread(entry, default_interval).await {
                    Ok(built) => {
                        if manager.update_from_source(built) {
                            report.updated += 1;
                        }
                    }
                    Err(error) => {
                        report.rejected += 1;
                        warn!(%error, "registrant source: cannot update a trunk");
                    }
                }
            }
            ReconcileAction::Remove(aor) => {
                // `remove` queues the de-registration, so a trunk deleted in
                // the controller stops being offered calls rather than sitting
                // on the registrar until its Expires runs out.
                manager.remove(&aor);
                report.removed += 1;
            }
        }
    }

    Ok(report)
}

/// [`entry_from_desired`] off the runtime: it resolves DNS, which blocks.
async fn build_entry_off_thread(
    desired: DesiredRegistrant,
    default_interval: u32,
) -> Result<super::RegistrantEntry, String> {
    tokio::task::spawn_blocking(move || entry_from_desired(&desired, default_interval))
        .await
        .map_err(|error| format!("the entry builder panicked: {error}"))?
}

/// The configured source, so an out-of-band refresh can reach it.
///
/// A process-wide `OnceLock` for the same reason the gateway manager is one:
/// the admin API is built from config long after this, and threading the source
/// through every layer between them buys nothing.
static SOURCE: std::sync::OnceLock<std::sync::Arc<RegistrantSource>> = std::sync::OnceLock::new();

/// Record the configured source. Called once, at start-up.
pub fn set_source(source: std::sync::Arc<RegistrantSource>) {
    let _ = SOURCE.set(source);
}

/// The configured source, if `registrant.backend` names one.
pub fn configured_source() -> Option<&'static std::sync::Arc<RegistrantSource>> {
    SOURCE.get()
}

/// Poll the source and reconcile, for the life of the process.
///
/// The interval is the floor, not the mechanism: `POST
/// /admin/registrants/refresh` applies a change at once.
pub async fn reconcile_loop(
    manager: std::sync::Arc<super::RegistrantManager>,
    source: std::sync::Arc<RegistrantSource>,
) {
    let interval = source.refresh_interval();
    info!(
        refresh_secs = interval.as_secs(),
        "outbound registrations follow a configured source"
    );
    let mut health = SourceHealth::new(crate::source_health::SourceKind::Registrant);
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
                        "registrant source reconciled"
                    );
                }
                interval
            }
            Err(error) => {
                // The current registrations are left alone on purpose: an
                // unreadable source is not evidence that the trunks went away.
                // But the retry comes sooner than the next interval, so a
                // controller that comes back is followed in seconds — and the
                // streak is counted and escalated, because a `warn` per poll at
                // the default 30 s refresh makes a six-hour outage 720 lines
                // that read as normal.
                //
                // Unlike the gateway source this loop is spawned *after* the
                // listeners bind, so there is no start-up ordering to close:
                // nothing inbound depends on a trunk registration, and the
                // worst a slow first read costs is a late REGISTER.
                health.record_failure(&error);
                backoff.next_delay()
            }
        };
        tokio::time::sleep(delay).await;
    }
}

/// Stand-in when the `postgres-backend` feature is off.
///
/// Config load refuses `registrant.backend: database` without the feature, so
/// this exists to keep the call sites compiling rather than to be used.
#[cfg(not(feature = "postgres-backend"))]
#[derive(Debug)]
pub struct DatabaseSource {
    pub(super) config: crate::config::RegistrantDatabaseConfig,
}

#[cfg(not(feature = "postgres-backend"))]
impl DatabaseSource {
    pub fn new(config: crate::config::RegistrantDatabaseConfig, _instance_id: String) -> Self {
        Self { config }
    }

    pub(super) async fn fetch(&self) -> Result<Vec<RegistrantRow>, String> {
        Err(
            "registrant.backend: database needs the postgres-backend feature, which this binary \
             was built without"
                .to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(aor: &str) -> RegistrantRow {
        RegistrantRow {
            aor: aor.to_string(),
            registrar: "sip:carrier.example:5060".to_string(),
            username: "trunk1".to_string(),
            password: Some("secret123".to_string()),
            ha1: None,
            ha1_algorithm: "md5".to_string(),
            realm: None,
            interval: None,
            contact: None,
            transport: "udp".to_string(),
            enabled: true,
            gateway: None,
        }
    }

    fn desired(aor: &str) -> DesiredRegistrant {
        DesiredRegistrant::from_row(&row(aor))
            .expect("the row is valid")
            .expect("the row is enabled")
    }

    fn live_from(entries: &[&DesiredRegistrant]) -> HashMap<String, u64> {
        entries
            .iter()
            .map(|entry| (entry.aor.clone(), entry.fingerprint()))
            .collect()
    }

    // --- Row validation ---

    #[test]
    fn a_disabled_row_is_not_an_error() {
        // A UI's "disable" switch keeps the row and stops the registration.
        let mut disabled = row("sip:a@carrier.example");
        disabled.enabled = false;
        assert_eq!(DesiredRegistrant::from_row(&disabled), Ok(None));
    }

    #[test]
    fn a_row_may_carry_an_ha1_instead_of_a_password() {
        let mut hashed = row("sip:a@carrier.example");
        hashed.password = None;
        hashed.ha1 = Some("939e7578ed9e3c518a452acee763bce9".to_string());
        let entry = DesiredRegistrant::from_row(&hashed)
            .expect("valid")
            .expect("enabled");
        assert!(matches!(entry.secret, StoredSecret::Ha1 { .. }));
    }

    #[test]
    fn a_row_with_two_secrets_is_refused() {
        let mut both = row("sip:a@carrier.example");
        both.ha1 = Some("939e7578ed9e3c518a452acee763bce9".to_string());
        let error = DesiredRegistrant::from_row(&both).expect_err("ambiguous");
        assert!(error.contains("not both"), "{error}");
    }

    #[test]
    fn a_row_with_no_secret_is_refused() {
        let mut bare = row("sip:a@carrier.example");
        bare.password = None;
        let error = DesiredRegistrant::from_row(&bare).expect_err("no secret");
        assert!(error.contains("password"), "{error}");
    }

    #[test]
    fn a_row_with_an_unknown_transport_is_refused() {
        let mut odd = row("sip:a@carrier.example");
        odd.transport = "sctp".to_string();
        let error = DesiredRegistrant::from_row(&odd).expect_err("unknown transport");
        assert!(error.contains("sctp"), "{error}");
    }

    #[test]
    fn transport_is_case_insensitive() {
        let mut shouty = row("sip:a@carrier.example");
        shouty.transport = "TLS".to_string();
        let entry = DesiredRegistrant::from_row(&shouty)
            .expect("valid")
            .expect("enabled");
        assert_eq!(entry.transport, "tls");
    }

    // --- Fingerprint ---

    #[test]
    fn the_fingerprint_follows_every_registration_visible_field() {
        let base = desired("sip:a@carrier.example");
        let mut changed = row("sip:a@carrier.example");

        changed.password = Some("rotated".to_string());
        assert_ne!(
            base.fingerprint(),
            DesiredRegistrant::from_row(&changed)
                .expect("valid")
                .expect("enabled")
                .fingerprint(),
            "a rotated password must re-register"
        );

        let mut retargeted = row("sip:a@carrier.example");
        retargeted.registrar = "sip:other.example:5060".to_string();
        assert_ne!(
            base.fingerprint(),
            DesiredRegistrant::from_row(&retargeted)
                .expect("valid")
                .expect("enabled")
                .fingerprint()
        );

        let mut retimed = row("sip:a@carrier.example");
        retimed.interval = Some(120);
        assert_ne!(
            base.fingerprint(),
            DesiredRegistrant::from_row(&retimed)
                .expect("valid")
                .expect("enabled")
                .fingerprint()
        );
    }

    #[test]
    fn an_unchanged_row_keeps_its_fingerprint() {
        assert_eq!(
            desired("sip:a@carrier.example").fingerprint(),
            desired("sip:a@carrier.example").fingerprint()
        );
    }

    // --- Reconcile ---

    #[test]
    fn an_empty_live_set_adds_everything() {
        let wanted = vec![
            desired("sip:a@carrier.example"),
            desired("sip:b@carrier.example"),
        ];
        let actions = reconcile(&wanted, &HashMap::new());
        assert_eq!(actions.len(), 2);
        assert!(actions
            .iter()
            .all(|action| matches!(action, ReconcileAction::Add(_))));
    }

    #[test]
    fn an_unchanged_source_produces_no_actions() {
        // The one that matters: a poll every 30 seconds must not re-register
        // the estate, and `add` on this manager is replace-not-merge.
        let a = desired("sip:a@carrier.example");
        let b = desired("sip:b@carrier.example");
        let live = live_from(&[&a, &b]);

        assert!(reconcile(&[a, b], &live).is_empty());
    }

    #[test]
    fn a_changed_row_updates_rather_than_re_adding() {
        let before = desired("sip:a@carrier.example");
        let live = live_from(&[&before]);

        let mut rotated = row("sip:a@carrier.example");
        rotated.password = Some("rotated".to_string());
        let after = DesiredRegistrant::from_row(&rotated)
            .expect("valid")
            .expect("enabled");

        let actions = reconcile(std::slice::from_ref(&after), &live);
        assert_eq!(actions, vec![ReconcileAction::Update(after)]);
    }

    #[test]
    fn a_row_the_source_dropped_is_removed() {
        let a = desired("sip:a@carrier.example");
        let b = desired("sip:b@carrier.example");
        let live = live_from(&[&a, &b]);

        assert_eq!(
            reconcile(&[a], &live),
            vec![ReconcileAction::Remove("sip:b@carrier.example".to_string())]
        );
    }

    #[test]
    fn a_disabled_row_is_removed_like_a_deleted_one() {
        // `from_row` filters it out before reconcile sees it, so a disabled
        // trunk de-registers rather than lingering.
        let a = desired("sip:a@carrier.example");
        let live = live_from(&[&a]);

        let mut disabled = row("sip:a@carrier.example");
        disabled.enabled = false;
        let wanted: Vec<DesiredRegistrant> = [disabled]
            .iter()
            .filter_map(|row| DesiredRegistrant::from_row(row).expect("valid"))
            .collect();

        assert_eq!(
            reconcile(&wanted, &live),
            vec![ReconcileAction::Remove("sip:a@carrier.example".to_string())]
        );
    }

    // --- Wire contract ---

    #[test]
    fn the_http_contract_parses_a_minimal_row() {
        // Only the three required fields: everything else defaults, so an
        // endpoint author is not forced to emit nulls.
        let json = r#"{"registrants":[{"aor":"sip:a@carrier.example",
            "registrar":"sip:carrier.example:5060","username":"trunk1",
            "password":"secret123"}]}"#;
        let response: RegistrantListResponse =
            serde_json::from_str(json).expect("the contract parses");
        assert_eq!(response.version, CONTRACT_VERSION);
        let parsed = &response.registrants[0];
        assert_eq!(parsed.transport, "udp");
        assert!(parsed.enabled);
        assert_eq!(parsed.ha1_algorithm, "md5");
    }

    #[test]
    fn the_http_contract_round_trips() {
        let response = RegistrantListResponse {
            version: CONTRACT_VERSION.to_string(),
            registrants: vec![row("sip:a@carrier.example")],
        };
        let json = serde_json::to_string(&response).expect("serializes");
        let back: RegistrantListResponse = serde_json::from_str(&json).expect("re-parses");
        assert_eq!(back.registrants.len(), 1);
        assert_eq!(back.registrants[0].aor, "sip:a@carrier.example");
        // Absent optionals are omitted rather than emitted as null, so the
        // sample in the docs is what an endpoint actually has to produce.
        assert!(!json.contains("null"), "{json}");
    }
}
