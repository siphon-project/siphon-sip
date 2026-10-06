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
    /// Health-probe this group with SIP `OPTIONS`. Group-wide, like every
    /// `probe_*` field: each is taken from the first row that carries it.
    /// Absent means probed, as a `gateway.groups` entry is by default.
    ///
    /// `false` is for a carrier that does not answer `OPTIONS`, which would
    /// otherwise fail its probe and be taken out of service by the act of
    /// provisioning it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<bool>,
    /// Seconds between probes. Default 30; `0` is refused as a row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_interval_secs: Option<u32>,
    /// Consecutive failed probes before a destination is marked down. Default 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_failure_threshold: Option<u32>,
    /// User part of the probe's `From`. Default `siphon`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_from_user: Option<String>,
    /// Host part of the probe's `From`. Default the local address. For a
    /// carrier that rejects an `OPTIONS` from a domain it does not know, which
    /// is otherwise indistinguishable from a carrier that is down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_from_domain: Option<String>,
    /// Ceiling on the calls up at once from the sources this group admits.
    /// Group-wide, like every `inbound_*` field: each is taken from the first
    /// row that carries it. Absent or `0` is unlimited. Enforced in B2BUA mode,
    /// on the inbound INVITE, before the script runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_max_concurrent_calls: Option<u32>,
    /// Ceiling on new calls per second from this group's sources, with a burst
    /// of one second's worth. Absent or `0` is unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_max_calls_per_second: Option<u32>,
    /// Status code a call past either ceiling is answered with. Default `503`;
    /// anything outside 400-699 is refused as a row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_reject_code: Option<u16>,
    /// `Retry-After` on that answer, in seconds. Default `1`; `0` omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_retry_after_secs: Option<u32>,
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
    pub probe: DesiredProbe,
    pub inbound_limit: DesiredInboundLimit,
    pub destinations: Vec<DesiredDestination>,
}

/// The group's `inbound_*` fields as the rows gave them, each from the first
/// row that carries it. A group whose rows set neither ceiling has no limit.
#[derive(Debug, Clone, Default)]
pub struct DesiredInboundLimit {
    max_concurrent_calls: Option<u32>,
    max_calls_per_second: Option<u32>,
    reject_code: Option<u16>,
    retry_after_secs: Option<u32>,
}

impl DesiredInboundLimit {
    fn of(row: &GatewayRow) -> Self {
        Self {
            max_concurrent_calls: row.inbound_max_concurrent_calls,
            max_calls_per_second: row.inbound_max_calls_per_second,
            reject_code: row.inbound_reject_code,
            retry_after_secs: row.inbound_retry_after_secs,
        }
    }

    /// Fill whatever this group has not set yet from a later row.
    fn fill_from(&mut self, row: &GatewayRow) {
        self.max_concurrent_calls = self
            .max_concurrent_calls
            .or(row.inbound_max_concurrent_calls);
        self.max_calls_per_second = self
            .max_calls_per_second
            .or(row.inbound_max_calls_per_second);
        self.reject_code = self.reject_code.or(row.inbound_reject_code);
        self.retry_after_secs = self.retry_after_secs.or(row.inbound_retry_after_secs);
    }

    /// The limit to enforce, or `None` when no ceiling is set.
    pub fn limits(&self) -> Option<crate::admission::InboundLimits> {
        use crate::admission::InboundLimits;
        Some(InboundLimits {
            max_concurrent_calls: self.max_concurrent_calls.unwrap_or(0),
            max_calls_per_second: self.max_calls_per_second.unwrap_or(0),
            reject_code: self
                .reject_code
                .unwrap_or(InboundLimits::DEFAULT_REJECT_CODE),
            retry_after_secs: self
                .retry_after_secs
                .unwrap_or(InboundLimits::DEFAULT_RETRY_AFTER_SECS),
        })
        .filter(InboundLimits::is_limited)
    }
}

/// The group's `probe_*` fields as the rows gave them, each from the first row
/// that carries it. Unset fields fall back to [`ProbeConfig::default`], so a
/// source that sets none of them provisions exactly what it did before they
/// existed.
#[derive(Debug, Clone, Default)]
pub struct DesiredProbe {
    enabled: Option<bool>,
    interval_secs: Option<u32>,
    failure_threshold: Option<u32>,
    from_user: Option<String>,
    from_domain: Option<String>,
}

impl DesiredProbe {
    fn of(row: &GatewayRow) -> Self {
        Self {
            enabled: row.probe,
            interval_secs: row.probe_interval_secs,
            failure_threshold: row.probe_failure_threshold,
            from_user: row.probe_from_user.clone(),
            from_domain: row.probe_from_domain.clone(),
        }
    }

    /// Fill whatever this group has not set yet from a later row.
    fn fill_from(&mut self, row: &GatewayRow) {
        self.enabled = self.enabled.or(row.probe);
        self.interval_secs = self.interval_secs.or(row.probe_interval_secs);
        self.failure_threshold = self.failure_threshold.or(row.probe_failure_threshold);
        if self.from_user.is_none() {
            self.from_user = row.probe_from_user.clone();
        }
        if self.from_domain.is_none() {
            self.from_domain = row.probe_from_domain.clone();
        }
    }

    pub fn config(&self) -> ProbeConfig {
        let default = ProbeConfig::default();
        ProbeConfig {
            enabled: self.enabled.unwrap_or(default.enabled),
            interval: self
                .interval_secs
                .map(|seconds| std::time::Duration::from_secs(u64::from(seconds)))
                .unwrap_or(default.interval),
            failure_threshold: self.failure_threshold.unwrap_or(default.failure_threshold),
            from_user: self.from_user.clone().or(default.from_user),
            from_domain: self.from_domain.clone().or(default.from_domain),
        }
    }
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
                group.probe.fill_from(row);
                group.inbound_limit.fill_from(row);
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
                probe: DesiredProbe::of(row),
                inbound_limit: DesiredInboundLimit::of(row),
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

    // An explicit column wins; otherwise the URI's `;transport=` decides. Both
    // go through the shared parser, so neither can fall through to udp: the
    // explicit one was already refused, but a URI-borne `sctp` / `ws` / typo used
    // to be downgraded silently and route a carrier over plaintext.
    let transport = match row.transport.as_deref() {
        Some(token) if !token.eq_ignore_ascii_case("udp") => {
            crate::config::parse_outbound_transport(token).ok_or_else(|| {
                crate::config::outbound_transport_error("`transport` column", token)
            })?
        }
        _ => transport_from_uri(&row.uri)?,
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

    // A zero period panics `tokio::time::interval`, which would kill the
    // group's prober task and leave the group looking probed.
    if row.probe_interval_secs == Some(0) {
        return Err("`probe_interval_secs` must be at least 1".to_string());
    }

    // A refusal is a final failure response (RFC 3261 §21): a 2xx or 3xx here
    // would answer or redirect the call the limit exists to turn away.
    if let Some(code) = row.inbound_reject_code {
        if !(400..=699).contains(&code) {
            return Err(format!(
                "`inbound_reject_code` is {code}; it must be a failure response, 400 to 699"
            ));
        }
    }

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

/// The transport a destination URI's `;transport=` parameter names, defaulting to
/// UDP when it carries none (RFC 3261 §19.1.1).
///
/// A parameter siphon cannot dial is an error rather than a silent UDP
/// downgrade: this row provisions an *outbound* destination, so a `;transport=tls`
/// read as UDP puts a carrier's traffic on the wire in the clear.
fn transport_from_uri(uri: &str) -> Result<Transport, String> {
    let lowered = uri.to_ascii_lowercase();
    let Some(rest) = lowered.split(";transport=").nth(1) else {
        return Ok(Transport::Udp);
    };
    let value = rest.split([';', '>', ' ']).next().unwrap_or("udp");
    crate::config::parse_outbound_transport(value).ok_or_else(|| {
        crate::config::outbound_transport_error("`;transport=` parameter in `uri`", value)
    })
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
        let probe = group.probe.config();
        let inbound_limits = group.inbound_limit.limits();
        let group_changed = live_group.as_ref().is_some_and(|existing| {
            existing.algorithm != group.algorithm
                || existing.source_networks != source_networks
                || existing.probe_config != probe
                || existing.inbound_limits() != inbound_limits
        });

        if existed && !changed && !group_changed {
            // Nothing to do — and importantly, no group replacement, so the
            // health prober keeps running rather than being aborted and
            // respawned every poll.
            continue;
        }

        // A probe change does replace the group, because the prober's period
        // and `From` are fixed when it is spawned. What it has learned is not
        // lost with it: that lives on the destinations, carried over above.
        //
        // Except when probing is switched off. A destination the prober marked
        // down would then stay down for good, since only a probe ever marks one
        // up again, and switching probing off is exactly what an operator does
        // for the carrier that failed its probes by not answering OPTIONS.
        if !probe.enabled
            && live_group
                .as_ref()
                .is_some_and(|existing| existing.probe_config.enabled)
        {
            for destination in &destinations {
                if !destination.is_healthy() {
                    info!(group = %group.name, uri = %destination.uri,
                          "gateway source: probing switched off — marking the destination up");
                    destination.mark_up();
                }
            }
        }

        manager.add_group(
            DispatcherGroup::from_existing(group.name.clone(), group.algorithm, destinations)
                .with_probe_config(probe)
                .with_source_networks(source_networks)
                // The manager keeps the group's call count by name, so a limit
                // changed here applies to the calls already up.
                .with_inbound_limits(inbound_limits)
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
            probe: boolean(row, "probe"),
            // Clamped rather than dropped: a negative interval reaches the row
            // check as 0 and is refused there, not silently defaulted.
            probe_interval_secs: integer(row, "probe_interval_secs")
                .map(|value| value.clamp(0, i64::from(u32::MAX)) as u32),
            probe_failure_threshold: integer(row, "probe_failure_threshold")
                .map(|value| value.clamp(0, i64::from(u32::MAX)) as u32),
            probe_from_user: text(row, "probe_from_user"),
            probe_from_domain: text(row, "probe_from_domain"),
            inbound_max_concurrent_calls: integer(row, "inbound_max_concurrent_calls")
                .map(|value| value.clamp(0, i64::from(u32::MAX)) as u32),
            inbound_max_calls_per_second: integer(row, "inbound_max_calls_per_second")
                .map(|value| value.clamp(0, i64::from(u32::MAX)) as u32),
            // Clamped into range of the type, not of the rule: an out-of-range
            // code reaches the row check and is refused there, not defaulted.
            inbound_reject_code: integer(row, "inbound_reject_code")
                .map(|value| value.clamp(0, i64::from(u16::MAX)) as u16),
            inbound_retry_after_secs: integer(row, "inbound_retry_after_secs")
                .map(|value| value.clamp(0, i64::from(u32::MAX)) as u32),
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
            probe: None,
            probe_interval_secs: None,
            probe_failure_threshold: None,
            probe_from_user: None,
            probe_from_domain: None,
            inbound_max_concurrent_calls: None,
            inbound_max_calls_per_second: None,
            inbound_reject_code: None,
            inbound_retry_after_secs: None,
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

    /// A URI parameter naming a transport siphon cannot dial is a rejected row,
    /// not a UDP downgrade: an explicit `transport` column was already refused,
    /// but this way in put a carrier's traffic on the wire in the clear.
    #[test]
    fn an_undialable_uri_transport_param_rejects_the_row() {
        for token in ["sctp", "ws", "wss", "tpc"] {
            let row = row(
                "carriers",
                &format!("sip:gw1.carrier.example:5060;transport={token}"),
            );
            let (groups, rejected) = group_rows(&[row]);
            assert!(groups.is_empty(), "{token} must not produce a destination");
            assert_eq!(rejected, 1, "{token} must be rejected");
        }
    }

    /// The refusal names the parameter rather than the column, so an operator
    /// looks in the right place.
    #[test]
    fn the_uri_transport_refusal_names_the_parameter() {
        let error = desired_destination(&row(
            "carriers",
            "sip:gw1.carrier.example:5060;transport=sctp",
        ))
        .expect_err("sctp must be refused");
        assert!(error.contains("`;transport=`"), "{error}");
        assert!(error.contains("udp, tcp or tls"), "{error}");
    }

    /// Mixed case in the URI parameter still resolves, as it always did (the URI
    /// is lowercased before the parameter is read).
    #[test]
    fn a_mixed_case_uri_transport_param_still_resolves() {
        let row = row("carriers", "sip:gw1.carrier.example:5061;transport=TLS");
        let (groups, rejected) = group_rows(&[row]);
        assert_eq!(rejected, 0);
        assert_eq!(groups[0].destinations[0].transport, Transport::Tls);
    }

    /// An explicit column is case-insensitive too, and beats the URI parameter.
    #[test]
    fn a_mixed_case_transport_column_wins_over_the_uri_param() {
        let mut shouty = row("carriers", "sip:gw1.carrier.example:5060;transport=udp");
        shouty.transport = Some("TLS".to_string());
        let (groups, rejected) = group_rows(&[shouty]);
        assert_eq!(rejected, 0);
        assert_eq!(groups[0].destinations[0].transport, Transport::Tls);
    }

    /// An explicit `udp` column defers to the URI parameter, which is what makes
    /// the default column value harmless. Unchanged behaviour, pinned because the
    /// refusal now runs through the same branch.
    #[test]
    fn an_explicit_udp_column_still_defers_to_the_uri_param() {
        let mut plain = row("carriers", "sip:gw1.carrier.example:5061;transport=tls");
        plain.transport = Some("udp".to_string());
        let (groups, _) = group_rows(&[plain]);
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

    // --- Probe policy from the source ---

    #[test]
    fn a_source_that_sets_no_probe_field_keeps_the_default() {
        // Nothing changes for a source written before the fields existed.
        let manager = manager();
        apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);
        let group = manager.get_group("carriers").expect("group");
        assert_eq!(group.probe_config, ProbeConfig::default());
    }

    #[test]
    fn a_row_provisions_an_unprobed_group() {
        let manager = manager();
        let mut unprobed = row("carriers", "sip:gw1.carrier.example:5060");
        unprobed.probe = Some(false);
        apply_rows(&manager, &[unprobed]);
        let group = manager.get_group("carriers").expect("group");
        assert!(!group.probe_config.enabled);
        assert!(group.probing_disabled());
    }

    #[test]
    fn a_row_sets_the_probe_period_threshold_and_from() {
        let manager = manager();
        let mut probed = row("carriers", "sip:gw1.carrier.example:5060");
        probed.probe_interval_secs = Some(10);
        probed.probe_failure_threshold = Some(5);
        probed.probe_from_user = Some("edge".to_string());
        probed.probe_from_domain = Some("sbc.example.com".to_string());
        apply_rows(&manager, &[probed]);
        let group = manager.get_group("carriers").expect("group");
        assert_eq!(
            group.probe_config,
            ProbeConfig {
                enabled: true,
                interval: std::time::Duration::from_secs(10),
                failure_threshold: 5,
                from_user: Some("edge".to_string()),
                from_domain: Some("sbc.example.com".to_string()),
            }
        );
    }

    #[test]
    fn probe_fields_are_group_wide_and_each_comes_from_the_first_row_carrying_it() {
        let mut first = row("carriers", "sip:gw1.carrier.example:5060");
        first.probe_interval_secs = Some(10);
        let mut second = row("carriers", "sip:gw2.carrier.example:5060");
        second.probe_interval_secs = Some(99);
        second.probe_from_domain = Some("sbc.example.com".to_string());
        let (groups, rejected) = group_rows(&[first, second]);
        assert_eq!(rejected, 0);
        let probe = groups[0].probe.config();
        assert_eq!(probe.interval, std::time::Duration::from_secs(10));
        assert_eq!(probe.from_domain.as_deref(), Some("sbc.example.com"));
    }

    #[test]
    fn a_zero_probe_interval_is_rejected_as_a_row() {
        let mut zero = row("carriers", "sip:gw1.carrier.example:5060");
        zero.probe_interval_secs = Some(0);
        let (groups, rejected) = group_rows(&[zero]);
        assert!(groups.is_empty());
        assert_eq!(rejected, 1);
    }

    #[test]
    fn an_unchanged_probe_policy_leaves_the_group_alone() {
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gw1.carrier.example:5060")];
        rows[0].probe_interval_secs = Some(10);
        rows[0].probe_from_domain = Some("sbc.example.com".to_string());
        apply_rows(&manager, &rows);
        let first = manager.get_group("carriers").expect("group");

        assert_eq!(apply_rows(&manager, &rows), ReconcileReport::default());
        assert!(Arc::ptr_eq(
            &first,
            &manager.get_group("carriers").expect("group")
        ));
    }

    #[test]
    fn a_probe_change_replaces_the_group_but_keeps_what_the_prober_learned() {
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gw1.carrier.example:5060")];
        apply_rows(&manager, &rows);
        let destination = Arc::clone(&manager.get_group("carriers").unwrap().all_destinations()[0]);
        destination.mark_down();

        rows[0].probe_from_domain = Some("sbc.example.com".to_string());
        assert_eq!(apply_rows(&manager, &rows).updated, 1);
        let group = manager.get_group("carriers").expect("group");
        assert_eq!(
            group.probe_config.from_domain.as_deref(),
            Some("sbc.example.com")
        );
        assert!(Arc::ptr_eq(&destination, &group.all_destinations()[0]));
        assert!(!destination.is_healthy(), "a probe change reset health");
    }

    #[test]
    fn switching_probing_off_puts_a_prober_verdict_back_in_service() {
        // The migration case: the carrier does not answer OPTIONS, so the
        // default probing marked it down. Without this it would stay down for
        // good, because only a probe ever marks a destination up again.
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gw1.carrier.example:5060")];
        apply_rows(&manager, &rows);
        let destination = Arc::clone(&manager.get_group("carriers").unwrap().all_destinations()[0]);
        destination
            .mark_down_until(std::time::Instant::now() + std::time::Duration::from_secs(600));

        rows[0].probe = Some(false);
        assert_eq!(apply_rows(&manager, &rows).updated, 1);
        assert!(destination.is_healthy());
        assert!(!destination.in_cooldown());
    }

    #[test]
    fn a_new_unprobed_group_does_not_touch_health() {
        // Only a transition from probed marks anything up; a group that was
        // never probed has no prober verdict to undo.
        let manager = manager();
        let mut rows = vec![row("carriers", "sip:gw1.carrier.example:5060")];
        rows[0].probe = Some(false);
        apply_rows(&manager, &rows);
        let destination = Arc::clone(&manager.get_group("carriers").unwrap().all_destinations()[0]);
        destination.mark_down();

        rows.push(row("carriers", "sip:gw2.carrier.example:5060"));
        assert_eq!(apply_rows(&manager, &rows).updated, 1);
        assert!(!destination.is_healthy());
    }

    #[tokio::test]
    async fn the_prober_runs_only_for_a_probed_source_group_and_survives_an_unchanged_poll() {
        let uac = crate::gateway::tests::test_uac();
        let manager = manager();
        crate::gateway::spawn_health_probers(Arc::clone(&manager), Arc::clone(&uac.sender));

        let mut unprobed = row("quiet", "sip:gw1.carrier.example:5060");
        unprobed.probe = Some(false);
        let mut probed = row("probed", "sip:gw2.carrier.example:5060");
        probed.probe_from_user = Some("edge".to_string());
        probed.probe_from_domain = Some("sbc.example.com".to_string());
        let rows = vec![unprobed, probed];
        apply_rows(&manager, &rows);

        assert!(manager.prober_handle("quiet").is_none());
        let handle = manager
            .prober_handle("probed")
            .expect("probed group has a prober");

        let sent = tokio::time::timeout(std::time::Duration::from_secs(5), uac.udp.recv_async())
            .await
            .expect("the prober sent nothing")
            .expect("outbound channel closed");
        let options = String::from_utf8_lossy(&sent.data);
        let from = options
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("from:"))
            .expect("From header");
        assert!(
            from.contains("sip:edge@sbc.example.com"),
            "the probe's From is not the one the row asked for: {from}"
        );

        apply_rows(&manager, &rows);
        assert!(
            !handle.is_finished(),
            "an unchanged poll restarted the prober"
        );
        assert_eq!(manager.prober_count(), 1);
    }

    // --- Inbound limit ---

    fn limited_row(max_concurrent_calls: u32) -> GatewayRow {
        let mut limited = row("carriers", "sip:gw1.carrier.example:5060");
        limited.inbound_max_concurrent_calls = Some(max_concurrent_calls);
        limited
    }

    /// The address `row()` gives its destination, which is what makes a caller
    /// a member of the group.
    fn carrier_source() -> std::net::IpAddr {
        "203.0.113.10".parse().expect("a literal address")
    }

    #[test]
    fn a_source_that_sets_no_inbound_field_provisions_no_limit() {
        let manager = manager();
        apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);
        let group = manager.get_group("carriers").expect("group");
        assert_eq!(group.inbound_limits(), None);
        assert!(manager
            .inbound_limits_admitting(carrier_source())
            .is_empty());
    }

    #[test]
    fn the_inbound_fields_provision_the_groups_limit_with_the_defaults_filled_in() {
        let manager = manager();
        apply_rows(&manager, &[limited_row(300)]);
        assert_eq!(
            manager
                .get_group("carriers")
                .expect("group")
                .inbound_limits(),
            Some(crate::admission::InboundLimits {
                max_concurrent_calls: 300,
                max_calls_per_second: 0,
                reject_code: 503,
                retry_after_secs: 1,
            })
        );
        assert_eq!(manager.inbound_limits_admitting(carrier_source()).len(), 1);
    }

    #[test]
    fn each_inbound_field_comes_from_the_first_row_that_carries_it() {
        let mut first = row("carriers", "sip:gw1.carrier.example:5060");
        first.inbound_max_concurrent_calls = Some(300);
        let mut second = row("carriers", "sip:gw2.carrier.example:5060");
        second.inbound_max_concurrent_calls = Some(999);
        second.inbound_max_calls_per_second = Some(30);
        second.inbound_reject_code = Some(486);
        second.inbound_retry_after_secs = Some(0);

        let (groups, rejected) = group_rows(&[first, second]);
        assert_eq!(rejected, 0);
        assert_eq!(
            groups[0].inbound_limit.limits(),
            Some(crate::admission::InboundLimits {
                max_concurrent_calls: 300,
                max_calls_per_second: 30,
                reject_code: 486,
                retry_after_secs: 0,
            })
        );
    }

    #[test]
    fn a_reject_code_with_no_ceiling_is_no_limit() {
        let mut only_code = row("carriers", "sip:gw1.carrier.example:5060");
        only_code.inbound_reject_code = Some(486);
        let (groups, _) = group_rows(&[only_code]);
        assert_eq!(groups[0].inbound_limit.limits(), None);
    }

    #[test]
    fn a_row_whose_reject_code_is_not_a_failure_response_is_refused() {
        for code in [200, 302, 399, 700] {
            let mut bad = limited_row(10);
            bad.inbound_reject_code = Some(code);
            let (groups, rejected) = group_rows(&[bad]);
            assert_eq!(rejected, 1, "{code}");
            assert!(groups.is_empty(), "{code}");
        }
    }

    #[test]
    fn an_unchanged_inbound_limit_leaves_the_group_alone() {
        let manager = manager();
        let rows = [limited_row(300)];
        apply_rows(&manager, &rows);
        let first = manager.get_group("carriers").expect("group");
        assert_eq!(apply_rows(&manager, &rows), ReconcileReport::default());
        assert!(Arc::ptr_eq(
            &first,
            &manager.get_group("carriers").expect("group")
        ));
    }

    /// A limit changed at the source replaces the group, and the calls that
    /// were up before the reconcile are still counted after it.
    #[test]
    fn a_changed_inbound_limit_replaces_the_group_and_keeps_the_calls_that_are_up() {
        let manager = manager();
        let controller = crate::admission::AdmissionController::unlimited();
        apply_rows(&manager, &[limited_row(2)]);
        let before = manager.get_group("carriers").expect("group");
        let _held: Vec<_> = (0..2)
            .map(|_| {
                controller
                    .admit_from(&manager.inbound_limits_admitting(carrier_source()))
                    .expect("a slot")
            })
            .collect();

        assert_eq!(apply_rows(&manager, &[limited_row(3)]).updated, 1);
        let after = manager.get_group("carriers").expect("group");
        assert!(!Arc::ptr_eq(&before, &after));
        assert_eq!(after.inbound_calls_active(), Some(2));

        let limits = manager.inbound_limits_admitting(carrier_source());
        let _third = controller.admit_from(&limits).expect("the raised ceiling");
        controller
            .admit_from(&limits)
            .expect_err("three are up and the ceiling is three");
    }

    #[test]
    fn a_limit_removed_at_the_source_stops_being_enforced() {
        let manager = manager();
        apply_rows(&manager, &[limited_row(1)]);
        assert_eq!(
            apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]).updated,
            1
        );
        assert!(manager
            .inbound_limits_admitting(carrier_source())
            .is_empty());
        assert!(manager.inbound_usage().is_empty());
    }

    #[test]
    fn a_group_removed_at_the_source_takes_its_limit_with_it() {
        let manager = manager();
        apply_rows(&manager, &[limited_row(1)]);
        assert_eq!(apply_rows(&manager, &[]).removed, 1);
        assert!(manager.inbound_usage().is_empty());
    }

    // --- Wire contract ---

    #[test]
    fn the_http_contract_carries_the_inbound_limit_fields() {
        let json = r#"{"gateways":[{"group":"carriers","uri":"sip:gw1.carrier.example:5060",
            "inbound_max_concurrent_calls":300,"inbound_max_calls_per_second":30,
            "inbound_reject_code":486,"inbound_retry_after_secs":0}]}"#;
        let response: GatewayListResponse =
            serde_json::from_str(json).expect("the contract parses");
        let parsed = &response.gateways[0];
        assert_eq!(parsed.inbound_max_concurrent_calls, Some(300));
        assert_eq!(parsed.inbound_max_calls_per_second, Some(30));
        assert_eq!(parsed.inbound_reject_code, Some(486));
        assert_eq!(parsed.inbound_retry_after_secs, Some(0));

        // A row that sets none of them serialises without them, so a
        // controller on the older contract sees the shape it always did.
        let plain = serde_json::to_string(&row("carriers", "sip:gw1.carrier.example:5060"))
            .expect("a row serialises");
        assert!(!plain.contains("inbound_"), "{plain}");
    }

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
    fn the_http_contract_carries_the_probe_fields() {
        let json = r#"{"gateways":[{"group":"carriers","uri":"sip:gw1.carrier.example:5060",
            "probe":false,"probe_interval_secs":15,"probe_failure_threshold":2,
            "probe_from_user":"edge","probe_from_domain":"sbc.example.com"}]}"#;
        let response: GatewayListResponse =
            serde_json::from_str(json).expect("the contract parses");
        let parsed = &response.gateways[0];
        assert_eq!(parsed.probe, Some(false));
        assert_eq!(parsed.probe_interval_secs, Some(15));
        assert_eq!(parsed.probe_failure_threshold, Some(2));
        assert_eq!(parsed.probe_from_user.as_deref(), Some("edge"));
        assert_eq!(parsed.probe_from_domain.as_deref(), Some("sbc.example.com"));
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

    // --- security.trust_gateways across a reconcile ---

    /// The row helper's carrier address.
    const CARRIER: &str = "203.0.113.10";

    fn apiban_client(
        manager: &Arc<DispatcherManager>,
    ) -> (
        crate::apiban::ApiBanClient,
        tokio::sync::mpsc::Receiver<crate::firewall::Command>,
    ) {
        let (firewall, commands) = crate::firewall::KernelFirewall::capturing();
        let config = crate::config::ApiBanConfig {
            api_key: "test-key".to_string(),
            interval_secs: 300,
            ban_ttl_secs: 604_800,
        };
        let client = crate::apiban::ApiBanClient::new(&config, &[])
            .expect("client builds")
            .with_firewall(Some(firewall))
            .with_gateway_trust(Some(manager.gateway_view()));
        client.follow_gateway_view();
        (client, commands)
    }

    #[tokio::test]
    async fn the_reconcile_that_provisions_a_listed_carrier_evicts_it_from_apiban() {
        let manager = manager();
        let (client, mut commands) = apiban_client(&manager);
        let carrier: std::net::IpAddr = CARRIER.parse().unwrap();

        // The feed lists the address before any carrier holds it.
        assert_eq!(client.ingest(&[CARRIER.to_string()]), 1);
        assert!(client.banned().contains(&carrier));
        assert!(matches!(
            commands.try_recv(),
            Ok(crate::firewall::Command::Ban { .. })
        ));

        apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);

        assert!(!client.banned().contains(&carrier), "still in the store");
        assert_eq!(
            commands.try_recv().ok(),
            Some(crate::firewall::Command::Unban { ip: carrier }),
            "not lifted from the kernel set"
        );
    }

    #[tokio::test]
    async fn a_carrier_removed_from_the_source_is_back_under_the_policy() {
        let manager = manager();
        let (client, _commands) = apiban_client(&manager);
        let carrier: std::net::IpAddr = CARRIER.parse().unwrap();
        let config = crate::config::SecurityConfig {
            max_message_bytes: None,
            rate_limit: Some(crate::config::RateLimitConfig {
                window_secs: 60,
                max_requests: 5,
                ban_duration_secs: 600,
            }),
            scanner_block: None,
            trusted_cidrs: Vec::new(),
            trust_gateways: true,
            failed_auth_ban: None,
            apiban: None,
            firewall: None,
            connection_limits: Default::default(),
        };
        let filter = crate::security::SecurityFilter::from_config_with_gateways(
            &config,
            Some(manager.gateway_view()),
        )
        .expect("rate_limit is configured");
        let allowed = |count: u32| {
            (0..count)
                .map(|_| filter.evaluate(carrier, None))
                .filter(|verdict| *verdict == crate::security::SecurityVerdict::Allow)
                .count()
        };

        apply_rows(&manager, &[row("carriers", "sip:gw1.carrier.example:5060")]);
        assert_eq!(allowed(50), 50, "a provisioned carrier was rate-limited");
        assert_eq!(client.ingest(&[CARRIER.to_string()]), 0);

        // The reconcile that removes it.
        apply_rows(&manager, &[]);
        // Counted again from zero, not retroactively banned for the fifty.
        assert_eq!(allowed(5), 5);
        assert_eq!(allowed(1), 0, "a removed carrier is exempt still");
        assert_eq!(client.ingest(&[CARRIER.to_string()]), 1);
        assert!(client.banned().contains(&carrier));
    }
}
