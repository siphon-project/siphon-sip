//! `diameter:` peers, tenants and application routing, plus `auth.diameter` (Cx).

use serde::{Deserialize, Serialize};

/// Diameter Cx connection to an HSS for IMS authentication (MAR/MAA, SAR/SAA).
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterCxConfig {
    /// HSS hostname or IP address.
    pub host: String,
    /// HSS Diameter port (default: 3868).
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    /// Origin-Host identity for this SIPhon node.
    pub origin_host: String,
    /// Origin-Realm for this SIPhon node.
    pub origin_realm: String,
    /// Destination-Realm (HSS realm).
    pub destination_realm: String,
    /// Destination-Host (optional, for targeted routing).
    pub destination_host: Option<String>,
    /// Transport protocol: "tcp" (default) or "sctp".
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
    /// Watchdog (DWR) interval in seconds.
    #[serde(default = "default_watchdog_interval")]
    pub watchdog_interval: u64,
    /// Reconnect delay in seconds after connection failure.
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,
}

fn default_diameter_port() -> u16 {
    3868
}
fn default_diameter_transport() -> String {
    "tcp".to_string()
}
fn default_watchdog_interval() -> u64 {
    30
}
fn default_disconnect_timeout_ms() -> u64 {
    1000
}
fn default_reconnect_delay_max() -> u64 {
    60
}
fn default_reopen_watchdog_answers() -> u32 {
    3
}
fn default_reconnect_delay() -> u64 {
    5
}
fn default_diameter_route_algorithm() -> String {
    "failover".to_string()
}

// ---------------------------------------------------------------------------
// Diameter peer + routing table (top-level `diameter:` section)
// ---------------------------------------------------------------------------

/// Top-level Diameter configuration with named peers and application routing.
///
/// SIPhon acts as a Diameter client — it connects outbound to peers (HSS, OCS,
/// PCRF, CDF) and uses the routing table to decide which peer(s) to use for
/// each application interface.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterConfig {
    /// DNS refresh interval for address groups, in seconds.
    #[serde(default = "default_watchdog_interval")]
    pub resolve_interval: u64,
    /// Origin-Host identity for this SIPhon node (used in all client-mode CER
    /// messages). Optional for pure Diameter server deployments, which carry identity
    /// per-tenant under `tenants.<name>.identity` instead.
    #[serde(default)]
    pub origin_host: String,
    /// Origin-Realm for this SIPhon node.
    #[serde(default)]
    pub origin_realm: String,
    /// Product-Name advertised in CER/CEA. When unset, falls back to the
    /// product name resolved by `SiphonServer::product()` (default "SIPhon").
    #[serde(default)]
    pub product_name: Option<String>,
    /// Default transport for all peers: "tcp" (default) or "sctp".
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
    /// Default DWR/DWA watchdog interval in seconds for all peers.
    #[serde(default = "default_watchdog_interval")]
    pub watchdog_interval: u64,
    /// Default reconnect delay in seconds after connection failure.
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,
    /// How long a Disconnect-Peer-Request waits for its answer, in
    /// milliseconds, when a connection is closed at shutdown or because its
    /// peer left a DNS group. The connection is closed when it passes, so a
    /// dead peer cannot hold the shutdown.
    #[serde(default = "default_disconnect_timeout_ms")]
    pub disconnect_timeout_ms: u64,
    /// Default ceiling of the reconnect backoff in seconds: the wait between
    /// attempts starts at `reconnect_delay` and doubles up to this.
    #[serde(default = "default_reconnect_delay_max")]
    pub reconnect_delay_max: u64,
    /// Watchdogs a peer must answer after a reconnection before it takes
    /// traffic again (RFC 3539 REOPEN). 0 skips REOPEN.
    #[serde(default = "default_reopen_watchdog_answers")]
    pub reopen_watchdog_answers: u32,
    /// Watchdog interval in milliseconds, for a finer timer than
    /// `watchdog_interval` allows.
    #[serde(default)]
    pub watchdog_interval_ms: Option<u64>,
    /// Requests that may be sent once to another peer of their route when the
    /// first peer could not serve them. Nothing is retried without an entry.
    #[serde(default)]
    pub retry: Vec<DiameterRetryEntry>,
    /// Overload control (RFC 7683 DOIC, loss algorithm), as a reacting node,
    /// a reporting node, or both. Absent: no OC-* AVP is sent or acted on;
    /// a relay passes the ones it is given through either way.
    #[serde(default)]
    pub overload: Option<DiameterOverloadConfig>,
    /// Named Diameter peers (HSS, OCS, PCRF, CDF, etc.).
    #[serde(default)]
    pub peers: Vec<DiameterPeerEntry>,
    /// Application → peer routing table.
    #[serde(default)]
    pub routes: Vec<DiameterRouteEntry>,

    // ── Server mode — all opt-in, additive ────────────────────────────
    /// Inbound listener addresses. Presence enables server mode.
    #[serde(default)]
    pub listen: Option<DiameterListenConfig>,
    /// Inbound peers (source-IP ACL + optional Origin-Host validation) for the
    /// single-domain server. Folded into the implicit `"default"` tenant when
    /// `tenants` is omitted. See [`DiameterConfig::effective_tenants`].
    #[serde(default)]
    pub clients: Vec<DiameterClientEntry>,
    /// Backends this server connects out to and relays toward, for the
    /// single-domain server. Folded into the implicit `"default"` tenant.
    #[serde(default)]
    pub servers: Vec<DiameterServerEntry>,
    /// Outbound connections siphon initiates but serves inbound requests on
    /// (e.g. this node dialling an upstream), for the single-domain server.
    /// Folded into the implicit `"default"` tenant.
    #[serde(default)]
    pub connect_to: Vec<DiameterServerEntry>,
    /// Applications this server advertises in the capabilities exchange, for
    /// the single-domain server, on top of the ones its `@diameter.on_request`
    /// filters name. Folded into the implicit `"default"` tenant. See
    /// [`DiameterTenant::applications`].
    #[serde(default)]
    pub applications: Vec<DiameterAdvertisedApplication>,
    /// Per-tenant identity + peer tables. Optional — the common single-domain
    /// case omits this and uses the flat `clients` / `servers` / `connect_to`
    /// fields above instead.
    #[serde(default)]
    pub tenants: std::collections::HashMap<String, DiameterTenant>,
    /// Generic event sink for Python-emitted signalling events.
    #[serde(default)]
    pub event_sink: Option<EventSinkConfig>,
}

impl DiameterConfig {
    /// Resolve the tenant map the server bootstrap runs against.
    ///
    /// Multi-tenant deployments declare `diameter.tenants.<name>` explicitly.
    /// The common single-domain case omits it and uses the flat
    /// `diameter.{origin_host,origin_realm,clients,servers,connect_to}` fields;
    /// those are folded into one implicit `"default"` tenant here, so the rest
    /// of the server runs through exactly the same path either way. Pure
    /// client-mode NFs (no identity, no peer lists) yield an empty map and
    /// never reach the server bootstrap.
    pub fn effective_tenants(&self) -> std::collections::HashMap<String, DiameterTenant> {
        if !self.tenants.is_empty() {
            return self.tenants.clone();
        }
        // Trigger synthesis on the server-specific fields only. `origin_host`
        // alone is set by pure client-mode NFs too, so it must not by itself
        // conjure a server tenant.
        if self.clients.is_empty() && self.servers.is_empty() && self.connect_to.is_empty() {
            return std::collections::HashMap::new();
        }
        let mut tenants = std::collections::HashMap::new();
        tenants.insert(
            "default".to_string(),
            DiameterTenant {
                identity: DiameterTenantIdentity {
                    origin_host: self.origin_host.clone(),
                    origin_realm: self.origin_realm.clone(),
                },
                clients: self.clients.clone(),
                servers: self.servers.clone(),
                connect_to: self.connect_to.clone(),
                applications: self.applications.clone(),
            },
        );
        tenants
    }
}

/// Inbound Diameter listener addresses for server mode.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterListenConfig {
    /// TCP bind address, e.g. "0.0.0.0:3868".
    #[serde(default)]
    pub tcp: Option<String>,
    /// SCTP bind address, e.g. "0.0.0.0:3868".
    #[serde(default)]
    pub sctp: Option<String>,
}

/// A Diameter server tenant: its advertised identity, inbound clients, and
/// outbound servers. siphon does no routing — where a request goes is decided
/// by the script (`@diameter.on_request` + `forward_to`), so there is no
/// routing table here; the script sources its own (constants, a cache, an
/// external store, …).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterTenant {
    pub identity: DiameterTenantIdentity,
    #[serde(default)]
    pub clients: Vec<DiameterClientEntry>,
    #[serde(default)]
    pub servers: Vec<DiameterServerEntry>,
    /// Outbound connections siphon **initiates** but **serves** inbound
    /// requests on — e.g. an HSS dialling a Diameter server, then answering the AIR/ULR
    /// the Diameter server relays back over that same connection. siphon sends the CER
    /// (this tenant's identity) and routes inbound requests to
    /// `@diameter.on_request`, exactly like the listener path. The transport
    /// direction is independent of the request direction (RFC 6733 §2.1).
    #[serde(default)]
    pub connect_to: Vec<DiameterServerEntry>,
    /// Applications advertised in the CEA this tenant's clients receive and in
    /// the CER siphon sends on this tenant's `servers` and `connect_to`
    /// connections (RFC 6733 §5.3), on top of the ones the script's
    /// `@diameter.on_request("<App>:<CMD>")` filters name. A filter without an
    /// application names none, so a script that serves through a bare-command
    /// or catch-all handler lists its applications here; a relay lists
    /// `relay`. When the resulting set is not empty, a client whose CER has no
    /// application in common with it is refused with
    /// `DIAMETER_NO_COMMON_APPLICATION` (5010).
    #[serde(default)]
    pub applications: Vec<DiameterAdvertisedApplication>,
}

impl DiameterTenant {
    /// The configured `applications` as `(vendor_id, application_id)` pairs.
    pub fn application_ids(&self) -> Vec<(u32, u32)> {
        self.applications
            .iter()
            .map(DiameterAdvertisedApplication::to_app_id)
            .collect()
    }
}

/// One entry of a server-mode `applications` list: an application this node
/// serves itself, or `relay` for an agent that forwards every application.
#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiameterAdvertisedApplication {
    /// The Relay application id, 0xffffffff (RFC 6733 §2.4): common with
    /// whatever the peer advertises.
    Relay,
    #[serde(untagged)]
    Application(DiameterApplication),
}

// By hand rather than derived: a derived untagged variant reports a typo as
// "data did not match any variant", where this names the value and lists the
// applications that would have been accepted.
impl<'de> Deserialize<'de> for DiameterAdvertisedApplication {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::IntoDeserializer;
        let name = String::deserialize(deserializer)?;
        if name == "relay" {
            return Ok(Self::Relay);
        }
        DiameterApplication::deserialize(name.as_str().into_deserializer()).map(Self::Application)
    }
}

impl DiameterAdvertisedApplication {
    /// Map to the `(vendor_id, application_id)` tuple for the CER/CEA.
    pub fn to_app_id(&self) -> (u32, u32) {
        match self {
            Self::Relay => (0, crate::diameter::dictionary::RELAY_APP_ID),
            Self::Application(application) => application.to_app_id(),
        }
    }
}

/// The (origin_host, origin_realm) a tenant advertises in its CEA.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterTenantIdentity {
    #[serde(default)]
    pub origin_host: String,
    #[serde(default)]
    pub origin_realm: String,
}

/// An inbound (client) peer the Diameter server accepts connections from.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterClientEntry {
    pub name: String,
    /// Source IPs / CIDRs allowed to connect as this peer (ACL gate).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Optional asserted-Origin-Host validator (exact match).
    #[serde(default)]
    pub expected_origin_host: Option<String>,
}

/// `diameter.overload`: DOIC (RFC 7683).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterOverloadConfig {
    /// Advertise DOIC in the requests this node originates and abate what
    /// overload reports ask for.
    #[serde(default)]
    pub reacting: Option<DiameterReactingConfig>,
    /// Report this node's own overload in answers to requesters that
    /// advertised DOIC.
    #[serde(default)]
    pub reporting: Option<DiameterReportingConfig>,
}

/// What a reacting node does with a request it abates.
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiameterAbatementAction {
    /// Fail it with DIAMETER_TOO_BUSY (3004) here.
    #[default]
    Reject,
    /// Send it to another peer of its route; fail it as above when none is
    /// left.
    Divert,
}

/// `diameter.overload.reacting`: its presence turns the reacting node on.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterReactingConfig {
    #[serde(default)]
    pub action: DiameterAbatementAction,
}

/// One `diameter.retry` entry: the requests of an application that may be
/// sent once to another peer of their route when the first could not serve
/// them.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiameterRetryEntry {
    pub application: DiameterApplication,
    /// The commands that may be repeated (`AIR`, `User-Authorization`, ...).
    /// Left out, every command that is safe to repeat: not accounting or
    /// credit-control records, re-auth, abort or termination, which are
    /// retried only when listed.
    #[serde(default)]
    pub commands: Vec<String>,
    /// The failures that trigger it: `too_busy` (3004), `unable_to_deliver`
    /// (3002, or the connection lost), `timeout`. Left out, all three.
    #[serde(default)]
    pub on: Vec<String>,
}

/// `diameter.overload.reporting`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiameterReportingConfig {
    /// OC-Validity-Duration of a report, in seconds (default 30, at most
    /// 86400).
    #[serde(default = "default_overload_validity")]
    pub validity: u32,
    /// Derive the reduction from the requests being served: none up to
    /// `start`, rising linearly to `max_reduction` at `full`. The application
    /// sets its own with `diameter.set_overload`; the larger is reported.
    #[serde(default)]
    pub pending_requests: Option<DiameterPendingRequestsScale>,
}

/// `diameter.overload.reporting.pending_requests`.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DiameterPendingRequestsScale {
    pub start: usize,
    pub full: usize,
    #[serde(default = "default_overload_max_reduction")]
    pub max_reduction: u32,
}

fn default_overload_validity() -> u32 {
    30
}
fn default_overload_max_reduction() -> u32 {
    100
}

/// An outbound (server) peer the Diameter server relays to, using the tenant's identity.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterServerEntry {
    /// Connect to every resolved address and refresh membership periodically.
    #[serde(default)]
    pub all_addresses: bool,
    pub name: String,
    pub host: String,
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
    /// Watchdog interval in seconds (default 30).
    #[serde(default)]
    pub watchdog_interval: Option<u64>,
    /// First reconnect delay in seconds (default 5).
    #[serde(default)]
    pub reconnect_delay: Option<u64>,
    /// Ceiling of the reconnect backoff in seconds (default 60).
    #[serde(default)]
    pub reconnect_delay_max: Option<u64>,
    /// Local address to originate the connection from, for a host with
    /// several. Bound before the connect, any port; unset leaves it to the
    /// routing table.
    #[serde(default)]
    pub source_address: Option<std::net::IpAddr>,
}

impl DiameterServerEntry {
    /// The timers of this entry's connection, over the defaults of
    /// [`PeerConfig`](crate::diameter::peer::PeerConfig).
    pub fn lifecycle(&self) -> crate::diameter::lifecycle::PeerLifecycle {
        let defaults = crate::diameter::lifecycle::PeerLifecycle::default();
        crate::diameter::lifecycle::PeerLifecycle {
            reconnect_delay_max: self
                .reconnect_delay_max
                .unwrap_or(defaults.reconnect_delay_max),
            ..defaults
        }
    }
}

/// Generic batched event sink (Python-emitted signalling events).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventSinkConfig {
    /// "file" | "none" (v1). "clickhouse" / "kafka" are feature-gated stubs.
    #[serde(default = "default_event_sink_backend")]
    pub backend: String,
    #[serde(default)]
    pub file: Option<EventSinkFileConfig>,
}

/// File backend for the event sink (newline-delimited JSON).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventSinkFileConfig {
    pub path: String,
}

fn default_event_sink_backend() -> String {
    "none".to_string()
}

/// A named Diameter peer endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterPeerEntry {
    /// Connect to every resolved address and refresh membership periodically.
    #[serde(default)]
    pub all_addresses: bool,
    /// Unique name for this peer (referenced in routes).
    pub name: String,
    /// Peer hostname or IP address.
    pub host: String,
    /// Peer Diameter port (default: 3868).
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    /// Destination-Realm for this peer.
    pub destination_realm: String,
    /// Destination-Host (optional, for targeted routing).
    pub destination_host: Option<String>,
    /// Transport override: "tcp" or "sctp" (inherits parent default if absent).
    pub transport: Option<String>,
    /// Watchdog interval override in seconds.
    pub watchdog_interval: Option<u64>,
    /// Reconnect delay override in seconds.
    pub reconnect_delay: Option<u64>,
    /// Local address to originate the connection from, for a host with
    /// several. Bound before the connect, any port; unset leaves it to the
    /// routing table.
    #[serde(default)]
    pub source_address: Option<std::net::IpAddr>,
    /// Reconnect backoff ceiling override in seconds.
    #[serde(default)]
    pub reconnect_delay_max: Option<u64>,
    /// REOPEN watchdog answers override.
    #[serde(default)]
    pub reopen_watchdog_answers: Option<u32>,
}

/// Maps a Diameter application to one or more peers.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterRouteEntry {
    /// Which Diameter application this route serves.
    pub application: DiameterApplication,
    /// Optional realm filter — only match requests for this destination realm.
    pub realm: Option<String>,
    /// Peer names in priority order.
    pub peers: Vec<String>,
    /// Selection algorithm: "failover" (default) or "round_robin".
    #[serde(default = "default_diameter_route_algorithm")]
    pub algorithm: String,
}

/// Supported Diameter application identifiers.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiameterApplication {
    Cx,
    Sh,
    Ro,
    Rf,
    Rx,
    /// Gx (TS 29.212) — policy and charging control, PCEF ↔ PCRF.
    Gx,
    /// S6c (TS 29.336) — SMSC ↔ HSS for SMS-over-Diameter.
    S6c,
    /// SGd (TS 29.338) — SMSC ↔ MME/SGSN for SMS-over-NAS delivery.
    Sgd,
    /// S6a (TS 29.272) — MME ↔ HSS for LTE attach/auth.
    S6a,
    /// S13 (TS 29.272) — MME or SGSN ↔ EIR for the ME identity check.
    S13,
    /// Zh (TS 29.109), GBA: BSF to HSS for the authentication vector and
    /// the user security settings.
    Zh,
    /// Zn (TS 29.109), GBA: NAF to BSF for the key material of a
    /// bootstrapping transaction.
    Zn,
}

impl DiameterApplication {
    /// Map to (vendor_id, auth_application_id) tuple for CER/CEA.
    pub fn to_app_id(&self) -> (u32, u32) {
        use crate::diameter::dictionary;
        match self {
            Self::Cx => (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID),
            Self::Sh => (dictionary::VENDOR_3GPP, dictionary::SH_APP_ID),
            Self::Rx => (dictionary::VENDOR_3GPP, dictionary::RX_APP_ID),
            Self::Gx => (dictionary::VENDOR_3GPP, dictionary::GX_APP_ID),
            Self::Ro => (0, dictionary::RO_APP_ID),
            Self::Rf => (0, dictionary::RF_APP_ID),
            Self::S6c => (dictionary::VENDOR_3GPP, dictionary::S6C_APP_ID),
            Self::Sgd => (dictionary::VENDOR_3GPP, dictionary::SGD_APP_ID),
            Self::S6a => (dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID),
            Self::S13 => (dictionary::VENDOR_3GPP, dictionary::S13_APP_ID),
            Self::Zh => (dictionary::VENDOR_3GPP, dictionary::ZH_APP_ID),
            Self::Zn => (dictionary::VENDOR_3GPP, dictionary::ZN_APP_ID),
        }
    }
}

impl DiameterConfig {
    /// Look up the ordered peer entries for an application, optionally filtered by realm.
    pub fn peers_for_application(
        &self,
        application: &DiameterApplication,
        realm: Option<&str>,
    ) -> Vec<&DiameterPeerEntry> {
        for route in &self.routes {
            if &route.application != application {
                continue;
            }
            if let Some(ref route_realm) = route.realm {
                if let Some(requested_realm) = realm {
                    if route_realm != requested_realm {
                        continue;
                    }
                }
            }
            return route
                .peers
                .iter()
                .filter_map(|name| self.peers.iter().find(|p| &p.name == name))
                .collect();
        }
        Vec::new()
    }

    /// Build a `PeerConfig` for a specific peer entry.
    ///
    /// Application IDs are collected from all routes that reference this peer,
    /// so a single peer connection can advertise support for multiple interfaces
    /// (e.g., Cx + Sh on the same HSS).
    ///
    /// `product_name` and `product_version` are the values resolved by
    /// `SiphonServer::product()` — they back the Product-Name and
    /// Firmware-Revision AVPs when the YAML `diameter.product_name`
    /// override is unset.
    pub fn to_peer_config(
        &self,
        peer: &DiameterPeerEntry,
        product_name: &str,
        product_version: &str,
    ) -> crate::diameter::peer::PeerConfig {
        let application_ids: Vec<(u32, u32)> = self
            .routes
            .iter()
            .filter(|r| r.peers.contains(&peer.name))
            .map(|r| r.application.to_app_id())
            .collect();

        crate::diameter::peer::PeerConfig {
            host: peer.host.clone(),
            port: peer.port,
            origin_host: self.origin_host.clone(),
            origin_realm: self.origin_realm.clone(),
            destination_host: peer.destination_host.clone(),
            destination_realm: peer.destination_realm.clone(),
            local_ip: std::net::Ipv4Addr::UNSPECIFIED,
            application_ids,
            watchdog_interval: peer.watchdog_interval.unwrap_or(self.watchdog_interval),
            reconnect_delay: peer.reconnect_delay.unwrap_or(self.reconnect_delay),
            source_address: peer.source_address,
            lifecycle: crate::diameter::lifecycle::PeerLifecycle {
                disconnect_timeout_ms: self.disconnect_timeout_ms,
                reconnect_delay_max: peer.reconnect_delay_max.unwrap_or(self.reconnect_delay_max),
                reopen_watchdog_answers: peer
                    .reopen_watchdog_answers
                    .unwrap_or(self.reopen_watchdog_answers),
                watchdog_interval_ms: self.watchdog_interval_ms,
                ..Default::default()
            },
            product_name: self
                .product_name
                .clone()
                .unwrap_or_else(|| product_name.to_string()),
            firmware_revision: crate::diameter::peer::version_to_firmware_revision(product_version),
        }
    }
}
