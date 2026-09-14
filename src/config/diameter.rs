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

/// An outbound (server) peer the Diameter server relays to, using the tenant's identity.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterServerEntry {
    pub name: String,
    pub host: String,
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
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
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiameterApplication {
    Cx,
    Sh,
    Ro,
    Rf,
    Rx,
    /// S6c (TS 29.336) — SMSC ↔ HSS for SMS-over-Diameter.
    S6c,
    /// SGd (TS 29.338) — SMSC ↔ MME/SGSN for SMS-over-NAS delivery.
    Sgd,
    /// S6a (TS 29.272) — MME ↔ HSS for LTE attach/auth.
    S6a,
}

impl DiameterApplication {
    /// Map to (vendor_id, auth_application_id) tuple for CER/CEA.
    pub fn to_app_id(&self) -> (u32, u32) {
        use crate::diameter::dictionary;
        match self {
            Self::Cx => (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID),
            Self::Sh => (dictionary::VENDOR_3GPP, dictionary::SH_APP_ID),
            Self::Rx => (dictionary::VENDOR_3GPP, dictionary::RX_APP_ID),
            Self::Ro => (0, dictionary::RO_APP_ID),
            Self::Rf => (0, dictionary::RF_APP_ID),
            Self::S6c => (dictionary::VENDOR_3GPP, dictionary::S6C_APP_ID),
            Self::Sgd => (dictionary::VENDOR_3GPP, dictionary::SGD_APP_ID),
            Self::S6a => (dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID),
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
            product_name: self
                .product_name
                .clone()
                .unwrap_or_else(|| product_name.to_string()),
            firmware_revision: crate::diameter::peer::version_to_firmware_revision(product_version),
        }
    }
}
