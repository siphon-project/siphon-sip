//! `registrant:` outbound registration (UAC registrant).

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Outbound Registration (UAC Registrant)
// ---------------------------------------------------------------------------

/// Outbound registrant configuration in `siphon.yaml`.
///
/// ```yaml
/// registrant:
///   default_interval: 3600
///   retry_interval: 60
///   max_retry_interval: 300
///   entries:
///     - aor: "sip:alice@carrier.com"
///       registrar: "sip:registrar.carrier.com:5060"
///       user: "alice"
///       password: "secret123"
///       realm: "carrier.com"
///       interval: 1800
///       contact: "sip:alice@1.2.3.4"
///       transport: "udp"
/// ```
///
/// A process registering many IMS UEs, each from an address of its own, sets
/// `local_addr` per entry and usually paces itself:
///
/// ```yaml
/// registrant:
///   refresh_window: [0.4, 0.6]     # refresh at 40-60 % of the grant
///   max_registers_per_sec: 50      # cap on new REGISTERs per second
///   entries:
///     - aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
///       local_addr: "192.0.2.77"   # UDP only
///       # ... auth: aka, aka:, ipsec:, ims: as for one UE
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantYamlConfig {
    /// Where the registering trunks come from. Default: `static`, the
    /// `entries` list below.
    ///
    /// `database` and `http` read them from a source the controller owns and
    /// reconcile against it on an interval, so a trunk added, edited or deleted
    /// there is followed without a restart. Entries added by a script
    /// (`registration.add`) and the `entries` list are never touched by that
    /// reconcile — it owns only what it created.
    #[serde(default = "default_registrant_backend")]
    pub backend: RegistrantBackendType,
    /// SQL source for `backend: database`.
    pub database: Option<RegistrantDatabaseConfig>,
    /// HTTP source for `backend: http`.
    pub http: Option<RegistrantHttpConfig>,
    /// Default registration interval in seconds. Default: 3600.
    #[serde(default = "default_registrant_interval")]
    pub default_interval: u32,
    /// Base retry interval on failure in seconds. Default: 60.
    #[serde(default = "default_registrant_retry")]
    pub retry_interval: u64,
    /// Maximum retry interval (backoff cap) in seconds. Default: 300.
    #[serde(default = "default_registrant_max_retry")]
    pub max_retry_interval: u64,
    /// Static registration entries.
    #[serde(default)]
    pub entries: Vec<RegistrantEntryConfig>,
    /// When to refresh a binding, as `[low, high]` fractions of the granted
    /// Expires, drawn uniformly per refresh. Default `[0.5, 0.5]`: exactly half,
    /// as always. A wider window keeps a fleet registered together from
    /// refreshing together for ever. Each entry may override it.
    pub refresh_window: Option<[f64; 2]>,
    /// Cap on new REGISTERs (initial, refresh, retry) the loop starts per
    /// second, in any one-second window. The authenticated REGISTER answering a
    /// 401 is not held back. Unset: no cap, and the loop ticks every 5 s; set,
    /// it ticks every 200 ms and starts the longest-overdue entries first.
    pub max_registers_per_sec: Option<u32>,
    /// How many state-change events (`@registration.on_change`,
    /// `RegistrantChanged`) may wait for a slow consumer before it lags and is
    /// sent a snapshot instead. Default: the larger of 1024 and four per
    /// configured entry; raise it to at least the number of entries a script
    /// adds.
    pub event_capacity: Option<usize>,
}

/// Where `registrant:` reads its registering trunks from.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RegistrantBackendType {
    /// The `entries` list in this file.
    Static,
    /// A PostgreSQL query the controller owns.
    Database,
    /// A JSON endpoint the controller serves.
    Http,
}

/// SQL source for `registrant.backend: database`.
///
/// The query is the operator's, not siphon's: schemas differ and a fixed one
/// would mean every deployment maintaining a view for us. Columns are read by
/// name — `aor`, `registrar` and `username` are required; `password`, `ha1`,
/// `ha1_algorithm`, `realm`, `interval`, `contact`, `transport`, `enabled` and
/// `gateway` are optional. When the statement references `$1`, the instance id
/// (`server.instance_id`) is bound to it, so a deployment can shard its trunks
/// across nodes with `WHERE node = $1`.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantDatabaseConfig {
    /// libpq connection URI, e.g. `postgresql://siphon@db.internal/siphon`.
    pub url: String,
    /// Statement returning one row per registering trunk.
    #[serde(default = "default_registrant_query")]
    pub query: String,
    /// How often to re-read the source and reconcile, in seconds. A change is
    /// applied at once by `POST /admin/registrants/refresh`, so this is the
    /// floor rather than the mechanism.
    #[serde(default = "default_registrant_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-query deadline in milliseconds, connection included.
    #[serde(default = "default_registrant_source_timeout_ms")]
    pub timeout_ms: u64,
}

/// JSON source for `registrant.backend: http`.
///
/// The endpoint answers `GET {url}` with the contract in
/// `docs/reference/registrant-api.md` (typed in `siphon_sdk.registrants`).
///
/// This is the form to use when trunk passwords are sealed at rest: the
/// controller unseals in-process and serves the credential over a trusted local
/// channel, so siphon never sees the sealed form and no sealing construction
/// has to enter siphon.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantHttpConfig {
    /// URL siphon `GET`s the trunk list from.
    pub url: String,
    /// How often to re-read the source and reconcile, in seconds.
    #[serde(default = "default_registrant_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-request deadline in milliseconds.
    #[serde(default = "default_registrant_source_timeout_ms")]
    pub timeout_ms: u64,
    /// Full `Authorization` header value sent with each request (e.g.
    /// `"Bearer …"`). Supports `${VAR}` expansion.
    pub auth_header: Option<String>,
}

fn default_registrant_backend() -> RegistrantBackendType {
    RegistrantBackendType::Static
}

fn default_registrant_query() -> String {
    "SELECT aor, registrar, username, password, realm, expires AS interval, contact, \
     transport, enabled FROM registrants"
        .to_string()
}

fn default_registrant_refresh_secs() -> u64 {
    30
}

fn default_registrant_source_timeout_ms() -> u64 {
    2000
}

/// A single static registrant entry.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantEntryConfig {
    /// Address-of-Record (e.g. "sip:alice@carrier.com"). For IMS AKA this is
    /// the IMPU.
    pub aor: String,
    /// Registrar URI (e.g. "sip:registrar.carrier.com:5060"). For IMS this is
    /// the P-CSCF.
    pub registrar: String,
    /// Authentication username. For IMS AKA this is the IMPI.
    pub user: String,
    /// Authentication password (digest only; unused for AKA).
    #[serde(default)]
    pub password: String,
    /// Optional realm hint — derived from 401 challenge if omitted (the home
    /// domain for IMS).
    pub realm: Option<String>,
    /// Registration interval override in seconds.
    pub interval: Option<u32>,
    /// Contact URI override (auto-generated if omitted).
    pub contact: Option<String>,
    /// Transport: "udp" (default), "tcp", "tls".
    #[serde(default = "default_registrant_transport")]
    pub transport: String,
    /// Authentication mode: "digest" (default) or "aka" for IMS AKAv1-MD5
    /// (RFC 3310 / 3GPP TS 33.203).
    pub auth: Option<String>,
    /// IMS AKA credentials — required when `auth: aka`.
    pub aka: Option<RegistrantAkaConfig>,
    /// IPsec sec-agree (UE side) — only valid with `auth: aka`.
    pub ipsec: Option<RegistrantIpsecConfig>,
    /// IMS Contact feature tags (instance ID + MMTel/video/SMS) so the S-CSCF
    /// registers the implied services.
    pub ims: Option<RegistrantImsConfig>,
    /// The address this entry registers from: Via and Contact host, the UDP
    /// source of every REGISTER, and with `ipsec` the UE side of its SAs (its
    /// protected ports opened on this address, so they may repeat across
    /// entries). siphon opens the sockets itself, with IP_FREEBIND, so the
    /// address need not exist yet. UDP only. Unset: the process's address.
    pub local_addr: Option<std::net::IpAddr>,
    /// Never register from the process's address: with no `local_addr` (or
    /// once a script takes it away with `registration.set_local_addr(aor,
    /// None)`) the entry waits as `awaiting_address`. Implied by `local_addr`.
    #[serde(default)]
    pub require_local_addr: bool,
    /// This entry's refresh window, overriding `registrant.refresh_window`.
    pub refresh_window: Option<[f64; 2]>,
}

/// IMS Contact feature tags for a registrant entry (TS 24.229 / GSMA IR.92).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantImsConfig {
    /// IMEI for `+sip.instance="<urn:gsma:imei:…>"` (RFC 5626 instance ID).
    pub imei: Option<String>,
    /// Feature tags to advertise: any of "mmtel", "video", "smsip".
    #[serde(default)]
    pub features: Vec<String>,
}

/// IMS AKA credentials for a registrant entry (3GPP TS 33.203).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantAkaConfig {
    /// Subscriber key K as 32 hex chars.
    pub k: String,
    /// Operator variant OP as 32 hex chars (supply `op` OR `opc`).
    pub op: Option<String>,
    /// Pre-computed OPc as 32 hex chars (supply `op` OR `opc`).
    pub opc: Option<String>,
    /// Authentication Management Field as 4 hex chars.
    #[serde(default = "default_aka_amf")]
    pub amf: String,
    /// Initial stored sequence number SQN_MS as 12 hex chars.
    #[serde(default = "default_aka_sqn")]
    pub sqn: String,
}

/// IPsec sec-agree parameters for a registrant entry (UE side, TS 33.203).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantIpsecConfig {
    /// UE protected client port. The UE rotates through it and the two ports
    /// above the higher of `ue_port_c` and `ue_port_s` across authenticated
    /// re-registrations (TS 33.203 7.4.0); siphon opens all of them.
    pub ue_port_c: u16,
    /// UE protected server port.
    pub ue_port_s: u16,
    /// Offered integrity algorithm: "hmac-sha-1-96" (default), "hmac-md5-96",
    /// or "hmac-sha-256-128".
    #[serde(default = "default_ipsec_alg")]
    pub alg: String,
    /// Offered encryption algorithm: "null" (default) or "aes-cbc".
    #[serde(default = "default_ipsec_ealg")]
    pub ealg: String,
}

fn default_aka_amf() -> String {
    "8000".to_string()
}

fn default_aka_sqn() -> String {
    "000000000000".to_string()
}

fn default_ipsec_alg() -> String {
    "hmac-sha-1-96".to_string()
}

fn default_ipsec_ealg() -> String {
    "null".to_string()
}

fn default_registrant_interval() -> u32 {
    3600
}

fn default_registrant_retry() -> u64 {
    60
}

fn default_registrant_max_retry() -> u64 {
    300
}

fn default_registrant_transport() -> String {
    "udp".to_string()
}

impl RegistrantYamlConfig {
    /// Refuse what the per-UE address and pacing settings cannot honour: a
    /// window outside `0 < low <= high < 1`, a zero start rate, a `local_addr`
    /// on a stream transport, and two entries sharing one address and UE
    /// protected client port.
    pub fn validate_ue_entries(&self) -> std::result::Result<(), String> {
        if let Some(pair) = self.refresh_window {
            crate::registrant::RefreshWindow::from_pair(pair)
                .map_err(|reason| format!("registrant.{reason}"))?;
        }
        if self.max_registers_per_sec == Some(0) {
            return Err(
                "registrant.max_registers_per_sec must be at least 1 (leave it unset for no cap)"
                    .to_string(),
            );
        }
        // Per address: the protected ports each entry there holds or may
        // offer (its three client ports and server port), or none.
        let mut seen: Vec<(std::net::IpAddr, Vec<u16>, &str)> = Vec::new();
        for entry in &self.entries {
            if let Some(pair) = entry.refresh_window {
                crate::registrant::RefreshWindow::from_pair(pair)
                    .map_err(|reason| format!("registrant.entries[{}].{reason}", entry.aor))?;
            }
            let ports: Vec<u16> = match entry.ipsec.as_ref() {
                Some(ipsec) => {
                    if let Some(problem) = crate::registrant::protected::protected_ports_problem(
                        ipsec.ue_port_c,
                        ipsec.ue_port_s,
                    ) {
                        return Err(format!(
                            "registrant.entries[{}].ipsec: {problem}",
                            entry.aor
                        ));
                    }
                    let mut ports = crate::registrant::protected::protected_client_ports(
                        ipsec.ue_port_c,
                        ipsec.ue_port_s,
                    )
                    .to_vec();
                    ports.push(ipsec.ue_port_s);
                    ports
                }
                None => Vec::new(),
            };
            let Some(local_addr) = entry.local_addr else {
                continue;
            };
            if !entry.transport.eq_ignore_ascii_case("udp") {
                return Err(format!(
                    "registrant.entries[{}].local_addr needs transport udp, not {}",
                    entry.aor, entry.transport
                ));
            }
            let holder = seen.iter().find(|(address, theirs, _)| {
                *address == local_addr
                    && (ports.is_empty() && theirs.is_empty()
                        || ports.iter().any(|port| theirs.contains(port)))
            });
            if let Some((_, _, holder)) = holder {
                return Err(format!(
                    "registrant.entries[{}].local_addr {local_addr} (protected ports {ports:?}) \
                     is already used by {holder}",
                    entry.aor
                ));
            }
            seen.push((local_addr, ports, &entry.aor));
        }
        Ok(())
    }

    /// The state-change channel capacity: `event_capacity`, else the larger of
    /// 1024 and four per configured entry.
    pub fn effective_event_capacity(&self) -> usize {
        self.event_capacity
            .unwrap_or_else(|| (self.entries.len().saturating_mul(4)).max(1024))
    }
}

impl RegistrantEntryConfig {
    /// The transport this trunk's REGISTER will leave over, or the refusal to
    /// report under `field`.
    ///
    /// The one place the entry's transport string becomes a
    /// [`Transport`](crate::transport::Transport), so nothing is left that can
    /// match `"tcp"`/`"tls"` and register the rest over UDP.
    pub fn outbound_transport(
        &self,
        field: &str,
    ) -> std::result::Result<crate::transport::Transport, String> {
        crate::config::parse_outbound_transport(&self.transport)
            .ok_or_else(|| crate::config::outbound_transport_error(field, &self.transport))
    }
}
