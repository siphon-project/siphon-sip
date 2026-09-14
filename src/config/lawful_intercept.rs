//! `lawful_intercept:` ETSI X1/X2/X3 and SIPREC.

use super::default_true;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Lawful Intercept — ETSI X1/X2/X3 + SIPREC
// ---------------------------------------------------------------------------

/// Top-level `lawful_intercept:` configuration.
///
/// ```yaml
/// lawful_intercept:
///   enabled: false
///   audit_log: "/var/log/siphon/li-audit.log"
///   x1:
///     listen: "127.0.0.1:8443"
///     tls:
///       certificate: "/etc/siphon/li/x1.crt"
///       private_key: "/etc/siphon/li/x1.key"
///       verify_client: true
///     auth_token: "warrant-auth-xyz"
///   x2:
///     delivery_address: "10.0.0.50:6543"
///     transport: tcp
///     reconnect_interval_secs: 5
///     channel_size: 10000
///   x3:
///     enabled: true
///   siprec:
///     srs_uri: "sip:srs@recorder.example.com"
///     session_copies: 1
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct LawfulInterceptConfig {
    /// Master switch — disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Mandatory audit trail log file. Every X1 operation is recorded here.
    pub audit_log: Option<String>,
    /// X1: ETSI TS 103 221-1 admin interface for intercept provisioning.
    pub x1: Option<LiX1Config>,
    /// X2: ETSI TS 102 232 IRI (signaling event) delivery.
    pub x2: Option<LiX2Config>,
    /// X3: ETSI TS 102 232 CC (media content) delivery via RTPEngine.
    pub x3: Option<LiX3Config>,
    /// SIPREC: RFC 7866 SIP-based media recording.
    pub siprec: Option<LiSiprecConfig>,
}

/// X1 admin interface — separate HTTPS listener with mTLS.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1Config {
    /// Bind address for the X1 HTTPS listener (e.g. "0.0.0.0:8443").
    pub listen: String,
    /// Path the single X1 endpoint is served on.
    ///
    /// TS 103 221-1 mandates one endpoint but does not name it. `/X1/NE` is
    /// the convention (it is the default target of the sipgate X1/X2/X3
    /// simulator, among others); confirm it with the mediation partner, since
    /// a wrong path stops the very first message reaching the server.
    #[serde(default = "default_x1_path")]
    pub path: String,
    /// TLS for the listener. Mutual TLS is the authentication on X1, so
    /// `client_ca` is required — see [`LiX1TlsConfig`].
    pub tls: LiX1TlsConfig,
    /// This network element's identifier, as it appears in `neIdentifier`.
    pub ne_identifier: String,
    /// The ADMF identifier this element expects in `admfIdentifier`.
    ///
    /// When set, a message naming a different ADMF is refused with
    /// `UnexpectedAdmfIdentifier` (1040). When unset, any well-formed
    /// identifier is accepted and only the certificate binding applies.
    pub admf_identifier: Option<String>,
    /// The schema version declared in every message's `version` element.
    ///
    /// Defaults to the version this build implements. Override only when a
    /// mediation partner pins an older one; the message set is identical
    /// across the published v1.x range, so only the declared string differs.
    #[serde(default = "default_x1_version")]
    pub version: String,
    /// Bind the `admfIdentifier` to the presented client certificate.
    ///
    /// When true (the default), a message whose `admfIdentifier` does not
    /// match the certificate's subject Common Name is refused with
    /// `AdmfIdentifierDoesNotMatchCertificateDetails` (1030). Turn it off only
    /// when the ADMF's certificate legitimately carries an unrelated CN.
    #[serde(default = "default_true")]
    pub bind_admf_identifier_to_certificate: bool,
    /// The network-element-to-ADMF direction. Absent means siphon serves X1
    /// but never initiates toward the ADMF.
    pub admf: Option<LiX1AdmfConfig>,
}

fn default_x1_path() -> String {
    "/X1/NE".to_string()
}

fn default_x1_version() -> String {
    crate::li::x1::types::DEFAULT_VERSION.to_string()
}

/// TLS for the X1 listener.
///
/// All three fields are mandatory. X1 carries warrant provisioning, and mutual
/// TLS is the only authentication the specification defines for it, so a
/// listener without a client CA would accept anyone. A missing field is a
/// startup error, not a silent downgrade — the same fail-closed rule the SIP
/// TLS listener applies to `verify_client` without `client_ca`.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1TlsConfig {
    /// PEM certificate chain this element presents.
    pub certificate: String,
    /// PEM private key for `certificate`.
    pub private_key: String,
    /// PEM CA bundle that ADMF client certificates must chain to.
    pub client_ca: String,
}

/// The network-element-to-ADMF direction (TS 103 221-1 clause 6.5).
///
/// Without this block siphon answers X1 but never speaks first: no issue
/// reports, no keepalives, and no reconciliation of provisioned state after a
/// restart.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1AdmfConfig {
    /// Absolute URL of the ADMF's X1 endpoint.
    pub endpoint: String,
    /// PEM client certificate this element presents to the ADMF.
    pub client_certificate: String,
    /// PEM private key for `client_certificate`.
    pub client_private_key: String,
    /// PEM CA bundle used to verify the ADMF's server certificate.
    ///
    /// Absent falls back to the platform/webpki roots, which is right for a
    /// publicly-issued certificate and wrong for the private CA most ADMF
    /// deployments use — set it.
    pub server_ca: Option<String>,
    /// Keepalive interval in seconds. Zero disables keepalives.
    #[serde(default = "default_x1_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Per-request timeout in seconds.
    #[serde(default = "default_x1_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Reconcile provisioned state with the ADMF at startup.
    ///
    /// Issues `GetAllDetails` outbound so the two sides agree after a restart.
    /// Without it, a bounce silently diverges the ADMF's view from the
    /// element's.
    #[serde(default = "default_true")]
    pub reconcile_on_start: bool,
}

fn default_x1_keepalive_secs() -> u64 {
    30
}

fn default_x1_request_timeout_secs() -> u64 {
    10
}

/// X2 IRI delivery — ASN.1/BER encoded signaling events over TCP/TLS.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX2Config {
    /// Mediation device IRI collector address (host:port).
    pub delivery_address: String,
    /// Transport: "tcp" or "tls". Default: "tcp".
    #[serde(default = "default_li_x2_transport")]
    pub transport: String,
    /// Reconnect interval on connection loss. Default: 5.
    #[serde(default = "default_li_reconnect_interval")]
    pub reconnect_interval_secs: u64,
    /// Async channel buffer size. Default: 10000.
    #[serde(default = "default_li_channel_size")]
    pub channel_size: usize,
    /// TLS settings for X2 delivery (when transport = "tls").
    pub tls: Option<LiTlsConfig>,
}

/// X3 content delivery.
///
/// Presence is the switch, and there is deliberately nothing else to set.
///
/// The TS 103 221-2 content framing lives in the media engine, because that is
/// where the RTP is, and the engine delivers straight to the destinations the
/// ADMF provisioned over X1. So this process has no collector address to dial,
/// no transport to choose and no encapsulation to pick — every one of those was
/// a setting for a path that no longer exists, and a setting that changes
/// nothing is worse than no setting at all.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX3Config {
    /// Whether this node delivers content.
    ///
    /// Required, so that writing the block is a statement rather than an empty
    /// gesture. `true` requires `media.backend: siphon-rtp` and is refused at
    /// load on anything else; `false` is the same as omitting the block, and is
    /// there so content can be turned off without deleting configuration.
    pub enabled: bool,
}

/// SIPREC (RFC 7866) — SIP-based media recording.
#[derive(Debug, Deserialize, Clone)]
pub struct LiSiprecConfig {
    /// SIP Recording Server URI (e.g. "sip:srs@recorder.example.com").
    pub srs_uri: String,
    /// Number of parallel recording sessions per call. Default: 1.
    #[serde(default = "default_siprec_session_copies")]
    pub session_copies: u32,
    /// Transport for SRS INVITE: "udp", "tcp", or "tls". Default: "tcp".
    #[serde(default = "default_siprec_transport")]
    pub transport: String,
    /// RTPEngine media profile for subscribe (media fork) commands. Default: "siprec_src".
    #[serde(default = "default_siprec_src_profile")]
    pub rtpengine_profile: String,
}

/// TLS configuration for LI interfaces (X1 admin, X2/X3 delivery).
#[derive(Debug, Deserialize, Clone)]
pub struct LiTlsConfig {
    /// Path to TLS certificate file.
    pub certificate: Option<String>,
    /// Path to TLS private key file.
    pub private_key: Option<String>,
    /// CA certificate for verifying the remote peer.
    pub ca_cert: Option<String>,
    /// Require client certificate (mTLS). Default: false.
    #[serde(default)]
    pub verify_client: bool,
    /// SNI server name for outbound TLS connections.
    pub server_name: Option<String>,
}

fn default_li_x2_transport() -> String {
    "tcp".to_string()
}
fn default_li_reconnect_interval() -> u64 {
    5
}
fn default_li_channel_size() -> usize {
    10_000
}
fn default_siprec_session_copies() -> u32 {
    1
}
fn default_siprec_transport() -> String {
    "tcp".to_string()
}
fn default_siprec_src_profile() -> String {
    "siprec_src".to_string()
}
