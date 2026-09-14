//! `stir:` STIR/SHAKEN (RFC 8224/8225/8226, ATIS-1000074).

use serde::Deserialize;

// ---------------------------------------------------------------------------
// STIR/SHAKEN (RFC 8224/8225/8226, ATIS-1000074)
// ---------------------------------------------------------------------------

/// Top-level `stir:` configuration. Either or both of `signing` (the
/// Authentication Service) and `verification` (the Verification Service)
/// may be present; omitting one disables that side.
#[derive(Debug, Deserialize, Clone)]
pub struct StirConfig {
    /// Master on/off switch. Defaults to `true` when the `stir:` block is
    /// present, so adding the block enables it without an extra flag.
    #[serde(default = "default_stir_enabled")]
    pub enabled: bool,
    /// Outbound signing parameters (Authentication Service). When absent,
    /// `stir.sign()` / `stir.sign_div()` raise.
    pub signing: Option<StirSigningConfig>,
    /// Inbound verification parameters (Verification Service). When absent,
    /// `stir.verify()` raises.
    pub verification: Option<StirVerificationConfig>,
}

/// `stir.signing` — Authentication Service parameters.
#[derive(Debug, Deserialize, Clone)]
pub struct StirSigningConfig {
    /// Path to the PEM EC P-256 private key used to sign PASSporTs.
    pub private_key: String,
    /// Public certificate URL embedded as the Identity `info=` parameter and
    /// the PASSporT `x5u` header (RFC 8224 §4).
    pub x5u: String,
    /// Default attestation level (`A`, `B`, or `C`) when the script does not
    /// pass one to `stir.sign()`.
    #[serde(default = "default_stir_attestation")]
    pub default_attestation: String,
    /// Fixed `origid` (UUID) to stamp on every PASSporT. When unset, a fresh
    /// v4 UUID is generated per call.
    #[serde(default)]
    pub origid: Option<String>,
}

/// `stir.verification` — Verification Service parameters.
#[derive(Debug, Deserialize, Clone)]
pub struct StirVerificationConfig {
    /// STI-CA trust-anchor (root) certificate files (PEM).
    #[serde(default)]
    pub trust_anchors: Vec<String>,
    /// Optional directory of PEM trust anchors — every `*.pem`/`*.crt` file
    /// in it is loaded in addition to `trust_anchors`.
    #[serde(default)]
    pub trust_anchor_dir: Option<String>,
    /// PASSporT `iat` freshness window in seconds (ATIS-1000074).
    #[serde(default = "default_stir_freshness_secs")]
    pub freshness_secs: u64,
    /// Log-only rollout mode: x5u/infra failures degrade to
    /// `No-TN-Validation` instead of `TN-Validation-Failed`. Genuine bad
    /// signatures / expired certs / stale PASSporTs always fail.
    #[serde(default)]
    pub permissive: bool,
    /// Default x5u certificate cache TTL in seconds (overridden by a
    /// response `Cache-Control: max-age`).
    #[serde(default = "default_stir_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Maximum accepted size of an x5u certificate response, in bytes.
    #[serde(default = "default_stir_max_cert_bytes")]
    pub max_cert_bytes: usize,
    /// Require the leaf certificate to carry the RFC 8226 TNAuthList
    /// extension.
    #[serde(default)]
    pub require_tnauthlist: bool,
}

fn default_stir_enabled() -> bool {
    true
}

fn default_stir_attestation() -> String {
    "A".to_string()
}

fn default_stir_freshness_secs() -> u64 {
    60
}

fn default_stir_cache_ttl_secs() -> u64 {
    3600
}

fn default_stir_max_cert_bytes() -> usize {
    65536
}
