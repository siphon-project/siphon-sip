//! STIR/SHAKEN — caller-ID attestation (RFC 8224/8225/8226, ATIS-1000074).
//!
//! This module is the protocol core, shared by the `stir` Python namespace
//! ([`crate::script::api::stir`]). It provides two operations:
//!
//! - **Sign** (Authentication Service): build an ES256-signed PASSporT and the
//!   RFC 8224 `Identity` header for an outbound INVITE.
//! - **Verify** (Verification Service): parse inbound `Identity` headers, fetch
//!   the signing certificate (x5u, cached), validate the chain to a configured
//!   STI-CA trust anchor, check PASSporT freshness + the orig/dest numbers, and
//!   produce a `verstat` outcome.
//!
//! The diverted-call PASSporT (`ppt=div`, RFC 8946) is supported on both sides.

pub mod cert;
pub mod error;
pub mod identity;
pub mod passport;

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use p256::ecdsa::SigningKey;
use p256::ecdsa::VerifyingKey;
use tracing::{debug, warn};
use x509_cert::Certificate;

use crate::config::{StirConfig, StirSigningConfig, StirVerificationConfig};
pub use error::StirError;
pub use passport::Attestation;

/// Wall-clock Unix time in whole seconds. `chrono` is built without the
/// `clock` feature here, so we read the system clock directly.
pub fn current_unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// SHAKEN verification status (ATIS-1000074 §5.3.1 — the `verstat` value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verstat {
    /// The PASSporT validated end to end.
    Passed,
    /// A PASSporT was present but failed cryptographic / freshness / TN checks.
    Failed,
    /// No PASSporT, or (in permissive mode) the cert could not be retrieved.
    NoValidation,
}

impl Verstat {
    /// The tel-URI `verstat` parameter value.
    pub fn as_str(self) -> &'static str {
        match self {
            Verstat::Passed => "TN-Validation-Passed",
            Verstat::Failed => "TN-Validation-Failed",
            Verstat::NoValidation => "No-TN-Validation",
        }
    }
}

/// Outcome of verifying the `Identity` header(s) on a request.
#[derive(Debug, Clone)]
pub struct StirVerification {
    /// Overall verstat.
    pub verstat: Verstat,
    /// `true` only when [`Verstat::Passed`].
    pub passed: bool,
    /// Attestation level from the SHAKEN PASSporT, if one validated.
    pub attestation: Option<String>,
    /// `origid` from the SHAKEN PASSporT, if one validated.
    pub origid: Option<String>,
    /// Originating TN from the SHAKEN PASSporT, if one validated.
    pub orig_tn: Option<String>,
    /// Human-readable reason (diagnostic / failure cause).
    pub reason: String,
    /// Decoded claim sets of every PASSporT that parsed (for script inspection).
    pub passports: Vec<serde_json::Value>,
}

impl StirVerification {
    fn no_validation(reason: impl Into<String>) -> Self {
        Self {
            verstat: Verstat::NoValidation,
            passed: false,
            attestation: None,
            origid: None,
            orig_tn: None,
            reason: reason.into(),
            passports: Vec::new(),
        }
    }
}

/// A signed `Identity` header plus the `origid` that was used.
#[derive(Debug, Clone)]
pub struct SignedIdentity {
    /// The full `Identity` header field value.
    pub header_value: String,
    /// The `origid` (UUID) stamped on the PASSporT.
    pub origid: String,
}

/// Loaded signing parameters (Authentication Service).
struct SigningContext {
    signing_key: SigningKey,
    x5u: String,
    default_attestation: Attestation,
    fixed_origid: Option<String>,
}

/// Loaded verification parameters (Verification Service) + the x5u cache.
struct VerificationContext {
    anchors: Vec<Certificate>,
    freshness_secs: i64,
    permissive: bool,
    cache_ttl_secs: u64,
    max_cert_bytes: usize,
    require_tnauthlist: bool,
    http_client: reqwest::Client,
    cache: DashMap<String, CachedChain>,
}

/// A cached x5u certificate chain with its expiry.
struct CachedChain {
    chain: Vec<Certificate>,
    expires_at_unix: i64,
}

/// The STIR/SHAKEN service. Cheap to share behind an `Arc`.
pub struct StirService {
    signing: Option<SigningContext>,
    verification: Option<VerificationContext>,
}

impl StirService {
    /// Build a service from the `stir:` config block. Loads the signing key
    /// and trust anchors from disk and constructs the x5u HTTP client.
    pub fn from_config(config: &StirConfig) -> Result<Arc<Self>, StirError> {
        let signing = match &config.signing {
            Some(signing_config) => Some(build_signing_context(signing_config)?),
            None => None,
        };
        let verification = match &config.verification {
            Some(verification_config) => Some(build_verification_context(verification_config)?),
            None => None,
        };
        Ok(Arc::new(Self {
            signing,
            verification,
        }))
    }

    /// The configured default attestation level, if signing is enabled.
    pub fn default_attestation(&self) -> Option<Attestation> {
        self.signing
            .as_ref()
            .map(|context| context.default_attestation)
    }

    /// Whether the Authentication Service (signing) is configured.
    pub fn signing_enabled(&self) -> bool {
        self.signing.is_some()
    }

    /// Whether the Verification Service is configured.
    pub fn verification_enabled(&self) -> bool {
        self.verification.is_some()
    }

    /// Build and sign a SHAKEN `Identity` header for an outbound request.
    pub fn sign(
        &self,
        attestation: Attestation,
        orig_tn: &str,
        dest_tn: &str,
        origid: Option<String>,
        now_unix: i64,
    ) -> Result<SignedIdentity, StirError> {
        let context = self
            .signing
            .as_ref()
            .ok_or(StirError::SigningNotConfigured)?;
        if orig_tn.is_empty() {
            return Err(StirError::MissingTn("orig".to_string()));
        }
        if dest_tn.is_empty() {
            return Err(StirError::MissingTn("dest".to_string()));
        }
        let origid = origid
            .or_else(|| context.fixed_origid.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let token = passport::build_shaken_token(
            &context.signing_key,
            &context.x5u,
            attestation,
            orig_tn,
            dest_tn,
            &origid,
            now_unix,
        )?;
        Ok(SignedIdentity {
            header_value: identity::build(&token, &context.x5u, "shaken"),
            origid,
        })
    }

    /// Build and sign a diverted-call (`div`) `Identity` header (RFC 8946).
    pub fn sign_div(
        &self,
        orig_tn: &str,
        dest_tn: &str,
        div_tn: &str,
        now_unix: i64,
    ) -> Result<String, StirError> {
        let context = self
            .signing
            .as_ref()
            .ok_or(StirError::SigningNotConfigured)?;
        if orig_tn.is_empty() {
            return Err(StirError::MissingTn("orig".to_string()));
        }
        if dest_tn.is_empty() {
            return Err(StirError::MissingTn("dest".to_string()));
        }
        if div_tn.is_empty() {
            return Err(StirError::MissingTn("div".to_string()));
        }
        let token = passport::build_div_token(
            &context.signing_key,
            &context.x5u,
            orig_tn,
            dest_tn,
            div_tn,
            now_unix,
        )?;
        Ok(identity::build(&token, &context.x5u, "div"))
    }

    /// Verify the `Identity` header(s) on an inbound request.
    pub fn verify(
        &self,
        identity_values: &[String],
        call_orig_tn: Option<&str>,
        call_dest_tn: Option<&str>,
        now_unix: i64,
    ) -> Result<StirVerification, StirError> {
        let context = self
            .verification
            .as_ref()
            .ok_or(StirError::VerificationNotConfigured)?;

        if identity_values.is_empty() {
            return Ok(StirVerification::no_validation(
                "no Identity header present",
            ));
        }

        let mut decoded: Vec<serde_json::Value> = Vec::new();
        let mut shaken_passed = false;
        let mut attestation = None;
        let mut origid = None;
        let mut orig_tn = None;
        let mut hard_fail: Option<String> = None;
        let mut unable: Option<String> = None;

        for value in identity_values {
            let outcome = context.process_one(value, call_orig_tn, call_dest_tn, now_unix);
            if let Some(claims) = outcome.claims {
                decoded.push(claims);
            }
            match outcome.result {
                PassportResult::Passed => {
                    if outcome.ppt.as_deref() == Some("shaken") {
                        shaken_passed = true;
                        attestation = outcome.attestation;
                        origid = outcome.origid;
                        orig_tn = outcome.orig_tn;
                    }
                }
                PassportResult::HardFail(reason) => {
                    hard_fail.get_or_insert(reason);
                }
                PassportResult::Unable(reason) => {
                    unable.get_or_insert(reason);
                }
            }
        }

        let verification = if let Some(reason) = hard_fail {
            StirVerification {
                verstat: Verstat::Failed,
                passed: false,
                attestation,
                origid,
                orig_tn,
                reason,
                passports: decoded,
            }
        } else if shaken_passed {
            StirVerification {
                verstat: Verstat::Passed,
                passed: true,
                attestation,
                origid,
                orig_tn,
                reason: "ok".to_string(),
                passports: decoded,
            }
        } else if let Some(reason) = unable {
            let verstat = if context.permissive {
                Verstat::NoValidation
            } else {
                Verstat::Failed
            };
            StirVerification {
                verstat,
                passed: false,
                attestation,
                origid,
                orig_tn,
                reason,
                passports: decoded,
            }
        } else {
            StirVerification {
                verstat: Verstat::NoValidation,
                passed: false,
                attestation,
                origid,
                orig_tn,
                reason: "no SHAKEN PASSporT present".to_string(),
                passports: decoded,
            }
        };

        Ok(verification)
    }
}

/// Per-PASSporT verification outcome.
enum PassportResult {
    /// Validated end to end.
    Passed,
    /// Definitively invalid (bad signature / chain / freshness / TN mismatch).
    HardFail(String),
    /// Could not validate due to an infrastructure problem (x5u fetch, etc.).
    Unable(String),
}

/// Detailed outcome of processing one `Identity` header value.
struct ProcessedPassport {
    ppt: Option<String>,
    claims: Option<serde_json::Value>,
    attestation: Option<String>,
    origid: Option<String>,
    orig_tn: Option<String>,
    result: PassportResult,
}

impl VerificationContext {
    fn process_one(
        &self,
        identity_value: &str,
        call_orig_tn: Option<&str>,
        call_dest_tn: Option<&str>,
        now_unix: i64,
    ) -> ProcessedPassport {
        let header = match identity::parse(identity_value) {
            Ok(header) => header,
            Err(error) => return ProcessedPassport::hard_fail(None, None, error.to_string()),
        };
        let parsed = match passport::parse_token(&header.token) {
            Ok(parsed) => parsed,
            Err(error) => {
                return ProcessedPassport::hard_fail(header.ppt.clone(), None, error.to_string())
            }
        };
        let ppt = Some(parsed.ppt.clone());
        let claims = Some(parsed.claims.clone());

        if parsed.alg != "ES256" {
            return ProcessedPassport::hard_fail(
                ppt,
                claims,
                format!("unsupported PASSporT alg {:?} (only ES256)", parsed.alg),
            );
        }

        // Fetch + validate the signing certificate chain.
        let chain = match self.fetch_chain(&parsed.x5u, now_unix) {
            Ok(chain) => chain,
            Err(reason) => {
                return ProcessedPassport::unable(ppt, claims, reason);
            }
        };
        let leaf_key =
            match cert::validate_chain(&chain, &self.anchors, now_unix, self.require_tnauthlist) {
                Ok(key) => key,
                Err(reason) => return ProcessedPassport::hard_fail(ppt, claims, reason),
            };

        if !parsed.verify_signature(&leaf_key) {
            return ProcessedPassport::hard_fail(
                ppt,
                claims,
                "PASSporT signature does not verify".to_string(),
            );
        }

        // Freshness (ATIS-1000074): |now - iat| within the configured window.
        match parsed.iat() {
            Some(iat) => {
                if (now_unix - iat).abs() > self.freshness_secs {
                    return ProcessedPassport::hard_fail(
                        ppt,
                        claims,
                        format!("PASSporT iat is stale ({} s skew)", (now_unix - iat).abs()),
                    );
                }
            }
            None => {
                return ProcessedPassport::hard_fail(
                    ppt,
                    claims,
                    "PASSporT missing iat claim".to_string(),
                );
            }
        }

        // Orig/dest TN cross-check against the call — SHAKEN PASSporTs only.
        if parsed.ppt == "shaken" {
            if let Some(call_orig) = call_orig_tn {
                let passport_orig = parsed.orig_tn().unwrap_or_default();
                if !tn_matches(&passport_orig, call_orig) {
                    return ProcessedPassport::hard_fail(
                        ppt,
                        claims,
                        "PASSporT orig TN does not match the calling number".to_string(),
                    );
                }
            }
            if let Some(call_dest) = call_dest_tn {
                let dest_tns = parsed.dest_tns();
                if !dest_tns.iter().any(|tn| tn_matches(tn, call_dest)) {
                    return ProcessedPassport::hard_fail(
                        ppt,
                        claims,
                        "PASSporT dest TN does not match the called number".to_string(),
                    );
                }
            }
        }

        ProcessedPassport {
            ppt,
            claims,
            attestation: parsed.attestation(),
            origid: parsed.origid(),
            orig_tn: parsed.orig_tn(),
            result: PassportResult::Passed,
        }
    }

    /// Fetch the x5u certificate chain, using the in-memory cache when fresh.
    fn fetch_chain(&self, url: &str, now_unix: i64) -> Result<Vec<Certificate>, String> {
        if let Some(entry) = self.cache.get(url) {
            if entry.expires_at_unix > now_unix {
                return Ok(entry.chain.clone());
            }
        }

        let response = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.http_client.get(url).send())
        })
        .map_err(|error| format!("x5u fetch failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!("x5u fetch returned HTTP {}", response.status()));
        }

        let max_age = parse_max_age(&response);

        let body = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(response.bytes())
        })
        .map_err(|error| format!("x5u body read failed: {error}"))?;

        if body.len() > self.max_cert_bytes {
            return Err(format!(
                "x5u certificate response too large ({} > {} bytes)",
                body.len(),
                self.max_cert_bytes
            ));
        }

        let chain = cert::parse_pem_chain(&body)?;
        let ttl = max_age.unwrap_or(self.cache_ttl_secs);
        self.cache.insert(
            url.to_string(),
            CachedChain {
                chain: chain.clone(),
                expires_at_unix: now_unix.saturating_add(ttl as i64),
            },
        );
        debug!(url, ttl_secs = ttl, "cached x5u certificate chain");
        Ok(chain)
    }
}

impl ProcessedPassport {
    fn hard_fail(ppt: Option<String>, claims: Option<serde_json::Value>, reason: String) -> Self {
        Self {
            ppt,
            claims,
            attestation: None,
            origid: None,
            orig_tn: None,
            result: PassportResult::HardFail(reason),
        }
    }

    fn unable(ppt: Option<String>, claims: Option<serde_json::Value>, reason: String) -> Self {
        Self {
            ppt,
            claims,
            attestation: None,
            origid: None,
            orig_tn: None,
            result: PassportResult::Unable(reason),
        }
    }
}

/// Parse a `Cache-Control: max-age=N` directive from a response, if present.
fn parse_max_age(response: &reqwest::Response) -> Option<u64> {
    let value = response.headers().get(reqwest::header::CACHE_CONTROL)?;
    let value = value.to_str().ok()?;
    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(seconds) = directive.strip_prefix("max-age=") {
            return seconds.trim().parse::<u64>().ok();
        }
    }
    None
}

/// Normalize a telephone number to its digits for loose comparison.
fn normalize_tn(tn: &str) -> String {
    tn.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Loosely compare two telephone numbers (digits only, tolerating a leading
/// country-code `1` on either side).
fn tn_matches(left: &str, right: &str) -> bool {
    let left = normalize_tn(left);
    let right = normalize_tn(right);
    if left.is_empty() || right.is_empty() {
        return false;
    }
    left == right || left.trim_start_matches('1') == right.trim_start_matches('1')
}

/// Load the P-256 signing key from a PEM file (PKCS#8 or SEC1).
fn load_signing_key(path: &str) -> Result<SigningKey, StirError> {
    use p256::pkcs8::DecodePrivateKey;
    use p256::SecretKey;

    let pem = std::fs::read_to_string(path)
        .map_err(|error| StirError::KeyLoad(format!("reading {path}: {error}")))?;
    if let Ok(key) = SigningKey::from_pkcs8_pem(&pem) {
        return Ok(key);
    }
    // Fall back to SEC1 ("EC PRIVATE KEY") encoding.
    let secret = SecretKey::from_sec1_pem(&pem).map_err(|error| {
        StirError::KeyLoad(format!(
            "{path} is not a valid PKCS#8 or SEC1 P-256 private key: {error}"
        ))
    })?;
    Ok(SigningKey::from(secret))
}

fn build_signing_context(config: &StirSigningConfig) -> Result<SigningContext, StirError> {
    let signing_key = load_signing_key(&config.private_key)?;
    // Validate the key produces a usable public key early.
    let _ = VerifyingKey::from(&signing_key);
    let default_attestation = Attestation::parse(&config.default_attestation)?;
    Ok(SigningContext {
        signing_key,
        x5u: config.x5u.clone(),
        default_attestation,
        fixed_origid: config.origid.clone(),
    })
}

fn build_verification_context(
    config: &StirVerificationConfig,
) -> Result<VerificationContext, StirError> {
    let mut anchors: Vec<Certificate> = Vec::new();
    for path in &config.trust_anchors {
        anchors.extend(load_anchor_file(path)?);
    }
    if let Some(dir) = &config.trust_anchor_dir {
        anchors.extend(load_anchor_dir(dir)?);
    }
    if anchors.is_empty() {
        warn!("stir.verification configured with no trust anchors — all verifications will fail to build a chain");
    }

    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|error| StirError::HttpClient(error.to_string()))?;

    Ok(VerificationContext {
        anchors,
        freshness_secs: config.freshness_secs as i64,
        permissive: config.permissive,
        cache_ttl_secs: config.cache_ttl_secs,
        max_cert_bytes: config.max_cert_bytes,
        require_tnauthlist: config.require_tnauthlist,
        http_client,
        cache: DashMap::new(),
    })
}

fn load_anchor_file(path: &str) -> Result<Vec<Certificate>, StirError> {
    let pem = std::fs::read(path)
        .map_err(|error| StirError::TrustAnchorLoad(format!("reading {path}: {error}")))?;
    cert::parse_pem_chain(&pem)
        .map_err(|error| StirError::TrustAnchorLoad(format!("{path}: {error}")))
}

fn load_anchor_dir(dir: &str) -> Result<Vec<Certificate>, StirError> {
    let mut anchors = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|error| StirError::TrustAnchorLoad(format!("reading dir {dir}: {error}")))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| StirError::TrustAnchorLoad(format!("dir {dir}: {error}")))?;
        let path = entry.path();
        let is_cert = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(|extension| {
                let extension = extension.to_ascii_lowercase();
                extension == "pem" || extension == "crt" || extension == "cer"
            })
            .unwrap_or(false);
        if !is_cert {
            continue;
        }
        if let Some(path_str) = path.to_str() {
            anchors.extend(load_anchor_file(path_str)?);
        }
    }
    Ok(anchors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verstat_strings() {
        assert_eq!(Verstat::Passed.as_str(), "TN-Validation-Passed");
        assert_eq!(Verstat::Failed.as_str(), "TN-Validation-Failed");
        assert_eq!(Verstat::NoValidation.as_str(), "No-TN-Validation");
    }

    #[test]
    fn tn_matching_is_loose_on_country_code() {
        assert!(tn_matches("+1-202-555-0100", "12025550100"));
        assert!(tn_matches("2025550100", "12025550100"));
        assert!(tn_matches("tel:+12025550100", "12025550100"));
        assert!(!tn_matches("2025550100", "2025550199"));
        assert!(!tn_matches("", "12025550100"));
    }

    #[test]
    fn current_time_is_after_2020() {
        // Sanity: the system clock helper returns a plausible value.
        assert!(current_unix_time() > 1_577_836_800);
    }

    // --- End-to-end sign → verify (cache-seeded, no network) ---------------

    const TEST_X5U: &str = "https://certs.example.test/sti.pem";
    const TEST_NOW: i64 = 1_700_000_000; // 2023-11-14, inside rcgen default window

    /// Build a service whose signing key matches the leaf cert, with the
    /// verification cache pre-seeded so `verify` never touches the network.
    fn service_with_seeded_cache(permissive: bool) -> Arc<StirService> {
        let generated = cert::testchain::generate();
        let chain = cert::parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let anchors = cert::parse_pem_chain(generated.anchor_pem.as_bytes()).unwrap();

        let verification = VerificationContext {
            anchors,
            freshness_secs: 60,
            permissive,
            cache_ttl_secs: 3600,
            max_cert_bytes: 65536,
            require_tnauthlist: false,
            http_client: reqwest::Client::new(),
            cache: DashMap::new(),
        };
        verification.cache.insert(
            TEST_X5U.to_string(),
            CachedChain {
                chain,
                expires_at_unix: i64::MAX,
            },
        );

        Arc::new(StirService {
            signing: Some(SigningContext {
                signing_key: generated.leaf_key,
                x5u: TEST_X5U.to_string(),
                default_attestation: Attestation::A,
                fixed_origid: None,
            }),
            verification: Some(verification),
        })
    }

    #[test]
    fn sign_then_verify_passes() {
        let service = service_with_seeded_cache(false);
        let signed = service
            .sign(Attestation::A, "12155550112", "12025550100", None, TEST_NOW)
            .unwrap();
        assert!(!signed.origid.is_empty());

        let verification = service
            .verify(
                &[signed.header_value],
                Some("12155550112"),
                Some("12025550100"),
                TEST_NOW,
            )
            .unwrap();
        assert_eq!(verification.verstat, Verstat::Passed);
        assert!(verification.passed);
        assert_eq!(verification.attestation.as_deref(), Some("A"));
        assert_eq!(verification.orig_tn.as_deref(), Some("12155550112"));
        assert_eq!(verification.passports.len(), 1);
    }

    #[test]
    fn verify_fails_on_orig_tn_mismatch() {
        let service = service_with_seeded_cache(false);
        let signed = service
            .sign(Attestation::A, "12155550112", "12025550100", None, TEST_NOW)
            .unwrap();
        // The call claims a different calling number than the PASSporT.
        let verification = service
            .verify(
                &[signed.header_value],
                Some("19998887777"),
                Some("12025550100"),
                TEST_NOW,
            )
            .unwrap();
        assert_eq!(verification.verstat, Verstat::Failed);
        assert!(!verification.passed);
        assert!(verification.reason.contains("orig"));
    }

    #[test]
    fn verify_fails_on_stale_iat() {
        let service = service_with_seeded_cache(false);
        let signed = service
            .sign(Attestation::A, "12155550112", "12025550100", None, TEST_NOW)
            .unwrap();
        // Verify 1 hour later — outside the 60 s freshness window.
        let verification = service
            .verify(
                &[signed.header_value],
                Some("12155550112"),
                Some("12025550100"),
                TEST_NOW + 3600,
            )
            .unwrap();
        assert_eq!(verification.verstat, Verstat::Failed);
        assert!(verification.reason.contains("stale"));
    }

    #[test]
    fn verify_no_identity_header_is_no_validation() {
        let service = service_with_seeded_cache(false);
        let verification = service.verify(&[], Some("1"), Some("2"), TEST_NOW).unwrap();
        assert_eq!(verification.verstat, Verstat::NoValidation);
        assert!(!verification.passed);
    }

    #[test]
    fn shaken_plus_div_round_trip() {
        let service = service_with_seeded_cache(false);
        let shaken = service
            .sign(Attestation::B, "12155550112", "12025550100", None, TEST_NOW)
            .unwrap();
        let div = service
            .sign_div("12155550112", "12025550100", "12155550199", TEST_NOW)
            .unwrap();

        let verification = service
            .verify(
                &[shaken.header_value, div],
                Some("12155550112"),
                Some("12025550100"),
                TEST_NOW,
            )
            .unwrap();
        assert_eq!(verification.verstat, Verstat::Passed);
        assert_eq!(verification.attestation.as_deref(), Some("B"));
        assert_eq!(verification.passports.len(), 2);
    }

    #[test]
    fn tampered_passport_fails() {
        let service = service_with_seeded_cache(false);
        let signed = service
            .sign(Attestation::A, "12155550112", "12025550100", None, TEST_NOW)
            .unwrap();
        // Corrupt the signature segment of the token inside the Identity value.
        let parsed = identity::parse(&signed.header_value).unwrap();
        let mut token_parts: Vec<String> = parsed.token.split('.').map(str::to_string).collect();
        let flipped: String = token_parts[2]
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if index == 0 {
                    if character == 'A' {
                        'B'
                    } else {
                        'A'
                    }
                } else {
                    character
                }
            })
            .collect();
        token_parts[2] = flipped;
        let tampered_token = token_parts.join(".");
        let tampered_value = identity::build(&tampered_token, TEST_X5U, "shaken");

        let verification = service
            .verify(
                &[tampered_value],
                Some("12155550112"),
                Some("12025550100"),
                TEST_NOW,
            )
            .unwrap();
        assert_eq!(verification.verstat, Verstat::Failed);
    }
}
