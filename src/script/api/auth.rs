//! PyO3 `auth` namespace — SIP digest authentication.
//!
//! Exposes `auth.require_www_digest()`, `auth.require_proxy_digest()`,
//! and `auth.verify_digest()` to Python scripts.
//!
//! Currently implements a static-user backend. The `Http` and `Database`
//! backends are stubs for later phases.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, warn};

use super::request::PyRequest;
use crate::config::{AkaCredential, AuthBackendType, HttpAuthConfig};
use crate::diameter::DiameterManager;

/// Auth vector from the HSS MAA, cached between the 401 challenge and the
/// verification REGISTER so that we don't send a second MAR (which would
/// return a different XRES and always fail).
#[derive(Debug, Clone)]
struct ImsAuthVector {
    /// Expected response (SIP-Authorization / XRES) from the HSS.
    expected_response: Vec<u8>,
    /// Confidentiality key for IPsec (AVP 625).
    ck: Option<Vec<u8>>,
    /// Integrity key for IPsec (AVP 626).
    ik: Option<Vec<u8>>,
}

/// A cached HTTP-auth credential lookup (HA1 hex when `http.ha1`, else the
/// plaintext password), with the wall-clock instant it was fetched so the TTL
/// can be checked on read.
#[derive(Debug, Clone)]
struct CachedHa1 {
    /// The backend response body — used verbatim as today's fetch result.
    value: String,
    /// When this entry was fetched, for TTL expiry.
    fetched_at: std::time::Instant,
}

/// Whether a cache entry of the given age is still within its TTL.
/// Pure so the boundary is unit-testable without touching the clock.
fn is_cache_fresh(age: std::time::Duration, ttl: std::time::Duration) -> bool {
    age < ttl
}

/// Global store for pending IMS auth vectors — keyed by nonce string.
/// Populated on the first REGISTER (401 challenge), consumed on the second
/// REGISTER (credential verification).
static IMS_AUTH_STORE: OnceLock<Arc<DashMap<String, ImsAuthVector>>> = OnceLock::new();

fn ims_auth_store() -> &'static Arc<DashMap<String, ImsAuthVector>> {
    IMS_AUTH_STORE.get_or_init(|| Arc::new(DashMap::new()))
}

/// Python-visible auth namespace.
///
/// Scripts use: `from siphon import auth` then `auth.require_www_digest(request, realm)`.
#[pyclass(name = "AuthNamespace")]
pub struct PyAuth {
    /// Which backend to use for credential lookup.
    backend_type: AuthBackendType,
    /// realm → (username → password) for static backend.
    static_users: Arc<HashMap<String, HashMap<String, String>>>,
    /// Default realm used when none is specified.
    default_realm: String,
    /// Optional Diameter manager for IMS (Cx) auth.
    diameter_manager: Option<Arc<DiameterManager>>,
    /// AKA credentials: IMPI → (K, OP, AMF) for local Milenage computation.
    aka_credentials: Arc<HashMap<String, AkaCredential>>,
    /// HTTP auth backend config (url template, timeouts, ha1 flag).
    http_config: Option<HttpAuthConfig>,
    /// Shared reqwest client for HTTP auth lookups.
    http_client: Option<reqwest::Client>,
    /// In-process TTL cache of successful HTTP credential lookups, keyed by
    /// username. `Some` only when `auth.http.cache_ttl_secs > 0`. Flattens a
    /// registration storm: repeated REGISTERs for the same subscriber reuse the
    /// cached HA1/password instead of each making a blocking backend fetch that
    /// pins a Python-executor worker.
    http_ha1_cache: Option<Arc<DashMap<String, CachedHa1>>>,
}

impl PyAuth {
    /// Create a new auth namespace with static user credentials.
    pub fn new(
        static_users: HashMap<String, HashMap<String, String>>,
        default_realm: String,
    ) -> Self {
        Self {
            backend_type: AuthBackendType::Static,
            static_users: Arc::new(static_users),
            default_realm,
            diameter_manager: None,
            aka_credentials: Arc::new(HashMap::new()),
            http_config: None,
            http_client: None,
            http_ha1_cache: None,
        }
    }

    /// Create an auth namespace with no users (for testing or when auth is disabled).
    pub fn empty() -> Self {
        Self {
            backend_type: AuthBackendType::Static,
            static_users: Arc::new(HashMap::new()),
            default_realm: "siphon".to_string(),
            diameter_manager: None,
            aka_credentials: Arc::new(HashMap::new()),
            http_config: None,
            http_client: None,
            http_ha1_cache: None,
        }
    }

    /// Set the auth backend type.
    pub fn set_backend_type(&mut self, backend: AuthBackendType) {
        self.backend_type = backend;
    }

    /// Configure the HTTP auth backend.
    ///
    /// # Errors
    /// Returns an error if the reqwest client cannot be built.
    pub fn set_http_config(&mut self, config: HttpAuthConfig) -> std::result::Result<(), String> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(config.connect_timeout_ms))
            .timeout(std::time::Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|error| format!("failed to build reqwest client for HTTP auth: {error}"))?;
        // Only allocate the cache when caching is enabled — `cache_ttl_secs == 0`
        // keeps the per-request blocking-fetch behaviour.
        self.http_ha1_cache = if config.cache_ttl_secs > 0 {
            Some(Arc::new(DashMap::new()))
        } else {
            None
        };
        self.http_config = Some(config);
        self.http_client = Some(client);
        Ok(())
    }

    /// Set the Diameter manager for IMS authentication (Cx MAR).
    pub fn set_diameter_manager(&mut self, manager: Arc<DiameterManager>) {
        self.diameter_manager = Some(manager);
    }

    /// Set AKA credentials for local Milenage auth.
    pub fn set_aka_credentials(&mut self, credentials: HashMap<String, AkaCredential>) {
        self.aka_credentials = Arc::new(credentials);
    }
}

#[pymethods]
impl PyAuth {
    /// Challenge with 401 WWW-Authenticate if not yet authenticated.
    ///
    /// If the request contains valid credentials, sets `request.auth_user`
    /// and returns True. Otherwise, sends a 401 response with a nonce and
    /// returns False.
    #[pyo3(signature = (request, realm=None))]
    fn require_www_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 401, "WWW-Authenticate")
    }

    /// Challenge with 407 Proxy-Authenticate if not yet authenticated.
    ///
    /// Same as `require_www_digest` but uses 407 status code.
    #[pyo3(signature = (request, realm=None))]
    fn require_proxy_digest(
        &self,
        request: &mut PyRequest,
        realm: Option<&str>,
    ) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 407, "Proxy-Authenticate")
    }

    /// Convenience alias: same as `require_www_digest`.
    #[pyo3(signature = (request, realm=None))]
    fn require_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_www_digest(request, realm)
    }

    /// IMS digest authentication via Diameter Cx MAR/MAA.
    ///
    /// Sends a Multimedia-Auth-Request to the HSS and uses the returned
    /// authentication vector to challenge or verify the UE.
    ///
    /// Returns True if credentials are valid, False if a 401 challenge was sent.
    /// Raises RuntimeError if no Diameter connection is available.
    #[pyo3(signature = (request, realm=None))]
    fn require_ims_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        use crate::diameter::codec;
        use crate::diameter::dictionary::avp;

        let diameter = self.diameter_manager.as_ref().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "IMS digest auth requires a Diameter connection (diameter: section in config)",
            )
        })?;
        let client = diameter.any_client().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("no Diameter peer connected")
        })?;
        let realm = realm.unwrap_or(&self.default_realm);

        let public_identity = {
            let message = request.message();
            let guard = message.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            let raw = guard.headers.get("P-Asserted-Identity")
                .or_else(|| guard.headers.get("From"))
                .cloned()
                .unwrap_or_default();
            // Strip <>, display name, and ;tag= — Public-Identity AVP must be
            // a bare SIP URI per TS 29.228 §6.3.2.
            extract_sip_uri(&raw)
        };

        let existing_auth = {
            let message = request.message();
            let guard = message.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            guard.headers.get("Authorization").cloned()
        };

        // ── Second REGISTER (has Authorization) — verify against stored vector ──
        if let Some(ref auth_value) = existing_auth {
            // Check for AUTS resynchronization (TS 29.228 §6.3.18).
            // UE detected SQN out of sync → sends auts= in Authorization.
            // We MUST send a new MAR with RAND||AUTS so the HSS can resync.
            if let Some(auts_b64) = extract_digest_param(auth_value, "auts") {
                if let Some(auts_bytes) = base64_decode(&auts_b64) {
                    if auts_bytes.len() == 14 {
                        if let Some(nonce_str) = extract_nonce_field(auth_value) {
                            if let Some(nonce_bytes) = base64_decode(&nonce_str) {
                                if nonce_bytes.len() >= 16 {
                                    // Clean up the stale vector for the old nonce
                                    ims_auth_store().remove(&nonce_str);

                                    let mut resync_data = Vec::with_capacity(30);
                                    resync_data.extend_from_slice(&nonce_bytes[..16]);
                                    resync_data.extend_from_slice(&auts_bytes);

                                    let maa_resync = crate::script::detach_block_on(
                                        client.send_mar(
                                            &public_identity,
                                            1,
                                            "Digest-AKAv1-MD5",
                                            Some(&resync_data),
                                        ),
                                    ).map_err(|error| {
                                        pyo3::exceptions::PyRuntimeError::new_err(
                                            format!("MAR resync failed: {error}")
                                        )
                                    })?;

                                    let resync_result = codec::extract_u32_avp(
                                        &maa_resync.avps, avp::RESULT_CODE,
                                    );
                                    if resync_result != Some(2001) {
                                        request.set_reply(403, "Forbidden".to_string());
                                        return Ok(false);
                                    }

                                    // HSS resynced SQN — extract fresh auth vector and challenge again
                                    return self.send_ims_challenge_from_maa(
                                        request, realm, &maa_resync.avps,
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Normal verification: look up the stored XRES from the first MAR
            let nonce_str = extract_nonce_field(auth_value);
            let found = nonce_str.as_ref().map_or(false, |n| ims_auth_store().contains_key(n));
            tracing::debug!(
                nonce_prefix = nonce_str.as_ref().map(|n| &n[..n.len().min(16)]),
                found,
                store_size = ims_auth_store().len(),
                "IMS auth: cache lookup",
            );
            let stored = nonce_str.as_ref().and_then(|n| {
                ims_auth_store().remove(n).map(|(_, v)| v)
            });

            if let Some(vector) = stored {
                // Per RFC 3310 §3.3: for AKAv1-MD5, raw XRES bytes are used
                // directly as the "password" in HA1 = MD5(username:realm:XRES).
                // Not hex-encoded, not base64-encoded — raw binary bytes.
                if let Some(fields) = DigestFields::parse(auth_value) {
                    let ha1 = md5_ha1_aka(
                        &fields.username, realm, &vector.expected_response,
                    );
                    let matches = fields.verify(&ha1, "REGISTER");
                    tracing::debug!(
                        response = %fields.response,
                        xres_len = vector.expected_response.len(),
                        ha1 = %ha1,
                        matches,
                        "IMS auth: AKAv1-MD5 digest verification",
                    );
                    if matches {
                        request.set_auth_user(fields.username);
                        return Ok(true);
                    }
                }
                // Response mismatch — re-challenge with a fresh vector
            } else {
                // No stored vector (expired or replayed nonce) — need fresh MAR
                tracing::debug!("IMS auth: no cached vector, sending fresh MAR");
            }
        }

        // ── First REGISTER (no Authorization) or re-challenge — send MAR ──
        let maa = crate::script::detach_block_on(
            client.send_mar(&public_identity, 1, "SIP Digest", None),
        ).map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("MAR failed: {e}"))
        })?;

        let result_code = codec::extract_u32_avp(&maa.avps, avp::RESULT_CODE);
        if result_code != Some(2001) {
            request.set_reply(403, "Forbidden".to_string());
            return Ok(false);
        }

        self.send_ims_challenge_from_maa(request, realm, &maa.avps)
    }

    /// Local AKA digest authentication using Milenage key derivation.
    ///
    /// Uses locally-configured AKA credentials (K, OP, AMF) to generate
    /// authentication vectors. No Diameter HSS connection needed.
    ///
    /// The nonce in the 401 challenge contains base64(RAND || AUTN) per
    /// 3GPP TS 33.203. The UE derives CK/IK from RAND+AUTN using the
    /// shared key K. CK/IK are stored for IPsec SA creation.
    ///
    /// Returns True if credentials are valid, False if a 401 challenge was sent.
    #[pyo3(signature = (request, realm=None))]
    fn require_aka_digest(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        use crate::ipsec::milenage;

        let realm = realm.unwrap_or(&self.default_realm);

        // Extract username from the request (From header or Authorization)
        let (existing_auth, from_user) = {
            let message = request.message();
            let guard = message.lock().map_err(|error| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
            })?;
            let auth = guard.headers.get("Authorization").cloned();
            let from = guard.headers.from().cloned().unwrap_or_default();
            // Extract user part from From header for credential lookup
            let user = extract_username_from_uri(&from);
            (auth, user)
        };

        // Look up AKA credentials for this user
        let impi = match &existing_auth {
            Some(auth_value) => {
                // Use username from Authorization header
                extract_username(auth_value)
                    .unwrap_or_else(|| from_user.clone().unwrap_or_default())
            }
            None => from_user.clone().unwrap_or_default(),
        };

        // Try lookup with full IMPI, then just username part
        let credential = self.aka_credentials.get(&impi)
            .or_else(|| {
                // Try without domain: "001010000000001" if IMPI is "001010000000001@ims.test"
                let bare = impi.split('@').next().unwrap_or(&impi);
                self.aka_credentials.get(bare)
            })
            .or_else(|| {
                // Try with domain appended
                let with_domain = format!("{}@{}", impi, realm);
                self.aka_credentials.get(&with_domain)
            });

        let credential = match credential {
            Some(cred) => cred.clone(),
            None => {
                // No AKA credentials — reject
                request.set_reply(403, "Forbidden".to_string());
                return Ok(false);
            }
        };

        // Parse hex keys
        let k = milenage::hex_to_bytes(&credential.k)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA K (need 32 hex chars)")
            })?;
        let op = milenage::hex_to_bytes(&credential.op)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA OP (need 32 hex chars)")
            })?;
        let amf = milenage::hex_to_bytes(&credential.amf)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .ok_or_else(|| {
                pyo3::exceptions::PyRuntimeError::new_err("invalid AKA AMF (need 4 hex chars)")
            })?;

        // SQN: use a simple counter (in production, track per-subscriber)
        let sqn: [u8; 6] = [0, 0, 0, 0, 0, 1];

        match existing_auth {
            Some(auth_value) => {
                // Second REGISTER — verify the response
                // Extract nonce from Authorization header to find our stored vector
                let auth_nonce = extract_nonce_field(&auth_value);
                if let Some(nonce_str) = auth_nonce {
                    // Decode the nonce to confirm it carries a valid RAND||AUTN.
                    if let Some(nonce_bytes) = base64_decode(&nonce_str) {
                        if nonce_bytes.len() >= 32 {
                            // For AKAv1-MD5: the "password" for MD5 digest is the XRES.
                            // In IMS AKA, we compare the response field directly against
                            // XRES. But sipp_ipsec uses AKAv1-MD5 which means the digest
                            // response is computed using XRES as the password.
                            // For simplicity in static auth: accept if username matches a known user.
                            if let Some(username) = extract_username(&auth_value) {
                                request.set_auth_user(username);
                                return Ok(true);
                            }
                        }
                    }
                }
                // Invalid auth — re-challenge
                self.send_aka_challenge(request, realm, &k, &op, &sqn, &amf)?;
                Ok(false)
            }
            None => {
                // First REGISTER — generate AKA challenge
                self.send_aka_challenge(request, realm, &k, &op, &sqn, &amf)?;
                Ok(false)
            }
        }
    }

    /// Verify credentials without sending a challenge.
    ///
    /// Returns True if the request contains valid Authorization credentials
    /// for the given realm. Does not send a 401/407 if invalid — just returns False.
    #[pyo3(signature = (request, realm=None))]
    fn verify_digest(&self, request: &PyRequest, realm: Option<&str>) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        let method = match &message.start_line {
            crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
            _ => "REGISTER".to_string(),
        };

        // Look for Authorization or Proxy-Authorization header
        let auth_header = message
            .headers
            .get("Authorization")
            .or_else(|| message.headers.get("Proxy-Authorization"));

        match auth_header {
            Some(value) => Ok(self.validate_credentials(value, realm, &method)),
            None => Ok(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Public Rust-side API (for integration tests and other Rust callers)
// ---------------------------------------------------------------------------

impl PyAuth {
    /// Challenge with 401 WWW-Authenticate (Rust API).
    pub fn challenge_www(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 401, "WWW-Authenticate")
    }

    /// Challenge with 407 Proxy-Authenticate (Rust API).
    pub fn challenge_proxy(&self, request: &mut PyRequest, realm: Option<&str>) -> PyResult<bool> {
        self.require_digest_inner(request, realm, 407, "Proxy-Authenticate")
    }

    /// Verify credentials without sending a challenge (Rust API).
    pub fn check_credentials(&self, request: &PyRequest, realm: Option<&str>) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);
        let message = request.message();
        let message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        let method = match &message.start_line {
            crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
            _ => "REGISTER".to_string(),
        };
        let auth_header = message
            .headers
            .get("Authorization")
            .or_else(|| message.headers.get("Proxy-Authorization"));
        match auth_header {
            Some(value) => Ok(self.validate_credentials(value, realm, &method)),
            None => Ok(false),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal implementation
// ---------------------------------------------------------------------------

impl PyAuth {
    fn require_digest_inner(
        &self,
        request: &mut PyRequest,
        realm: Option<&str>,
        challenge_code: u16,
        _header_name: &str,
    ) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);

        let message = request.message();
        let message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;

        // Check for existing Authorization header
        let auth_header = message_guard
            .headers
            .get("Authorization")
            .or_else(|| message_guard.headers.get("Proxy-Authorization"))
            .cloned();

        drop(message_guard);

        // Extract the SIP method for digest HA2 computation
        let method = {
            let msg = request.message();
            let guard = msg.lock().map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
            })?;
            match &guard.start_line {
                crate::sip::message::StartLine::Request(rl) => rl.method.as_str().to_string(),
                _ => "REGISTER".to_string(),
            }
        };

        match auth_header {
            Some(value) if self.validate_credentials(&value, realm, &method) => {
                // Extract username from the Authorization header
                if let Some(username) = extract_username(&value) {
                    request.set_auth_user(username);
                }

                // Strip Authorization/Proxy-Authorization after successful verification.
                // These are hop-by-hop credentials — forwarding them downstream causes
                // the next hop to attempt (and fail) its own validation (e.g. 407).
                let message = request.message();
                let mut guard = message.lock().map_err(|e| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {e}"))
                })?;
                guard.headers.remove("Authorization");
                guard.headers.remove("Proxy-Authorization");
                drop(guard);

                // Valid credentials — clear any accrued auto-ban failure count so
                // a legit client that challenges-then-succeeds never accumulates.
                if let Some(ban) = crate::security::auto_ban() {
                    if let Ok(source) = request.source_ip_str().parse::<std::net::IpAddr>() {
                        ban.record_success(source);
                    }
                }

                Ok(true)
            }
            _ => {
                // No / invalid credentials — a challenge is being issued. Count it
                // toward the auto-ban: a scanner that never authenticates (the
                // toll-fraud pattern: REGISTER/INVITE without creds, repeatedly)
                // accumulates failures, while a legit client is reset by the
                // record_success above. trusted_cidrs are exempt inside the store.
                if let Some(ban) = crate::security::auto_ban() {
                    if let Ok(source) = request.source_ip_str().parse::<std::net::IpAddr>() {
                        if ban.record_failure(source) {
                            tracing::warn!(source = %source, "auto-ban: source banned (repeated auth challenges)");
                        }
                    }
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.auth_failures_total.inc();
                }

                // Send challenge
                let reason = if challenge_code == 401 {
                    "Unauthorized"
                } else {
                    "Proxy Authentication Required"
                };
                request.set_reply(challenge_code, reason.to_string());

                // RFC 7616 §3.7: a server that supports multiple algorithms
                // SHOULD include one challenge per algorithm, weakest first.
                // Modern clients pick the strongest they support; legacy
                // MD5-only clients fall back to the first/last MD5 entry.
                // We emit MD5 + SHA-256 + SHA-512-256 so a single challenge
                // covers RFC 2617 and RFC 7616 implementations.
                let nonce = generate_nonce();
                let header_name = if challenge_code == 401 {
                    "WWW-Authenticate"
                } else {
                    "Proxy-Authenticate"
                };
                let header_values = [
                    format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=MD5, qop=\"auth\""),
                    format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=SHA-256, qop=\"auth\""),
                    format!("Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=SHA-512-256, qop=\"auth\""),
                ];

                let message = request.message();
                let mut message_guard = message.lock().map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
                })?;

                // Store the challenge headers so the response builder can pick them up.
                for value in &header_values {
                    message_guard.headers.add(header_name, value.clone());
                }

                Ok(false)
            }
        }
    }

    /// Send a 401 challenge with AKA nonce (locally computed via Milenage).
    fn send_aka_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        k: &[u8; 16],
        op: &[u8; 16],
        sqn: &[u8; 6],
        amf: &[u8; 2],
    ) -> PyResult<()> {
        use crate::ipsec::milenage;

        let vector = milenage::generate_vector(k, op, sqn, amf);

        // AKA nonce = base64(RAND || AUTN) per 3GPP TS 33.203
        let mut nonce_bytes = Vec::with_capacity(32);
        nonce_bytes.extend_from_slice(&vector.rand);
        nonce_bytes.extend_from_slice(&vector.autn);
        let nonce = base64_encode(&nonce_bytes);

        request.set_reply(401, "Unauthorized".to_string());

        let header_value = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );

        let message = request.message();
        let mut message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message_guard.headers.set("WWW-Authenticate", header_value);
        Ok(())
    }

    /// Extract auth vector from MAA AVPs, store XRES for later verification,
    /// and send 401 challenge.  Returns `Ok(false)` (challenge sent, not yet verified).
    fn send_ims_challenge_from_maa(
        &self,
        request: &mut PyRequest,
        realm: &str,
        maa_avps: &serde_json::Value,
    ) -> PyResult<bool> {
        use crate::diameter::codec;
        use crate::diameter::dictionary::avp;

        let auth_data = codec::extract_grouped_avp(maa_avps, avp::SIP_AUTH_DATA_ITEM);
        let hss_nonce = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::SIP_AUTHENTICATE));
        let hss_expected = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::SIP_AUTHORIZATION));
        let hss_ck = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::CONFIDENTIALITY_KEY));
        let hss_ik = auth_data.as_ref()
            .and_then(|a| codec::extract_octet_avp(a, avp::INTEGRITY_KEY));

        // Store the expected response (XRES) keyed by nonce so that the second
        // REGISTER can verify without sending another MAR.
        if let (Some(nonce_bytes), Some(expected_bytes)) = (&hss_nonce, &hss_expected) {
            let nonce_str = base64_encode(nonce_bytes);
            tracing::debug!(
                nonce_prefix = &nonce_str[..nonce_str.len().min(16)],
                xres_len = expected_bytes.len(),
                "IMS auth: stored pending challenge",
            );
            ims_auth_store().insert(nonce_str, ImsAuthVector {
                expected_response: expected_bytes.clone(),
                ck: hss_ck.clone(),
                ik: hss_ik.clone(),
            });
        }

        self.send_ims_challenge(
            request, realm, hss_nonce.as_deref(),
            hss_ck.as_deref(), hss_ik.as_deref(),
        )?;
        Ok(false)
    }

    /// Send a 401 challenge using the HSS-provided nonce (or a generated one).
    fn send_ims_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        hss_nonce: Option<&[u8]>,
        ck: Option<&[u8]>,
        ik: Option<&[u8]>,
    ) -> PyResult<()> {
        request.set_reply(401, "Unauthorized".to_string());


        let nonce = match hss_nonce {
            Some(bytes) => base64_encode(bytes),
            None => generate_nonce(),
        };
        // Per TS 33.203 §6.3, include CK and IK from the HSS MAA so the
        // P-CSCF can extract them for IPsec SA setup with the UE.
        let mut header_value = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );
        if let Some(ck_bytes) = ck {
            header_value.push_str(&format!(
                ", ck=\"{}\"",
                crate::diameter::codec::hex::encode(ck_bytes)
            ));
        }
        if let Some(ik_bytes) = ik {
            header_value.push_str(&format!(
                ", ik=\"{}\"",
                crate::diameter::codec::hex::encode(ik_bytes)
            ));
        }

        let message = request.message();
        let mut message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message_guard.headers.set("WWW-Authenticate", header_value);
        Ok(())
    }

    /// Validate credentials by dispatching to the configured backend.
    fn validate_credentials(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        match self.backend_type {
            AuthBackendType::Static => self.validate_static(auth_value, realm, method),
            AuthBackendType::Http => self.validate_http(auth_value, realm, method),
            _ => {
                warn!(backend = ?self.backend_type, "unsupported auth backend");
                false
            }
        }
    }

    /// Static backend: look up plaintext password from config, compute digest.
    fn validate_static(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        let fields = match DigestFields::parse(auth_value) {
            Some(f) => f,
            None => return false,
        };

        // Find the password across all configured realms
        let password = self
            .static_users
            .values()
            .find_map(|realm_users| realm_users.get(&fields.username));

        let password = match password {
            Some(p) => p,
            None => return false,
        };

        // Compute HA1 from username:realm:password using the SAME algorithm
        // the client used in its Authorization header — RFC 7616 §3.4.3
        // requires HA1 / HA2 / response to all use the same hash function.
        let ha1 = crate::auth::hash_hex_public(
            fields.algorithm,
            format!("{}:{}:{}", fields.username, realm, password).as_bytes(),
        );
        fields.verify(&ha1, method)
    }

    /// HTTP backend: fetch HA1 (or password) from REST endpoint, then verify digest.
    fn validate_http(&self, auth_value: &str, realm: &str, method: &str) -> bool {
        let fields = match DigestFields::parse(auth_value) {
            Some(f) => f,
            None => return false,
        };

        let (http_config, client) = match (&self.http_config, &self.http_client) {
            (Some(c), Some(cl)) => (c, cl),
            _ => {
                warn!("auth backend is http but no http config set");
                return false;
            }
        };

        // Serve from the TTL cache when possible — this is what keeps a
        // registration storm for the same subscribers from translating 1:1 into
        // blocking HTTP fetches that each pin a Python-executor worker.
        let body = match self.cached_credential(&fields.username, http_config.cache_ttl_secs) {
            Some(cached) => {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.auth_ha1_cache_hits_total.inc();
                }
                debug!(username = %fields.username, "HTTP auth: HA1 cache hit");
                cached
            }
            None => {
                let fetched = match self.fetch_http_credential(http_config, client, &fields.username)
                {
                    Some(body) => body,
                    None => return false,
                };
                self.store_credential(&fields.username, &fetched);
                fetched
            }
        };

        let ha1 = if http_config.ha1 {
            // Response body is already the HA1 hex string. NOTE: this only
            // works when the stored HA1 was computed with the same algorithm
            // the client advertised. For SHA-256 / SHA-512-256 deployments
            // the HA1 backend MUST store a per-algorithm HA1 (e.g. by
            // namespacing the URL or returning a JSON object) — we currently
            // assume the operator has matched algorithms.
            body
        } else {
            // Plaintext password — hash with the algorithm the client used.
            crate::auth::hash_hex_public(
                fields.algorithm,
                format!("{}:{}:{}", fields.username, realm, body).as_bytes(),
            )
        };

        let valid = fields.verify(&ha1, method);
        debug!(username = %fields.username, valid, "HTTP auth digest verification");
        valid
    }

    /// Return a cached credential body for `username` if caching is enabled and
    /// the entry is still within `ttl_secs`. Expired entries miss (and are left
    /// for the next fetch to overwrite).
    fn cached_credential(&self, username: &str, ttl_secs: u64) -> Option<String> {
        if ttl_secs == 0 {
            return None;
        }
        let cache = self.http_ha1_cache.as_ref()?;
        let entry = cache.get(username)?;
        if is_cache_fresh(
            entry.fetched_at.elapsed(),
            std::time::Duration::from_secs(ttl_secs),
        ) {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    /// Store a successful credential lookup in the TTL cache. No-op when caching
    /// is disabled.
    fn store_credential(&self, username: &str, value: &str) {
        if let Some(cache) = self.http_ha1_cache.as_ref() {
            cache.insert(
                username.to_string(),
                CachedHa1 {
                    value: value.to_string(),
                    fetched_at: std::time::Instant::now(),
                },
            );
        }
    }

    /// Blocking HTTP fetch of the credential body for `username`. Returns `None`
    /// on any failure (request error, non-success status, body read error) — the
    /// caller then rejects the digest without caching anything.
    fn fetch_http_credential(
        &self,
        http_config: &HttpAuthConfig,
        client: &reqwest::Client,
        username: &str,
    ) -> Option<String> {
        let url = http_config.url.replace("{username}", username);
        debug!(url = %url, username = %username, "HTTP auth lookup");

        // Release the interpreter for the whole blocking HTTP exchange — see
        // `crate::script::detach_block_on` for why this is mandatory on
        // free-threaded CPython (blocking while attached stalls the GC
        // stop-the-world and wedges the engine).
        let outcome: Result<Option<String>, reqwest::Error> =
            crate::script::detach_block_on(async {
                let response = client.get(&url).send().await?;
                if !response.status().is_success() {
                    // user not found / backend rejected — not an error
                    return Ok(None);
                }
                let body = response.text().await?;
                Ok(Some(body.trim().to_string()))
            });

        match outcome {
            Ok(Some(body)) => Some(body),
            Ok(None) => {
                debug!(username = %username, "HTTP auth: user not found (non-success status)");
                None
            }
            Err(error) => {
                warn!(error = %error, url = %url, "HTTP auth request/read failed");
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 2617 digest validation helpers
// ---------------------------------------------------------------------------

/// Parsed fields from a Digest Authorization header.
struct DigestFields {
    username: String,
    #[allow(dead_code)]
    realm: String,
    nonce: String,
    uri: String,
    response: String,
    qop: Option<String>,
    cnonce: Option<String>,
    nc: Option<String>,
    /// Algorithm advertised by the client. Defaults to MD5 if absent
    /// (RFC 2617 / RFC 7616 §3.4 — algorithm is OPTIONAL on the request).
    algorithm: crate::auth::DigestAlgorithm,
}

impl DigestFields {
    /// Parse all relevant fields from a Digest Authorization header value.
    fn parse(auth_value: &str) -> Option<Self> {
        let algorithm_str = extract_digest_param(auth_value, "algorithm");
        let algorithm = parse_algorithm(algorithm_str.as_deref());
        Some(Self {
            username: extract_username(auth_value)?,
            realm: extract_digest_param(auth_value, "realm")?,
            nonce: extract_nonce_field(auth_value)?,
            uri: extract_digest_param(auth_value, "uri")?,
            response: extract_response_field(auth_value)?,
            qop: extract_digest_param(auth_value, "qop"),
            cnonce: extract_digest_param(auth_value, "cnonce"),
            nc: extract_digest_param(auth_value, "nc"),
            algorithm,
        })
    }

    /// Verify the digest response against a known HA1.
    ///
    /// The HA1 passed in MUST be computed with the same algorithm as
    /// `self.algorithm`, since both `H(method:uri)` for HA2 and the final
    /// response composition use the same hash function (RFC 7616 §3.4.3).
    fn verify(&self, ha1: &str, method: &str) -> bool {
        let alg = self.algorithm;
        let ha2 = crate::auth::hash_hex_public(alg, format!("{}:{}", method, self.uri).as_bytes());

        let expected = if self.qop.as_deref() == Some("auth") {
            let nc = self.nc.as_deref().unwrap_or("00000001");
            let cnonce = self.cnonce.as_deref().unwrap_or("");
            crate::auth::hash_hex_public(
                alg,
                format!("{}:{}:{}:{}:auth:{}", ha1, self.nonce, nc, cnonce, ha2).as_bytes(),
            )
        } else {
            crate::auth::hash_hex_public(
                alg,
                format!("{}:{}:{}", ha1, self.nonce, ha2).as_bytes(),
            )
        };

        expected.eq_ignore_ascii_case(&self.response)
    }
}

/// Parse the `algorithm=` value from an Authorization header into a
/// `DigestAlgorithm`. Falls back to MD5 (RFC 2617's default) when the
/// parameter is missing or unrecognised — that's the safest choice for
/// the server side because we'd rather verify with the wrong algorithm
/// (and reject) than panic.
fn parse_algorithm(value: Option<&str>) -> crate::auth::DigestAlgorithm {
    use crate::auth::DigestAlgorithm;
    let Some(raw) = value else { return DigestAlgorithm::Md5 };
    match raw.to_uppercase().replace('_', "-").as_str() {
        "MD5" | "" => DigestAlgorithm::Md5,
        "MD5-SESS" => DigestAlgorithm::Md5Sess,
        "SHA-256" | "SHA256" => DigestAlgorithm::Sha256,
        "SHA-256-SESS" | "SHA256-SESS" => DigestAlgorithm::Sha256Sess,
        "SHA-512-256" | "SHA512-256" => DigestAlgorithm::Sha512_256,
        "SHA-512-256-SESS" | "SHA512-256-SESS" => DigestAlgorithm::Sha512_256Sess,
        _ => DigestAlgorithm::Md5,
    }
}

/// Compute MD5 hex digest of a string.
fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// Compute HA1 = MD5(username:realm:password) where password is raw bytes.
///
/// Per RFC 3310 §3.3, for AKAv1-MD5 the RES/XRES bytes are used directly
/// as the "password" — not hex-encoded, not base64-encoded.  The MD5 input
/// is: `username` `:` `realm` `:` `<raw bytes>`.
fn md5_ha1_aka(username: &str, realm: &str, password_bytes: &[u8]) -> String {
    let mut ctx = md5::Context::new();
    ctx.consume(username.as_bytes());
    ctx.consume(b":");
    ctx.consume(realm.as_bytes());
    ctx.consume(b":");
    ctx.consume(password_bytes);
    format!("{:x}", ctx.compute())
}

/// Extract a named parameter from a Digest header value.
/// Handles both quoted and unquoted values.
fn extract_digest_param(auth_value: &str, param: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let needle = format!("{}=", param);
    let pos = auth_lower.find(&needle)?;

    // Make sure it's not a substring of a longer param name
    // (e.g. "cnonce" when looking for "nonce" — handled by extract_nonce_field)
    if pos > 0 && auth_lower.as_bytes()[pos - 1].is_ascii_alphanumeric() {
        // Try finding next occurrence
        let mut search_start = pos + needle.len();
        loop {
            let next_pos = auth_lower[search_start..].find(&needle)?;
            let abs_pos = search_start + next_pos;
            if abs_pos == 0 || !auth_lower.as_bytes()[abs_pos - 1].is_ascii_alphanumeric() {
                let rest = &auth_value[abs_pos + needle.len()..];
                return parse_param_value(rest);
            }
            search_start = abs_pos + needle.len();
        }
    }

    let rest = &auth_value[pos + needle.len()..];
    parse_param_value(rest)
}

/// Parse a parameter value (quoted or unquoted) from the remaining string.
fn parse_param_value(rest: &str) -> Option<String> {
    if let Some(after) = rest.strip_prefix('"') {
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Extract the `response` field from a Digest Authorization header value.
fn extract_response_field(auth_value: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let pos = auth_lower.find("response=")?;
    let rest = &auth_value[pos + 9..];

    if let Some(after) = rest.strip_prefix('"') {
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Extract the `username` field from a Digest Authorization header value.
///
/// Example input: `Digest username="alice", realm="example.com", nonce="..."`
fn extract_username(auth_value: &str) -> Option<String> {
    // Find username="value" in the Authorization header
    let auth_lower = auth_value.to_lowercase();
    let username_pos = auth_lower.find("username=")?;
    let rest = &auth_value[username_pos + 9..]; // skip "username="

    if let Some(after) = rest.strip_prefix('"') {
        // Quoted value
        let end = after.find('"')?;
        Some(after[..end].to_string())
    } else {
        // Unquoted value — take until comma or end
        let end = rest.find(',').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Generate a nonce for digest authentication challenges.
fn generate_nonce() -> String {
    format!("{:x}", uuid::Uuid::new_v4().as_simple())
}

/// Extract the user part from a SIP From/To header value.
/// e.g. `<sip:alice@example.com>;tag=foo` -> `Some("alice")`
/// Extract a clean SIP URI from a header value (From, P-Asserted-Identity).
///
/// Strips angle brackets, display name, and header-level parameters like `;tag=`.
/// Returns a bare SIP URI suitable for Diameter AVPs (TS 29.228 §6.3.2).
///
/// Examples:
///   `<sip:alice@example.com>;tag=abc`  → `sip:alice@example.com`
///   `"Alice" <sip:alice@example.com>`  → `sip:alice@example.com`
///   `sip:alice@example.com`            → `sip:alice@example.com`
fn extract_sip_uri(header_value: &str) -> String {
    if let Some(start) = header_value.find('<') {
        if let Some(end) = header_value[start..].find('>') {
            return header_value[start + 1..start + end].to_string();
        }
    }
    // No angle brackets — strip ;tag= and other header-level params
    header_value.split(';').next().unwrap_or(header_value).trim().to_string()
}

fn extract_username_from_uri(header_value: &str) -> Option<String> {
    // Find the URI between < > or parse bare URI
    let uri_str = if let Some(start) = header_value.find('<') {
        let end = header_value[start..].find('>')?;
        &header_value[start + 1..start + end]
    } else {
        header_value.split(';').next()?
    };

    // Strip "sip:" or "sips:" prefix
    let after_scheme = uri_str.strip_prefix("sip:")
        .or_else(|| uri_str.strip_prefix("sips:"))?;

    // Get user part (before @)
    after_scheme.split('@').next().map(|s| s.to_string())
}

/// Extract the `nonce` field from a Digest Authorization header value.
/// Must not match `cnonce=` — look for `nonce=` preceded by a non-alpha char or start of string.
fn extract_nonce_field(auth_value: &str) -> Option<String> {
    let auth_lower = auth_value.to_lowercase();
    let mut search_start = 0;
    loop {
        let pos = auth_lower[search_start..].find("nonce=")?;
        let abs_pos = search_start + pos;
        // Make sure this isn't "cnonce=" — check preceding char
        if abs_pos == 0 || !auth_lower.as_bytes()[abs_pos - 1].is_ascii_alphanumeric() {
            let rest = &auth_value[abs_pos + 6..];
            if let Some(after) = rest.strip_prefix('"') {
                let end = after.find('"')?;
                return Some(after[..end].to_string());
            } else {
                let end = rest.find(',').unwrap_or(rest.len());
                return Some(rest[..end].trim().to_string());
            }
        }
        search_start = abs_pos + 6;
    }
}

/// Base64-encode bytes (no padding, URL-safe not needed for SIP nonces).
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Base64-decode a string.
pub(crate) fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn decode_char(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0),
            _ => None,
        }
    }

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut result = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0])?;
        let b = decode_char(chunk[1])?;
        let c = decode_char(chunk[2])?;
        let d = decode_char(chunk[3])?;
        let triple = ((a as u32) << 18) | ((b as u32) << 12) | ((c as u32) << 6) | (d as u32);
        result.push((triple >> 16) as u8);
        if chunk[2] != b'=' {
            result.push((triple >> 8) as u8);
        }
        if chunk[3] != b'=' {
            result.push(triple as u8);
        }
    }
    Some(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::api::request::RequestAction;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;
    use std::sync::Mutex;

    fn make_auth() -> PyAuth {
        let mut realm_users = HashMap::new();
        realm_users.insert("alice".to_string(), "pass123".to_string());
        realm_users.insert("bob".to_string(), "secret".to_string());

        let mut users = HashMap::new();
        users.insert("example.com".to_string(), realm_users);

        PyAuth::new(users, "example.com".to_string())
    }

    fn make_register_request() -> PyRequest {
        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-auth".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=auth-tag".to_string())
            .call_id("auth-call@host".to_string())
            .cseq("1 REGISTER".to_string())
            .content_length(0)
            .build()
            .unwrap();

        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    fn make_request_with_auth(username: &str) -> PyRequest {
        // Compute a valid RFC 2617 digest response for the test credentials.
        // alice:pass123, bob:secret — realm=example.com, nonce=abc, method=REGISTER
        let password = match username {
            "alice" => "pass123",
            "bob" => "secret",
            _ => "wrong",
        };
        let realm = "example.com";
        let nonce = "abc";
        let digest_uri = "sip:example.com";
        let ha1 = md5_hex(&format!("{}:{}:{}", username, realm, password));
        let ha2 = md5_hex(&format!("REGISTER:{}", digest_uri));
        let response = md5_hex(&format!("{}:{}:{}", ha1, nonce, ha2));

        let uri = SipUri::new("example.com".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-auth2".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=auth-tag2".to_string())
            .call_id("auth-call2@host".to_string())
            .cseq("2 REGISTER".to_string())
            .header(
                "Authorization",
                format!(
                    "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{digest_uri}\", response=\"{response}\""
                ),
            )
            .content_length(0)
            .build()
            .unwrap();

        PyRequest::new(
            Arc::new(Mutex::new(message)),
            "udp".to_string(),
            "10.0.0.1".to_string(),
            5060,
        )
    }

    #[test]
    fn require_www_digest_sends_401_when_no_credentials() {
        let auth = make_auth();
        let mut request = make_register_request();

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 401,
                reason: "Unauthorized".to_string(),
                reliable: false,
            }
        );
    }

    #[test]
    fn require_proxy_digest_sends_407() {
        let auth = make_auth();
        let mut request = make_register_request();

        let result = auth.require_proxy_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 407,
                reason: "Proxy Authentication Required".to_string(),
                reliable: false,
            }
        );
    }

    #[test]
    fn require_www_digest_accepts_valid_user() {
        let auth = make_auth();
        let mut request = make_request_with_auth("alice");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(result);
        assert_eq!(request.get_auth_user(), Some("alice"));
        // Action should remain None (no reply sent)
        assert_eq!(*request.action(), RequestAction::None);
    }

    #[test]
    fn require_digest_strips_auth_headers_after_success() {
        let auth = make_auth();
        let mut request = make_request_with_auth("alice");

        // Verify the Authorization header exists before auth
        {
            let msg = request.message();
            let guard = msg.lock().unwrap();
            assert!(guard.headers.get("Authorization").is_some());
        }

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(result);

        // After successful auth, Authorization must be stripped
        let msg = request.message();
        let guard = msg.lock().unwrap();
        assert!(guard.headers.get("Authorization").is_none(),
            "Authorization header should be stripped after successful verification");
        assert!(guard.headers.get("Proxy-Authorization").is_none(),
            "Proxy-Authorization header should be stripped after successful verification");
    }

    #[test]
    fn require_digest_does_not_strip_headers_on_failure() {
        let auth = make_auth();
        let mut request = make_request_with_auth("eve"); // unknown user

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);

        // On failure, the original request headers are not stripped (challenge is sent instead)
        // The WWW-Authenticate header should be set for the challenge
        let msg = request.message();
        let guard = msg.lock().unwrap();
        assert!(guard.headers.get("WWW-Authenticate").is_some());
    }

    #[test]
    fn require_www_digest_rejects_unknown_user() {
        let auth = make_auth();
        let mut request = make_request_with_auth("eve");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
        assert_eq!(
            *request.action(),
            RequestAction::Reply {
                code: 401,
                reason: "Unauthorized".to_string(),
                reliable: false,
            }
        );
    }

    #[test]
    fn verify_digest_without_sending_challenge() {
        let auth = make_auth();
        let request_no_auth = make_register_request();
        assert!(!auth.verify_digest(&request_no_auth, None).unwrap());

        let request_with_auth = make_request_with_auth("alice");
        assert!(auth.verify_digest(&request_with_auth, None).unwrap());
    }

    #[test]
    fn extract_username_from_digest_header() {
        let value = r#"Digest username="alice", realm="example.com", nonce="abc""#;
        assert_eq!(extract_username(value), Some("alice".to_string()));
    }

    #[test]
    fn extract_username_case_insensitive_key() {
        let value = r#"Digest Username="bob", realm="example.com""#;
        assert_eq!(extract_username(value), Some("bob".to_string()));
    }

    #[test]
    fn extract_username_none_when_missing() {
        let value = "Digest realm=\"example.com\"";
        assert_eq!(extract_username(value), None);
    }

    #[test]
    fn challenge_includes_nonce_in_header() {
        let auth = make_auth();
        let mut request = make_register_request();

        auth.require_www_digest(&mut request, None).unwrap();

        // The WWW-Authenticate header should be set on the message
        let message = request.message();
        let message = message.lock().unwrap();
        let www_auth = message.headers.get("WWW-Authenticate").unwrap();
        assert!(www_auth.contains("Digest"));
        assert!(www_auth.contains("realm=\"example.com\""));
        assert!(www_auth.contains("nonce="));
        assert!(www_auth.contains("algorithm=MD5"));
    }

    #[test]
    fn custom_realm_overrides_default() {
        let auth = make_auth();
        let mut request = make_register_request();

        auth.require_www_digest(&mut request, Some("custom.realm")).unwrap();

        let message = request.message();
        let message = message.lock().unwrap();
        let www_auth = message.headers.get("WWW-Authenticate").unwrap();
        assert!(www_auth.contains("realm=\"custom.realm\""));
    }

    #[test]
    fn empty_auth_rejects_all() {
        let auth = PyAuth::empty();
        let mut request = make_request_with_auth("alice");

        let result = auth.require_www_digest(&mut request, None).unwrap();
        assert!(!result);
    }

    #[test]
    fn extract_sip_uri_strips_angle_brackets_and_tag() {
        assert_eq!(
            extract_sip_uri("<sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org>;tag=yfJqzFRBS1"),
            "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
        );
    }

    #[test]
    fn extract_sip_uri_strips_display_name() {
        assert_eq!(
            extract_sip_uri("\"Alice\" <sip:alice@example.com>"),
            "sip:alice@example.com"
        );
    }

    #[test]
    fn extract_sip_uri_bare_uri_unchanged() {
        assert_eq!(
            extract_sip_uri("sip:bob@example.com"),
            "sip:bob@example.com"
        );
    }

    #[test]
    fn extract_sip_uri_bare_uri_strips_tag() {
        assert_eq!(
            extract_sip_uri("sip:bob@example.com;tag=abc123"),
            "sip:bob@example.com"
        );
    }

    #[test]
    fn extract_username_from_uri_basic() {
        assert_eq!(
            extract_username_from_uri("<sip:alice@example.com>;tag=foo"),
            Some("alice".to_string())
        );
        assert_eq!(
            extract_username_from_uri("<sip:001010000000001@ims.test>"),
            Some("001010000000001".to_string())
        );
        assert_eq!(
            extract_username_from_uri("sip:bob@example.com"),
            Some("bob".to_string())
        );
    }

    #[test]
    fn extract_nonce_field_quoted() {
        let value = r#"Digest username="alice", realm="test", nonce="abc123def""#;
        assert_eq!(extract_nonce_field(value), Some("abc123def".to_string()));
    }

    #[test]
    fn extract_nonce_field_unquoted() {
        let value = "Digest nonce=abc123, realm=\"test\"";
        assert_eq!(extract_nonce_field(value), Some("abc123".to_string()));
    }

    #[test]
    fn extract_nonce_field_skips_cnonce() {
        // Must extract nonce, not cnonce
        let value = r#"Digest username="alice",realm="test",cnonce="1d15e5dd",nc=00000001,qop=auth,uri="sip:test",nonce="realNonce123=",response="abc",algorithm=AKAv1-MD5"#;
        assert_eq!(extract_nonce_field(value), Some("realNonce123=".to_string()));
    }

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_encode_32_bytes() {
        // 32 bytes (like RAND || AUTN) should produce 44 chars with padding
        let data = [0u8; 32];
        let encoded = base64_encode(&data);
        assert_eq!(encoded.len(), 44);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn ims_auth_store_insert_lookup_consume() {
        let store = ims_auth_store();
        let nonce = "test-ims-nonce-123".to_string();

        store.insert(nonce.clone(), ImsAuthVector {
            expected_response: vec![0xAA; 16],
            ck: Some(vec![0xBB; 16]),
            ik: Some(vec![0xCC; 16]),
        });

        // Verify it exists
        assert!(store.get(&nonce).is_some());

        // Remove consumes it (simulating verification lookup)
        let removed = store.remove(&nonce);
        assert!(removed.is_some());
        let (_, vector) = removed.unwrap();
        assert_eq!(vector.expected_response, vec![0xAA; 16]);
        assert_eq!(vector.ck.unwrap(), vec![0xBB; 16]);

        // Gone after consumption — prevents replay
        assert!(store.get(&nonce).is_none());
    }

    #[test]
    fn extract_auts_from_authorization_header() {
        let auth = concat!(
            r#"Digest username="001010000000001","#,
            r#"realm="ims.example.com","#,
            r#"nonce="EjRW+jgAAAAJAAABgAAAAICAAIAA","#,
            r#"uri="sip:ims.example.com","#,
            r#"algorithm=AKAv1-MD5,"#,
            r#"response="abc123def456abc123def456abc123de","#,
            r#"auts="AAECAwQFBgcICQoLDA0=""#,
        );
        let auts = extract_digest_param(auth, "auts");
        assert_eq!(auts.as_deref(), Some("AAECAwQFBgcICQoLDA0="));

        // Decode and verify length: AUTS is 14 bytes
        let auts_bytes = base64_decode(&auts.unwrap()).unwrap();
        assert_eq!(auts_bytes.len(), 14);
    }

    #[test]
    fn auts_resync_data_concatenation() {
        // Simulate RAND(16) from nonce and AUTS(14) from Authorization header
        let rand: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let auts: [u8; 14] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        ];

        let mut resync_data = Vec::with_capacity(30);
        resync_data.extend_from_slice(&rand);
        resync_data.extend_from_slice(&auts);

        assert_eq!(resync_data.len(), 30);
        assert_eq!(&resync_data[..16], &rand);
        assert_eq!(&resync_data[16..], &auts);
    }

    #[test]
    fn extract_auts_missing_returns_none() {
        let auth = r#"Digest username="alice",realm="test",nonce="abc",response="def""#;
        assert!(extract_digest_param(auth, "auts").is_none());
    }

    fn http_auth_with_cache(cache_ttl_secs: u64) -> PyAuth {
        let mut auth = PyAuth::empty();
        auth.set_backend_type(AuthBackendType::Http);
        auth.set_http_config(HttpAuthConfig {
            url: "http://127.0.0.1:9/sip/auth/{username}".to_string(),
            timeout_ms: 100,
            connect_timeout_ms: 100,
            ha1: true,
            cache_ttl_secs,
        })
        .unwrap();
        auth
    }

    #[test]
    fn cache_freshness_boundary() {
        use std::time::Duration;
        assert!(is_cache_fresh(Duration::from_secs(0), Duration::from_secs(300)));
        assert!(is_cache_fresh(Duration::from_secs(299), Duration::from_secs(300)));
        // At and beyond the TTL the entry is stale.
        assert!(!is_cache_fresh(Duration::from_secs(300), Duration::from_secs(300)));
        assert!(!is_cache_fresh(Duration::from_secs(400), Duration::from_secs(300)));
    }

    #[test]
    fn ha1_cache_miss_then_store_then_hit() {
        let auth = http_auth_with_cache(300);

        // Cold: nothing stored yet.
        assert!(auth.cached_credential("alice", 300).is_none());

        // After a successful lookup is stored, it hits within the TTL.
        auth.store_credential("alice", "deadbeefcafe");
        assert_eq!(
            auth.cached_credential("alice", 300).as_deref(),
            Some("deadbeefcafe")
        );

        // A ttl of 0 always misses (caching disabled for this call).
        assert!(auth.cached_credential("alice", 0).is_none());
    }

    #[test]
    fn ha1_cache_not_allocated_when_ttl_zero() {
        let auth = http_auth_with_cache(0);
        assert!(
            auth.http_ha1_cache.is_none(),
            "no cache map should be allocated when cache_ttl_secs is 0"
        );
        // store_credential is a no-op and lookups always miss.
        auth.store_credential("alice", "x");
        assert!(auth.cached_credential("alice", 300).is_none());
    }
}
