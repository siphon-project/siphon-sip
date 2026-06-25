//! Client-side SIP digest authentication (RFC 2617 / RFC 7616).
//!
//! This module handles the *client* side of digest auth — computing
//! Authorization/Proxy-Authorization responses when SIPhon receives
//! a 401/407 challenge on outbound requests (REGISTER, INVITE, etc.).
//!
//! The *server* side (challenging incoming requests) lives in
//! `crate::script::api::auth`.

use std::fmt;
use std::sync::Mutex;

/// Parsed WWW-Authenticate or Proxy-Authenticate challenge.
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub algorithm: DigestAlgorithm,
    pub stale: bool,
}

/// Supported digest algorithms.
///
/// MD5 and MD5-sess are defined by RFC 2617. SHA-256, SHA-256-sess,
/// SHA-512-256, and SHA-512-256-sess are added by RFC 7616. The `-sess`
/// variants derive a per-session HA1 by re-hashing the credential hash with
/// the server nonce and a client cnonce, so even if the password hash leaks
/// it can't be replayed across sessions (RFC 7616 §3.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
    Sha512_256,
    Sha512_256Sess,
    /// IMS AKAv1-MD5 (RFC 3310 / 3GPP TS 33.203). The underlying hash is MD5;
    /// the difference is that the digest "password" is the binary AKA RES
    /// (computed via Milenage from the RAND/AUTN carried base64 in `nonce`),
    /// not a stored secret. See [`compute_aka_response`].
    AkaV1Md5,
}

impl DigestAlgorithm {
    /// Whether this is a session-variant algorithm (`-sess` suffix).
    ///
    /// Session variants compute HA1 as `H(H(user:realm:pass):nonce:cnonce)`
    /// instead of just `H(user:realm:pass)` — this re-hashing requires a
    /// cnonce on the first request, so callers must supply one for `-sess`.
    pub fn is_session(self) -> bool {
        matches!(
            self,
            DigestAlgorithm::Md5Sess
                | DigestAlgorithm::Sha256Sess
                | DigestAlgorithm::Sha512_256Sess
        )
    }

    /// Algorithm-preference order for negotiation: when the server sends
    /// multiple challenges, clients SHOULD pick the strongest they support
    /// (RFC 7616 §3.7). Higher strength = larger number.
    pub fn strength(self) -> u8 {
        match self {
            // AKAv1-MD5 is network-selected (the IMS offers it alone for AKA),
            // so it never competes in strength-based negotiation; rank it with
            // its underlying MD5 hash.
            DigestAlgorithm::AkaV1Md5 => 1,
            DigestAlgorithm::Md5 => 1,
            DigestAlgorithm::Md5Sess => 2,
            DigestAlgorithm::Sha256 => 3,
            DigestAlgorithm::Sha256Sess => 4,
            DigestAlgorithm::Sha512_256 => 5,
            DigestAlgorithm::Sha512_256Sess => 6,
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DigestAlgorithm::Md5 => write!(formatter, "MD5"),
            DigestAlgorithm::Md5Sess => write!(formatter, "MD5-sess"),
            DigestAlgorithm::Sha256 => write!(formatter, "SHA-256"),
            DigestAlgorithm::Sha256Sess => write!(formatter, "SHA-256-sess"),
            DigestAlgorithm::Sha512_256 => write!(formatter, "SHA-512-256"),
            DigestAlgorithm::Sha512_256Sess => write!(formatter, "SHA-512-256-sess"),
            DigestAlgorithm::AkaV1Md5 => write!(formatter, "AKAv1-MD5"),
        }
    }
}

/// Credentials for digest authentication.
#[derive(Debug, Clone)]
pub struct DigestCredentials {
    pub username: String,
    pub password: String,
}

/// Tracks the nonce-count (`nc`) value for digest authentication.
///
/// Per RFC 7616 §3.3, `nc` MUST start at 1 for each fresh server nonce and
/// increment by 1 for every subsequent request that reuses the same nonce.
/// When the server returns a new nonce (e.g. after `stale=true`, or simply a
/// fresh challenge on a different transaction), `nc` resets to 1.
///
/// This tracker holds the most recent `(nonce, count)` pair so that
/// [`next_for`](Self::next_for) returns the correct value for the requested
/// nonce: 1 if the nonce is new (or unseen), or `count + 1` if it matches
/// the previously seen nonce.
#[derive(Debug, Default)]
pub struct NonceCounter {
    state: Mutex<Option<(String, u32)>>,
}

impl NonceCounter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Return the next `nc` value to use for `nonce`.
    ///
    /// Resets to 1 when `nonce` differs from the last-seen nonce (RFC 7616
    /// §3.3); otherwise increments and returns the new count.
    pub fn next_for(&self, nonce: &str) -> u32 {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some((last, count)) if last == nonce => {
                *count = count.saturating_add(1);
                *count
            }
            _ => {
                *guard = Some((nonce.to_string(), 1));
                1
            }
        }
    }

    /// Forget the last-seen nonce. The next call to [`Self::next_for`] will
    /// return 1 regardless of which nonce is passed.
    pub fn reset(&self) {
        if let Ok(mut guard) = self.state.lock() {
            *guard = None;
        }
    }
}

/// Parse a `WWW-Authenticate` or `Proxy-Authenticate` header value.
///
/// Expects format: `Digest realm="...", nonce="...", ...`
pub fn parse_challenge(header_value: &str) -> Option<DigestChallenge> {
    let body = header_value.strip_prefix("Digest")?.trim();

    let mut realm = None;
    let mut nonce = None;
    let mut opaque = None;
    let mut qop = None;
    let mut algorithm = DigestAlgorithm::Md5;
    let mut stale = false;

    for param in split_params(body) {
        let param = param.trim();
        if let Some((key, value)) = param.split_once('=') {
            let key = key.trim().to_lowercase();
            let value = unquote(value.trim());
            match key.as_str() {
                "realm" => realm = Some(value),
                "nonce" => nonce = Some(value),
                "opaque" => opaque = Some(value),
                "qop" => qop = Some(value),
                "algorithm" => {
                    // Algorithm name matching is case-insensitive per
                    // RFC 7616 §3.3; real-world deployments vary on
                    // hyphen vs underscore vs no separator for the
                    // SHA-* names.
                    let normalized = value.to_uppercase().replace('_', "-");
                    algorithm = match normalized.as_str() {
                        "MD5" | "" => DigestAlgorithm::Md5,
                        "MD5-SESS" => DigestAlgorithm::Md5Sess,
                        "SHA-256" | "SHA256" => DigestAlgorithm::Sha256,
                        "SHA-256-SESS" | "SHA256-SESS" => DigestAlgorithm::Sha256Sess,
                        "SHA-512-256" | "SHA512-256" => DigestAlgorithm::Sha512_256,
                        "SHA-512-256-SESS" | "SHA512-256-SESS" => {
                            DigestAlgorithm::Sha512_256Sess
                        }
                        "AKAV1-MD5" => DigestAlgorithm::AkaV1Md5,
                        _ => return None, // unsupported algorithm
                    };
                }
                "stale" => stale = value.eq_ignore_ascii_case("true"),
                _ => {} // ignore unknown params
            }
        }
    }

    Some(DigestChallenge {
        realm: realm?,
        nonce: nonce?,
        opaque,
        qop,
        algorithm,
        stale,
    })
}

/// Generate a cryptographically random client nonce (cnonce).
///
/// RFC 2617 §3.2.2 / RFC 7616 §3.4 use the cnonce to thwart chosen-plaintext
/// replay attacks: the server's nonce alone is chosen by the server, so the
/// client mixes in its own fresh random value. Returning a *predictable*
/// cnonce (for example a hardcoded `"0a1b2c3d"`) makes the response hash
/// replayable and silently defeats that protection — which is why we never
/// fall back to a static string.
///
/// 16 hex chars = 64 bits of entropy, which is well above the "sufficient"
/// guidance in RFC 7616 §5.5 and matches what most modern SIP stacks emit.
pub fn generate_cnonce() -> String {
    let u = uuid::Uuid::new_v4();
    // Take the first 8 bytes of the UUID v4 — `uuid` uses `getrandom`
    // under the hood so these bytes are drawn from the OS CSPRNG.
    let bytes = u.as_bytes();
    let mut output = String::with_capacity(16);
    for byte in &bytes[..8] {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Compute the digest response per RFC 2617 (MD5) or RFC 7616 (SHA-256,
/// SHA-512-256, and `-sess` variants).
///
/// The caller is responsible for passing a `cnonce` whenever the challenge
/// has `qop=auth` or uses a `-sess` algorithm — if omitted in those cases
/// a fresh random cnonce is generated, but callers that also build the
/// Authorization header separately must ensure the SAME value flows into
/// both places (see `format_authorization_header`, which handles this).
///
/// Returns the hex-encoded response hash.
pub fn compute_digest_response(
    challenge: &DigestChallenge,
    credentials: &DigestCredentials,
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let base_ha1 = hash_hex(
        challenge.algorithm,
        format!(
            "{}:{}:{}",
            credentials.username, challenge.realm, credentials.password
        )
        .as_bytes(),
    );
    digest_response_from_ha1(challenge, base_ha1, method, digest_uri, nonce_count, cnonce)
}

/// Compute an IMS AKAv1-MD5 digest response (RFC 3310 §3.3).
///
/// Identical to [`compute_digest_response`] except that the digest "password"
/// is the **binary** AKA RES (the UE's Milenage f2 output), not a stored text
/// secret. RES bytes are not valid UTF-8, so HA1 must hash the raw octets —
/// `H(username : realm : RES)` over bytes — which is why this can't go through
/// the `String`-password path. The RAND/AUTN that produced RES are carried
/// base64 in `challenge.nonce`, but the nonce is used *as-is* (the base64
/// string) in the digest, exactly like a normal nonce (RFC 3310 §3.2).
pub fn compute_aka_response(
    challenge: &DigestChallenge,
    username: &str,
    res: &[u8],
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let mut ha1_input = Vec::with_capacity(username.len() + challenge.realm.len() + res.len() + 2);
    ha1_input.extend_from_slice(username.as_bytes());
    ha1_input.push(b':');
    ha1_input.extend_from_slice(challenge.realm.as_bytes());
    ha1_input.push(b':');
    ha1_input.extend_from_slice(res);

    let base_ha1 = hash_hex(challenge.algorithm, &ha1_input);
    digest_response_from_ha1(challenge, base_ha1, method, digest_uri, nonce_count, cnonce)
}

/// Finish a digest computation given a base HA1 (the `H(user:realm:secret)`
/// hex string before any `-sess` re-hashing). Shared by the text-password
/// ([`compute_digest_response`]) and AKA-RES ([`compute_aka_response`]) paths.
fn digest_response_from_ha1(
    challenge: &DigestChallenge,
    base_ha1: String,
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let hash = challenge.algorithm;
    let mut ha1 = base_ha1;

    // RFC 7616 §3.4.2: -sess variants re-hash HA1 with nonce + cnonce so the
    // per-session key can't be replayed across sessions even if the raw
    // credential hash leaks. A cnonce is required on this path.
    let generated_cnonce;
    let cnonce_value: &str = if hash.is_session() || challenge.qop.is_some() {
        match cnonce {
            Some(value) => value,
            None => {
                generated_cnonce = generate_cnonce();
                &generated_cnonce
            }
        }
    } else {
        ""
    };

    if hash.is_session() {
        ha1 = hash_hex(
            hash,
            format!("{ha1}:{}:{cnonce_value}", challenge.nonce).as_bytes(),
        );
    }

    let ha2 = hash_hex(hash, format!("{method}:{digest_uri}").as_bytes());

    let has_qop_auth = challenge
        .qop
        .as_ref()
        .map(|qop| qop.split(',').any(|token| token.trim() == "auth"))
        .unwrap_or(false);

    if has_qop_auth {
        let nc = nonce_count.unwrap_or(1);
        let nc_str = format!("{nc:08x}");
        hash_hex(
            hash,
            format!(
                "{ha1}:{}:{nc_str}:{cnonce_value}:auth:{ha2}",
                challenge.nonce
            )
            .as_bytes(),
        )
    } else {
        hash_hex(hash, format!("{ha1}:{}:{ha2}", challenge.nonce).as_bytes())
    }
}

/// Build the complete `Authorization` or `Proxy-Authorization` header value.
///
/// If the caller does not supply a `cnonce` but the challenge requires one
/// (qop=auth or a `-sess` algorithm), a cryptographically random cnonce is
/// generated and used consistently for both the response hash and the
/// emitted `cnonce=` parameter in the header.
pub fn format_authorization_header(
    challenge: &DigestChallenge,
    credentials: &DigestCredentials,
    method: &str,
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
) -> String {
    let has_qop_auth = qop_has_auth(challenge);
    let mut owned_cnonce: Option<String> = None;
    let cnonce_ref = derive_cnonce(challenge, cnonce, has_qop_auth, &mut owned_cnonce);

    let response = compute_digest_response(
        challenge,
        credentials,
        method,
        digest_uri,
        nonce_count,
        cnonce_ref,
    );

    build_authorization_header(
        &credentials.username,
        challenge,
        digest_uri,
        &response,
        has_qop_auth,
        nonce_count,
        cnonce_ref,
        None,
    )
}

/// Build a complete IMS AKAv1-MD5 `Authorization` header (RFC 3310).
///
/// Like [`format_authorization_header`] but the response is computed from the
/// binary AKA RES via [`compute_aka_response`]. When `auts` is `Some` (a
/// base64-encoded re-synchronisation token), it is appended as the `auts=`
/// directive so the registrar of record re-bases its sequence counter
/// (RFC 3310 §3.4 / 3GPP TS 33.102 §6.3.3).
pub fn format_aka_authorization_header(
    challenge: &DigestChallenge,
    username: &str,
    res: &[u8],
    digest_uri: &str,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
    auts: Option<&str>,
) -> String {
    let has_qop_auth = qop_has_auth(challenge);
    let mut owned_cnonce: Option<String> = None;
    let cnonce_ref = derive_cnonce(challenge, cnonce, has_qop_auth, &mut owned_cnonce);

    let response = compute_aka_response(
        challenge,
        username,
        res,
        method_for(challenge),
        digest_uri,
        nonce_count,
        cnonce_ref,
    );

    build_authorization_header(
        username,
        challenge,
        digest_uri,
        &response,
        has_qop_auth,
        nonce_count,
        cnonce_ref,
        auts,
    )
}

/// AKA Authorization is only ever built for REGISTER in this codebase; keep the
/// method local so [`format_aka_authorization_header`] needs no method param.
fn method_for(_challenge: &DigestChallenge) -> &'static str {
    "REGISTER"
}

/// Whether the challenge advertises `qop=auth` (the only qop we implement).
fn qop_has_auth(challenge: &DigestChallenge) -> bool {
    challenge
        .qop
        .as_ref()
        .map(|qop| qop.split(',').any(|token| token.trim() == "auth"))
        .unwrap_or(false)
}

/// Derive the single cnonce value shared by the response hash and the emitted
/// `cnonce=` parameter. Without a shared value the two would each fall back to
/// their own fresh random string and the server's verification would fail.
/// `owned` provides storage for a generated cnonce that outlives the borrow.
fn derive_cnonce<'a>(
    challenge: &DigestChallenge,
    cnonce: Option<&'a str>,
    has_qop_auth: bool,
    owned: &'a mut Option<String>,
) -> Option<&'a str> {
    if cnonce.is_some() {
        cnonce
    } else if has_qop_auth || challenge.algorithm.is_session() {
        *owned = Some(generate_cnonce());
        owned.as_deref()
    } else {
        None
    }
}

/// Assemble the `Digest ...` Authorization header value from a precomputed
/// response. Shared by the text-password and AKA-RES paths.
fn build_authorization_header(
    username: &str,
    challenge: &DigestChallenge,
    digest_uri: &str,
    response: &str,
    has_qop_auth: bool,
    nonce_count: Option<u32>,
    cnonce: Option<&str>,
    auts: Option<&str>,
) -> String {
    let mut header = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", algorithm={}, response=\"{}\"",
        username, challenge.realm, challenge.nonce, digest_uri, challenge.algorithm, response
    );

    if has_qop_auth {
        let nc = nonce_count.unwrap_or(1);
        // cnonce is always Some when qop=auth because of derive_cnonce above.
        let cnonce_value = cnonce.unwrap_or("");
        header.push_str(&format!(
            ", qop=auth, nc={:08x}, cnonce=\"{cnonce_value}\"",
            nc
        ));
    }

    if let Some(opaque) = &challenge.opaque {
        header.push_str(&format!(", opaque=\"{opaque}\""));
    }

    if let Some(auts) = auts {
        header.push_str(&format!(", auts=\"{auts}\""));
    }

    header
}

/// Split comma-separated params, respecting quoted strings.
fn split_params(input: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;

    for (index, byte) in input.bytes().enumerate() {
        match byte {
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => {
                result.push(&input[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < input.len() {
        result.push(&input[start..]);
    }
    result
}

/// Remove surrounding double quotes if present.
fn unquote(value: &str) -> String {
    if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

/// Compute the configured digest hash of `input` and return lowercase hex.
///
/// Selects MD5, SHA-256, or SHA-512/256 based on `algorithm`. For the
/// `-sess` variants the underlying hash matches the non-sess counterpart
/// (the only difference is how HA1 is derived, handled above).
///
/// RFC 7616 §5 specifies SHA-512/256, meaning "SHA-512 with truncation to
/// 256 bits" — exactly what the `sha2::Sha512_256` type produces.
fn hash_hex(algorithm: DigestAlgorithm, input: &[u8]) -> String {
    use sha2::Digest;
    match algorithm {
        DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess | DigestAlgorithm::AkaV1Md5 => {
            let digest = md5::compute(input);
            format!("{digest:x}")
        }
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(input);
            hex_encode(&hasher.finalize())
        }
        DigestAlgorithm::Sha512_256 | DigestAlgorithm::Sha512_256Sess => {
            let mut hasher = sha2::Sha512_256::new();
            hasher.update(input);
            hex_encode(&hasher.finalize())
        }
    }
}

/// Public re-export of `hash_hex` for the server-side digest verifier
/// in `crate::script::api::auth`. Kept as a thin pub wrapper so the
/// internal `hash_hex` symbol stays available to inline tests without
/// pinning the rest of the crate to a `pub use` path.
pub fn hash_hex_public(algorithm: DigestAlgorithm, input: &[u8]) -> String {
    hash_hex(algorithm, input)
}

/// Lowercase hex encoding for hash output bytes (shared by SHA-256 and
/// SHA-512/256 paths; MD5 uses the `md5` crate's built-in `LowerHex`).
fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

/// Back-compat helper used by existing tests — forwards to `hash_hex` with
/// MD5. Kept so the RFC 2617 test vectors stay unchanged.
#[cfg(test)]
fn md5_hex(input: &str) -> String {
    hash_hex(DigestAlgorithm::Md5, input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_challenge() {
        let header = r#"Digest realm="biloxi.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", algorithm=MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "biloxi.com");
        assert_eq!(challenge.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5);
        assert!(challenge.opaque.is_none());
        assert!(challenge.qop.is_none());
        assert!(!challenge.stale);
    }

    #[test]
    fn parse_challenge_with_qop_and_opaque() {
        let header = r#"Digest realm="testrealm@host.com", qop="auth,auth-int", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "testrealm@host.com");
        assert_eq!(challenge.qop.as_deref(), Some("auth,auth-int"));
        assert_eq!(
            challenge.opaque.as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41")
        );
    }

    #[test]
    fn parse_challenge_with_stale() {
        let header = r#"Digest realm="example.com", nonce="abc123", stale=true"#;
        let challenge = parse_challenge(header).unwrap();
        assert!(challenge.stale);
    }

    #[test]
    fn parse_challenge_missing_realm_returns_none() {
        let header = r#"Digest nonce="abc123""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_missing_nonce_returns_none() {
        let header = r#"Digest realm="example.com""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_not_digest_returns_none() {
        let header = r#"Basic realm="example.com""#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_unsupported_algorithm_returns_none() {
        // SHA3-256 is not supported (RFC 7616 only specifies MD5, SHA-256,
        // SHA-512-256 and their -sess variants).
        let header = r#"Digest realm="example.com", nonce="abc", algorithm=SHA3-256"#;
        assert!(parse_challenge(header).is_none());
    }

    #[test]
    fn parse_challenge_sha256() {
        let header = r#"Digest realm="http-auth@example.org", nonce="abc", algorithm=SHA-256"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.algorithm, DigestAlgorithm::Sha256);
    }

    #[test]
    fn parse_challenge_sha512_256() {
        let header = r#"Digest realm="x", nonce="abc", algorithm=SHA-512-256"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.algorithm, DigestAlgorithm::Sha512_256);
    }

    #[test]
    fn parse_challenge_sha256_sess() {
        let header = r#"Digest realm="x", nonce="abc", algorithm=SHA-256-sess"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.algorithm, DigestAlgorithm::Sha256Sess);
        assert!(challenge.algorithm.is_session());
    }

    #[test]
    fn algorithm_strength_ordering() {
        assert!(DigestAlgorithm::Sha512_256.strength() > DigestAlgorithm::Sha256.strength());
        assert!(DigestAlgorithm::Sha256.strength() > DigestAlgorithm::Md5.strength());
    }

    /// RFC 7616 §3.9.1 — SHA-256 example (the "Circle of Life" password has
    /// a typographical difference between RFC 2617 and RFC 7616: capital "O"
    /// in 7616, lowercase in 2617's equivalent).
    ///
    /// Uses the exact username/realm/password and expected response hash
    /// from the spec's worked example.
    #[test]
    fn rfc7616_sha256_test_vector() {
        let challenge = DigestChallenge {
            realm: "http-auth@example.org".to_string(),
            nonce: "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v".to_string(),
            opaque: Some("FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "Mufasa".to_string(),
            password: "Circle of Life".to_string(),
        };

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "GET",
            "/dir/index.html",
            Some(1),
            Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"),
        );

        // RFC 7616 §3.9.1 expected response
        assert_eq!(
            response,
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
    }

    /// Sanity check the SHA-512/256 path with a known-good computation
    /// (no RFC 7616 worked example exists for this algorithm). Verifies
    /// the hash selection actually reaches the Sha512_256 code path by
    /// cross-checking HA1/HA2 manually.
    #[test]
    fn sha512_256_response_matches_manual_computation() {
        use sha2::Digest;
        let challenge = DigestChallenge {
            realm: "realm".to_string(),
            nonce: "nonce-value".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha512_256,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };

        let h = |input: &str| -> String {
            let mut hasher = sha2::Sha512_256::new();
            hasher.update(input.as_bytes());
            hex_encode(&hasher.finalize())
        };
        let ha1 = h("alice:realm:secret");
        let ha2 = h("REGISTER:sip:realm");
        let expected = h(&format!("{ha1}:nonce-value:00000001:abcd:auth:{ha2}"));

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:realm",
            Some(1),
            Some("abcd"),
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn sha256_sess_ha1_rehashing() {
        // -sess variants hash HA1 a second time with nonce + cnonce per
        // RFC 7616 §3.4.2. Verify the -sess response differs from plain
        // SHA-256 for the same inputs.
        let base = DigestChallenge {
            realm: "r".to_string(),
            nonce: "N".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };
        let sess = DigestChallenge {
            algorithm: DigestAlgorithm::Sha256Sess,
            ..base.clone()
        };
        let creds = DigestCredentials {
            username: "u".to_string(),
            password: "p".to_string(),
        };

        let plain = compute_digest_response(&base, &creds, "INVITE", "sip:x", Some(1), Some("c"));
        let sessed = compute_digest_response(&sess, &creds, "INVITE", "sip:x", Some(1), Some("c"));
        assert_ne!(plain, sessed, "-sess must re-hash HA1 with nonce+cnonce");
    }

    /// RFC 2617 §3.2.2 / RFC 7616 §5.5: cnonce MUST be unpredictable. A
    /// hardcoded placeholder (we used to fall back to `"0a1b2c3d"`) silently
    /// defeats replay protection. Verify that omitting cnonce from
    /// `format_authorization_header` injects a fresh random value and that
    /// two back-to-back calls produce different values.
    #[test]
    fn format_authorization_generates_unique_cnonce_when_absent() {
        let challenge = DigestChallenge {
            realm: "r".to_string(),
            nonce: "N".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };
        let creds = DigestCredentials {
            username: "u".to_string(),
            password: "p".to_string(),
        };

        let extract_cnonce = |header: &str| -> String {
            let start = header.find("cnonce=\"").unwrap() + 8;
            let end = header[start..].find('"').unwrap() + start;
            header[start..end].to_string()
        };

        let h1 = format_authorization_header(&challenge, &creds, "INVITE", "sip:x", Some(1), None);
        let h2 = format_authorization_header(&challenge, &creds, "INVITE", "sip:x", Some(1), None);

        let c1 = extract_cnonce(&h1);
        let c2 = extract_cnonce(&h2);

        assert_ne!(c1, "0a1b2c3d", "must not fall back to a hardcoded cnonce");
        assert_ne!(c2, "0a1b2c3d", "must not fall back to a hardcoded cnonce");
        assert_ne!(c1, c2, "two consecutive calls must produce different cnonces");
        assert_eq!(c1.len(), 16, "cnonce is 16 hex chars (64 bits of entropy)");
        assert!(c1.chars().all(|character| character.is_ascii_hexdigit()));
    }

    /// When the caller DOES supply a cnonce, format_authorization_header
    /// must use exactly that value — not generate its own.
    #[test]
    fn format_authorization_honors_explicit_cnonce() {
        let challenge = DigestChallenge {
            realm: "r".to_string(),
            nonce: "N".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let creds = DigestCredentials {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let header = format_authorization_header(&challenge, &creds, "INVITE", "sip:x", Some(1), Some("explicitcnonce"));
        assert!(header.contains("cnonce=\"explicitcnonce\""));
    }

    #[test]
    fn generate_cnonce_is_random() {
        let c1 = generate_cnonce();
        let c2 = generate_cnonce();
        assert_ne!(c1, c2);
        assert_eq!(c1.len(), 16);
    }

    #[test]
    fn format_authorization_emits_sha256_algorithm() {
        let challenge = DigestChallenge {
            realm: "r".to_string(),
            nonce: "N".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Sha256,
            stale: false,
        };
        let creds = DigestCredentials {
            username: "u".to_string(),
            password: "p".to_string(),
        };
        let header = format_authorization_header(&challenge, &creds, "INVITE", "sip:x", Some(1), Some("c"));
        assert!(header.contains("algorithm=SHA-256"));
        // Response field must be 64 hex chars for SHA-256.
        let response_start = header.find("response=\"").unwrap() + 10;
        let response_end = header[response_start..].find('"').unwrap() + response_start;
        let response = &header[response_start..response_end];
        assert_eq!(response.len(), 64, "SHA-256 digest is 64 hex chars");
        assert!(response.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn parse_challenge_unquoted_values() {
        // Some SIP servers send unquoted values for non-string params
        let header = r#"Digest realm="example.com", nonce="abc123", algorithm=MD5, stale=false"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert!(!challenge.stale);
    }

    /// RFC 2617 Section 3.5 test vector.
    #[test]
    fn rfc2617_test_vector_without_qop() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "Mufasa".to_string(),
            password: "Circle Of Life".to_string(),
        };

        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let expected = md5_hex(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:{ha2}"
        ));

        let response =
            compute_digest_response(&challenge, &credentials, "GET", "/dir/index.html", None, None);
        assert_eq!(response, expected);
    }

    /// RFC 2617 Section 3.5 test vector with qop=auth.
    #[test]
    fn rfc2617_test_vector_with_qop_auth() {
        let challenge = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "Mufasa".to_string(),
            password: "Circle Of Life".to_string(),
        };

        let ha1 = md5_hex("Mufasa:testrealm@host.com:Circle Of Life");
        let ha2 = md5_hex("GET:/dir/index.html");
        let expected = md5_hex(&format!(
            "{ha1}:dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:0a4f113b:auth:{ha2}"
        ));

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "GET",
            "/dir/index.html",
            Some(1),
            Some("0a4f113b"),
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn format_authorization_without_qop() {
        let challenge = DigestChallenge {
            realm: "biloxi.com".to_string(),
            nonce: "abc123".to_string(),
            opaque: None,
            qop: None,
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:biloxi.com",
            None,
            None,
        );

        assert!(header.starts_with("Digest "));
        assert!(header.contains("username=\"alice\""));
        assert!(header.contains("realm=\"biloxi.com\""));
        assert!(header.contains("nonce=\"abc123\""));
        assert!(header.contains("uri=\"sip:biloxi.com\""));
        assert!(header.contains("algorithm=MD5"));
        assert!(header.contains("response=\""));
        assert!(!header.contains("qop="));
        assert!(!header.contains("nc="));
    }

    #[test]
    fn format_authorization_with_qop() {
        let challenge = DigestChallenge {
            realm: "atlanta.com".to_string(),
            nonce: "84a4cc6f3082121f32b42a2187831a9e".to_string(),
            opaque: Some("opaque_value".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "bob".to_string(),
            password: "zanzibar".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "INVITE",
            "sip:bob@biloxi.com",
            Some(1),
            Some("deadbeef"),
        );

        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("cnonce=\"deadbeef\""));
        assert!(header.contains("opaque=\"opaque_value\""));
    }

    #[test]
    fn format_authorization_round_trips_through_parse() {
        let challenge = DigestChallenge {
            realm: "sip.example.com".to_string(),
            nonce: "testNonce123".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "testuser".to_string(),
            password: "testpass".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            Some(1),
            Some("abcd1234"),
        );

        // Verify the response field is present and is a valid 32-char hex string
        let response_start = header.find("response=\"").unwrap() + 10;
        let response_end = header[response_start..].find('"').unwrap() + response_start;
        let response = &header[response_start..response_end];
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|character| character.is_ascii_hexdigit()));
    }

    #[test]
    fn nonce_counter_increments_for_same_nonce() {
        let counter = NonceCounter::new();
        assert_eq!(counter.next_for("nonce-A"), 1);
        assert_eq!(counter.next_for("nonce-A"), 2);
        assert_eq!(counter.next_for("nonce-A"), 3);
    }

    #[test]
    fn nonce_counter_resets_on_new_nonce() {
        let counter = NonceCounter::new();
        assert_eq!(counter.next_for("nonce-A"), 1);
        assert_eq!(counter.next_for("nonce-A"), 2);
        // RFC 7616 §3.3: a fresh nonce restarts the count at 1.
        assert_eq!(counter.next_for("nonce-B"), 1);
        assert_eq!(counter.next_for("nonce-B"), 2);
        // Switching back to the old nonce also resets — the tracker only
        // keeps the most recently seen nonce, which is correct: the server
        // doesn't accept old-nonce nc values out of order.
        assert_eq!(counter.next_for("nonce-A"), 1);
    }

    #[test]
    fn nonce_counter_reset_clears_state() {
        let counter = NonceCounter::new();
        assert_eq!(counter.next_for("nonce-A"), 1);
        assert_eq!(counter.next_for("nonce-A"), 2);
        counter.reset();
        assert_eq!(counter.next_for("nonce-A"), 1);
    }

    #[test]
    fn split_params_respects_quotes() {
        let input = r#"realm="test,realm", nonce="abc""#;
        let params = split_params(input);
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].trim(), r#"realm="test,realm""#);
        assert_eq!(params[1].trim(), r#"nonce="abc""#);
    }

    #[test]
    fn unquote_strips_quotes() {
        assert_eq!(unquote("\"hello\""), "hello");
        assert_eq!(unquote("hello"), "hello");
        assert_eq!(unquote("\"\""), "");
    }

    #[test]
    fn sip_register_digest_response() {
        // Simulate a typical SIP REGISTER 401 challenge/response
        let challenge = DigestChallenge {
            realm: "atlanta.com".to_string(),
            nonce: "84a4cc6f3082121f32b42a2187831a9e".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "alice".to_string(),
            password: "password123".to_string(),
        };

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:atlanta.com",
            Some(1),
            Some("08ad4e30"),
        );

        // Verify it's a valid 32-char hex MD5 hash
        assert_eq!(response.len(), 32);
        assert!(response.chars().all(|character| character.is_ascii_hexdigit()));

        // Verify it's deterministic
        let response2 = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:atlanta.com",
            Some(1),
            Some("08ad4e30"),
        );
        assert_eq!(response, response2);
    }

    #[test]
    fn parse_challenge_with_extra_whitespace() {
        let header =
            r#"Digest  realm = "example.com" , nonce = "abc123" , algorithm = MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert_eq!(challenge.nonce, "abc123");
    }

    #[test]
    fn parse_challenge_case_insensitive_keys() {
        let header = r#"Digest Realm="example.com", Nonce="abc123", Algorithm=MD5, Stale=TRUE"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.realm, "example.com");
        assert!(challenge.stale);
    }

    #[test]
    fn qop_auth_int_not_selected_when_only_auth_int() {
        // auth-int alone: we only support auth, so should fall back to no-qop
        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: Some("auth-int".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        // Should use no-qop path since we don't support auth-int
        let ha1 = md5_hex("user:example.com:pass");
        let ha2 = md5_hex("REGISTER:sip:example.com");
        let expected = md5_hex(&format!("{ha1}:abc:{ha2}"));

        let response = compute_digest_response(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            None,
            None,
        );
        assert_eq!(response, expected);
    }

    #[test]
    fn qop_selects_auth_from_multiple() {
        let challenge = DigestChallenge {
            realm: "example.com".to_string(),
            nonce: "abc".to_string(),
            opaque: None,
            qop: Some("auth-int,auth".to_string()),
            algorithm: DigestAlgorithm::Md5,
            stale: false,
        };
        let credentials = DigestCredentials {
            username: "user".to_string(),
            password: "pass".to_string(),
        };

        let header = format_authorization_header(
            &challenge,
            &credentials,
            "REGISTER",
            "sip:example.com",
            Some(1),
            Some("cnonce"),
        );
        // Should use qop=auth since it's in the list
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
    }

    // -- IMS AKAv1-MD5 (RFC 3310 / TS 33.203) --

    #[test]
    fn parse_challenge_akav1_md5() {
        // The nonce carries base64(RAND||AUTN); parsing keeps it verbatim.
        let header = r#"Digest realm="ims.mnc01.mcc001.3gppnetwork.org", nonce="I1U8vpY3qJ0hiuZN", qop="auth", algorithm=AKAv1-MD5"#;
        let challenge = parse_challenge(header).unwrap();
        assert_eq!(challenge.algorithm, DigestAlgorithm::AkaV1Md5);
        assert!(!challenge.algorithm.is_session());
        assert_eq!(challenge.nonce, "I1U8vpY3qJ0hiuZN");
    }

    #[test]
    fn akav1_md5_displays_correctly() {
        assert_eq!(DigestAlgorithm::AkaV1Md5.to_string(), "AKAv1-MD5");
    }

    /// AKAv1-MD5 response is MD5 digest with the **binary** RES as the password
    /// (RFC 3310 §3.3). Cross-check against a manual computation using the
    /// Milenage TS 35.208 Test Set 1 RES (a54211d5e3ba50bf).
    #[test]
    fn aka_response_matches_manual_with_binary_res() {
        // 3GPP test IMSI range (MCC 001 / MNC 01) — never a real subscriber.
        let realm = "ims.mnc01.mcc001.3gppnetwork.org";
        let username = "001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
        let uri = "sip:ims.mnc01.mcc001.3gppnetwork.org";
        let nonce = "I1U8vpY3qJ0hiuZNrkbN";
        let res: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];

        let challenge = DigestChallenge {
            realm: realm.to_string(),
            nonce: nonce.to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::AkaV1Md5,
            stale: false,
        };

        // Manual HA1 over raw octets: H(user ":" realm ":" RES_bytes).
        let mut ha1_input = Vec::new();
        ha1_input.extend_from_slice(username.as_bytes());
        ha1_input.push(b':');
        ha1_input.extend_from_slice(realm.as_bytes());
        ha1_input.push(b':');
        ha1_input.extend_from_slice(&res);
        let ha1 = format!("{:x}", md5::compute(&ha1_input));
        let ha2 = format!("{:x}", md5::compute(format!("REGISTER:{uri}").as_bytes()));
        let expected = format!(
            "{:x}",
            md5::compute(format!("{ha1}:{nonce}:00000001:abcd:auth:{ha2}").as_bytes())
        );

        let response =
            compute_aka_response(&challenge, username, &res, "REGISTER", uri, Some(1), Some("abcd"));
        assert_eq!(response, expected);
    }

    /// Lock in the binary semantics: feeding RES as a hex *string* through the
    /// normal text-password path MUST differ from the binary-RES path. If these
    /// ever matched, RES would be getting double-encoded.
    #[test]
    fn aka_response_is_binary_not_hex_string() {
        let realm = "ims.mnc01.mcc001.3gppnetwork.org";
        let username = "001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
        let uri = "sip:ims.mnc01.mcc001.3gppnetwork.org";
        let res: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];

        let challenge = DigestChallenge {
            realm: realm.to_string(),
            nonce: "nonce".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::AkaV1Md5,
            stale: false,
        };

        let binary = compute_aka_response(&challenge, username, &res, "REGISTER", uri, Some(1), Some("c"));

        let hex_creds = DigestCredentials {
            username: username.to_string(),
            password: "a54211d5e3ba50bf".to_string(),
        };
        let as_hex = compute_digest_response(&challenge, &hex_creds, "REGISTER", uri, Some(1), Some("c"));

        assert_ne!(binary, as_hex);
    }

    #[test]
    fn format_aka_authorization_header_shape() {
        let challenge = DigestChallenge {
            realm: "ims.mnc01.mcc001.3gppnetwork.org".to_string(),
            nonce: "I1U8vpY3qJ0hiuZN".to_string(),
            opaque: Some("op".to_string()),
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::AkaV1Md5,
            stale: false,
        };
        let username = "001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
        let res: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];

        let header = format_aka_authorization_header(
            &challenge,
            username,
            &res,
            "sip:ims.mnc01.mcc001.3gppnetwork.org",
            Some(1),
            Some("deadbeef"),
            None,
        );

        assert!(header.contains("algorithm=AKAv1-MD5"));
        assert!(header.contains(&format!("username=\"{username}\"")));
        assert!(header.contains("qop=auth"));
        assert!(header.contains("nc=00000001"));
        assert!(header.contains("cnonce=\"deadbeef\""));
        assert!(header.contains("opaque=\"op\""));
        assert!(!header.contains("auts="));
        // 32-char MD5 response.
        let response_start = header.find("response=\"").unwrap() + 10;
        let response_end = header[response_start..].find('"').unwrap() + response_start;
        assert_eq!(header[response_start..response_end].len(), 32);
    }

    #[test]
    fn format_aka_authorization_header_includes_auts_on_resync() {
        let challenge = DigestChallenge {
            realm: "ims.mnc01.mcc001.3gppnetwork.org".to_string(),
            nonce: "I1U8vpY3qJ0hiuZN".to_string(),
            opaque: None,
            qop: Some("auth".to_string()),
            algorithm: DigestAlgorithm::AkaV1Md5,
            stale: false,
        };
        let res: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];

        let header = format_aka_authorization_header(
            &challenge,
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            &res,
            "sip:ims.mnc01.mcc001.3gppnetwork.org",
            Some(1),
            Some("deadbeef"),
            Some("RgXovKQ7VhY="),
        );
        assert!(header.contains("auts=\"RgXovKQ7VhY=\""));
    }
}
