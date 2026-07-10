//! STI certificate handling (RFC 8226): PEM parsing, public-key extraction,
//! and manual PKIX-lite chain validation to a configured STI-CA trust anchor.
//!
//! This module is deliberately network-free and side-effect-free so it can be
//! unit-tested without sockets. The x5u fetch + cache lives in [`super`].
//!
//! Chain validation is done by hand rather than via `rustls-webpki` because
//! webpki is built around TLS serverAuth EKU + DNS-name semantics, which fight
//! the SHAKEN/TNAuthList certificate profile. v1 supports EC P-256 chains
//! (ECDSA-with-SHA-256); RSA STI-CA chains are a documented follow-up.

use p256::ecdsa::{Signature, VerifyingKey};
use p256::ecdsa::signature::Verifier;
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::BasicConstraints;
use x509_cert::Certificate;

/// OID for `ecdsa-with-SHA256` (ANSI X9.62) — the only cert signature
/// algorithm accepted in v1.
const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// OID for the RFC 8226 TNAuthList certificate extension.
const TNAUTHLIST_OID: &str = "1.3.6.1.5.5.7.1.26";

/// Maximum certificate-chain depth — guards against loops / pathological input.
const MAX_CHAIN_DEPTH: usize = 8;

/// Parse a PEM bundle (one or more concatenated certificates) into a chain.
/// The first certificate is treated as the leaf.
pub fn parse_pem_chain(pem: &[u8]) -> Result<Vec<Certificate>, String> {
    let chain = Certificate::load_pem_chain(pem)
        .map_err(|error| format!("PEM certificate parse failed: {error}"))?;
    if chain.is_empty() {
        return Err("no certificates found in PEM input".to_string());
    }
    Ok(chain)
}

/// Extract the ECDSA P-256 public key from a certificate's SubjectPublicKeyInfo.
pub fn verifying_key(certificate: &Certificate) -> Result<VerifyingKey, String> {
    let point = certificate
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| "subject public key is not octet-aligned".to_string())?;
    VerifyingKey::from_sec1_bytes(point)
        .map_err(|error| format!("not a valid P-256 public key: {error}"))
}

/// Validate `chain` (leaf first) up to one of the configured `anchors`,
/// enforcing signatures, validity windows, and CA basic-constraints.
///
/// On success returns the leaf's public key so the caller can verify the
/// PASSporT signature with it. On failure returns a human-readable reason.
pub fn validate_chain(
    chain: &[Certificate],
    anchors: &[Certificate],
    now_unix: i64,
    require_tnauthlist: bool,
) -> Result<VerifyingKey, String> {
    let leaf = chain.first().ok_or_else(|| "empty certificate chain".to_string())?;
    check_validity(leaf, now_unix)?;
    if require_tnauthlist && !has_tnauthlist(leaf) {
        return Err("leaf certificate is missing the RFC 8226 TNAuthList extension".to_string());
    }
    let leaf_key = verifying_key(leaf)?;

    let mut current_der = der_bytes(leaf)?;
    let mut visited: Vec<Vec<u8>> = vec![current_der.clone()];

    for _ in 0..MAX_CHAIN_DEPTH {
        let current = Certificate::from_der(&current_der)
            .map_err(|error| format!("internal re-decode failed: {error}"))?;

        // 1. Does any trust anchor directly sign `current`? If so, done.
        for anchor in anchors {
            if names_equal(anchor.tbs_certificate().subject(), current.tbs_certificate().issuer())?
                && verify_signed_by(&current, anchor)?
            {
                check_validity(anchor, now_unix)?;
                return Ok(leaf_key);
            }
        }

        // 2. Otherwise find an intermediate in the supplied chain that signs it.
        let issuer = chain.iter().find(|candidate| {
            let candidate_der = der_bytes(candidate).unwrap_or_default();
            !visited.contains(&candidate_der)
                && is_ca(candidate)
                && names_equal(
                    candidate.tbs_certificate().subject(),
                    current.tbs_certificate().issuer(),
                )
                .unwrap_or(false)
        });

        match issuer {
            Some(issuer) => {
                if !verify_signed_by(&current, issuer)? {
                    return Err("signature mismatch in certificate chain".to_string());
                }
                check_validity(issuer, now_unix)?;
                current_der = der_bytes(issuer)?;
                visited.push(current_der.clone());
            }
            None => {
                return Err(
                    "unable to build certificate chain to a trusted STI-CA anchor".to_string(),
                );
            }
        }
    }

    Err("certificate chain exceeds maximum depth".to_string())
}

/// True when the certificate carries the RFC 8226 TNAuthList extension.
pub fn has_tnauthlist(certificate: &Certificate) -> bool {
    certificate
        .tbs_certificate()
        .extensions()
        .into_iter()
        .flatten()
        .any(|extension| extension.extn_id.to_string() == TNAUTHLIST_OID)
}

/// DER-encode a whole certificate (used as an identity key for cycle checks).
fn der_bytes(certificate: &Certificate) -> Result<Vec<u8>, String> {
    certificate
        .to_der()
        .map_err(|error| format!("certificate DER encode failed: {error}"))
}

/// Verify that `child` was signed by `issuer`'s private key (ECDSA-P256/SHA-256).
fn verify_signed_by(child: &Certificate, issuer: &Certificate) -> Result<bool, String> {
    if child.signature_algorithm().oid.to_string() != ECDSA_WITH_SHA256_OID {
        return Err(format!(
            "unsupported certificate signature algorithm {} (only ecdsa-with-SHA256 in v1)",
            child.signature_algorithm().oid
        ));
    }
    let issuer_key = verifying_key(issuer)?;
    let tbs = child
        .tbs_certificate()
        .to_der()
        .map_err(|error| format!("TBSCertificate DER encode failed: {error}"))?;
    let signature_der = child
        .signature()
        .as_bytes()
        .ok_or_else(|| "certificate signature is not octet-aligned".to_string())?;
    let signature = match Signature::from_der(signature_der) {
        Ok(signature) => signature,
        Err(_) => return Ok(false),
    };
    Ok(issuer_key.verify(&tbs, &signature).is_ok())
}

/// Ensure `now_unix` falls within the certificate's validity window.
fn check_validity(certificate: &Certificate, now_unix: i64) -> Result<(), String> {
    let not_before = certificate
        .tbs_certificate()
        .validity()
        .not_before
        .to_unix_duration()
        .as_secs() as i64;
    let not_after = certificate
        .tbs_certificate()
        .validity()
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    if now_unix < not_before {
        return Err("certificate is not yet valid".to_string());
    }
    if now_unix > not_after {
        return Err("certificate has expired".to_string());
    }
    Ok(())
}

/// True when the certificate asserts CA:TRUE in basicConstraints.
fn is_ca(certificate: &Certificate) -> bool {
    match certificate.tbs_certificate().get_extension::<BasicConstraints>() {
        Ok(Some((_critical, basic_constraints))) => basic_constraints.ca,
        _ => false,
    }
}

/// DER-equality comparison of two X.509 Names.
fn names_equal(
    left: &x509_cert::name::Name,
    right: &x509_cert::name::Name,
) -> Result<bool, String> {
    let left_der = left
        .to_der()
        .map_err(|error| format!("name DER encode failed: {error}"))?;
    let right_der = right
        .to_der()
        .map_err(|error| format!("name DER encode failed: {error}"))?;
    Ok(left_der == right_der)
}

#[cfg(test)]
pub(crate) mod testchain {
    //! In-process certificate-chain generation for tests (uses the `rcgen`
    //! dev-dependency). Returns PEMs + the leaf's P-256 signing key.

    use p256::ecdsa::SigningKey;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
    };

    pub struct GeneratedChain {
        /// Self-signed root (the STI-CA trust anchor), PEM.
        pub anchor_pem: String,
        /// Leaf certificate signed by the root, PEM.
        pub leaf_pem: String,
        /// Leaf's P-256 signing key (for signing PASSporTs in tests).
        pub leaf_key: SigningKey,
    }

    /// Generate root → leaf where the leaf is valid for the wide rcgen default
    /// window (1975..4096).
    pub fn generate() -> GeneratedChain {
        generate_with_leaf(|_params| {})
    }

    /// Generate root → leaf, applying `customize` to the leaf params first
    /// (e.g. to set an expired validity window).
    pub fn generate_with_leaf<F: FnOnce(&mut CertificateParams)>(customize: F) -> GeneratedChain {
        let ca_key = KeyPair::generate().expect("ca keygen");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test STI-CA Root");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
        let anchor_pem = ca_cert.pem();
        let issuer = Issuer::new(ca_params, ca_key);

        let leaf_key_pair = KeyPair::generate().expect("leaf keygen");
        let mut leaf_params =
            CertificateParams::new(vec!["sti.example.com".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "Test SHAKEN Leaf");
        customize(&mut leaf_params);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key_pair, &issuer)
            .expect("leaf sign");
        let leaf_pem = leaf_cert.pem();

        let leaf_key = SigningKey::from_pkcs8_pem(&leaf_key_pair.serialize_pem())
            .expect("load leaf p256 key");

        GeneratedChain {
            anchor_pem,
            leaf_pem,
            leaf_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_chain_to_anchor_succeeds() {
        let generated = testchain::generate();
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let anchors = parse_pem_chain(generated.anchor_pem.as_bytes()).unwrap();
        // 2000-01-01 is inside the default rcgen window.
        let result = validate_chain(&chain, &anchors, 946_684_800, false);
        assert!(result.is_ok(), "chain should validate: {result:?}");
    }

    #[test]
    fn untrusted_anchor_rejected() {
        let generated = testchain::generate();
        let other = testchain::generate(); // different, unrelated root
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let wrong_anchors = parse_pem_chain(other.anchor_pem.as_bytes()).unwrap();
        let result = validate_chain(&chain, &wrong_anchors, 946_684_800, false);
        assert!(result.is_err(), "leaf must not validate against a foreign root");
    }

    #[test]
    fn expired_leaf_rejected() {
        let generated = testchain::generate_with_leaf(|params| {
            params.not_before = rcgen::date_time_ymd(2018, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        });
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let anchors = parse_pem_chain(generated.anchor_pem.as_bytes()).unwrap();
        // 2024 is past the leaf's not_after.
        let result = validate_chain(&chain, &anchors, 1_704_067_200, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn not_yet_valid_leaf_rejected() {
        let generated = testchain::generate_with_leaf(|params| {
            params.not_before = rcgen::date_time_ymd(2030, 1, 1);
            params.not_after = rcgen::date_time_ymd(2031, 1, 1);
        });
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let anchors = parse_pem_chain(generated.anchor_pem.as_bytes()).unwrap();
        let result = validate_chain(&chain, &anchors, 1_704_067_200, false);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not yet valid"));
    }

    #[test]
    fn require_tnauthlist_rejects_plain_leaf() {
        let generated = testchain::generate();
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let anchors = parse_pem_chain(generated.anchor_pem.as_bytes()).unwrap();
        // rcgen leaf has no TNAuthList → strict mode must reject.
        let result = validate_chain(&chain, &anchors, 946_684_800, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TNAuthList"));
    }

    #[test]
    fn leaf_public_key_matches_signing_key() {
        let generated = testchain::generate();
        let chain = parse_pem_chain(generated.leaf_pem.as_bytes()).unwrap();
        let extracted = verifying_key(&chain[0]).unwrap();
        let expected = VerifyingKey::from(&generated.leaf_key);
        assert_eq!(extracted, expected);
    }

    #[test]
    fn garbage_pem_rejected() {
        assert!(parse_pem_chain(b"not a pem").is_err());
    }
}
