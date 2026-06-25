//! Integration tests for STIR/SHAKEN — exercise the real x5u HTTP fetch path
//! end to end through the public `StirService` API.
//!
//! A throwaway root → leaf P-256 chain is generated in-process with `rcgen`;
//! the leaf certificate is served over a local HTTP server at the configured
//! x5u, and the leaf's private key is used to sign. Verification then fetches
//! the cert for real, validates the chain to the root, and checks the result.

use std::net::SocketAddr;

use siphon::config::{StirConfig, StirSigningConfig, StirVerificationConfig};
use siphon::stir::{current_unix_time, Attestation, StirService, Verstat};

struct GeneratedChain {
    anchor_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
}

/// Generate a self-signed root and a leaf signed by it (both ECDSA P-256).
fn generate_chain() -> GeneratedChain {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    let ca_key = KeyPair::generate().expect("ca keygen");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test STI-CA Root");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
    let anchor_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().expect("leaf keygen");
    let mut leaf_params =
        CertificateParams::new(vec!["sti.example.com".to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Test SHAKEN Leaf");
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf sign");

    GeneratedChain {
        anchor_pem,
        leaf_pem: leaf_cert.pem(),
        leaf_key_pem: leaf_key.serialize_pem(),
    }
}

/// Serve `pem` at `/sti.pem` on an ephemeral local port; returns its address.
async fn serve_cert(pem: String) -> SocketAddr {
    use axum::{routing::get, Router};

    let app = Router::new().route(
        "/sti.pem",
        get(move || {
            let pem = pem.clone();
            async move { pem }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind x5u server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

/// Build a `StirConfig` wired to temp key/anchor files + the served x5u URL.
fn build_config(
    chain: &GeneratedChain,
    x5u: &str,
    directory: &tempfile::TempDir,
    permissive: bool,
) -> StirConfig {
    let key_path = directory.path().join("sti.key");
    let anchor_path = directory.path().join("anchor.pem");
    std::fs::write(&key_path, &chain.leaf_key_pem).unwrap();
    std::fs::write(&anchor_path, &chain.anchor_pem).unwrap();

    StirConfig {
        enabled: true,
        signing: Some(StirSigningConfig {
            private_key: key_path.to_str().unwrap().to_string(),
            x5u: x5u.to_string(),
            default_attestation: "A".to_string(),
            origid: None,
        }),
        verification: Some(StirVerificationConfig {
            trust_anchors: vec![anchor_path.to_str().unwrap().to_string()],
            trust_anchor_dir: None,
            freshness_secs: 60,
            permissive,
            cache_ttl_secs: 3600,
            max_cert_bytes: 65536,
            require_tnauthlist: false,
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sign_then_verify_over_real_http() {
    let chain = generate_chain();
    let addr = serve_cert(chain.leaf_pem.clone()).await;
    let x5u = format!("http://{addr}/sti.pem");

    let directory = tempfile::tempdir().unwrap();
    let config = build_config(&chain, &x5u, &directory, false);
    let service = StirService::from_config(&config).expect("build service");

    let now = current_unix_time();
    let signed = service
        .sign(Attestation::A, "12155550112", "12025550100", None, now)
        .expect("sign");
    assert!(signed.header_value.contains("ppt=shaken"));
    assert!(signed.header_value.contains(&x5u));

    let verification = service
        .verify(
            &[signed.header_value],
            Some("12155550112"),
            Some("12025550100"),
            now,
        )
        .expect("verify");
    assert_eq!(
        verification.verstat,
        Verstat::Passed,
        "reason: {}",
        verification.reason
    );
    assert!(verification.passed);
    assert_eq!(verification.attestation.as_deref(), Some("A"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_x5u_is_failed_strict_but_no_validation_permissive() {
    let chain = generate_chain();
    let addr = serve_cert(chain.leaf_pem.clone()).await;
    // Point x5u at a path the server does NOT serve → HTTP 404 on fetch.
    let bad_x5u = format!("http://{addr}/missing.pem");

    let now = current_unix_time();

    // Strict mode: a fetch failure is a hard failure.
    let directory_strict = tempfile::tempdir().unwrap();
    let strict = StirService::from_config(&build_config(
        &chain,
        &bad_x5u,
        &directory_strict,
        false,
    ))
    .unwrap();
    let signed = strict
        .sign(Attestation::A, "12155550112", "12025550100", None, now)
        .unwrap();
    let verification = strict
        .verify(
            std::slice::from_ref(&signed.header_value),
            Some("12155550112"),
            Some("12025550100"),
            now,
        )
        .unwrap();
    assert_eq!(verification.verstat, Verstat::Failed);

    // Permissive mode: the same fetch failure degrades to No-TN-Validation.
    let directory_permissive = tempfile::tempdir().unwrap();
    let permissive = StirService::from_config(&build_config(
        &chain,
        &bad_x5u,
        &directory_permissive,
        true,
    ))
    .unwrap();
    let verification = permissive
        .verify(
            &[signed.header_value],
            Some("12155550112"),
            Some("12025550100"),
            now,
        )
        .unwrap();
    assert_eq!(verification.verstat, Verstat::NoValidation);
    assert!(!verification.passed);
}
