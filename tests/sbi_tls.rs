//! SBI TLS tests use ephemeral rcgen certificates; no external PKI or fixtures.
#![allow(clippy::disallowed_methods)] // test runtime may block, as in integration_tests.rs
use siphon::config::SbiYamlConfig;
use siphon::sbi::{SbiConfig, SbiManager};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;

fn parse(yaml: &str) -> Result<SbiYamlConfig, serde_saphyr::Error> {
    serde_saphyr::from_str(yaml)
}

#[test]
fn config_defaults_and_pair_validation() {
    let config = parse("{}").unwrap().to_sbi_config();
    assert!(config.tls.is_none());
    assert_eq!(config.timeout_secs, 5);
    for yaml in ["tls: {cert: client.pem}", "tls: {key: key.pem}"] {
        assert!(parse(yaml).is_err());
    }
    let config = parse("tls: {ca: ca.pem, cert: client.pem, key: key.pem}")
        .unwrap()
        .to_sbi_config();
    let tls = config.tls.unwrap();
    assert!(tls.trust_public_roots);
    assert_eq!(tls.ca.as_deref(), Some("ca.pem"));
    assert_eq!(tls.cert.as_deref(), Some("client.pem"));
    assert_eq!(tls.key.as_deref(), Some("key.pem"));
    let expanded = siphon::config::expand_env_vars("tls: {ca: '${SBI_TEST_UNSET:-/tmp/ca.pem}'}");
    assert_eq!(
        parse(&expanded)
            .unwrap()
            .to_sbi_config()
            .tls
            .unwrap()
            .ca
            .as_deref(),
        Some("/tmp/ca.pem")
    );
}

struct Pki {
    dir: tempfile::TempDir,
    ca: rcgen::Certificate,
    server: rcgen::Certificate,
    server_key: rcgen::KeyPair,
}
impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(params, ca_key);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server = rcgen::CertificateParams::new(vec!["127.0.0.1".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client = rcgen::CertificateParams::new(vec!["client.example.com".into()])
            .unwrap()
            .signed_by(&client_key, &issuer)
            .unwrap();
        for (name, pem) in [
            ("ca", ca.pem()),
            ("cert", client.pem()),
            ("key", client_key.serialize_pem()),
        ] {
            std::fs::write(dir.path().join(name), pem).unwrap();
        }
        Self {
            dir,
            ca,
            server,
            server_key,
        }
    }
    fn config(&self, identity: bool) -> SbiConfig {
        let root = self.dir.path().display();
        let yaml = if identity {
            format!("tls: {{ca: '{root}/ca', cert: '{root}/cert', key: '{root}/key', trust_public_roots: false}}")
        } else {
            format!("tls: {{ca: '{root}/ca'}}")
        };
        parse(&yaml).unwrap().to_sbi_config()
    }
}

#[test]
fn construction_errors_name_files() {
    let pki = Pki::new();
    SbiManager::new(pki.config(true)).unwrap();
    // Bundles must retain every CA, and reject a malformed trailing PEM block.
    let ca_path = pki.dir.path().join("ca");
    let ca = std::fs::read_to_string(&ca_path).unwrap();
    std::fs::write(&ca_path, format!("{ca}{ca}")).unwrap();
    SbiManager::new(pki.config(true)).unwrap();
    std::fs::write(
        &ca_path,
        format!("{ca}-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    assert!(SbiManager::new(pki.config(true)).is_err());
    std::fs::write(&ca_path, ca).unwrap();
    for name in ["ca", "cert", "key"] {
        let path = pki.dir.path().join(name);
        let original = std::fs::read(&path).unwrap();
        for bad in [
            "",
            "not PEM",
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----",
        ] {
            std::fs::write(&path, bad).unwrap();
            let error = SbiManager::new(pki.config(true)).unwrap_err().to_string();
            assert!(error.contains(path.to_str().unwrap()), "{error}");
        }
        std::fs::remove_file(&path).unwrap();
        assert!(SbiManager::new(pki.config(true))
            .unwrap_err()
            .to_string()
            .contains(path.to_str().unwrap()));
        std::fs::write(&path, original).unwrap();
    }
    std::fs::write(
        pki.dir.path().join("key"),
        rcgen::KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let error = SbiManager::new(pki.config(true)).unwrap_err().to_string();
    assert!(error.contains("/cert") && error.contains("/key"), "{error}");
}

#[test]
fn tls_material_is_cached_and_rust_config_is_validated() {
    let pki = Pki::new();
    let mut config = pki.config(true);
    let manager = SbiManager::new(config.clone()).unwrap();
    config.tls.as_mut().unwrap().key = None;
    assert!(SbiManager::new(config)
        .unwrap_err()
        .contains("supplied together"));
    std::fs::remove_dir_all(pki.dir.path()).unwrap();
    manager
        .client_with_timeout(Duration::from_millis(100))
        .unwrap();
    SbiManager::new(SbiConfig::default()).unwrap();
}

#[tokio::test]
async fn private_ca_mutual_tls() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = Pki::new();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pki.ca.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let server = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![pki.server.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(pki.server_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}/", listener.local_addr().unwrap());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(tcp).await {
                    let mut buf = [0; 4096];
                    if stream.read(&mut buf).await.is_ok() {
                        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
                    }
                }
            });
        }
    });
    let manager = SbiManager::new(pki.config(true)).unwrap();
    let no_identity = SbiManager::new(pki.config(false)).unwrap();
    let mut public_config = pki.config(true);
    public_config.tls.as_mut().unwrap().ca = None;
    public_config.tls.as_mut().unwrap().trust_public_roots = true;
    let public = SbiManager::new(public_config).unwrap();
    // Building another timeout client after deleting the files must use cached material.
    std::fs::remove_dir_all(pki.dir.path()).unwrap();
    let client = manager.client_with_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        client.get(&url).send().await.unwrap().text().await.unwrap(),
        "ok"
    );
    assert!(no_identity.client().get(&url).send().await.is_err());
    assert!(public.client().get(&url).send().await.is_err());
    task.abort();
}
