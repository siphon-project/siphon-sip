//! Client-certificate verification: the subject matcher rules, name
//! extraction, and real in-process handshakes against listeners built from
//! per-listener merged configs.

use std::sync::Arc;

use super::*;
use crate::config::{ListenerClientAuth, TlsServerConfig};
use crate::transport::tls::build_tls_acceptor;

fn ensure_crypto_provider() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
}

fn patterns(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn names(dns: &[&str], common_name: Option<&str>) -> PresentedNames {
    PresentedNames {
        dns: patterns(dns),
        common_name: common_name.map(str::to_string),
    }
}

// ---------------------------------------------------------------------------
// ClientSubjectMatcher
// ---------------------------------------------------------------------------

#[test]
fn exact_pattern_matches_case_insensitively_and_ignores_a_root_dot() {
    let matcher = ClientSubjectMatcher::new(&patterns(&["Trunk.SIP.example.net"])).unwrap();
    assert!(matcher.matches(&names(&["trunk.sip.example.net"], None)));
    assert!(matcher.matches(&names(&["TRUNK.sip.example.net."], None)));
    assert!(!matcher.matches(&names(&["other.sip.example.net"], None)));
}

#[test]
fn wildcard_pattern_matches_exactly_one_leftmost_label() {
    let matcher = ClientSubjectMatcher::new(&patterns(&["*.sip.example.net"])).unwrap();
    assert!(matcher.matches(&names(&["edge1.sip.example.net"], None)));
    assert!(!matcher.matches(&names(&["sip.example.net"], None)));
    assert!(!matcher.matches(&names(&["a.b.sip.example.net"], None)));
    assert!(!matcher.matches(&names(&["edge1.sip.example.org"], None)));
    // A wildcard certificate is covered by the same wildcard pattern only.
    assert!(matcher.matches(&names(&["*.sip.example.net"], None)));
    let exact = ClientSubjectMatcher::new(&patterns(&["edge1.sip.example.net"])).unwrap();
    assert!(!exact.matches(&names(&["*.sip.example.net"], None)));
}

#[test]
fn any_dns_name_on_the_certificate_may_match() {
    let matcher = ClientSubjectMatcher::new(&patterns(&["trunk.example.net"])).unwrap();
    assert!(matcher.matches(&names(&["first.example.org", "trunk.example.net"], None)));
}

#[test]
fn common_name_counts_only_when_the_certificate_has_no_dns_name() {
    let matcher = ClientSubjectMatcher::new(&patterns(&["trunk.example.net"])).unwrap();
    assert!(matcher.matches(&names(&[], Some("trunk.example.net"))));
    // RFC 6125 §6.4.4: with a DNS-ID present the CN is not consulted.
    assert!(!matcher.matches(&names(&["other.example.net"], Some("trunk.example.net"))));
    assert!(!matcher.matches(&names(&[], None)));
}

#[test]
fn malformed_patterns_are_refused() {
    for bad in [
        vec![""],
        vec!["*"],
        vec!["*."],
        vec!["*.net"],
        vec!["edge*.example.net"],
        vec!["edge.*.example.net"],
        vec!["*.*.example.net"],
        vec!["*..example.net"],
    ] {
        assert!(
            ClientSubjectMatcher::new(&patterns(&bad)).is_err(),
            "{bad:?} must be refused"
        );
    }
    assert!(
        ClientSubjectMatcher::new(&[]).is_err(),
        "an empty list would refuse everyone"
    );
}

// ---------------------------------------------------------------------------
// presented_names
// ---------------------------------------------------------------------------

#[test]
fn presented_names_reads_dns_sans_and_common_name() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![
        "a.example.net".to_string(),
        "b.example.net".to_string(),
    ])
    .unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cn.example.net");
    let certificate = params.self_signed(&key).unwrap();
    let presented = presented_names(certificate.der()).unwrap();
    assert_eq!(presented.dns, patterns(&["a.example.net", "b.example.net"]));
    assert_eq!(presented.common_name.as_deref(), Some("cn.example.net"));
}

#[test]
fn presented_names_without_a_san_extension_is_empty_dns() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "cn-only.example.net");
    let certificate = params.self_signed(&key).unwrap();
    let presented = presented_names(certificate.der()).unwrap();
    assert!(presented.dns.is_empty());
    assert_eq!(
        presented.common_name.as_deref(),
        Some("cn-only.example.net")
    );
}

#[test]
fn presented_names_refuses_garbage() {
    assert!(presented_names(b"not a certificate").is_err());
}

// ---------------------------------------------------------------------------
// client_cert_verifier — fail-closed config rules
// ---------------------------------------------------------------------------

/// A CA, the server certificate it does not need to sign, and helpers to mint
/// client certificates under it.
struct Pki {
    directory: tempfile::TempDir,
    ca_certificate: rcgen::Certificate,
    ca_issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    server: TlsServerConfig,
}

impl Pki {
    fn new() -> Self {
        ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();

        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test client CA");
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        std::fs::write(directory.path().join("ca.pem"), ca_certificate.pem()).unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        let server_key = rcgen::KeyPair::generate().unwrap();
        let server_certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&server_key)
            .unwrap();
        let certificate = directory.path().join("server.pem");
        let private_key = directory.path().join("server.key");
        std::fs::write(&certificate, server_certificate.pem()).unwrap();
        std::fs::write(&private_key, server_key.serialize_pem()).unwrap();

        let server = TlsServerConfig {
            certificate: certificate.to_string_lossy().into_owned(),
            private_key: private_key.to_string_lossy().into_owned(),
            certificates: Vec::new(),
            method: crate::config::TlsMethod::default(),
            verify_client: false,
            client_ca: None,
            client_subject: Vec::new(),
            client_certificate: None,
            client_private_key: None,
        };
        Self {
            directory,
            ca_certificate,
            ca_issuer,
            server,
        }
    }

    fn ca_path(&self) -> String {
        self.directory
            .path()
            .join("ca.pem")
            .to_string_lossy()
            .into_owned()
    }

    /// A client certificate signed by this CA for `dns_names`.
    fn client_identity(
        &self,
        dns_names: &[&str],
    ) -> (
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    ) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(patterns(dns_names)).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.signed_by(&key, &self.ca_issuer).unwrap();
        let key_der = rustls_pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        (
            vec![certificate.der().clone(), self.ca_certificate.der().clone()],
            key_der,
        )
    }
}

#[test]
fn no_verifier_when_verify_client_is_off() {
    let pki = Pki::new();
    assert!(client_cert_verifier(&pki.server, "tls").unwrap().is_none());
}

#[test]
fn verify_client_without_a_ca_names_the_listener() {
    let pki = Pki::new();
    let mut config = pki.server.clone();
    config.verify_client = true;
    let error =
        client_cert_verifier(&config, "listen.tls[192.0.2.10:5062]").expect_err("fails closed");
    assert!(
        error.to_string().contains("listen.tls[192.0.2.10:5062]"),
        "{error}"
    );
}

#[test]
fn a_missing_or_empty_ca_bundle_fails_closed() {
    let pki = Pki::new();
    let mut config = pki.server.clone();
    config.verify_client = true;
    config.client_ca = Some("/nonexistent/ca.pem".to_string());
    assert!(client_cert_verifier(&config, "tls").is_err());

    let empty = pki.directory.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    config.client_ca = Some(empty.to_string_lossy().into_owned());
    assert!(client_cert_verifier(&config, "tls").is_err());
}

#[test]
fn client_subject_without_verify_client_is_refused() {
    let pki = Pki::new();
    let mut config = pki.server.clone();
    config.client_subject = patterns(&["*.sip.example.net"]);
    assert!(client_cert_verifier(&config, "tls").is_err());
}

#[test]
fn a_malformed_client_subject_is_refused() {
    let pki = Pki::new();
    let mut config = pki.server.clone();
    config.verify_client = true;
    config.client_ca = Some(pki.ca_path());
    config.client_subject = patterns(&["edge*.example.net"]);
    let error = client_cert_verifier(&config, "tls").expect_err("refused");
    assert!(error.to_string().contains("tls.client_subject"), "{error}");
}

// ---------------------------------------------------------------------------
// Real handshakes, one acceptor per listener
// ---------------------------------------------------------------------------

/// Run one handshake against an acceptor built from `config`, with the client
/// presenting `identity` (or nothing). Returns whether the *server* accepted
/// it — under TLS 1.3 the client can finish its side before the server has
/// judged the client certificate, so the server's verdict is the one that
/// counts.
async fn server_accepts(
    config: &TlsServerConfig,
    identity: Option<(
        Vec<rustls_pki_types::CertificateDer<'static>>,
        rustls_pki_types::PrivateKeyDer<'static>,
    )>,
) -> bool {
    use rustls_pki_types::pem::PemObject;
    use tokio_rustls::TlsConnector;

    let acceptor = build_tls_acceptor(config).expect("acceptor builds");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.is_ok()
    });

    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pki_types::CertificateDer::pem_file_iter(&config.certificate).unwrap()
    {
        roots.add(certificate.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let client_config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
    // The client outcome is irrelevant (see above); keep the stream alive
    // until the server has decided.
    let client = connector.connect(name, stream).await;
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("server decided")
        .expect("server task");
    drop(client);
    accepted
}

#[tokio::test]
async fn a_listener_without_verify_accepts_a_certless_client_while_its_sibling_refuses_it() {
    let pki = Pki::new();
    // Phones listener: the tls: block as-is (no client certificate).
    let phones = pki.server.for_listener(None);
    // Trunk listener: mutual TLS switched on by its own entry.
    let trunk_overrides = ListenerClientAuth {
        verify_client: Some(true),
        client_ca: Some(pki.ca_path()),
        client_subject: None,
    };
    let trunk = pki.server.for_listener(Some(&trunk_overrides));

    assert!(
        server_accepts(&phones, None).await,
        "phones: no cert needed"
    );
    assert!(
        !server_accepts(&trunk, None).await,
        "trunk: a client without a certificate must be refused"
    );
    assert!(
        server_accepts(&trunk, Some(pki.client_identity(&["trunk.example.net"]))).await,
        "trunk: a certificate from the configured CA is accepted"
    );
}

#[tokio::test]
async fn a_certificate_from_another_ca_is_refused() {
    let pki = Pki::new();
    let other = Pki::new();
    let overrides = ListenerClientAuth {
        verify_client: Some(true),
        client_ca: Some(pki.ca_path()),
        client_subject: None,
    };
    let trunk = pki.server.for_listener(Some(&overrides));
    assert!(!server_accepts(&trunk, Some(other.client_identity(&["trunk.example.net"]))).await);
}

#[tokio::test]
async fn client_subject_refuses_a_mismatch_and_accepts_a_match() {
    let pki = Pki::new();
    let overrides = ListenerClientAuth {
        verify_client: Some(true),
        client_ca: Some(pki.ca_path()),
        client_subject: Some(patterns(&["*.sip.example.net"])),
    };
    let trunk = pki.server.for_listener(Some(&overrides));

    assert!(
        server_accepts(
            &trunk,
            Some(pki.client_identity(&["edge1.sip.example.net"]))
        )
        .await,
        "a wildcard-covered name is accepted"
    );
    assert!(
        !server_accepts(
            &trunk,
            Some(pki.client_identity(&["edge1.other.example.net"]))
        )
        .await,
        "right CA, wrong name: refused"
    );
    assert!(
        !server_accepts(&trunk, Some(pki.client_identity(&["a.b.sip.example.net"]))).await,
        "a wildcard covers one label only"
    );
}

#[tokio::test]
async fn top_level_mutual_tls_still_applies_to_listeners_without_an_override() {
    let pki = Pki::new();
    let mut block = pki.server.clone();
    block.verify_client = true;
    block.client_ca = Some(pki.ca_path());
    block.client_subject = patterns(&["trunk.example.net"]);

    let inherited = block.for_listener(None);
    assert!(!server_accepts(&inherited, None).await);
    assert!(
        server_accepts(
            &inherited,
            Some(pki.client_identity(&["trunk.example.net"]))
        )
        .await
    );

    // A listener that opts out drops the inherited subject list with it.
    let opted_out = block.for_listener(Some(&ListenerClientAuth {
        verify_client: Some(false),
        client_ca: None,
        client_subject: None,
    }));
    assert!(opted_out.client_subject.is_empty());
    assert!(server_accepts(&opted_out, None).await);
}
