//! Outbound SIP TLS server verification: the RFC 5922 name rules on their own,
//! and real in-process rustls handshakes through the connection pool.

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use tokio::io::AsyncReadExt;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::transport::pool::ConnectionPool;

pub(crate) const ROUTED_HOST: &str = "gw.example.net";

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A CA that signs leaf certificates for the handshake tests.
pub(crate) struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
}

pub(crate) fn test_ca(name: &str) -> TestCa {
    let key = KeyPair::generate().expect("ca keygen");
    let mut params = CertificateParams::new(vec![name.to_string()]).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let certificate = params.self_signed(&key).expect("ca self-sign");
    TestCa {
        pem: certificate.pem(),
        issuer: Issuer::new(params, key),
    }
}

/// A leaf certificate carrying exactly `names` as its subjectAltNames.
pub(crate) struct Leaf {
    der: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

pub(crate) fn leaf(ca: &TestCa, names: Vec<SanType>) -> Leaf {
    let key = KeyPair::generate().expect("leaf keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params.subject_alt_names = names;
    let certificate = params.signed_by(&key, &ca.issuer).expect("leaf sign");
    Leaf {
        der: certificate.der().clone(),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

pub(crate) fn dns(name: &str) -> SanType {
    SanType::DnsName(Ia5String::try_from(name).expect("ia5 dns"))
}

pub(crate) fn uri(value: &str) -> SanType {
    SanType::URI(Ia5String::try_from(value).expect("ia5 uri"))
}

pub(crate) fn ip(address: &str) -> SanType {
    SanType::IpAddress(address.parse().expect("ip"))
}

/// A trust store holding only `ca`, through the production `tls.server_ca`
/// loader, with `verify_by_default` as `tls.verify_server`.
pub(crate) fn trusting(
    ca: &TestCa,
    verify_by_default: bool,
) -> (tempfile::TempDir, ServerVerification) {
    let directory = tempfile::tempdir().expect("temp dir");
    let path = directory.path().join("server-ca.pem");
    std::fs::write(&path, &ca.pem).expect("write ca");
    let verification = ServerVerification::new(verify_by_default, Some(&path.to_string_lossy()))
        .expect("server_ca must load");
    (directory, verification)
}

pub(crate) fn pool_with(
    verification: &ServerVerification,
    identity: Option<OutboundClientIdentity>,
) -> ConnectionPool {
    ensure_crypto_provider();
    let configs = build_outbound_tls_configs(identity, TlsMethod::default(), verification)
        .expect("outbound tls configs");
    ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("addr"),
        None,
        None,
        None,
        Arc::clone(&configs.unverified),
    )
    .with_tls_configs(configs)
}

/// A TLS peer serving `leaf`: counts completed handshakes and keeps every
/// connection open until the peer closes it, or until `close_after` reads.
pub(crate) struct Peer {
    pub(crate) address: SocketAddr,
    pub(crate) handshakes: Arc<AtomicUsize>,
}

pub(crate) async fn spawn_peer(
    leaf: &Leaf,
    client_ca: Option<&TestCa>,
    close_after_first_read: bool,
) -> Peer {
    use tokio_rustls::rustls::server::WebPkiClientVerifier;
    use tokio_rustls::rustls::ServerConfig;

    ensure_crypto_provider();
    let builder = ServerConfig::builder();
    let builder = match client_ca {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            let pem = ca.pem.clone();
            use tokio_rustls::rustls::pki_types::pem::PemObject;
            roots
                .add(CertificateDer::from_pem_slice(pem.as_bytes()).expect("ca der"))
                .expect("add client ca");
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .expect("client verifier"),
            )
        }
        None => builder.with_no_client_auth(),
    };
    let config = builder
        .with_single_cert(vec![leaf.der.clone()], leaf.key.clone_key())
        .expect("server config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("local addr");
    let handshakes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&handshakes);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                let mut buffer = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) if close_after_first_read => return,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    Peer {
        address,
        handshakes,
    }
}

/// The peer's handshake count once it stops moving. The peer counts a
/// handshake when its side completes, which can lag the client's.
async fn settled_handshakes(peer: &Peer) -> usize {
    let mut last = peer.handshakes.load(Ordering::SeqCst);
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = peer.handshakes.load(Ordering::SeqCst);
        if now == last && now > 0 {
            return now;
        }
        last = now;
    }
    last
}

fn ping() -> Bytes {
    Bytes::from_static(b"OPTIONS sip:gw.example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n")
}

// --- RFC 5922 §7 name rules ------------------------------------------------

#[test]
fn a_sip_uri_without_a_user_part_names_its_domain() {
    assert_eq!(
        sip_uri_domain("sip:example.net").as_deref(),
        Some("example.net")
    );
    assert_eq!(
        sip_uri_domain("SIP:Example.NET:5061;transport=tls").as_deref(),
        Some("example.net")
    );
    assert_eq!(
        sip_uri_domain("sip:[2001:db8::1]:5061").as_deref(),
        Some("2001:db8::1")
    );
}

#[test]
fn a_uri_naming_a_user_or_another_scheme_is_no_domain_identity() {
    assert_eq!(sip_uri_domain("sip:alice@example.net"), None);
    assert_eq!(sip_uri_domain("sips:example.net"), None);
    assert_eq!(sip_uri_domain("https://example.net"), None);
    assert_eq!(sip_uri_domain("sip:"), None);
    assert_eq!(sip_uri_domain("sip:[2001:db8::1"), None);
}

#[test]
fn matching_is_exact_ignores_case_and_a_root_dot_and_never_expands_a_wildcard() {
    let identities = vec!["gw.example.net".to_string(), "*.example.net".to_string()];
    assert!(matches_sip_domain("gw.example.net", &identities));
    assert!(matches_sip_domain("GW.Example.Net.", &identities));
    assert!(!matches_sip_domain("other.example.net", &identities));
    assert!(!matches_sip_domain("example.net", &identities));
}

#[test]
fn a_sip_uri_subject_alt_name_outranks_the_dns_names() {
    let ca = test_ca("rfc5922-ca");
    let certificate = leaf(&ca, vec![uri("sip:sip.example.net"), dns(ROUTED_HOST)]);
    assert_eq!(
        sip_domain_identities(certificate.der.as_ref()),
        vec!["sip.example.net".to_string()],
        "with a sip: URI present the dNSName entries are not SIP domain identities"
    );
}

#[test]
fn dns_names_are_the_identities_when_no_sip_uri_names_a_domain() {
    let ca = test_ca("rfc5922-ca");
    let certificate = leaf(
        &ca,
        vec![
            uri("sip:alice@example.net"),
            uri("https://example.net/"),
            dns("GW.example.net"),
        ],
    );
    assert_eq!(
        sip_domain_identities(certificate.der.as_ref()),
        vec!["gw.example.net".to_string()]
    );
}

#[test]
fn garbage_asserts_no_identity() {
    assert!(sip_domain_identities(b"not a certificate").is_empty());
}

#[test]
fn the_expected_name_is_the_routed_host_else_the_ip_literal() {
    let destination: SocketAddr = "192.0.2.10:5061".parse().expect("addr");
    assert_eq!(
        expected_server_name(destination, Some("GW.Example.net.")),
        "gw.example.net"
    );
    assert_eq!(expected_server_name(destination, None), "192.0.2.10");
    assert_eq!(
        expected_server_name(destination, Some("[2001:db8::1]")),
        "2001:db8::1"
    );
}

#[test]
fn a_bracketed_ipv6_host_is_an_ip_address_server_name() {
    let destination: SocketAddr = "[2001:db8::1]:5061".parse().expect("addr");
    let name = resolve_server_name(destination, Some("[2001:db8::1]"))
        .expect("a bracketed IPv6 host must be a valid server name");
    assert!(matches!(name, ServerName::IpAddress(_)), "{name:?}");
}

#[test]
fn an_unreadable_server_ca_names_the_path() {
    let error = match ServerVerification::new(true, Some("/nonexistent/siphon-server-ca.pem")) {
        Ok(_) => panic!("a missing server_ca must fail"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("/nonexistent/siphon-server-ca.pem"),
        "{error}"
    );
}

// --- Real handshakes through the pool ---------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_valid_certificate_for_the_routed_name_connects() {
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    let outcome = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await;
    assert!(outcome.is_ok(), "{:?}", outcome.err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_certificate_for_another_name_is_refused() {
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns("other.example.net")]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    let error = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .expect_err("a certificate for another name must be refused");
    assert!(
        error.to_string().to_lowercase().contains("certificate"),
        "{error}"
    );
    assert_eq!(
        pool.active_connections(),
        0,
        "a refused connection is never pooled"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_certificate_is_refused_for_a_sip_domain() {
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns("*.example.net")]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    assert!(
        pool.send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
            .await
            .is_err(),
        "RFC 5922 §7.2: a wildcard must not match a SIP domain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sip_uri_only_certificate_connects() {
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![uri("sip:gw.example.net")]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    let outcome = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await;
    assert!(outcome.is_ok(), "{:?}", outcome.err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untrusted_ca_is_refused() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let pool = pool_with(&verification, None);

    assert!(pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verification_off_accepts_any_certificate_as_before() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns("other.example.net")]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let pool = pool_with(&verification, None);

    // Default off: plain send_tls and an explicit `false` both connect.
    assert!(pool
        .send_tls(peer.address, Some(ROUTED_HOST), ping())
        .await
        .is_ok());
    assert!(pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(false), ping())
        .await
        .is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ip_literal_target_needs_an_ip_address_subject_alt_name() {
    let ca = test_ca("verify-ca");
    let (_directory, verification) = trusting(&ca, false);

    let with_ip = spawn_peer(&leaf(&ca, vec![ip("127.0.0.1")]), None, false).await;
    let pool = pool_with(&verification, None);
    let outcome = pool
        .send_tls_with_policy(with_ip.address, None, Some(true), ping())
        .await;
    assert!(outcome.is_ok(), "{:?}", outcome.err());

    let dns_only = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, false).await;
    let pool = pool_with(&verification, None);
    assert!(
        pool.send_tls_with_policy(dns_only.address, None, Some(true), ping())
            .await
            .is_err(),
        "an IP-literal target is checked against the IP, never a DNS name"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_destination_setting_beats_the_global_default() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns(ROUTED_HOST)]), None, false).await;

    // Global on: a destination saying `false` is not verified.
    let (_on, verify_all) = trusting(&trusted, true);
    let pool = pool_with(&verify_all, None);
    assert!(pool.verifies(None) && !pool.verifies(Some(false)));
    assert!(
        pool.send_tls(peer.address, Some(ROUTED_HOST), ping())
            .await
            .is_err(),
        "tls.verify_server applies to a send naming no policy"
    );
    assert!(pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(false), ping())
        .await
        .is_ok());

    // Global off: a destination saying `true` is verified.
    let (_off, verify_none) = trusting(&trusted, false);
    let pool = pool_with(&verify_none, None);
    assert!(!pool.verifies(None) && pool.verifies(Some(true)));
    assert!(pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unverified_connection_is_never_reused_for_a_verified_send() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let pool = pool_with(&verification, None);

    pool.send_tls(peer.address, Some(ROUTED_HOST), ping())
        .await
        .expect("the unverified send connects");
    assert_eq!(pool.active_connections(), 1);

    // Reusing the pooled connection would have succeeded; verification
    // refusing it proves a fresh, verified handshake was attempted.
    assert!(pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .is_err());
    assert_eq!(pool.active_connections(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_and_unverified_sends_hold_separate_connections() {
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    let verified = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .expect("verified");
    let unverified = pool
        .send_tls(peer.address, Some(ROUTED_HOST), ping())
        .await
        .expect("unverified");
    assert_ne!(verified, unverified);
    assert_eq!(pool.active_connections(), 2);

    // Each policy reuses its own connection.
    let again = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .expect("verified again");
    assert_eq!(again, verified);
    assert_eq!(settled_handshakes(&peer).await, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_address_routed_send_reuses_the_connection_verified_for_its_name() {
    // The certificate carries no IP SAN, so a fresh handshake against the IP
    // literal would be refused: success proves the verified connection opened
    // for the routed name was reused (an in-dialog request to the dialog peer).
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    let first = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .expect("verified by name");
    let in_dialog = pool
        .send_tls_with_policy(peer.address, None, Some(true), ping())
        .await
        .expect("an address-routed verified send reuses the named connection");
    assert_eq!(first, in_dialog);
    assert_eq!(settled_handshakes(&peer).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_certificate_is_still_presented_with_verification_on() {
    let ca = test_ca("verify-ca");
    let server_leaf = leaf(&ca, vec![dns(ROUTED_HOST)]);
    let peer = spawn_peer(&server_leaf, Some(&ca), false).await;

    // A client identity signed by the same CA, through the production loader.
    let client_key = KeyPair::generate().expect("client keygen");
    let mut client_params =
        CertificateParams::new(vec!["siphon-client".to_string()]).expect("client params");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params
        .signed_by(&client_key, &ca.issuer)
        .expect("client sign");
    let directory = tempfile::tempdir().expect("temp dir");
    let certificate_path = directory.path().join("client.crt");
    let key_path = directory.path().join("client.key");
    std::fs::write(&certificate_path, client_certificate.pem()).expect("write cert");
    std::fs::write(&key_path, client_key.serialize_pem()).expect("write key");
    let identity = load_outbound_client_identity(
        &certificate_path.to_string_lossy(),
        &key_path.to_string_lossy(),
    )
    .expect("identity");

    let (_ca_directory, verification) = trusting(&ca, true);
    let pool = pool_with(&verification, Some(identity));
    pool.send_tls(peer.address, Some(ROUTED_HOST), ping())
        .await
        .expect("verified mutual TLS connects");
    // TLS 1.3 reports a refused client certificate after the client's side of
    // the handshake: the peer counting the handshake is the real check.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while peer.handshakes.load(Ordering::SeqCst) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer never accepted the client certificate"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verified_send_without_a_verifying_config_is_refused_not_downgraded() {
    ensure_crypto_provider();
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, false).await;
    let pool = ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("addr"),
        None,
        None,
        None,
        build_outbound_tls_config(None, TlsMethod::default()).expect("config"),
    );
    let error = pool
        .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
        .await
        .expect_err("no verifying config must refuse");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(peer.handshakes.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn verified_connections_drain_from_the_pool_when_the_peer_closes() {
    // The pool key gained the verified name; a closed verified connection must
    // still leave the pool, or every refreshed trunk connection would leak a
    // key.
    let ca = test_ca("verify-ca");
    let peer = spawn_peer(&leaf(&ca, vec![dns(ROUTED_HOST)]), None, true).await;
    let (_directory, verification) = trusting(&ca, false);
    let pool = pool_with(&verification, None);

    for _ in 0..20 {
        let _ = pool
            .send_tls_with_policy(peer.address, Some(ROUTED_HOST), Some(true), ping())
            .await;
        let _ = pool.send_tls(peer.address, Some(ROUTED_HOST), ping()).await;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while pool.active_connections() > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "closed connections never left the pool: {}",
                pool.active_connections()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    assert!(!pool.has_live(peer.address, crate::transport::Transport::Tls));
    assert!(peer.handshakes.load(Ordering::SeqCst) >= 20);
}
