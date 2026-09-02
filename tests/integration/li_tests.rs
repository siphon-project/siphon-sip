//! End-to-end lawful-interception tests: ETSI X1 provisioning through to X2
//! delivery, over real sockets where the point is the transport.
//!
//! The protocol-level tests live beside the code in `src/li/x1/`. What lives
//! here is the whole pipeline: a real mutual-TLS X1 listener, a real ADMF
//! client, and the path from a provisioned warrant to an IRI record on the
//! wire.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use siphon::config::{LawfulInterceptConfig, LiX1Config, LiX1TlsConfig};
use siphon::li::x1::message::{DestinationDetails, TaskDetails};
use siphon::li::x1::server::{serve, PeerIdentity, X1Server};
use siphon::li::x1::store::{ContentCapability, DestinationStore, TaskStore};
use siphon::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, IpAddressPort, Port, TargetIdentifier, XId, DEFAULT_VERSION,
};
use siphon::li::{IriEventType, LiManager};

const ADMF: &str = "admf-id";
const NE: &str = "siphon-ne";

/// Install the rustls crypto provider once per test process.
///
/// The binary does this in `Server::run` before any TLS operation; a test
/// binary has no such entry point, so every test that opens a TLS socket calls
/// this first. `install_default` fails if a provider is already installed,
/// which is exactly what happens on the second call — hence the ignored result.
fn install_crypto_provider() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    });
}

// ---------------------------------------------------------------------------
// Certificate fixtures
// ---------------------------------------------------------------------------

/// A CA plus a server and client certificate signed by it.
struct TestPki {
    ca_pem: String,
    server_cert_pem: String,
    server_key_pem: String,
    client_cert_pem: String,
    client_key_pem: String,
    /// A second, unrelated CA and a client signed by it.
    foreign_client_cert_pem: String,
    foreign_client_key_pem: String,
}

fn generate_pki(client_common_name: &str) -> TestPki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};

    let make_ca = |name: &str| {
        let key = KeyPair::generate().expect("ca keygen");
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.self_signed(&key).expect("ca self-sign");
        (certificate.pem(), Issuer::new(params, key))
    };

    let (ca_pem, issuer) = make_ca("Test LI Root");
    let (_foreign_ca_pem, foreign_issuer) = make_ca("Unrelated Root");

    // Server certificate, valid for localhost.
    let server_key = KeyPair::generate().expect("server keygen");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, NE);
    server_params.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().expect("dns name")),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .expect("server sign");

    let make_client = |name: &str, issuer: &Issuer<'_, KeyPair>| {
        let key = KeyPair::generate().expect("client keygen");
        let mut params = CertificateParams::new(Vec::new()).expect("client params");
        params.distinguished_name.push(DnType::CommonName, name);
        let certificate = params.signed_by(&key, issuer).expect("client sign");
        (certificate.pem(), key.serialize_pem())
    };

    let (client_cert_pem, client_key_pem) = make_client(client_common_name, &issuer);
    let (foreign_client_cert_pem, foreign_client_key_pem) =
        make_client(client_common_name, &foreign_issuer);

    TestPki {
        ca_pem,
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem,
        client_key_pem,
        foreign_client_cert_pem,
        foreign_client_key_pem,
    }
}

/// Write a PEM to a file in `directory` and return its path.
fn write_pem(directory: &tempfile::TempDir, name: &str, contents: &str) -> String {
    let path = directory.path().join(name);
    let mut file = std::fs::File::create(&path).expect("write pem");
    file.write_all(contents.as_bytes()).expect("write pem");
    path.to_string_lossy().into_owned()
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn x1_config(directory: &tempfile::TempDir, pki: &TestPki) -> LiX1Config {
    LiX1Config {
        listen: "127.0.0.1:0".to_string(),
        path: "/X1/NE".to_string(),
        tls: LiX1TlsConfig {
            certificate: write_pem(directory, "server.pem", &pki.server_cert_pem),
            private_key: write_pem(directory, "server.key", &pki.server_key_pem),
            client_ca: write_pem(directory, "ca.pem", &pki.ca_pem),
        },
        ne_identifier: NE.to_string(),
        admf_identifier: Some(ADMF.to_string()),
        version: DEFAULT_VERSION.to_string(),
        bind_admf_identifier_to_certificate: true,
        admf: None,
    }
}

fn li_config() -> LawfulInterceptConfig {
    LawfulInterceptConfig {
        enabled: true,
        audit_log: None,
        x1: None,
        x2: None,
        x3: None,
        siprec: None,
    }
}

fn destination(d_id: DId, delivery: DeliveryType, port: u16) -> DestinationDetails {
    DestinationDetails {
        d_id,
        friendly_name: Some("test mdf".to_string()),
        delivery_type: delivery,
        delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
            port: Port::Tcp(port),
        }),
    }
}

fn task(x_id: XId, d_id: DId, delivery: DeliveryType, target: &str) -> TaskDetails {
    TaskDetails {
        x_id,
        target_identifiers: vec![TargetIdentifier::SipUri(target.to_string())],
        delivery_type: delivery,
        list_of_dids: vec![d_id],
        list_of_dsids: Vec::new(),
        list_of_mediation_details: Vec::new(),
        correlation_id: None,
        implicit_deactivation_allowed: None,
        product_id: None,
        list_of_service_types: Vec::new(),
    }
}

/// Build an `X1Request` container holding one message.
fn request(type_name: &str, payload: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"
           xmlns:c="http://uri.etsi.org/03280/common/2017/07"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <x1RequestMessage xsi:type="{type_name}">
    <admfIdentifier>{ADMF}</admfIdentifier>
    <neIdentifier>{NE}</neIdentifier>
    <messageTimestamp>2026-08-31T09:00:00.000000Z</messageTimestamp>
    <version>{DEFAULT_VERSION}</version>
    <x1TransactionId>{}</x1TransactionId>
    {payload}
  </x1RequestMessage>
</X1Request>"#,
        XId::generate()
    )
}

fn create_destination_xml(d_id: DId, delivery: DeliveryType) -> String {
    request(
        "CreateDestinationRequest",
        &format!(
            r#"<destinationDetails>
      <dId>{d_id}</dId>
      <deliveryType>{delivery}</deliveryType>
      <deliveryAddress>
        <ipAddressAndPort>
          <c:address><c:IPv4Address>192.0.2.50</c:IPv4Address></c:address>
          <c:port><c:TCPPort>42069</c:TCPPort></c:port>
        </ipAddressAndPort>
      </deliveryAddress>
    </destinationDetails>"#
        ),
    )
}

fn activate_task_xml(x_id: XId, d_id: DId, delivery: DeliveryType, target: &str) -> String {
    request(
        "ActivateTaskRequest",
        &format!(
            r#"<taskDetails>
      <xId>{x_id}</xId>
      <targetIdentifiers>
        <targetIdentifier><sipUri>{target}</sipUri></targetIdentifier>
      </targetIdentifiers>
      <deliveryType>{delivery}</deliveryType>
      <listOfDIDs><dId>{d_id}</dId></listOfDIDs>
    </taskDetails>"#
        ),
    )
}

fn build_server(config: &LiX1Config, manager: &LiManager) -> Arc<X1Server> {
    let audit_manager = manager.clone();
    let hook: siphon::li::x1::server::AuditHook = Arc::new(move |operation, subject, detail| {
        audit_manager.audit(
            siphon::li::AuditOperation::Provisioning(operation.to_string()),
            subject,
            detail,
        );
    });
    Arc::new(
        X1Server::new(
            config,
            manager.tasks().clone(),
            manager.destinations().clone(),
            hook,
        )
        .expect("X1 server must build"),
    )
}

// ---------------------------------------------------------------------------
// Provisioning through to interception
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_provisioned_warrant_is_matched_and_produces_an_iri_record() {
    let (manager, mut iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let server = build_server(&config, &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    let x_id = XId::generate();
    let response =
        server.handle_container(&create_destination_xml(d_id, DeliveryType::X2AndX3), &peer);
    assert!(response.contains("CreateDestinationResponse"), "{response}");
    let response = server.handle_container(
        &activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );
    assert!(response.contains("ActivateTaskResponse"), "{response}");

    // The warrant is now findable by the matching path the dispatcher uses.
    let matched = manager.check_message(None, Some("sip:alice@example.com"), None, None);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].task.details.x_id, x_id);

    let event = manager.build_iri_event(
        &matched[0],
        IriEventType::Begin,
        "call-1@example.com",
        "INVITE",
        None,
        "sip:alice@example.com",
        "sip:bob@example.com",
        Some("sip:bob@example.com".to_string()),
        None,
        None,
    );
    manager.emit_iri(event);

    let delivered = iri.recv().await.expect("an IRI record must be delivered");
    assert_eq!(delivered.x_id, x_id);
    assert_ne!(delivered.correlation_id, 0);
    assert_eq!(
        delivered.destinations.len(),
        1,
        "only the named destination"
    );
}

#[tokio::test]
async fn deactivating_a_task_over_x1_stops_it_matching() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    let x_id = XId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2Only), &peer);
    server.handle_container(
        &activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );
    assert!(!manager
        .check_message(None, Some("sip:alice@example.com"), None, None)
        .is_empty());

    let response = server.handle_container(
        &request("DeactivateTaskRequest", &format!("<xId>{x_id}</xId>")),
        &peer,
    );
    assert!(response.contains("DeactivateTaskResponse"), "{response}");

    assert!(
        manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty(),
        "a deactivated warrant must stop matching"
    );
}

#[tokio::test]
async fn modifying_a_task_over_x1_moves_the_matching_target() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    let x_id = XId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2Only), &peer);
    server.handle_container(
        &activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );

    let modify = activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:bob@example.com")
        .replace("ActivateTaskRequest", "ModifyTaskRequest");
    let response = server.handle_container(&modify, &peer);
    assert!(response.contains("ModifyTaskResponse"), "{response}");

    assert!(
        manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .is_empty(),
        "the old target must stop matching"
    );
    assert!(
        !manager
            .check_message(None, Some("sip:bob@example.com"), None, None)
            .is_empty(),
        "the new target must start matching"
    );
}

#[tokio::test]
async fn a_task_delivers_only_to_the_destinations_it_names() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let named = DId::generate();
    let unnamed = DId::generate();
    server.handle_container(&create_destination_xml(named, DeliveryType::X2AndX3), &peer);
    server.handle_container(
        &create_destination_xml(unnamed, DeliveryType::X2AndX3),
        &peer,
    );

    let x_id = XId::generate();
    server.handle_container(
        &activate_task_xml(x_id, named, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );

    let resolved = manager.tasks().destinations_for(x_id);
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].details.d_id, named);
}

#[tokio::test]
async fn removing_a_destination_a_task_uses_is_refused() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    let x_id = XId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2Only), &peer);
    server.handle_container(
        &activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );

    let response = server.handle_container(
        &request("RemoveDestinationRequest", &format!("<dId>{d_id}</dId>")),
        &peer,
    );
    assert!(
        response.contains("<errorCode>7010</errorCode>"),
        "{response}"
    );
    assert!(manager.destinations().contains(d_id));

    // Once the task is gone, the destination can be removed.
    server.handle_container(
        &request("DeactivateTaskRequest", &format!("<xId>{x_id}</xId>")),
        &peer,
    );
    let response = server.handle_container(
        &request("RemoveDestinationRequest", &format!("<dId>{d_id}</dId>")),
        &peer,
    );
    assert!(response.contains("RemoveDestinationResponse"), "{response}");
}

// ---------------------------------------------------------------------------
// The capability gate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_content_warrant_is_refused_on_a_backend_that_cannot_deliver_content() {
    let (manager, _iri, _audit) = LiManager::new(
        li_config(),
        100,
        ContentCapability::WrongBackend {
            backend: "rtpengine",
        },
    );
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2AndX3), &peer);
    let response = server.handle_container(
        &activate_task_xml(
            XId::generate(),
            d_id,
            DeliveryType::X2AndX3,
            "sip:alice@example.com",
        ),
        &peer,
    );

    assert!(
        response.contains("<errorCode>3040</errorCode>"),
        "{response}"
    );
    assert!(
        manager.tasks().is_empty(),
        "a warrant that cannot be honoured must not read as provisioned"
    );
}

#[test]
fn configuring_x3_on_a_backend_that_cannot_deliver_it_fails_at_load() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x3:\n",
        "    enabled: true\n",
    );
    let error = siphon::config::Config::from_str(yaml)
        .expect_err("X3 on the default backend must be refused at load");
    let text = error.to_string();
    assert!(text.contains("lawful_intercept.x3"), "{text}");
    assert!(text.contains("siphon-rtp"), "{text}");
}

#[test]
fn configuring_x3_on_the_native_backend_loads() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x3:\n",
        "    enabled: true\n",
        "media:\n",
        "  backend: siphon-rtp\n",
    );
    siphon::config::Config::from_str(yaml).expect("X3 on siphon-rtp must load");
}

/// `enabled: false` is what the flag is for: it says content is off without
/// deleting the block, and a node that delivers no content is not held to the
/// backend requirement.
#[test]
fn x3_switched_off_does_not_require_the_native_backend() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x3:\n",
        "    enabled: false\n",
    );
    let config = siphon::config::Config::from_str(yaml)
        .expect("content switched off must load on any backend");
    let x3 = config
        .lawful_intercept
        .expect("lawful_intercept must parse")
        .x3
        .expect("the x3 block must parse");
    assert!(!x3.enabled);
}

/// Writing the block has to be a statement. An empty one is a mistake, not a
/// silent yes.
#[test]
fn an_x3_block_without_enabled_is_refused() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x3: {}\n",
        "media:\n",
        "  backend: siphon-rtp\n",
    );
    let error = siphon::config::Config::from_str(yaml)
        .expect_err("an x3 block must say whether content is on");
    assert!(error.to_string().contains("enabled"), "{error}");
}

#[test]
fn x2_only_needs_no_particular_media_backend() {
    // X1 and X2 are backend-independent; only X3 is gated.
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x2:\n",
        "    delivery_address: \"192.0.2.50:6543\"\n",
    );
    siphon::config::Config::from_str(yaml).expect("X2 must load on any backend");
}

// ---------------------------------------------------------------------------
// Mutual TLS over a real socket
// ---------------------------------------------------------------------------

/// Bind a real X1 listener and return its address.
async fn start_listener(config: LiX1Config, manager: &LiManager) -> SocketAddr {
    install_crypto_provider();
    let server = build_server(&config, manager);
    serve(Arc::new(config), server)
        .await
        .expect("the X1 listener must bind")
}

/// An HTTPS client presenting the given client certificate.
fn client_with(pki: &TestPki, certificate: &str, key: &str) -> reqwest::Client {
    install_crypto_provider();
    let mut identity_pem = certificate.as_bytes().to_vec();
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(key.as_bytes());
    reqwest::Client::builder()
        .identity(reqwest::Identity::from_pem(&identity_pem).expect("client identity"))
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).expect("root"))
        .build()
        .expect("client")
}

#[tokio::test]
async fn a_client_with_a_trusted_certificate_is_served() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let path = config.path.clone();
    let address = start_listener(config, &manager).await;

    let client = client_with(&pki, &pki.client_cert_pem, &pki.client_key_pem);
    let response = client
        .post(format!("https://localhost:{}{path}", address.port()))
        .header("content-type", "application/xml")
        .body(request("PingRequest", ""))
        .send()
        .await
        .expect("the request must reach the listener");

    assert!(response.status().is_success());
    let body = response.text().await.expect("body");
    assert!(body.contains("PingResponse"), "{body}");
}

#[tokio::test]
async fn a_client_with_no_certificate_is_rejected() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let path = config.path.clone();
    let address = start_listener(config, &manager).await;

    install_crypto_provider();
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(pki.ca_pem.as_bytes()).expect("root"))
        .build()
        .expect("client");

    let result = client
        .post(format!("https://localhost:{}{path}", address.port()))
        .body(request("PingRequest", ""))
        .send()
        .await;
    assert!(
        result.is_err(),
        "a client presenting no certificate must not be served"
    );
}

#[tokio::test]
async fn a_client_signed_by_an_unknown_ca_is_rejected() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let path = config.path.clone();
    let address = start_listener(config, &manager).await;

    let client = client_with(
        &pki,
        &pki.foreign_client_cert_pem,
        &pki.foreign_client_key_pem,
    );
    let result = client
        .post(format!("https://localhost:{}{path}", address.port()))
        .body(request("PingRequest", ""))
        .send()
        .await;
    assert!(
        result.is_err(),
        "a client signed by an unrelated CA must not be served"
    );
}

#[tokio::test]
async fn a_listener_whose_client_ca_is_unreadable_fails_to_start() {
    // Fail closed: X1 provisions warrants, so a listener that would accept
    // anyone must not come up at all.
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let mut config = x1_config(&directory, &pki);
    config.tls.client_ca = "/nonexistent/admf-ca.pem".to_string();

    install_crypto_provider();
    let server = build_server(&config, &manager);
    let result = serve(Arc::new(config), server).await;
    assert!(
        result.is_err(),
        "a missing client CA must be a startup error"
    );
}

#[tokio::test]
async fn a_listener_whose_client_ca_holds_no_certificates_fails_to_start() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let mut config = x1_config(&directory, &pki);
    config.tls.client_ca = write_pem(&directory, "empty-ca.pem", "# no certificates here\n");

    install_crypto_provider();
    let server = build_server(&config, &manager);
    let result = serve(Arc::new(config), server).await;
    assert!(
        result.is_err(),
        "an empty client CA bundle must be a startup error, not a listener that accepts anyone"
    );
}

#[tokio::test]
async fn the_certificate_common_name_is_bound_to_the_admf_identifier() {
    // The reason X1 owns its own listener: the message's claim about who sent
    // it is checked against what TLS proved.
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    // A client whose certificate names someone other than the admfIdentifier
    // its messages carry.
    let pki = generate_pki("not-the-admf");
    let config = x1_config(&directory, &pki);
    let path = config.path.clone();
    let address = start_listener(config, &manager).await;

    let client = client_with(&pki, &pki.client_cert_pem, &pki.client_key_pem);
    let response = client
        .post(format!("https://localhost:{}{path}", address.port()))
        .body(request("PingRequest", ""))
        .send()
        .await
        .expect("the handshake succeeds — the certificate is trusted, just not this ADMF");

    let body = response.text().await.expect("body");
    assert!(
        body.contains("<errorCode>1030</errorCode>"),
        "expected AdmfIdentifierDoesNotMatchCertificateDetails, got: {body}"
    );
}

#[tokio::test]
async fn a_request_to_the_wrong_path_is_not_served() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let address = start_listener(config, &manager).await;

    let client = client_with(&pki, &pki.client_cert_pem, &pki.client_key_pem);
    let response = client
        .post(format!(
            "https://localhost:{}/not/the/x1/path",
            address.port()
        ))
        .body(request("PingRequest", ""))
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn a_full_provisioning_round_trip_over_mutual_tls() {
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let config = x1_config(&directory, &pki);
    let path = config.path.clone();
    let address = start_listener(config, &manager).await;
    let client = client_with(&pki, &pki.client_cert_pem, &pki.client_key_pem);
    let url = format!("https://localhost:{}{path}", address.port());

    let post = |body: String| {
        let client = client.clone();
        let url = url.clone();
        async move {
            client
                .post(url)
                .header("content-type", "application/xml")
                .body(body)
                .send()
                .await
                .expect("request")
                .text()
                .await
                .expect("body")
        }
    };

    let d_id = DId::generate();
    let x_id = XId::generate();

    let created = post(create_destination_xml(d_id, DeliveryType::X2AndX3)).await;
    assert!(created.contains("CreateDestinationResponse"), "{created}");

    let activated = post(activate_task_xml(
        x_id,
        d_id,
        DeliveryType::X2Only,
        "sip:alice@example.com",
    ))
    .await;
    assert!(activated.contains("ActivateTaskResponse"), "{activated}");

    let all = post(request("GetAllDetailsRequest", "")).await;
    assert!(all.contains(&x_id.to_string()), "{all}");
    assert!(all.contains(&d_id.to_string()), "{all}");

    // And the warrant is live on the matching path.
    assert_eq!(
        manager
            .check_message(None, Some("sip:alice@example.com"), None, None)
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// The enforcement change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interception_does_not_depend_on_the_script_calling_anything() {
    // The regression guard for the compliance change. Interception is decided
    // by the dispatcher against provisioned warrants; a script that never
    // calls `li.intercept()` must not be able to prevent it.
    //
    // This asserts the property at the layer the dispatcher uses: matching is
    // a function of the provisioned task store alone, reachable with no script
    // in the picture at all. If the gate ever moves back into Python, the
    // matching call will need a script context and this stops compiling — or,
    // worse, starts returning nothing, which is what the assertion catches.
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    let x_id = XId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2Only), &peer);
    server.handle_container(
        &activate_task_xml(x_id, d_id, DeliveryType::X2Only, "sip:alice@example.com"),
        &peer,
    );

    // No script has run. No `li.*` call has been made. The warrant still
    // matches, on every identity the message carries.
    for (ruri, from, to) in [
        (Some("sip:alice@example.com"), None, None),
        (None, Some("sip:alice@example.com"), None),
        (None, None, Some("sip:alice@example.com")),
    ] {
        let matched = manager.check_message(ruri, from, to, None);
        assert_eq!(
            matched.len(),
            1,
            "the warrant must match on {ruri:?}/{from:?}/{to:?} with no script involvement"
        );
        assert_eq!(matched[0].task.details.x_id, x_id);
    }
}

#[tokio::test]
async fn every_leg_of_a_call_is_matched_not_just_the_first() {
    // The failure mode the enforcement change exists to prevent: a script that
    // acted on the A-leg and forgot the B-leg intercepted half the call.
    let (manager, _iri, _audit) = LiManager::new(li_config(), 100, ContentCapability::Available);
    let directory = tempfile::tempdir().expect("tempdir");
    let pki = generate_pki(ADMF);
    let server = build_server(&x1_config(&directory, &pki), &manager);
    let peer = PeerIdentity {
        common_name: Some(ADMF.to_string()),
    };

    let d_id = DId::generate();
    server.handle_container(&create_destination_xml(d_id, DeliveryType::X2Only), &peer);
    server.handle_container(
        &activate_task_xml(
            XId::generate(),
            d_id,
            DeliveryType::X2Only,
            "sip:alice@example.com",
        ),
        &peer,
    );

    // A-leg INVITE: alice calls bob.
    assert_eq!(
        manager
            .check_message(
                Some("sip:bob@example.com"),
                Some("sip:alice@example.com"),
                Some("sip:bob@example.com"),
                None
            )
            .len(),
        1
    );
    // B-leg INVITE built by the B2BUA: the same warrant still applies,
    // because alice is still the From.
    assert_eq!(
        manager
            .check_message(
                Some("sip:bob@carrier.example"),
                Some("sip:alice@example.com"),
                Some("sip:bob@carrier.example"),
                None
            )
            .len(),
        1
    );
    // And the 200 OK coming back.
    assert_eq!(
        manager
            .check_message(
                None,
                Some("sip:alice@example.com"),
                Some("sip:bob@example.com"),
                None
            )
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

#[test]
fn restarting_restores_provisioned_state_from_the_admf() {
    use siphon::li::x1::client::{apply_reconciled_state, ReconciledState};

    // Before the restart: what the ADMF has.
    let d_id = DId::generate();
    let x_id = XId::generate();
    let admf_view = ReconciledState {
        tasks: vec![task(
            x_id,
            d_id,
            DeliveryType::X2Only,
            "sip:alice@example.com",
        )],
        destinations: vec![destination(d_id, DeliveryType::X2AndX3, 42069)],
    };

    // After the restart: empty stores.
    let destinations = DestinationStore::new();
    let tasks = TaskStore::new(destinations.clone(), ContentCapability::Available);
    assert!(tasks.is_empty());

    let rejected = apply_reconciled_state(&admf_view, &tasks, &destinations);
    assert!(rejected.is_empty(), "{rejected:?}");
    assert_eq!(tasks.len(), 1);
    assert_eq!(destinations.len(), 1);

    // And the restored warrant matches, so interception resumes.
    assert_eq!(
        tasks
            .match_message(None, Some("sip:alice@example.com"), None, None)
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[test]
fn the_x1_block_parses_with_its_defaults() {
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x1:\n",
        "    listen: \"0.0.0.0:8443\"\n",
        "    ne_identifier: \"siphon-ne-1\"\n",
        "    tls:\n",
        "      certificate: \"/etc/siphon/li/x1.pem\"\n",
        "      private_key: \"/etc/siphon/li/x1.key\"\n",
        "      client_ca: \"/etc/siphon/li/admf-ca.pem\"\n",
    );
    let config = siphon::config::Config::from_str(yaml).expect("config must parse");
    let x1 = config
        .lawful_intercept
        .expect("lawful_intercept")
        .x1
        .expect("x1");
    assert_eq!(x1.path, "/X1/NE");
    assert_eq!(x1.version, DEFAULT_VERSION);
    assert!(x1.bind_admf_identifier_to_certificate);
    assert!(x1.admf.is_none(), "the outbound direction is opt-in");
}

#[test]
fn an_x1_block_without_a_client_ca_is_refused() {
    // Mutual TLS is the authentication on X1; a listener without a client CA
    // would accept anyone, so the field is mandatory.
    let yaml = concat!(
        "listen:\n",
        "  udp:\n",
        "    - \"0.0.0.0:5060\"\n",
        "domain:\n",
        "  local:\n",
        "    - \"example.com\"\n",
        "script:\n",
        "  path: \"scripts/proxy_default.py\"\n",
        "lawful_intercept:\n",
        "  enabled: true\n",
        "  x1:\n",
        "    listen: \"0.0.0.0:8443\"\n",
        "    ne_identifier: \"siphon-ne-1\"\n",
        "    tls:\n",
        "      certificate: \"/etc/siphon/li/x1.pem\"\n",
        "      private_key: \"/etc/siphon/li/x1.key\"\n",
    );
    assert!(
        siphon::config::Config::from_str(yaml).is_err(),
        "an X1 listener with no client CA must be refused at load"
    );
}
