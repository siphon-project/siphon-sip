//! Per-listener mutual TLS, from `siphon.yaml` to the socket.
//!
//! A config with two `listen.tls` entries (one plain, one demanding a client
//! certificate with a `client_subject`) and one `listen.wss` entry is loaded
//! the way the server loads it, and each listener is started the way the
//! server starts it: `tls.for_listener(entry.client_auth())` handed to the
//! transport. Real rustls clients then prove the two listeners built from one
//! `tls:` block disagree about client certificates exactly as configured.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::rustls;

use siphon::config::{Config, ListenEntry, TlsServerConfig};
use siphon::transport::acl::TransportAcl;
use siphon::transport::StreamConnections;
use siphon::transport::{tls, ws, ConnectionId, InboundMessage, OutboundMessage};

const SIP_OPTIONS: &str = concat!(
    "OPTIONS sip:siphon.example.net SIP/2.0\r\n",
    "Via: SIP/2.0/TLS 192.0.2.20:5061;branch=z9hG4bK-mtls-1\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:peer@example.net>;tag=mtls-1\r\n",
    "To: <sip:siphon.example.net>\r\n",
    "Call-ID: mtls-1@192.0.2.20\r\n",
    "CSeq: 1 OPTIONS\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

type ClientIdentity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

/// A client CA plus the server certificate, on disk.
struct Fixture {
    directory: tempfile::TempDir,
    ca_certificate: rcgen::Certificate,
    ca_issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

impl Fixture {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().expect("a temporary directory");

        let ca_key = rcgen::KeyPair::generate().expect("keygen");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "trunk client CA");
        let ca_certificate = ca_params.self_signed(&ca_key).expect("self-sign CA");
        std::fs::write(directory.path().join("trunk-ca.pem"), ca_certificate.pem()).unwrap();
        let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

        let server_key = rcgen::KeyPair::generate().expect("keygen");
        let server = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("params")
            .self_signed(&server_key)
            .expect("self-sign server");
        std::fs::write(directory.path().join("server.pem"), server.pem()).unwrap();
        std::fs::write(
            directory.path().join("server.key"),
            server_key.serialize_pem(),
        )
        .unwrap();

        Self {
            directory,
            ca_certificate,
            ca_issuer,
        }
    }

    fn path(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    /// A config whose `listen:` holds `listen_block`, `{ca}` in it replaced by
    /// the client CA path. (A tls and a wss entry on one address would be one
    /// muxed socket, so the TLS and WSS cases each get their own config.)
    fn config(&self, listen_block: &str) -> Config {
        let yaml = format!(
            concat!(
                "listen:\n",
                "{listen}",
                "domain:\n",
                "  local: [\"siphon.example.net\"]\n",
                "tls:\n",
                "  certificate: \"{certificate}\"\n",
                "  private_key: \"{key}\"\n",
            ),
            listen = listen_block.replace("{ca}", &self.path("trunk-ca.pem")),
            certificate = self.path("server.pem"),
            key = self.path("server.key"),
        );
        Config::from_str(&yaml).expect("the config loads")
    }

    fn client_identity(&self, dns_name: &str) -> ClientIdentity {
        let key = rcgen::KeyPair::generate().expect("keygen");
        let mut params = rcgen::CertificateParams::new(vec![dns_name.to_string()]).unwrap();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let certificate = params.signed_by(&key, &self.ca_issuer).expect("sign");
        (
            vec![certificate.der().clone(), self.ca_certificate.der().clone()],
            PrivateKeyDer::try_from(key.serialize_der()).expect("key der"),
        )
    }

    fn connector(&self, identity: Option<ClientIdentity>) -> tokio_rustls::TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_file_iter(self.path("server.pem")).unwrap() {
            roots.add(certificate.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let config = match identity {
            Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
            None => builder.with_no_client_auth(),
        };
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}

struct SipListener {
    address: SocketAddr,
    inbound: flume::Receiver<InboundMessage>,
    _outbound: flume::Sender<OutboundMessage>,
}

/// Start one `listen.tls` entry exactly as the server does.
async fn start_tls(block: &TlsServerConfig, entry: &ListenEntry) -> SipListener {
    let (inbound_tx, inbound) = flume::unbounded();
    let (outbound, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let address = tls::listen(
        entry.address().parse().expect("listen address"),
        &block.for_listener(entry.client_auth()),
        inbound_tx,
        outbound_rx,
        connection_map,
        Arc::new(TransportAcl::new(vec![], vec![])),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("the TLS listener binds");
    SipListener {
        address,
        inbound,
        _outbound: outbound,
    }
}

/// Whether a SIP request sent over a TLS session from `connector` reaches the
/// core. A refused client may still finish its own half of a TLS 1.3
/// handshake, so delivery to the core is the verdict, not the client's
/// `connect` result.
async fn delivered(listener: &SipListener, connector: tokio_rustls::TlsConnector) -> bool {
    let tcp = tokio::net::TcpStream::connect(listener.address)
        .await
        .expect("TCP connect");
    let name = ServerName::try_from("localhost").unwrap();
    let Ok(mut session) = connector.connect(name, tcp).await else {
        return false;
    };
    if session.write_all(SIP_OPTIONS.as_bytes()).await.is_err() {
        return false;
    }
    let _ = session.flush().await;
    matches!(
        tokio::time::timeout(Duration::from_secs(2), listener.inbound.recv_async()).await,
        Ok(Ok(_))
    )
}

#[tokio::test]
async fn two_tls_listeners_from_one_tls_block_differ_in_client_certificate_policy() {
    let fixture = Fixture::new();
    let config = fixture.config(concat!(
        "  tls:\n",
        "    - \"127.0.0.1:0\"\n",
        "    - address: \"127.0.0.1:0\"\n",
        "      verify_client: true\n",
        "      client_ca: \"{ca}\"\n",
        "      client_subject: [\"*.sip.example.net\"]\n",
    ));
    let block = config.tls.as_ref().expect("tls block");
    let phones = start_tls(block, &config.listen.tls[0]).await;
    let trunk = start_tls(block, &config.listen.tls[1]).await;

    assert!(
        delivered(&phones, fixture.connector(None)).await,
        "the plain listener serves a client without a certificate"
    );
    assert!(
        !delivered(&trunk, fixture.connector(None)).await,
        "the verifying listener refuses a client without a certificate"
    );
    assert!(
        delivered(
            &trunk,
            fixture.connector(Some(fixture.client_identity("edge1.sip.example.net")))
        )
        .await,
        "the verifying listener serves a certificate from its CA with a matching name"
    );
    assert!(
        !delivered(
            &trunk,
            fixture.connector(Some(fixture.client_identity("edge1.other.example.net")))
        )
        .await,
        "right CA, name outside client_subject: refused"
    );
    assert!(
        delivered(
            &phones,
            fixture.connector(Some(fixture.client_identity("edge1.other.example.net")))
        )
        .await,
        "the plain listener ignores a certificate it never asked for"
    );
}

/// The WSS listener takes its own entry's override too. Its acceptor is
/// observed at the TLS layer: a refused session is torn down by the server
/// right away, an accepted one stays open waiting for the WebSocket upgrade.
#[tokio::test]
async fn a_wss_listener_applies_its_own_client_certificate_policy() {
    let fixture = Fixture::new();
    let config = fixture.config(concat!(
        "  wss:\n",
        "    - address: \"127.0.0.1:0\"\n",
        "      verify_client: true\n",
        "      client_ca: \"{ca}\"\n",
    ));
    let block = config.tls.as_ref().expect("tls block");
    let entry = &config.listen.wss[0];

    let (inbound_tx, _inbound) = flume::unbounded();
    let (_outbound, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let address = ws::listen_secure(
        entry.address().parse().expect("listen address"),
        &block.for_listener(entry.client_auth()),
        inbound_tx,
        outbound_rx,
        Arc::new(DashMap::new()),
        Arc::new(TransportAcl::new(vec![], vec![])),
        StreamConnections::new(),
        None,
        None,
        None,
    )
    .await
    .expect("the WSS listener binds");

    async fn session_stays_open(
        address: SocketAddr,
        connector: tokio_rustls::TlsConnector,
    ) -> bool {
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let name = ServerName::try_from("localhost").unwrap();
        let Ok(mut session) = connector.connect(name, tcp).await else {
            return false;
        };
        let mut byte = [0u8; 1];
        // Accepted: the server waits for our HTTP upgrade, so the read times
        // out. Refused: the alert / close arrives at once.
        tokio::time::timeout(Duration::from_millis(1500), session.read(&mut byte))
            .await
            .is_err()
    }

    assert!(!session_stays_open(address, fixture.connector(None)).await);
    assert!(
        session_stays_open(
            address,
            fixture.connector(Some(fixture.client_identity("any.example.net")))
        )
        .await
    );
}
