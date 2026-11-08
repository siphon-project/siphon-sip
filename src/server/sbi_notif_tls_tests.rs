//! Wire integration coverage with a CA and identities generated per test.
use super::sbi_callbacks_tests::recording;
use super::sbi_notif_tls::{load, serve};
use crate::config::SbiYamlConfig;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::{sync::Arc, time::Duration};
use tokio_rustls::{rustls, TlsConnector};

struct Pki {
    dir: tempfile::TempDir,
    ca: rcgen::Certificate,
    client: rcgen::Certificate,
    client_key: rcgen::KeyPair,
}
impl Pki {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = params.self_signed(&key).unwrap();
        let issuer = rcgen::Issuer::new(params, key);
        let server_key = rcgen::KeyPair::generate().unwrap();
        let server = rcgen::CertificateParams::new(vec!["notif.example.net".into()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let client_key = rcgen::KeyPair::generate().unwrap();
        let client = rcgen::CertificateParams::new(vec!["pcf.example.net".into()])
            .unwrap()
            .signed_by(&client_key, &issuer)
            .unwrap();
        for (name, pem) in [
            ("ca", ca.pem()),
            ("cert", server.pem()),
            ("key", server_key.serialize_pem()),
        ] {
            std::fs::write(dir.path().join(name), pem).unwrap();
        }
        Self {
            dir,
            ca,
            client,
            client_key,
        }
    }
    fn config(&self, mutual: bool) -> SbiYamlConfig {
        let dir = self.dir.path().display();
        let ca = if mutual {
            format!(", client_ca: '{dir}/ca'")
        } else {
            String::new()
        };
        serde_saphyr::from_str(&format!(
            "notif_tls: {{cert: '{dir}/cert', key: '{dir}/key'{ca}}}"
        ))
        .unwrap()
    }
    fn client(&self, identity: bool, h2: bool) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.ca.der().clone()).unwrap();
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
        let mut config = if identity {
            builder
                .with_client_auth_cert(
                    vec![self.client.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.client_key.serialize_der())),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        config.alpn_protocols = vec![if h2 {
            b"h2".to_vec()
        } else {
            b"http/1.1".to_vec()
        }];
        TlsConnector::from(Arc::new(config))
    }
}

#[test]
fn startup_tls_errors_name_files_and_plain_is_optional() {
    assert!(load(None).unwrap().is_none());
    let empty: SbiYamlConfig = serde_saphyr::from_str("notif_tls: {cert: '', key: ''}").unwrap();
    assert!(load(empty.notif_tls.as_ref()).unwrap().is_none());
    let pki = Pki::new();
    assert!(load(pki.config(true).notif_tls.as_ref()).unwrap().is_some());
    for name in ["cert", "key", "ca"] {
        let path = pki.dir.path().join(name);
        let original = std::fs::read(&path).unwrap();
        for bad in [
            "",
            "not PEM",
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        ] {
            std::fs::write(&path, bad).unwrap();
            let error = load(pki.config(true).notif_tls.as_ref()).err().unwrap();
            assert!(error.contains(path.to_str().unwrap()), "{error}");
        }
        std::fs::remove_file(&path).unwrap();
        assert!(load(pki.config(true).notif_tls.as_ref())
            .err()
            .unwrap()
            .contains(path.to_str().unwrap()));
        std::fs::write(&path, original).unwrap();
    }
}

#[test]
fn startup_rejects_mismatched_keys_and_malformed_bundle_tails() {
    let pki = Pki::new();
    for name in ["cert", "ca", "key"] {
        let path = pki.dir.path().join(name);
        let original = std::fs::read_to_string(&path).unwrap();
        let label = if name == "key" {
            "PRIVATE KEY"
        } else {
            "CERTIFICATE"
        };
        std::fs::write(
            &path,
            format!("{original}-----BEGIN {label}-----\n!!!\n-----END {label}-----\n"),
        )
        .unwrap();
        assert!(load(pki.config(true).notif_tls.as_ref())
            .err()
            .unwrap()
            .contains(path.to_str().unwrap()));
        std::fs::write(&path, original).unwrap();
    }
    std::fs::write(
        pki.dir.path().join("key"),
        rcgen::KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let error = load(pki.config(true).notif_tls.as_ref()).err().unwrap();
    assert!(error.contains("/cert") && error.contains("/key"), "{error}");
    let mut config = pki.config(false).notif_tls.unwrap();
    config.key = Some(String::new());
    let error = load(Some(&config)).err().unwrap();
    assert!(error.contains("notif_tls.cert") && error.contains("notif_tls.key"));
}

async fn post(
    address: std::net::SocketAddr,
    connector: TlsConnector,
    h2: bool,
) -> Result<http::StatusCode, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = tokio::net::TcpStream::connect(address).await?;
    let tls = connector
        .connect(ServerName::try_from("notif.example.net")?, tcp)
        .await?;
    assert_eq!(
        tls.get_ref().1.alpn_protocol(),
        Some(if h2 {
            b"h2".as_slice()
        } else {
            b"http/1.1".as_slice()
        })
    );
    let request = http::Request::post("https://notif.example.net/sbi/events/notify")
        .header("content-type", "application/json")
        .body(http_body_util::Full::new(bytes::Bytes::from_static(
            b"{\"evSubsUri\":\"https://pcf.example.net/events\"}",
        )))?;
    if h2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender.send_request(request).await?.status())
    } else {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(sender.send_request(request).await?.status())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_h2_callback_mutual_tls_and_plain_rejection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let pki = Pki::new();
        for mutual in [false, true] {
            let recording = recording("on_event");
            // Loopback is transport plumbing; certificate names and payloads use example.net.
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let address = listener.local_addr().unwrap();
            let acceptor = load(pki.config(mutual).notif_tls.as_ref()).unwrap().unwrap();
            let task = tokio::spawn(serve(listener, super::sbi_callbacks::router(recording.script_state.clone()), acceptor));
            if mutual {
                assert!(post(address, pki.client(false, true), true).await.is_err());
                assert!(recording.received().is_empty());
            }
            for h2 in [true, false] {
                assert_eq!(post(address, pki.client(mutual, h2), h2).await.unwrap(), http::StatusCode::NO_CONTENT);
            }
            assert_eq!(recording.received().len(), 2);
            assert_eq!(recording.received()[0].1["evSubsUri"], "https://pcf.example.net/events");
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut plain = tokio::net::TcpStream::connect(address).await.unwrap();
            plain.write_all(b"POST /sbi/events/notify HTTP/1.1\r\nHost: notif.example.net\r\nContent-Length: 2\r\n\r\n{}").await.unwrap();
            let mut response = [0; 256];
            if let Ok(count) = plain.read(&mut response).await {
                assert!(!response[..count].starts_with(b"HTTP/"));
            }
            assert_eq!(recording.received().len(), 2);
            // A bad handshake must leave the listener serving later notifications.
            assert_eq!(post(address, pki.client(mutual, true), true).await.unwrap(), http::StatusCode::NO_CONTENT);
            task.abort();
        }
    }).await.unwrap();
}
