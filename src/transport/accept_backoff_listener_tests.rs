//! The real TCP and TLS listeners out of descriptors: the accept loop must back
//! off instead of spinning, and pick the pending connection up once
//! descriptors free up.
//!
//! Each test runs in its own process (it lowers the process's fd limit) and
//! exhausts descriptors deterministically: fill every free slot with
//! `/dev/null`, free exactly one, and spend it on a client connect. The
//! connection then sits in the listener's backlog with no descriptor left to
//! accept it into, the state in which `accept()` returns `EMFILE` without
//! consuming it.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use crate::config::{TlsMethod, TlsServerConfig};
use crate::transport::acl::TransportAcl;
use crate::transport::send_queue::SendQueue;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, StreamConnections};

/// How long the listener is held out of descriptors.
const HOLD: Duration = Duration::from_secs(2);
/// Backoff (5 ms doubling to 1 s) makes ~9 attempts in [`HOLD`]; a loop that
/// accepts again at once makes hundreds of thousands.
const MAX_ERRORS_IN_HOLD: u64 = 30;
/// A pending connection is accepted within the 1 s backoff cap, plus slack.
const RECOVERY: Duration = Duration::from_millis(1800);

fn set_soft_limit(soft: libc::rlim_t) {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointers for both calls.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = soft;
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}

/// Open `/dev/null` until the process is out of descriptors.
fn fill_descriptors() -> Vec<std::fs::File> {
    let mut filler = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => filler.push(file),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::EMFILE), "{error}");
                return filler;
            }
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

fn acl() -> Arc<TransportAcl> {
    Arc::new(TransportAcl::new(vec![], vec![]))
}

fn emfile_errors(transport: &str, listener: SocketAddr) -> u64 {
    crate::metrics::accept::errors(transport, &listener.to_string(), "emfile")
        .expect("metrics initialised")
}

/// Strand one connection in `listener`'s backlog with no descriptor free,
/// hold it there for [`HOLD`] and check the loop backed off. Returns the
/// stranded client and the remaining filler, still holding every descriptor.
fn strand_a_connection(transport: &str, listener: SocketAddr) -> (TcpStream, Vec<std::fs::File>) {
    let mut filler = fill_descriptors();
    drop(filler.pop());
    let client = TcpStream::connect(listener).expect("the kernel completes the handshake");
    // Nothing is free now: no filler can be opened.
    assert!(
        std::fs::File::open("/dev/null").is_err(),
        "still a descriptor free"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while emfile_errors(transport, listener) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "accept never hit EMFILE"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let before = emfile_errors(transport, listener);
    std::thread::sleep(HOLD);
    let during = emfile_errors(transport, listener) - before;
    assert!(
        (1..=MAX_ERRORS_IN_HOLD).contains(&during),
        "{transport} accept loop made {during} EMFILE attempts in {HOLD:?}; \
         a backed-off loop makes about 9"
    );
    (client, filler)
}

#[test]
fn tcp_listener_backs_off_when_out_of_descriptors() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::tcp_listener_backs_off_when_out_of_descriptors"
        ),
        || {
            set_soft_limit(64);
            crate::metrics::init().expect("metrics");
            let runtime = runtime();
            let (inbound_tx, inbound_rx) = flume::unbounded::<InboundMessage>();
            let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
            let connection_map: Arc<DashMap<ConnectionId, SendQueue>> = Arc::new(DashMap::new());
            let listener = runtime
                .block_on(crate::transport::tcp::listen(
                    "127.0.0.1:0".parse().expect("address"),
                    inbound_tx,
                    outbound_rx,
                    connection_map,
                    acl(),
                    StreamConnections::new(),
                    None,
                    None,
                    None,
                    None,
                    None,
                ))
                .expect("tcp listener binds");

            let (mut client, mut filler) = strand_a_connection("tcp", listener);

            // Free half of what is held: the stranded connection must be
            // taken within the backoff cap and its message read.
            let half = filler.len() / 2;
            filler.truncate(half);
            client
                .write_all(
                    concat!(
                        "OPTIONS sip:192.0.2.1 SIP/2.0\r\n",
                        "Via: SIP/2.0/TCP 192.0.2.2;branch=z9hG4bKaccept\r\n",
                        "From: <sip:a@192.0.2.2>;tag=1\r\n",
                        "To: <sip:192.0.2.1>\r\n",
                        "Call-ID: accept-backoff\r\n",
                        "CSeq: 1 OPTIONS\r\n",
                        "Content-Length: 0\r\n",
                        "\r\n",
                    )
                    .as_bytes(),
                )
                .expect("write");
            inbound_rx
                .recv_timeout(RECOVERY)
                .expect("the stranded connection is accepted once descriptors free up");
        },
    );
}

#[test]
fn tls_listener_backs_off_when_out_of_descriptors() {
    crate::own_process::run(
        concat!(
            module_path!(),
            "::tls_listener_backs_off_when_out_of_descriptors"
        ),
        || {
            let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
            let directory = tempfile::tempdir().expect("tempdir");
            let tls_config = test_tls_config(&directory);
            set_soft_limit(64);
            crate::metrics::init().expect("metrics");
            let runtime = runtime();
            let (inbound_tx, _inbound_rx) = flume::unbounded::<InboundMessage>();
            let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
            let connection_map: Arc<DashMap<ConnectionId, SendQueue>> = Arc::new(DashMap::new());
            let listener = runtime
                .block_on(crate::transport::tls::listen(
                    "127.0.0.1:0".parse().expect("address"),
                    &tls_config,
                    inbound_tx,
                    outbound_rx,
                    connection_map,
                    acl(),
                    StreamConnections::new(),
                    None,
                    None,
                    None,
                    None,
                    None,
                ))
                .expect("tls listener binds");

            let (mut client, mut filler) = strand_a_connection("tls", listener);

            // Once accepted, bytes that are not a ClientHello fail the
            // handshake and the server closes. A connection still in the
            // backlog would never answer.
            let half = filler.len() / 2;
            filler.truncate(half);
            client
                .write_all(b"this is not a TLS ClientHello\r\n\r\n")
                .expect("write");
            client
                .set_read_timeout(Some(RECOVERY))
                .expect("read timeout");
            let mut buffer = [0u8; 256];
            loop {
                match client.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(_) => continue, // a TLS alert before the close
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => break,
                    Err(error) => panic!(
                        "the stranded connection was not accepted once descriptors freed up: {error}"
                    ),
                }
            }
        },
    );
}

#[test]
fn diameter_listener_keeps_accepting_after_running_out_of_descriptors() {
    // The Diameter server's accept loop used to return on any accept error,
    // so one EMFILE stopped the listener for good.
    crate::own_process::run(
        concat!(
            module_path!(),
            "::diameter_listener_keeps_accepting_after_running_out_of_descriptors"
        ),
        || {
            set_soft_limit(64);
            crate::metrics::init().expect("metrics");
            let runtime = runtime();
            let listener = runtime
                .block_on(crate::diameter::transport::DiameterListener::bind_tcp(
                    "127.0.0.1:0",
                ))
                .expect("diameter listener binds");
            let address = listener.local_addr().expect("local address");
            let (accepted_tx, accepted_rx) = flume::unbounded::<SocketAddr>();
            runtime.spawn(async move {
                listener
                    .accept_forever(address, move |_stream, peer_addr| {
                        let _ = accepted_tx.send(peer_addr);
                    })
                    .await;
            });

            let (client, mut filler) = strand_a_connection("diameter", address);

            let half = filler.len() / 2;
            filler.truncate(half);
            let accepted = accepted_rx
                .recv_timeout(RECOVERY)
                .expect("the stranded connection is accepted once descriptors free up");
            assert_eq!(accepted, client.local_addr().expect("client address"));
        },
    );
}

fn test_tls_config(directory: &tempfile::TempDir) -> TlsServerConfig {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let certificate = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params")
        .self_signed(&key_pair)
        .expect("self-sign");
    let certificate_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&certificate_path, certificate.pem()).expect("write cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    TlsServerConfig {
        certificate: certificate_path.to_string_lossy().into_owned(),
        private_key: key_path.to_string_lossy().into_owned(),
        certificates: vec![],
        method: TlsMethod::default(),
        verify_client: false,
        client_ca: None,
        client_subject: Vec::new(),
        client_certificate: None,
        client_private_key: None,
        verify_server: false,
        server_ca: None,
    }
}
