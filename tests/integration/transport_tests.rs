//! Functional transport tests — end-to-end bidirectional data flow.
//!
//! Unlike unit tests (which test inbound-only or cleanup), these exercise the
//! full round-trip: client sends a SIP request → transport delivers it as an
//! InboundMessage → test code sends an OutboundMessage back → client receives
//! the response. This validates bidirectional routing through connection_map.
//!
//! Transports tested: UDP, TCP, TLS, WebSocket, WebSocket Secure (WSS).
//! SCTP is omitted — it requires libsctp-dev and kernel module, not available
//! in all CI environments.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use siphon::transport::acl::TransportAcl;
use siphon::transport::mux::MuxChannels;
use siphon::transport::proxy_protocol::ProxyProtocolAcl;
use siphon::transport::{mux, tcp, tls, udp, ws};
use siphon::transport::{
    ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport,
};

/// Helper: build a permissive ACL for tests.
fn test_acl() -> Arc<TransportAcl> {
    Arc::new(TransportAcl::new(vec![], vec![]))
}

/// A bind that cannot succeed has to reach the caller.
///
/// It used to be logged inside the spawned accept task and swallowed, so
/// `listen()` returned as if all was well and the socket simply never existed.
/// An operator got one `error!` line and a node that looked healthy while
/// missing a transport; a test got a connect timeout pointing at the wrong
/// thing entirely. Port 1 is privileged, so this bind always fails unprivileged.
#[tokio::test]
async fn bind_failure_reaches_the_caller() {
    let privileged: SocketAddr = "127.0.0.1:1".parse().expect("addr");
    let (inbound_tx, _inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();

    let result = tcp::listen(
        privileged,
        inbound_tx,
        outbound_rx,
        Arc::new(DashMap::new()),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await;

    assert!(
        result.is_err(),
        "a bind that cannot succeed must return Err, not log and carry on"
    );
}

/// Where every listener in this file binds: loopback, port 0.
///
/// The kernel picks a free port inside the bind itself, and `listen` returns the
/// address it bound, so no port is ever chosen ahead of the bind and left for
/// another socket or another test binary to take in between.
const LOOPBACK_ANY_PORT: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    0,
));

/// The address a listener returned must be a real one: the loopback it was
/// asked for, on the port the kernel picked.
fn assert_bound(addr: SocketAddr) {
    assert_eq!(addr.ip(), LOOPBACK_ANY_PORT.ip());
    assert_ne!(addr.port(), 0, "listen must return the port it bound");
}

/// Standard SIP OPTIONS request used across tests.
fn sip_options_request() -> &'static str {
    concat!(
        "OPTIONS sip:test@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfunc001\r\n",
        "From: <sip:alice@example.com>;tag=functest1\r\n",
        "To: <sip:test@example.com>\r\n",
        "Call-ID: functional-roundtrip@example.com\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
}

/// Standard SIP 200 OK response used across tests.
fn sip_200_ok() -> &'static str {
    concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKfunc001\r\n",
        "From: <sip:alice@example.com>;tag=functest1\r\n",
        "To: <sip:test@example.com>;tag=resp001\r\n",
        "Call-ID: functional-roundtrip@example.com\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
}

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Retry a connect while the listener is still coming up.
///
/// `listen()` returns once it has bound, but the accept loop is a spawned task
/// that may not be scheduled yet. The fixed `SETTLE` sleep that used to cover
/// that gap is a guess about scheduler latency, and on a loaded test binary the
/// guess expires first — the connect is refused and the test fails for reasons
/// that have nothing to do with what it asserts. Retrying against `TIMEOUT`
/// removes the guess: a listener that never comes up still fails, and one that
/// is merely slow no longer does.
async fn connect_with_retry<F, Fut, T, E>(what: &str, mut attempt: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    loop {
        match attempt().await {
            Ok(value) => return value,
            Err(error) => {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{what} never became connectable within {TIMEOUT:?}: {error}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UDP round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_roundtrip() {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();

    let addr = udp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        vec![outbound_rx],
        test_acl(),
        None,
        0,
    )
    .await
    .expect("udp listener must bind");
    assert_bound(addr);

    // Client: send OPTIONS
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(sip_options_request().as_bytes(), addr)
        .await
        .unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for UDP inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Udp);
    assert_eq!(inbound.local_addr, addr);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.contains("OPTIONS"),
        "expected OPTIONS: {}",
        data_str
    );

    // Send response back through outbound channel
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // Client receives the 200 OK
    let mut buffer = vec![0u8; 4096];
    let (size, _from) = tokio::time::timeout(TIMEOUT, client.recv_from(&mut buffer))
        .await
        .expect("timed out waiting for UDP response")
        .unwrap();

    let response = String::from_utf8_lossy(&buffer[..size]);
    assert!(response.contains("200 OK"), "expected 200 OK: {}", response);
}

// ---------------------------------------------------------------------------
// TCP round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_roundtrip() {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(addr);

    // Client: connect and send OPTIONS
    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for TCP inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(inbound.local_addr, addr);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.contains("OPTIONS"),
        "expected OPTIONS: {}",
        data_str
    );

    // Connection should be tracked
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back through outbound channel (routed via connection_map)
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // Client receives the 200 OK
    let mut buffer = vec![0u8; 4096];
    let size = tokio::time::timeout(TIMEOUT, client.read(&mut buffer))
        .await
        .expect("timed out waiting for TCP response")
        .unwrap();

    let response = String::from_utf8_lossy(&buffer[..size]);
    assert!(response.contains("200 OK"), "expected 200 OK: {}", response);
}

/// RFC 5626 §4.2.2 flow failure: when a TCP connection closes, the listener
/// must enqueue the dead `ConnectionId.0` on the close channel so the
/// registrar can deregister bindings that arrived on it.  This validates the
/// transport→registrar glue end-to-end on a real socket (the registrar-side
/// removal is unit-tested in `registrar::tests::unregister_flow_*`).
#[tokio::test]
async fn tcp_close_notifies_flow_failure() {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let (close_tx, close_rx) = flume::unbounded::<u64>();

    let addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        Some(close_tx),
        None,
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(addr);

    // Connect and send a request so we learn the assigned ConnectionId.
    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for TCP inbound")
        .expect("inbound channel closed");
    let connection_id = inbound.connection_id.0;
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Drop the client → the connection closes → close notification fires.
    drop(client);

    let closed = tokio::time::timeout(std::time::Duration::from_secs(2), close_rx.recv_async())
        .await
        .expect("no flow-failure close notification")
        .expect("close channel closed");
    assert_eq!(
        closed, connection_id,
        "close notification must carry the dead connection id"
    );
}

/// Regression: fire-and-forget outbound TCP with `ConnectionId::default()`
/// must open a fresh connection via the pool fallback.
///
/// Without the pool fallback the TCP outbound distributor silently dropped
/// any message whose `connection_id` was not present in the connection map
/// — which is exactly what `UacSender::send_request()` sends (sentinel
/// id 0) for in-dialog requests originated outside the proxy relay path
/// (e.g. S-CSCF reg-event NOTIFY).  The build path captured HEP, but the
/// frame never reached the socket.
#[tokio::test]
async fn tcp_outbound_fallback_to_pool_when_no_connection() {
    use siphon::transport::pool::ConnectionPool;

    // ConnectionPool builds a TlsConnector at construction; rustls needs
    // a process-wide CryptoProvider for that to succeed even when no TLS
    // is exercised by this test.  Install once; subsequent calls are
    // no-ops if another test got here first.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    // 1) A target TCP server stands in for the downstream SIP element
    //    (P-CSCF receiving a NOTIFY from S-CSCF).
    let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target_listener.local_addr().unwrap();
    let received = Arc::new(tokio::sync::Mutex::new(Vec::<u8>::new()));
    let received_clone = Arc::clone(&received);
    tokio::spawn(async move {
        let (mut socket, _) = target_listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 4096];
        let size = socket.read(&mut buffer).await.unwrap();
        received_clone
            .lock()
            .await
            .extend_from_slice(&buffer[..size]);
    });

    // 2) Build a real ConnectionPool sharing the listener's connection_map
    //    and inbound_tx — same wiring server.rs does in production.
    //    The pool takes the listener's address before the listener exists; it
    //    uses only the IP, to bind outbound connections, so port 0 stands in.
    let (inbound_tx, _inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let pool = Arc::new(ConnectionPool::new(
        Arc::clone(&connection_map),
        inbound_tx.clone(),
        LOOPBACK_ANY_PORT,
        None,
        None,
        None,
        siphon::transport::pool::build_outbound_tls_config(
            None,
            siphon::config::TlsMethod::default(),
        )
        .expect("outbound tls config"),
    ));

    // 3) Start the TCP listener with the pool wired in — this is the
    //    distributor task that should fall back to the pool when the
    //    sentinel connection_id misses the map.
    let listen_addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        Some(Arc::clone(&pool)),
        None,
        None,
        None,
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(listen_addr);

    // 4) Fire-and-forget: send the OutboundMessage UacSender::send_request()
    //    builds — sentinel id 0, no source_local_addr.
    let notify_bytes = Bytes::from_static(
        b"NOTIFY sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-pool-fallback\r\n\
        From: <sip:scscf@example.com>;tag=notifier\r\n\
        To: <sip:bob@example.com>;tag=subscriber\r\n\
        Call-ID: pool-fallback-test\r\n\
        CSeq: 1 NOTIFY\r\n\
        Event: reg\r\n\
        Subscription-State: active;expires=3600\r\n\
        Content-Length: 0\r\n\
        \r\n",
    );
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Tcp,
            destination: target_addr,
            data: notify_bytes.clone(),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // 5) Wait until the target server has the bytes — without the pool
    //    fallback this would time out (the distributor would drop the
    //    message at the connection_map.get() miss).
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for NOTIFY bytes at target server — pool fallback regressed");
        }
        if !received.lock().await.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let buf = received.lock().await.clone();
    let on_wire = String::from_utf8_lossy(&buf);
    assert!(
        on_wire.contains("NOTIFY"),
        "expected NOTIFY on wire, got: {on_wire}"
    );
    assert!(
        on_wire.contains("Event: reg"),
        "expected Event: reg on wire"
    );
}

// ---------------------------------------------------------------------------
// RFC 5626 §4.4.1 CRLF keepalive — peer pings get a CRLF pong over the wire
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_responds_to_peer_crlf_ping_with_pong() {
    // RFC 5626 §4.4.1 contract: a peer (typically an iOS/Android UE that
    // negotiated RFC 6223 Flow-Timer) sends `\r\n\r\n` to keep the NAT
    // pinhole and connection liveness alive.  The server must answer with
    // a single `\r\n`.  Verify the bytes leave the wire and that a SIP
    // message sent after the ping still frames correctly.
    use siphon::transport::crlf_keepalive::CrlfPongTracker;
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let tracker = Arc::new(CrlfPongTracker::new());

    let addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(Arc::clone(&tracker)),
        None,
        None,
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(addr);

    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;

    // 1) Peer ping → expect single-CRLF pong back.
    client.write_all(b"\r\n\r\n").await.unwrap();

    let mut pong = [0u8; 2];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut pong))
        .await
        .expect("timed out waiting for CRLF pong")
        .expect("read CRLF pong");
    assert_eq!(&pong, b"\r\n", "server must answer ping with `\\r\\n`");

    // 2) Peer pong → tracker records it; no bytes come back.
    client.write_all(b"\r\n").await.unwrap();
    // Wait a short moment so the read task processes the pong before we
    // check the tracker.  No way to await the tracker directly without
    // racing — a small sleep is the standard pattern in this file.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // 3) Real SIP message after keepalives still frames correctly.
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for OPTIONS after keepalives")
        .expect("inbound channel closed");
    assert_eq!(inbound.transport, Transport::Tcp);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.starts_with("OPTIONS"),
        "OPTIONS must not be polluted by leading CRLFs: {}",
        data_str
    );
    assert!(
        tracker.has_seen_pong(inbound.connection_id),
        "tracker should have recorded the peer pong"
    );
}

// ---------------------------------------------------------------------------
// TLS round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_roundtrip() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    use tokio_rustls::rustls;

    let directory = tempfile::tempdir().unwrap();
    let tls_config = generate_test_tls_config(&directory);

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = tls::listen(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("tls listener must bind");
    assert_bound(addr);

    // Build a TLS client that trusts our self-signed cert
    let tls_connector = build_test_tls_connector(&tls_config);

    let tcp_stream = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    // Send OPTIONS
    tls_stream
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for TLS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Tls);
    assert_eq!(inbound.local_addr, addr);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.contains("OPTIONS"),
        "expected OPTIONS: {}",
        data_str
    );
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // Client receives the 200 OK
    let mut buffer = vec![0u8; 4096];
    let size = tokio::time::timeout(TIMEOUT, tls_stream.read(&mut buffer))
        .await
        .expect("timed out waiting for TLS response")
        .unwrap();

    let response = String::from_utf8_lossy(&buffer[..size]);
    assert!(response.contains("200 OK"), "expected 200 OK: {}", response);
}

// ---------------------------------------------------------------------------
// WebSocket round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ws_roundtrip() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = ws::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
    )
    .await
    .expect("ws listener must bind");
    assert_bound(addr);

    // Client: connect via WebSocket
    let url = format!("ws://127.0.0.1:{}", addr.port());
    let (mut ws_stream, _) =
        connect_with_retry("ws listener", || tokio_tungstenite::connect_async(&url)).await;

    // Send OPTIONS as text frame
    ws_stream
        .send(Message::text(sip_options_request()))
        .await
        .unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for WS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::WebSocket);
    assert_eq!(inbound.local_addr, addr);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.contains("OPTIONS"),
        "expected OPTIONS: {}",
        data_str
    );
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back through outbound channel
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // Client receives the 200 OK as a WebSocket text frame
    let response_msg = tokio::time::timeout(TIMEOUT, ws_stream.next())
        .await
        .expect("timed out waiting for WS response")
        .expect("stream ended")
        .expect("WS read error");

    let response_text = response_msg.into_text().expect("expected text frame");
    assert!(
        response_text.contains("200 OK"),
        "expected 200 OK: {}",
        response_text
    );
}

// ---------------------------------------------------------------------------
// WebSocket Secure (WSS) round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wss_roundtrip() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    use futures_util::{SinkExt, StreamExt};
    use tokio_rustls::rustls;
    use tokio_tungstenite::tungstenite::Message;

    let directory = tempfile::tempdir().unwrap();
    let tls_config = generate_test_tls_config(&directory);

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = ws::listen_secure(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
    )
    .await
    .expect("ws listener must bind");
    assert_bound(addr);

    // Manual TLS connect then WebSocket upgrade
    let tls_connector = build_test_tls_connector(&tls_config);
    let tcp_stream = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .unwrap();

    let url = format!("wss://localhost:{}", addr.port());
    let request = url.parse::<http::Uri>().unwrap();
    let (mut ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
        .await
        .expect("WSS WebSocket upgrade failed");

    // Send OPTIONS
    ws_stream
        .send(Message::text(sip_options_request()))
        .await
        .unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for WSS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::WebSocketSecure);
    assert_eq!(inbound.local_addr, addr);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(
        data_str.contains("OPTIONS"),
        "expected OPTIONS: {}",
        data_str
    );
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back
    outbound_tx
        .send_async(OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
            server_name: None,
        })
        .await
        .unwrap();

    // Client receives the 200 OK
    let response_msg = tokio::time::timeout(TIMEOUT, ws_stream.next())
        .await
        .expect("timed out waiting for WSS response")
        .expect("stream ended")
        .expect("WSS read error");

    let response_text = response_msg.into_text().expect("expected text frame");
    assert!(
        response_text.contains("200 OK"),
        "expected 200 OK: {}",
        response_text
    );
}

// ---------------------------------------------------------------------------
// Multi-transport: same inbound channel, different transports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_transport_shared_inbound_channel() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    // All transports share the same inbound channel (like main.rs)
    let (inbound_tx, inbound_rx) = flume::unbounded();

    let (_udp_outbound_tx, udp_outbound_rx) = flume::unbounded::<OutboundMessage>();
    let (_tcp_outbound_tx, tcp_outbound_rx) = flume::unbounded::<OutboundMessage>();
    let (_ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<OutboundMessage>();

    let tcp_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());
    let ws_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());

    // Start all three transports with the same inbound_tx
    let udp_addr = udp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx.clone(),
        vec![udp_outbound_rx],
        test_acl(),
        None,
        0,
    )
    .await
    .expect("udp listener must bind");
    let tcp_addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx.clone(),
        tcp_outbound_rx,
        Arc::clone(&tcp_connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("tcp listener must bind");
    let ws_addr = ws::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx.clone(),
        ws_outbound_rx,
        Arc::clone(&ws_connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
    )
    .await
    .expect("ws listener must bind");
    drop(inbound_tx); // Only transport workers hold clones now

    // Send via UDP
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_client
        .send_to(b"OPTIONS sip:udp SIP/2.0\r\n\r\n", udp_addr)
        .await
        .unwrap();

    // Send via TCP
    let mut tcp_client = connect_with_retry("tcp listener", || TcpStream::connect(tcp_addr)).await;
    tcp_client
        .write_all(b"OPTIONS sip:tcp SIP/2.0\r\n\r\n")
        .await
        .unwrap();

    // Send via WS
    let url = format!("ws://127.0.0.1:{}", ws_addr.port());
    let (mut ws_client, _) =
        connect_with_retry("ws listener", || tokio_tungstenite::connect_async(&url)).await;
    ws_client
        .send(Message::text("OPTIONS sip:ws SIP/2.0\r\n\r\n"))
        .await
        .unwrap();

    // Collect three messages from the shared channel
    let mut transports_seen = Vec::new();
    for _ in 0..3 {
        let message = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
            .await
            .expect("timed out waiting for multi-transport message")
            .expect("inbound channel closed");
        transports_seen.push(message.transport);
    }

    // All three transport types should be represented
    assert!(
        transports_seen.contains(&Transport::Udp),
        "missing UDP: {:?}",
        transports_seen
    );
    assert!(
        transports_seen.contains(&Transport::Tcp),
        "missing TCP: {:?}",
        transports_seen
    );
    assert!(
        transports_seen.contains(&Transport::WebSocket),
        "missing WS: {:?}",
        transports_seen
    );
}

// ---------------------------------------------------------------------------
// PROXY protocol — the client address behind a connection-terminating front
//
// The unit tests in `transport::proxy_protocol` cover `parse` and
// `accept_proxied` in isolation; none of them reaches an `InboundMessage`. What
// follows drives the real listeners, so it fails if the accept sites stop
// calling the parser, stop substituting the address, or stop replaying the
// bytes read past the header.
// ---------------------------------------------------------------------------

/// The front, for tests. Connections here come from loopback, so loopback is
/// the only sender allowed to speak for someone else.
fn loopback_proxy_acl() -> Arc<ProxyProtocolAcl> {
    Arc::new(ProxyProtocolAcl::new(&["127.0.0.1/32".to_string()]))
}

/// An allowlist loopback is **not** in. A header from an unlisted sender is a
/// source-address forgery, so the connection must die at the accept loop.
fn foreign_proxy_acl() -> Arc<ProxyProtocolAcl> {
    Arc::new(ProxyProtocolAcl::new(&["198.51.100.7/32".to_string()]))
}

/// A v1 header. The client it declares is nothing like loopback and nothing
/// like the listener's own address, so no assertion below can pass by accident.
const PROXY_V1: &[u8] = b"PROXY TCP4 192.0.2.10 198.51.100.7 51234 5061\r\n";

/// The client endpoint `PROXY_V1` and [`proxy_v2`] both declare.
const PROXIED_CLIENT: &str = "192.0.2.10:51234";

/// The same endpoints as a v2 binary header.
///
/// Written out here rather than reusing siphon's own constants (they are
/// `pub(crate)` anyway): a header built from the same constant the parser reads
/// would still line up if that constant were wrong. This is the wire format
/// from the spec, independently.
fn proxy_v2() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&std::net::Ipv4Addr::new(192, 0, 2, 10).octets());
    body.extend_from_slice(&std::net::Ipv4Addr::new(198, 51, 100, 7).octets());
    body.extend_from_slice(&51234u16.to_be_bytes());
    body.extend_from_slice(&5061u16.to_be_bytes());

    let mut header = vec![
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ];
    header.push(0x21); // version 2, PROXY command
    header.push(0x11); // TCP over IPv4
    header.extend_from_slice(&(body.len() as u16).to_be_bytes());
    header.extend_from_slice(&body);
    header
}

fn proxied_client() -> SocketAddr {
    PROXIED_CLIENT.parse().expect("addr")
}

/// The assertion every substitution test makes.
///
/// Spelled out once because the failure it guards against is specific: the
/// dispatcher receiving loopback means the header was parsed and then thrown
/// away, which is the bug the whole feature exists to prevent and which a
/// "did a message arrive?" test passes straight through.
fn assert_client_address_substituted(inbound: &InboundMessage, what: &str) {
    assert_eq!(
        inbound.remote_addr,
        proxied_client(),
        "{what}: the dispatcher must see the client from the PROXY header, not \
         the front's own address ({})",
        inbound.remote_addr
    );
}

/// Prove a listener refused a connection: nothing reached the dispatcher and
/// the socket is closed.
async fn assert_connection_refused(
    addr: SocketAddr,
    opening: &[u8],
    inbound_rx: &flume::Receiver<InboundMessage>,
    what: &str,
) {
    let mut client = connect_with_retry(what, || TcpStream::connect(addr)).await;
    // A refusal in the accept loop can close the socket before this write is
    // scheduled, so a write error is one of the shapes of success here.
    let _ = client.write_all(opening).await;

    let mut buffer = [0u8; 64];
    match tokio::time::timeout(TIMEOUT, client.read(&mut buffer)).await {
        // EOF, or a reset: both are the connection being dropped.
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(size)) => panic!(
            "{what}: expected the connection to be dropped, got {size} bytes back: {:?}",
            String::from_utf8_lossy(&buffer[..size])
        ),
        Err(_) => panic!("{what}: the connection was held open instead of being dropped"),
    }

    // Wait a beat for a straggler rather than sampling once: a build that
    // delivers the message would do it before closing, but the channel send
    // and the socket close are not ordered with respect to each other.
    let leaked = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        inbound_rx.recv_async(),
    )
    .await;
    assert!(
        leaked.is_err(),
        "{what}: a refused connection must deliver nothing to the dispatcher"
    );
}

/// A listener under test, with the channel ends the caller has to keep alive.
struct ProxiedListener {
    addr: SocketAddr,
    inbound_rx: flume::Receiver<InboundMessage>,
    /// Dropping these closes the outbound distributor, so they are held for the
    /// life of the test and the listener stays in the shape production has.
    _outbound: Vec<flume::Sender<OutboundMessage>>,
}

/// Start a TCP listener, optionally behind a front.
async fn tcp_listener_with_proxy(proxy_protocol: Option<Arc<ProxyProtocolAcl>>) -> ProxiedListener {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        connection_map,
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        proxy_protocol,
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(addr);
    ProxiedListener {
        addr,
        inbound_rx,
        _outbound: vec![outbound_tx],
    }
}

#[tokio::test]
async fn tcp_proxy_protocol_substitutes_the_client_address() {
    let listener = tcp_listener_with_proxy(Some(loopback_proxy_acl())).await;
    let (addr, inbound_rx) = (listener.addr, &listener.inbound_rx);

    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    client.write_all(PROXY_V1).await.unwrap();
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "tcp v1");
    assert_eq!(inbound.transport, Transport::Tcp);
    // The bytes after the header have to survive the read that consumed it.
    assert!(
        String::from_utf8_lossy(&inbound.data).starts_with("OPTIONS"),
        "the request must be replayed intact after the header: {:?}",
        String::from_utf8_lossy(&inbound.data)
    );
}

#[tokio::test]
async fn tcp_proxy_protocol_v2_substitutes_the_client_address() {
    // HAProxy's `send-proxy-v2` is the binary form, so this is what a real
    // front actually emits.
    let listener = tcp_listener_with_proxy(Some(loopback_proxy_acl())).await;
    let (addr, inbound_rx) = (listener.addr, &listener.inbound_rx);

    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    client.write_all(&proxy_v2()).await.unwrap();
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "tcp v2");
    assert!(String::from_utf8_lossy(&inbound.data).starts_with("OPTIONS"));
}

#[tokio::test]
async fn tls_proxy_protocol_substitutes_the_client_address() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    use tokio_rustls::rustls;

    let directory = tempfile::tempdir().unwrap();
    let tls_config = generate_test_tls_config(&directory);

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = tls::listen(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        Some(loopback_proxy_acl()),
    )
    .await
    .expect("tls listener must bind");
    assert_bound(addr);

    // The header is cleartext and goes out BEFORE the ClientHello. This
    // ordering is the whole feature for a re-encrypting front, and it is also
    // what breaks first: read the header after the handshake and rustls sees
    // "PROXY TCP4 …" as a ClientHello and the connection dies here.
    let mut tcp_stream = connect_with_retry("tls listener", || TcpStream::connect(addr)).await;
    tcp_stream.write_all(PROXY_V1).await.unwrap();

    let tls_connector = build_test_tls_connector(&tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("the handshake must run after the cleartext PROXY header");
    tls_stream
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "tls");
    assert_eq!(inbound.transport, Transport::Tls);
}

#[tokio::test]
async fn ws_proxy_protocol_substitutes_the_client_address() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = ws::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(loopback_proxy_acl()),
    )
    .await
    .expect("ws listener must bind");
    assert_bound(addr);

    // The header precedes the HTTP upgrade the same way it precedes a SIP
    // start-line.
    let mut tcp_stream = connect_with_retry("ws listener", || TcpStream::connect(addr)).await;
    tcp_stream.write_all(PROXY_V1).await.unwrap();

    let uri = format!("ws://127.0.0.1:{}", addr.port())
        .parse::<http::Uri>()
        .unwrap();
    let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, tcp_stream)
        .await
        .expect("the upgrade must run after the PROXY header");
    ws_stream
        .send(Message::text(sip_options_request()))
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "ws");
    assert_eq!(inbound.transport, Transport::WebSocket);
}

#[tokio::test]
async fn wss_proxy_protocol_substitutes_the_client_address() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    use futures_util::SinkExt;
    use tokio_rustls::rustls;
    use tokio_tungstenite::tungstenite::Message;

    let directory = tempfile::tempdir().unwrap();
    let tls_config = generate_test_tls_config(&directory);

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());

    let addr = ws::listen_secure(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(loopback_proxy_acl()),
    )
    .await
    .expect("wss listener must bind");
    assert_bound(addr);

    let mut tcp_stream = connect_with_retry("wss listener", || TcpStream::connect(addr)).await;
    tcp_stream.write_all(PROXY_V1).await.unwrap();

    let tls_connector = build_test_tls_connector(&tls_config);
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = tls_connector
        .connect(server_name, tcp_stream)
        .await
        .expect("the handshake must run after the cleartext PROXY header");

    let uri = format!("wss://localhost:{}", addr.port())
        .parse::<http::Uri>()
        .unwrap();
    let (mut ws_stream, _) = tokio_tungstenite::client_async(uri, tls_stream)
        .await
        .expect("WSS upgrade failed");
    ws_stream
        .send(Message::text(sip_options_request()))
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "wss");
    assert_eq!(inbound.transport, Transport::WebSocketSecure);
}

/// Start the tcp+ws mux, optionally behind a front.
async fn mux_listener_with_proxy(proxy_protocol: Option<Arc<ProxyProtocolAcl>>) -> ProxiedListener {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (sip_outbound_tx, sip_outbound_rx) = flume::unbounded::<OutboundMessage>();
    let (websocket_outbound_tx, websocket_outbound_rx) = flume::unbounded::<OutboundMessage>();

    let addr = mux::listen(
        LOOPBACK_ANY_PORT,
        None,
        MuxChannels {
            sip_outbound_rx,
            sip_connection_map: Arc::new(DashMap::new()),
            websocket_outbound_rx,
            websocket_connection_map: Arc::new(DashMap::new()),
        },
        inbound_tx,
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        proxy_protocol,
    )
    .await
    .expect("mux listener must bind");
    assert_bound(addr);
    ProxiedListener {
        addr,
        inbound_rx,
        _outbound: vec![sip_outbound_tx, websocket_outbound_tx],
    }
}

#[tokio::test]
async fn mux_proxy_protocol_substitutes_the_client_address() {
    // One read serves both halves of the mux: the header precedes the SIP
    // start-line and the WebSocket GET alike, so it is taken before the
    // protocol sniff rather than inside either arm.
    let listener = mux_listener_with_proxy(Some(loopback_proxy_acl())).await;
    let (addr, inbound_rx) = (listener.addr, &listener.inbound_rx);

    let mut client = connect_with_retry("mux listener", || TcpStream::connect(addr)).await;
    client.write_all(PROXY_V1).await.unwrap();
    client
        .write_all(sip_options_request().as_bytes())
        .await
        .unwrap();

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the proxied OPTIONS")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "mux");
    assert_eq!(inbound.transport, Transport::Tcp);
    assert!(String::from_utf8_lossy(&inbound.data).starts_with("OPTIONS"));
}

// --- Refusals -------------------------------------------------------------
//
// Both refusals below happen in the accept loop, before any TLS handshake or
// WebSocket upgrade, so every transport can be driven with a plain socket.

#[tokio::test]
async fn a_sender_not_in_from_cannot_assert_a_client_address() {
    // The security property. If this check goes away, anyone who can reach the
    // port can claim to be any address on the internet, which turns the front
    // door into a forgery primitive.
    let mut opening = Vec::from(PROXY_V1);
    opening.extend_from_slice(sip_options_request().as_bytes());

    let tcp_listener = tcp_listener_with_proxy(Some(foreign_proxy_acl())).await;
    assert_connection_refused(
        tcp_listener.addr,
        &opening,
        &tcp_listener.inbound_rx,
        "tcp unlisted sender",
    )
    .await;

    let mux_listener = mux_listener_with_proxy(Some(foreign_proxy_acl())).await;
    assert_connection_refused(
        mux_listener.addr,
        &opening,
        &mux_listener.inbound_rx,
        "mux unlisted sender",
    )
    .await;
}

#[tokio::test]
async fn an_unlisted_sender_is_refused_on_every_stream_listener() {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let tls_config = generate_test_tls_config(&directory);
    let mut opening = Vec::from(PROXY_V1);
    opening.extend_from_slice(sip_options_request().as_bytes());

    // tls
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let addr = tls::listen(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        outbound_rx,
        Arc::new(DashMap::new()),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        Some(foreign_proxy_acl()),
    )
    .await
    .expect("tls listener must bind");
    assert_connection_refused(addr, &opening, &inbound_rx, "tls unlisted sender").await;

    // ws
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_ws_outbound_tx, ws_outbound_rx) = flume::unbounded::<OutboundMessage>();
    let addr = ws::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        ws_outbound_rx,
        Arc::new(DashMap::new()),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(foreign_proxy_acl()),
    )
    .await
    .expect("ws listener must bind");
    assert_connection_refused(addr, &opening, &inbound_rx, "ws unlisted sender").await;

    // wss
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_wss_outbound_tx, wss_outbound_rx) = flume::unbounded::<OutboundMessage>();
    let addr = ws::listen_secure(
        LOOPBACK_ANY_PORT,
        &tls_config,
        inbound_tx,
        wss_outbound_rx,
        Arc::new(DashMap::new()),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(foreign_proxy_acl()),
    )
    .await
    .expect("wss listener must bind");
    assert_connection_refused(addr, &opening, &inbound_rx, "wss unlisted sender").await;
}

#[tokio::test]
async fn a_connection_with_no_header_is_dropped_rather_than_read_as_plain_sip() {
    // The refusal that matters most: falling back to the socket's own address
    // would hand the front's address to the registrar, the ban store and the
    // CDR — silently, and for every call. On a listener that sits behind a
    // front, plain SIP is a bypass, not a client.
    let opening = sip_options_request().as_bytes().to_vec();

    let tcp_listener = tcp_listener_with_proxy(Some(loopback_proxy_acl())).await;
    assert_connection_refused(
        tcp_listener.addr,
        &opening,
        &tcp_listener.inbound_rx,
        "tcp headerless",
    )
    .await;

    let mux_listener = mux_listener_with_proxy(Some(loopback_proxy_acl())).await;
    assert_connection_refused(
        mux_listener.addr,
        &opening,
        &mux_listener.inbound_rx,
        "mux headerless",
    )
    .await;
}

#[tokio::test]
async fn tcp_proxy_protocol_replay_does_not_swallow_a_crlf_keepalive() {
    // A front can put the header, an RFC 5626 §4.4.1 keepalive and a real
    // request in ONE segment. An earlier cut of this feature classified every
    // keepalive as a misconfigured PROXY header (`\r\n\r\n` is also how the v2
    // signature opens) and killed the connection answering it, so both halves
    // are asserted here: the pong comes back AND the request still frames.
    use siphon::transport::crlf_keepalive::CrlfPongTracker;

    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let tracker = Arc::new(CrlfPongTracker::new());

    let addr = tcp::listen(
        LOOPBACK_ANY_PORT,
        inbound_tx,
        outbound_rx,
        Arc::new(DashMap::new()),
        test_acl(),
        StreamConnections::new(),
        None,
        None,
        Some(Arc::clone(&tracker)),
        None,
        Some(loopback_proxy_acl()),
    )
    .await
    .expect("tcp listener must bind");
    assert_bound(addr);

    let mut client = connect_with_retry("tcp listener", || TcpStream::connect(addr)).await;
    let mut opening = Vec::from(PROXY_V1);
    opening.extend_from_slice(b"\r\n\r\n");
    opening.extend_from_slice(sip_options_request().as_bytes());
    client.write_all(&opening).await.unwrap();

    let mut pong = [0u8; 2];
    tokio::time::timeout(TIMEOUT, client.read_exact(&mut pong))
        .await
        .expect("timed out waiting for the CRLF pong — the keepalive was swallowed")
        .expect("read CRLF pong");
    assert_eq!(&pong, b"\r\n", "server must answer the ping with `\\r\\n`");

    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for the OPTIONS behind the keepalive")
        .expect("inbound channel closed");

    assert_client_address_substituted(&inbound, "tcp keepalive");
    assert!(
        String::from_utf8_lossy(&inbound.data).starts_with("OPTIONS"),
        "the request must not be polluted by the header or the keepalive: {:?}",
        String::from_utf8_lossy(&inbound.data)
    );
}

#[tokio::test]
async fn a_proxy_header_on_a_listener_without_the_option_is_dropped_and_credits_no_ban() {
    // A front pointed at the wrong listener is a misconfiguration, not abuse.
    // Scoring it as a malformed message has siphon ban its own load balancer,
    // which is an outage with nothing in the log explaining it.
    //
    // The observable is the malformed-message counter that feeds the ban store
    // (`record_malformed_message` increments it and records the strong failure
    // together). Both halves run in this one test so the reading is a delta
    // against itself; no other test in this binary sends non-SIP bytes.
    let _ = siphon::metrics::init();
    let Some(metrics) = siphon::metrics::try_metrics() else {
        panic!("metrics must initialise for this assertion to mean anything");
    };

    let listener = tcp_listener_with_proxy(None).await;
    let (addr, inbound_rx) = (listener.addr, &listener.inbound_rx);

    let before = metrics.malformed_messages_total.get();
    assert_connection_refused(addr, PROXY_V1, inbound_rx, "proxy header, option off").await;
    assert_eq!(
        metrics.malformed_messages_total.get(),
        before,
        "a PROXY header on a listener without proxy_protocol must not be scored \
         as a malformed message — that is siphon banning its own front"
    );

    // Control: real garbage on the same listener still counts, so the arm
    // above cannot pass by the ban signal having been broken outright.
    assert_connection_refused(
        addr,
        b"\x00\x01\x02not sip at all",
        inbound_rx,
        "binary garbage",
    )
    .await;
    assert!(
        metrics.malformed_messages_total.get() > before,
        "non-SIP bytes must still be scored — the ban store has to keep working \
         for real probes"
    );
}

// ---------------------------------------------------------------------------
// The consumers: given the address the substitution produces, what do they
// keep?
//
// These sit in this file because they are the second half of the claim the
// tests above make. Together the two halves cover the path with one link
// missing: the hop from `InboundMessage` into the `PyRequest` a script sees is
// `dispatcher::request::handle_request`, which is private, so nothing in
// `tests/integration/` can drive it. The SIPp case
// (sipp/docker-compose.proxy-protocol.yaml) covers that hop end-to-end against
// a real HAProxy instead.
// ---------------------------------------------------------------------------

use std::sync::Mutex;

use pyo3::prelude::*;
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::script::api::registrar::PyRegistrar;
use siphon::script::api::request::PyRequest;
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::uri::SipUri;

const CLIENT_AOR: &str = "sip:ua@pbx.example";
/// The client the PROXY header declares, split the way the dispatcher splits it.
const PROXIED_CLIENT_IP: &str = "192.0.2.10";
const PROXIED_CLIENT_PORT: u16 = 51234;
/// The front. Nothing a consumer keeps may carry this.
const FRONT_IP: &str = "198.51.100.7";

/// A REGISTER as the dispatcher hands it to a script: the source is whatever
/// the accept site decided, which behind a front is the header's client.
///
/// The Via sent-by and the Contact are the UE's own private address — a NATed
/// handset, the case `fix_nated_register` exists for — so neither the client's
/// nor the front's address can turn up in an assertion by accident.
fn register_from(source_ip: &str, source_port: u16) -> PyRequest {
    let message = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new("pbx.example".to_string()))
        .via("SIP/2.0/TLS 10.0.0.5:5060;branch=z9hG4bK-behind-a-front".to_string())
        .to(format!("<{CLIENT_AOR}>"))
        .from(format!("<{CLIENT_AOR}>;tag=front"))
        .call_id("behind-a-front@pbx.example".to_string())
        .cseq("1 REGISTER".to_string())
        .header(
            "Contact",
            "<sip:ua@10.0.0.5:5060;transport=tls>".to_string(),
        )
        .header("Expires", "3600".to_string())
        .content_length(0)
        .build()
        .unwrap();
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "tls".to_string(),
        source_ip.to_string(),
        source_port,
    )
}

#[test]
fn a_registration_behind_a_front_stores_the_client_address() {
    // NAT return-routing, the liveness keepalive and `media.received_from` all
    // key on the binding's source address. Storing the front's would point
    // every one of them at the load balancer.
    let registrar = Arc::new(Registrar::new(RegistrarConfig::default()));

    Python::initialize();
    Python::attach(|python| {
        let namespace = Py::new(python, PyRegistrar::new(Arc::clone(&registrar))).unwrap();
        let request = Py::new(
            python,
            register_from(PROXIED_CLIENT_IP, PROXIED_CLIENT_PORT),
        )
        .unwrap();
        let saved: bool = namespace
            .bind(python)
            .call_method1("save", (request,))
            .expect("registrar.save() must not raise")
            .extract()
            .unwrap();
        assert!(saved, "the REGISTER must be accepted");
    });

    let contacts = registrar.lookup(CLIENT_AOR);
    assert_eq!(contacts.len(), 1, "one binding must be stored");
    assert_eq!(
        contacts[0].source_addr,
        Some(proxied_client()),
        "the binding must record the client behind the front, not the front"
    );
}

#[test]
fn fix_nated_register_writes_the_client_into_received_and_rport() {
    let request = register_from(PROXIED_CLIENT_IP, PROXIED_CLIENT_PORT);
    // Taken before the request moves into Python; both point at one message.
    let message = request.message();

    Python::initialize();
    Python::attach(|python| {
        let request = Py::new(python, request).unwrap();
        request
            .bind(python)
            .call_method0("fix_nated_register")
            .expect("fix_nated_register must not raise");
    });

    let via = {
        let guard = message.lock().expect("lock");
        guard.headers.get("Via").cloned().expect("Via")
    };
    assert!(
        via.contains(&format!("received={PROXIED_CLIENT_IP}")),
        "received= must carry the client behind the front: {via}"
    );
    assert!(
        via.contains(&format!("rport={PROXIED_CLIENT_PORT}")),
        "rport= must carry the client's port: {via}"
    );
    assert!(
        !via.contains(FRONT_IP),
        "the front's own address must never reach the Via: {via}"
    );
}

#[test]
fn source_ip_predicates_see_the_client_not_the_front() {
    // `source_ip_in` is how a script tells an access network from a trunk. Fed
    // the front's address it stops discriminating at all, and every request
    // lands in whichever branch the front happens to match.
    Python::initialize();
    Python::attach(|python| {
        let request = Py::new(
            python,
            register_from(PROXIED_CLIENT_IP, PROXIED_CLIENT_PORT),
        )
        .unwrap();
        let bound = request.bind(python);

        let source_ip: String = bound
            .getattr("source_ip")
            .unwrap()
            .extract()
            .expect("source_ip is a string");
        assert_eq!(source_ip, PROXIED_CLIENT_IP);

        let in_client_range: bool = bound
            .call_method1("source_ip_in", (vec!["192.0.2.0/24"],))
            .unwrap()
            .extract()
            .unwrap();
        assert!(
            in_client_range,
            "the client's own prefix must match the client"
        );

        let in_front_range: bool = bound
            .call_method1("source_ip_in", (vec!["198.51.100.0/24"],))
            .unwrap()
            .extract()
            .unwrap();
        assert!(
            !in_front_range,
            "the front's prefix must not match: that is the misrouting this \
             feature exists to stop"
        );
    });
}

// ---------------------------------------------------------------------------
// Helpers: TLS cert generation (shared across TLS and WSS tests)
// ---------------------------------------------------------------------------

fn generate_test_tls_config(directory: &tempfile::TempDir) -> siphon::config::TlsServerConfig {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let certificate_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
    let certificate = certificate_params
        .self_signed(&key_pair)
        .expect("self-sign");

    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    siphon::config::TlsServerConfig {
        certificate: cert_path.to_str().unwrap().to_string(),
        private_key: key_path.to_str().unwrap().to_string(),
        certificates: vec![],
        method: siphon::config::TlsMethod::default(),
        verify_client: false,
        client_ca: None,
        client_certificate: None,
        client_private_key: None,
    }
}

fn build_test_tls_connector(
    tls_config: &siphon::config::TlsServerConfig,
) -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls;

    let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem);
    use rustls_pki_types::pem::PemObject;
    let certs: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in &certs {
        root_store.add(cert.clone()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(client_config))
}
