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
use tokio::sync::mpsc;
use tokio::net::{TcpStream, UdpSocket};

use siphon::transport::{ConnectionId, OutboundMessage, StreamConnections, Transport};
use siphon::transport::{udp, tcp, tls, ws};
use siphon::transport::acl::TransportAcl;

/// Helper: build a permissive ACL for tests.
fn test_acl() -> Arc<TransportAcl> {
    Arc::new(TransportAcl::new(vec![], vec![]))
}

/// Helper: find a free port by binding and releasing.
fn free_port() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
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
const SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

// ---------------------------------------------------------------------------
// UDP round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn udp_roundtrip() {
    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();

    udp::listen(addr, inbound_tx, outbound_rx, test_acl(), None).await;
    tokio::time::sleep(SETTLE).await;

    // Client: send OPTIONS
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(sip_options_request().as_bytes(), addr).await.unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for UDP inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Udp);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(data_str.contains("OPTIONS"), "expected OPTIONS: {}", data_str);

    // Send response back through outbound channel
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
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
    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());

    tcp::listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), None, None, None, None).await;
    tokio::time::sleep(SETTLE).await;

    // Client: connect and send OPTIONS
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(sip_options_request().as_bytes()).await.unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for TCP inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Tcp);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(data_str.contains("OPTIONS"), "expected OPTIONS: {}", data_str);

    // Connection should be tracked
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back through outbound channel (routed via connection_map)
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
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
    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());
    let (close_tx, close_rx) = flume::unbounded::<u64>();

    tcp::listen(
        addr,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        None,
        None,
        None,
        Some(close_tx),
    )
    .await;
    tokio::time::sleep(SETTLE).await;

    // Connect and send a request so we learn the assigned ConnectionId.
    let mut client = TcpStream::connect(addr).await.unwrap();
    client.write_all(sip_options_request().as_bytes()).await.unwrap();
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
    assert_eq!(closed, connection_id, "close notification must carry the dead connection id");
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
        received_clone.lock().await.extend_from_slice(&buffer[..size]);
    });

    // 2) Build a real ConnectionPool sharing the listener's connection_map
    //    and inbound_tx — same wiring server.rs does in production.
    let listen_addr = free_port();
    let (inbound_tx, _inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());
    let pool = Arc::new(ConnectionPool::new(
        Arc::clone(&connection_map),
        inbound_tx.clone(),
        listen_addr,
        None,
        None,
        None,
    ));

    // 3) Start the TCP listener with the pool wired in — this is the
    //    distributor task that should fall back to the pool when the
    //    sentinel connection_id misses the map.
    tcp::listen(
        listen_addr,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        None,
        Some(Arc::clone(&pool)),
        None,
        None,
    )
    .await;
    tokio::time::sleep(SETTLE).await;

    // 4) Fire-and-forget: send the OutboundMessage UacSender::send_request()
    //    builds — sentinel id 0, no source_local_addr.
    let notify_bytes = Bytes::from_static(b"NOTIFY sip:bob@example.com SIP/2.0\r\n\
        Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-pool-fallback\r\n\
        From: <sip:scscf@example.com>;tag=notifier\r\n\
        To: <sip:bob@example.com>;tag=subscriber\r\n\
        Call-ID: pool-fallback-test\r\n\
        CSeq: 1 NOTIFY\r\n\
        Event: reg\r\n\
        Subscription-State: active;expires=3600\r\n\
        Content-Length: 0\r\n\
        \r\n");
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Tcp,
            destination: target_addr,
            data: notify_bytes.clone(),
            source_local_addr: None,
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
    assert!(on_wire.contains("NOTIFY"), "expected NOTIFY on wire, got: {on_wire}");
    assert!(on_wire.contains("Event: reg"), "expected Event: reg on wire");
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
    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());
    let tracker = Arc::new(CrlfPongTracker::new());

    tcp::listen(
        addr,
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        test_acl(),
        None,
        None,
        Some(Arc::clone(&tracker)),
        None,
    )
    .await;
    tokio::time::sleep(SETTLE).await;

    let mut client = TcpStream::connect(addr).await.unwrap();

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

    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());

    tls::listen(addr, &tls_config, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None, None, None).await;
    tokio::time::sleep(SETTLE).await;

    // Build a TLS client that trusts our self-signed cert
    let tls_connector = build_test_tls_connector(&tls_config);

    let tcp_stream = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_stream = tls_connector.connect(server_name, tcp_stream).await.unwrap();

    // Send OPTIONS
    tls_stream.write_all(sip_options_request().as_bytes()).await.unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for TLS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::Tls);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(data_str.contains("OPTIONS"), "expected OPTIONS: {}", data_str);
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
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

    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());

    ws::listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
    tokio::time::sleep(SETTLE).await;

    // Client: connect via WebSocket
    let url = format!("ws://127.0.0.1:{}", addr.port());
    let (mut ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    // Send OPTIONS as text frame
    ws_stream.send(Message::text(sip_options_request())).await.unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for WS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::WebSocket);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(data_str.contains("OPTIONS"), "expected OPTIONS: {}", data_str);
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back through outbound channel
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
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
    assert!(response_text.contains("200 OK"), "expected 200 OK: {}", response_text);
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

    let addr = free_port();
    let (inbound_tx, inbound_rx) = flume::unbounded();
    let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
        Arc::new(DashMap::new());

    ws::listen_secure(addr, &tls_config, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
    tokio::time::sleep(SETTLE).await;

    // Manual TLS connect then WebSocket upgrade
    let tls_connector = build_test_tls_connector(&tls_config);
    let tcp_stream = TcpStream::connect(addr).await.unwrap();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let tls_stream = tls_connector.connect(server_name, tcp_stream).await.unwrap();

    let url = format!("wss://localhost:{}", addr.port());
    let request = url.parse::<http::Uri>().unwrap();
    let (mut ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
        .await
        .expect("WSS WebSocket upgrade failed");

    // Send OPTIONS
    ws_stream.send(Message::text(sip_options_request())).await.unwrap();

    // Verify inbound arrives
    let inbound = tokio::time::timeout(TIMEOUT, inbound_rx.recv_async())
        .await
        .expect("timed out waiting for WSS inbound")
        .expect("inbound channel closed");

    assert_eq!(inbound.transport, Transport::WebSocketSecure);
    let data_str = String::from_utf8_lossy(&inbound.data);
    assert!(data_str.contains("OPTIONS"), "expected OPTIONS: {}", data_str);
    assert!(connection_map.contains_key(&inbound.connection_id));

    // Send response back
    outbound_tx
        .send_async(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination: inbound.remote_addr,
            data: Bytes::from_static(sip_200_ok().as_bytes()),
            source_local_addr: None,
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
    assert!(response_text.contains("200 OK"), "expected 200 OK: {}", response_text);
}

// ---------------------------------------------------------------------------
// Multi-transport: same inbound channel, different transports
// ---------------------------------------------------------------------------

#[tokio::test]
async fn multi_transport_shared_inbound_channel() {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let udp_addr = free_port();
    let tcp_addr = free_port();
    let ws_addr = free_port();

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
    udp::listen(udp_addr, inbound_tx.clone(), udp_outbound_rx, test_acl(), None).await;
    tcp::listen(tcp_addr, inbound_tx.clone(), tcp_outbound_rx, Arc::clone(&tcp_connection_map), test_acl(), None, None, None, None).await;
    ws::listen(ws_addr, inbound_tx.clone(), ws_outbound_rx, Arc::clone(&ws_connection_map), test_acl(), StreamConnections::new(), None, None).await;
    drop(inbound_tx); // Only transport workers hold clones now
    tokio::time::sleep(SETTLE).await;

    // Send via UDP
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_client.send_to(b"OPTIONS sip:udp SIP/2.0\r\n\r\n", udp_addr).await.unwrap();

    // Send via TCP
    let mut tcp_client = TcpStream::connect(tcp_addr).await.unwrap();
    tcp_client.write_all(b"OPTIONS sip:tcp SIP/2.0\r\n\r\n").await.unwrap();

    // Send via WS
    let url = format!("ws://127.0.0.1:{}", ws_addr.port());
    let (mut ws_client, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws_client.send(Message::text("OPTIONS sip:ws SIP/2.0\r\n\r\n")).await.unwrap();

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
    assert!(transports_seen.contains(&Transport::Udp), "missing UDP: {:?}", transports_seen);
    assert!(transports_seen.contains(&Transport::Tcp), "missing TCP: {:?}", transports_seen);
    assert!(transports_seen.contains(&Transport::WebSocket), "missing WS: {:?}", transports_seen);
}

// ---------------------------------------------------------------------------
// Helpers: TLS cert generation (shared across TLS and WSS tests)
// ---------------------------------------------------------------------------

fn generate_test_tls_config(directory: &tempfile::TempDir) -> siphon::config::TlsServerConfig {
    let key_pair = rcgen::KeyPair::generate().expect("keygen");
    let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .expect("cert params");
    let certificate = certificate_params.self_signed(&key_pair).expect("self-sign");

    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, certificate.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    siphon::config::TlsServerConfig {
        certificate: cert_path.to_str().unwrap().to_string(),
        private_key: key_path.to_str().unwrap().to_string(),
        method: "TLSv1_3".to_string(),
        verify_client: false,
        client_ca: None,
    }
}

fn build_test_tls_connector(tls_config: &siphon::config::TlsServerConfig) -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls;

    let cert_pem = std::fs::read(&tls_config.certificate).unwrap();
    let mut cursor = std::io::Cursor::new(cert_pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
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
