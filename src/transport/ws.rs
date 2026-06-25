//! WebSocket (WS) and WebSocket Secure (WSS) transport — RFC 7118.
//!
//! Both WS and WSS share a generic `handle_connection` that operates on any
//! `AsyncRead + AsyncWrite` stream after the WebSocket upgrade. The only
//! difference is whether TLS wraps the TCP connection before the upgrade.
//!
//! WSS reuses `transport::tls::build_tls_acceptor` for cert/key loading.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, info, warn};

use crate::config::TlsServerConfig;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport, CONNECTION_IDLE_TIMEOUT, configure_tcp_socket, next_connection_id};
use crate::transport::acl::TransportAcl;

/// Handle a single WebSocket connection after the upgrade handshake.
/// Generic over the underlying stream (plain TCP for WS, TLS for WSS).
// The `accept_hdr_async` upgrade callback below must return the
// tungstenite-dictated `Result<Response, ErrorResponse>`. Its Err variant
// (`http::Response<Option<String>>`) is large, but the type is fixed by the
// callback contract — it can't be boxed — so allow the lint here.
#[allow(clippy::result_large_err)]
async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: S,
    transport_variant: Transport,
    connection_id: ConnectionId,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    stream_connections: StreamConnections,
    close_tx: Option<flume::Sender<u64>>,
) {
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::http::HeaderValue;

    // RFC 7118 §4: a SIP-over-WebSocket server MUST confirm the "sip"
    // subprotocol the UA offers in `Sec-WebSocket-Protocol`.  Without it,
    // browser / JS WebSocket clients (sip.js, JsSIP) abort the connection
    // immediately after the handshake (close 1006).  `accept_async` ignores
    // subprotocols entirely, so negotiate it here.
    let ws_stream = match tokio_tungstenite::accept_hdr_async(
        stream,
        |request: &Request, mut response: Response| {
            let offers_sip = request
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|value| value.to_str().ok())
                .map(|value| value.split(',').any(|proto| proto.trim().eq_ignore_ascii_case("sip")))
                .unwrap_or(false);
            if offers_sip {
                response
                    .headers_mut()
                    .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
            }
            Ok(response)
        },
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            warn!("WebSocket upgrade failed from {}: {}", remote_addr, error);
            crate::security::record_handshake_failure(
                remote_addr.ip(),
                &transport_variant.to_string(),
            );
            return;
        }
    };

    let (mut ws_sink, mut ws_source) = ws_stream.split();

    // Per-connection outbound channel
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
    connection_map.insert(connection_id, outbound_tx);
    // Register in the unified stream registry so the relay path can reach this
    // UE — for WebSocket this is the *only* way back (client-initiated; RFC 7118
    // §5 / RFC 5626 §5.3).  Keyed by the UE source address, tagged with the
    // WS/WSS transport so a TLS relay never picks it up.
    stream_connections.register(remote_addr, transport_variant, connection_id);

    // Read task: WebSocket frames → InboundMessage (with idle timeout)
    let inbound_tx_clone = inbound_tx.clone();
    let read_task = tokio::spawn(async move {
        loop {
            match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, ws_source.next()).await {
                Ok(Some(Ok(Message::Text(text)))) => {
                    let data = Bytes::from(text);
                    let message = InboundMessage {
                        connection_id,
                        transport: transport_variant,
                        local_addr,
                        remote_addr,
                        data,
                    };
                    if let Err(error) = inbound_tx_clone.send_async(message).await {
                        error!("WS inbound enqueue failed: {}", error);
                        break;
                    }
                }
                Ok(Some(Ok(Message::Binary(data)))) => {
                    let message = InboundMessage {
                        connection_id,
                        transport: transport_variant,
                        local_addr,
                        remote_addr,
                        data,
                    };
                    if let Err(error) = inbound_tx_clone.send_async(message).await {
                        error!("WS inbound enqueue failed: {}", error);
                        break;
                    }
                }
                Ok(Some(Ok(Message::Close(_)))) => {
                    info!("WS connection {:?} closed by peer", connection_id);
                    break;
                }
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)))) => {
                    // Ping/Pong handled automatically by tungstenite; resets idle timer
                }
                Ok(Some(Err(error))) => {
                    warn!("WS read error on {:?}: {}", connection_id, error);
                    break;
                }
                Ok(None) => {
                    info!("WS connection {:?} stream ended", connection_id);
                    break;
                }
                Err(_) => {
                    info!("WS connection {:?} idle timeout ({}s)", connection_id, CONNECTION_IDLE_TIMEOUT.as_secs());
                    break;
                }
            }
        }
    });

    // Write task: per-connection channel → WebSocket text frames
    let write_task = tokio::spawn(async move {
        while let Some(data) = outbound_rx.recv().await {
            // SIP messages are text — send as text frame
            let text = String::from_utf8_lossy(&data).into_owned();
            if let Err(error) = ws_sink.send(Message::text(text)).await {
                warn!("WS write error on {:?}: {}", connection_id, error);
                break;
            }
        }
    });

    // Wait for either half to close, then clean up.
    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }

    connection_map.remove(&connection_id);
    stream_connections.unregister(&remote_addr);
    // RFC 5626 §4.2.2 flow failure: notify the registrar so it can deregister
    // any binding that arrived on this WS/WSS connection.  Best-effort.
    if let Some(close_tx) = &close_tx {
        let _ = close_tx.send(connection_id.0);
    }
    info!("WS connection {:?} cleaned up", connection_id);
}

/// Spawn an outbound dispatcher task that routes outbound messages to
/// per-connection senders via the connection map.
fn spawn_outbound_dispatcher(
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    label: &'static str,
) {
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here (see tcp.rs for
                // the full rationale). Awaiting a send to a non-reading peer's full
                // bounded channel would park this single distributor while holding
                // the `connection_map` shard guard — stalling all outbound and
                // blocking accept's `insert` on the same shard. `try_send` sheds
                // for a backed-up (stuck) peer instead.
                match sender.try_send(outbound.data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("{} outbound dropped: connection {:?} send buffer full (slow/stuck peer)", label, outbound.connection_id);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("{} outbound dropped: connection {:?} closed", label, outbound.connection_id);
                    }
                }
            } else {
                debug!("{} outbound: connection {:?} not found (may have closed)", label, outbound.connection_id);
            }
        }
    });
}

/// Create a TCP listener with SO_REUSEADDR/SO_REUSEPORT and optional TOS set
/// before binding.  Shared by WS and WSS listeners.
fn bind_tcp_listener(
    local_addr: SocketAddr,
    tos: Option<u32>,
    label: &str,
) -> std::io::Result<tokio::net::TcpListener> {
    let socket = if local_addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    if let Some(tos) = tos {
        let sock_ref = socket2::SockRef::from(&socket);
        if let Err(error) = sock_ref.set_tos_v4(tos) {
            tracing::error!("failed to set IP_TOS on {label} socket: {error}");
        }
    }
    socket.bind(local_addr)?;
    socket.listen(1024)
}

/// Spawn a plain WebSocket (WS) listener.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    close_tx: Option<flume::Sender<u64>>,
) {
    spawn_outbound_dispatcher(outbound_rx, connection_map.clone(), "WS");

    tokio::spawn(async move {
        let listener = match bind_tcp_listener(local_addr, tos, "WS") {
            Ok(listener) => listener,
            Err(error) => {
                error!("failed to bind WS listener on {local_addr}: {error}");
                return;
            }
        };
        info!("WS listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((tcp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        continue;
                    }
                    let connection_id = next_connection_id();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let stream_connections = stream_connections.clone();
                    let close_tx = close_tx.clone();

                    configure_tcp_socket(&tcp_stream, tos);
                    info!("WS accepted {} as {:?}", remote_addr, connection_id);

                    tokio::spawn(async move {
                        let local = tcp_stream.local_addr().unwrap_or(local_addr);
                        handle_connection(
                            tcp_stream,
                            Transport::WebSocket,
                            connection_id,
                            local,
                            remote_addr,
                            inbound_tx,
                            connection_map,
                            stream_connections,
                            close_tx,
                        )
                        .await;
                    });
                }
                Err(error) => {
                    error!("WS accept error: {}", error);
                }
            }
        }
    });
}

/// Spawn a secure WebSocket (WSS) listener. Reuses the TLS cert from
/// the top-level `tls:` config block via `transport::tls::build_tls_acceptor`.
pub async fn listen_secure(
    local_addr: SocketAddr,
    tls_config: &TlsServerConfig,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    close_tx: Option<flume::Sender<u64>>,
) {
    let acceptor = crate::transport::tls::build_hot_reload_acceptor(tls_config).unwrap_or_else(|error| {
        eprintln!("Failed to build TLS acceptor for WSS: {error}");
        std::process::exit(1);
    });

    spawn_outbound_dispatcher(outbound_rx, connection_map.clone(), "WSS");

    tokio::spawn(async move {
        let listener = match bind_tcp_listener(local_addr, tos, "WSS") {
            Ok(listener) => listener,
            Err(error) => {
                error!("failed to bind WSS listener on {local_addr}: {error}");
                return;
            }
        };
        info!("WSS listener on {}", local_addr);

        loop {
            match listener.accept().await {
                Ok((tcp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        continue;
                    }
                    // Hot-reloadable acceptor — read the live one each accept.
                    let acceptor = (**acceptor.load()).clone();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();
                    let stream_connections = stream_connections.clone();
                    let close_tx = close_tx.clone();

                    configure_tcp_socket(&tcp_stream, tos);

                    tokio::spawn(async move {
                        // TLS handshake first
                        let tls_stream = match acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                warn!("WSS TLS handshake failed from {}: {}", remote_addr, error);
                                crate::security::record_handshake_failure(remote_addr.ip(), "WSS");
                                return;
                            }
                        };

                        let connection_id = next_connection_id();
                        info!("WSS accepted {} as {:?}", remote_addr, connection_id);

                        let local = tls_stream.get_ref().0.local_addr().unwrap_or(local_addr);
                        handle_connection(
                            tls_stream,
                            Transport::WebSocketSecure,
                            connection_id,
                            local,
                            remote_addr,
                            inbound_tx,
                            connection_map,
                            stream_connections,
                            close_tx,
                        )
                        .await;
                    });
                }
                Err(error) => {
                    error!("WSS accept error: {}", error);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_acl() -> Arc<TransportAcl> {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }

    /// Helper: find a free port by binding and releasing.
    fn free_port() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn ws_connection_lifecycle() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect as a WebSocket client
        let url = format!("ws://127.0.0.1:{}", addr.port());
        let (mut ws_stream, _response) = tokio_tungstenite::connect_async(&url)
            .await
            .expect("WS connect failed");

        // Send a SIP REGISTER as a text frame
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/WS 10.0.0.1:5060;branch=z9hG4bK776\r\n",
            "From: <sip:alice@example.com>;tag=abc123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: test-ws-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        ws_stream
            .send(Message::text(sip_message))
            .await
            .unwrap();

        // Receive the inbound message
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timed out waiting for inbound message")
        .expect("inbound channel closed");

        assert_eq!(message.transport, Transport::WebSocket);
        assert!(!message.data.is_empty());
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("REGISTER"), "expected REGISTER in data: {}", data_str);

        // Verify connection is tracked
        assert!(connection_map.contains_key(&message.connection_id));
    }

    #[tokio::test]
    async fn ws_registers_in_stream_connections_and_clears_on_close() {
        // RFC 7118 §5 / RFC 5626 §5.3: a WS connection must appear in the
        // unified stream registry (keyed by UE source address, tagged WS) so
        // the relay path can reach the UE — the only way back over WebSocket —
        // and must clear on close so a stale flow reports dead.
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let registry = StreamConnections::new();

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), registry.clone(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}", addr.port());
        let (mut ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        ws_stream
            .send(Message::text("REGISTER sip:test SIP/2.0\r\n\r\n"))
            .await
            .unwrap();
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        // The UE source address is the registry key; the relay path reuses it.
        assert_eq!(
            registry.reuse(message.remote_addr, Transport::WebSocket),
            Some(message.connection_id),
            "WS connection must be registered for MT routing"
        );
        assert!(registry.is_alive(message.remote_addr, Transport::WebSocket, message.connection_id));
        // Must never be handed back for a TLS relay.
        assert_eq!(registry.reuse(message.remote_addr, Transport::Tls), None);

        // Close → registry entry must clear (RFC 5626 §4.2.2 flow failure).
        ws_stream.close(None).await.ok();
        drop(ws_stream);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        assert_eq!(
            registry.reuse(message.remote_addr, Transport::WebSocket),
            None,
            "registry entry must clear on connection close"
        );
    }

    #[tokio::test]
    async fn ws_echoes_sip_subprotocol() {
        // RFC 7118 §4: a UA that offers the "sip" subprotocol must get it back
        // in the handshake response, or browser/JS WebSocket clients (sip.js,
        // JsSIP) abort the connection right after the upgrade (close 1006).
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::http::HeaderValue;

        let addr = free_port();
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut request = format!("ws://127.0.0.1:{}", addr.port())
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert("Sec-WebSocket-Protocol", HeaderValue::from_static("sip"));
        let (_ws_stream, response) = tokio_tungstenite::connect_async(request)
            .await
            .expect("WS connect offering the sip subprotocol failed");
        assert_eq!(
            response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|value| value.to_str().ok()),
            Some("sip"),
            "server must echo the sip subprotocol (RFC 7118 §4)"
        );
    }

    #[tokio::test]
    async fn ws_connection_cleanup() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}", addr.port());
        let (mut ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Send data so the connection gets an ID
        ws_stream
            .send(Message::text("REGISTER sip:test SIP/2.0\r\n\r\n"))
            .await
            .unwrap();
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let connection_id = message.connection_id;
        assert!(connection_map.contains_key(&connection_id));

        // Close the WebSocket
        ws_stream.close(None).await.ok();
        drop(ws_stream);

        // Wait for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !connection_map.contains_key(&connection_id),
            "connection should have been cleaned up after client close"
        );
    }

    #[tokio::test]
    async fn ws_binary_frame_accepted() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let url = format!("ws://127.0.0.1:{}", addr.port());
        let (mut ws_stream, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Send as binary frame (some WebRTC UAs do this)
        ws_stream
            .send(Message::binary(&b"OPTIONS sip:test SIP/2.0\r\n\r\n"[..]))
            .await
            .unwrap();

        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        assert_eq!(message.transport, Transport::WebSocket);
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("OPTIONS"));
    }

    #[tokio::test]
    async fn wss_connection_lifecycle() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        use tokio_rustls::rustls;
        use tokio_rustls::TlsConnector;

        let directory = tempfile::tempdir().unwrap();
        let tls_config = write_test_cert(&directory);

        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen_secure(addr, &tls_config, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), StreamConnections::new(), None, None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Build a TLS client config that trusts our self-signed cert
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
        let tls_connector = TlsConnector::from(Arc::new(client_config));

        // Manual TLS connect then WebSocket upgrade
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let tls_stream = tls_connector.connect(server_name, tcp_stream).await.unwrap();

        let url = format!("wss://localhost:{}", addr.port());
        let request = url.parse::<http::Uri>().unwrap();
        let (mut ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
            .await
            .expect("WSS WebSocket upgrade failed");

        // Send SIP REGISTER
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/WSS 10.0.0.1:5061;branch=z9hG4bK777\r\n",
            "From: <sip:bob@example.com>;tag=def456\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: test-wss-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        ws_stream
            .send(Message::text(sip_message))
            .await
            .unwrap();

        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timed out")
        .expect("channel closed");

        assert_eq!(message.transport, Transport::WebSocketSecure);
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("REGISTER"));
        assert!(connection_map.contains_key(&message.connection_id));
    }

    fn generate_test_cert() -> (String, String) {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let certificate_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("failed to create cert params");
        let certificate = certificate_params.self_signed(&key_pair).expect("self-sign");
        (certificate.pem(), key_pair.serialize_pem())
    }

    fn write_test_cert(directory: &tempfile::TempDir) -> TlsServerConfig {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&cert_path, &cert_pem).unwrap();
        std::fs::write(&key_path, &key_pem).unwrap();
        TlsServerConfig {
            certificate: cert_path.to_str().unwrap().to_string(),
            private_key: key_path.to_str().unwrap().to_string(),
            method: "TLSv1_3".to_string(),
            verify_client: false,
            client_ca: None,
        }
    }
}
