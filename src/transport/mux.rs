//! Protocol-multiplexed stream listener: raw SIP and SIP-over-WebSocket
//! (RFC 7118) on one listening socket.
//!
//! Two pairings are supported, and they are the two that are actually
//! distinguishable on the wire:
//!
//! * `tls` + `wss` — one TLS handshake, then either raw SIP over the stream or
//!   an HTTP upgrade. This is the deployment case: one 443/5061 for both a
//!   browser/WebRTC UE and a SIP trunk, through one firewall pinhole and one
//!   certificate.
//! * `tcp` + `ws` — the same without TLS.
//!
//! Plaintext and TLS on one port is *not* supported (a TLS ClientHello is not
//! a SIP message and RFC 3261 §18 gives them separate ports); configuring that
//! is a startup error rather than something this module sniffs for.
//!
//! ## How the split is decided
//!
//! [`super::stream::sniff_first_line`] reads up to the first CRLF and keys on
//! the start-line grammar: ` SIP/2.0` (RFC 3261 §7.1/§7.2) versus ` HTTP/1.1`
//! (RFC 6455 §4.1). The two are disjoint — no SIP method is an HTTP method —
//! so the classification is exact, not heuristic. Once decided, the connection
//! is handed to exactly the same handler the dedicated listener would have
//! used, tagged with the transport it turned out to speak, so everything
//! downstream (Via/Contact generation, the flow registry, MT routing, outbound
//! distribution) behaves as if it had arrived on a dedicated port.
//!
//! Cost is one sniff per *connection*; there is nothing extra on the
//! per-message path.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::config::TlsServerConfig;
use crate::transport::acl::TransportAcl;
use crate::transport::crlf_keepalive::CrlfPongTracker;
use crate::transport::pool::ConnectionPool;
use crate::transport::stream::{
    bind_tcp_listener, serve_sip_stream, sniff_stream, spawn_outbound_distributor, PrefixedStream,
    StreamContext, StreamProtocol,
};
use crate::transport::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, OutboundMessage,
    StreamConnections, Transport,
};

/// The two transports a muxed listener carries, with the outbound plumbing of
/// each. Both halves stay separate exactly as they are for dedicated
/// listeners — a connection is inserted into the map of whichever transport it
/// turned out to speak.
pub struct MuxChannels {
    /// Outbound messages addressed to the raw-SIP half (`tcp` / `tls`).
    pub sip_outbound_rx: flume::Receiver<OutboundMessage>,
    pub sip_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    /// Outbound messages addressed to the WebSocket half (`ws` / `wss`).
    pub websocket_outbound_rx: flume::Receiver<OutboundMessage>,
    pub websocket_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
}

/// Spawn a protocol-multiplexed listener on `local_addr`.
///
/// `tls_config` selects the pairing: `Some` gives `tls` + `wss` (TLS handshake
/// first, sniff the plaintext), `None` gives `tcp` + `ws`.
pub async fn listen(
    local_addr: SocketAddr,
    tls_config: Option<&TlsServerConfig>,
    channels: MuxChannels,
    inbound_tx: flume::Sender<InboundMessage>,
    acl: Arc<TransportAcl>,
    stream_connections: StreamConnections,
    tos: Option<u32>,
    pool: Option<Arc<ConnectionPool>>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) {
    let secure = tls_config.is_some();
    let (sip_transport, websocket_transport) = if secure {
        (Transport::Tls, Transport::WebSocketSecure)
    } else {
        (Transport::Tcp, Transport::WebSocket)
    };

    // Each half keeps its own distributor, so outbound routing is identical to
    // the dedicated listeners'. Only the raw-SIP half gets the pool: WS/WSS are
    // client-initiated (RFC 7118 §5) and have no outbound-connect path.
    spawn_outbound_distributor(
        channels.sip_outbound_rx,
        Arc::clone(&channels.sip_connection_map),
        sip_transport,
        pool,
    );
    spawn_outbound_distributor(
        channels.websocket_outbound_rx,
        Arc::clone(&channels.websocket_connection_map),
        websocket_transport,
        None,
    );

    let acceptor = tls_config.map(|tls_config| {
        crate::transport::tls::build_hot_reload_acceptor(tls_config).unwrap_or_else(|error| {
            eprintln!("Failed to build TLS acceptor for {local_addr} ({sip_transport}+{websocket_transport} mux): {error}");
            std::process::exit(1);
        })
    });

    let sip_connection_map = channels.sip_connection_map;
    let websocket_connection_map = channels.websocket_connection_map;

    tokio::spawn(async move {
        let listener = match bind_tcp_listener(local_addr, tos) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::error!("failed to bind {sip_transport}+{websocket_transport} mux listener on {local_addr}: {error}");
                return;
            }
        };
        info!("{sip_transport}+{websocket_transport} mux listener on {local_addr}");

        loop {
            let (tcp_stream, remote_addr) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::error!(
                        "{sip_transport}+{websocket_transport} mux accept error: {error}"
                    );
                    continue;
                }
            };
            if !acl.is_allowed(remote_addr.ip()) {
                debug!("{sip_transport}+{websocket_transport} mux rejected {remote_addr} by ACL");
                continue;
            }
            // See the TLS listener for why this is taken here, before the spawn,
            // and dropped silently rather than banned.
            let permit = match crate::security::try_accept_connection(remote_addr.ip()) {
                Ok(permit) => permit,
                Err(reason) => {
                    debug!(
                        "{sip_transport}+{websocket_transport} mux refused {remote_addr} by \
                         connection limit: {reason}"
                    );
                    crate::security::record_connection_refused(reason);
                    continue;
                }
            };
            configure_tcp_socket(&tcp_stream, tos);

            // Read the *current* acceptor — it may have been swapped by the
            // hot-reload watcher since the previous accept().
            let acceptor = acceptor.as_ref().map(|shared| (**shared.load()).clone());
            let inbound_tx = inbound_tx.clone();
            let sip_connection_map = Arc::clone(&sip_connection_map);
            let websocket_connection_map = Arc::clone(&websocket_connection_map);
            let stream_connections = stream_connections.clone();
            let crlf_pong_tracker = crlf_pong_tracker.clone();
            let close_tx = close_tx.clone();

            tokio::spawn(async move {
                match acceptor {
                    Some(acceptor) => {
                        // Bounded handshake so a peer that connects and stalls
                        // mid-handshake (slowloris) cannot pin a task + socket.
                        let tls_stream = match tokio::time::timeout(
                            crate::transport::tls::TLS_HANDSHAKE_TIMEOUT,
                            acceptor.accept(tcp_stream),
                        )
                        .await
                        {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                warn!("TLS handshake failed from {remote_addr}: {error}");
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                            Err(_) => {
                                warn!("TLS handshake timed out from {remote_addr}");
                                crate::security::record_handshake_failure(remote_addr.ip(), "TLS");
                                return;
                            }
                        };
                        let local_addr = tls_stream.get_ref().0.local_addr().unwrap_or(local_addr);
                        dispatch(
                            tls_stream,
                            (Transport::Tls, Transport::WebSocketSecure),
                            local_addr,
                            remote_addr,
                            permit,
                            inbound_tx,
                            sip_connection_map,
                            websocket_connection_map,
                            stream_connections,
                            crlf_pong_tracker,
                            close_tx,
                        )
                        .await;
                    }
                    None => {
                        let local_addr = tcp_stream.local_addr().unwrap_or(local_addr);
                        dispatch(
                            tcp_stream,
                            (Transport::Tcp, Transport::WebSocket),
                            local_addr,
                            remote_addr,
                            permit,
                            inbound_tx,
                            sip_connection_map,
                            websocket_connection_map,
                            stream_connections,
                            crlf_pong_tracker,
                            close_tx,
                        )
                        .await;
                    }
                }
            });
        }
    });
}

/// Sniff one accepted (and, for `tls`/`wss`, already-decrypted) stream and run
/// it as whichever protocol it turned out to speak.
#[allow(clippy::too_many_arguments)]
async fn dispatch<S>(
    mut stream: S,
    transports: (Transport, Transport),
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    // Connection slot taken at accept. Released when this function returns,
    // so it covers the sniff and then the whole connection, whichever protocol
    // won.
    mut permit: crate::security::AcceptPermit,
    inbound_tx: flume::Sender<InboundMessage>,
    sip_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    websocket_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    stream_connections: StreamConnections,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sip_transport, websocket_transport) = transports;
    let (protocol, prefix) = match sniff_stream(&mut stream).await {
        Ok(sniffed) => sniffed,
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            warn!("non-SIP, non-WebSocket bytes from {remote_addr} on the {sip_transport}+{websocket_transport} mux; dropping connection");
            crate::security::record_malformed_message(remote_addr.ip(), &sip_transport.to_string());
            return;
        }
        Err(error) => {
            debug!("{sip_transport}+{websocket_transport} mux: {remote_addr} closed before its first line: {error}");
            return;
        }
    };
    // Protocol decided: the handshake slot goes back, the connection slot stays
    // held by `permit` until this function returns.
    permit.handshake_done();

    let connection_id = next_connection_id();
    match protocol {
        StreamProtocol::Sip => {
            debug!("{sip_transport} accepted {remote_addr} as {connection_id:?} (mux)");
            let (reader, writer) = tokio::io::split(stream);
            serve_sip_stream(
                reader,
                writer,
                StreamContext {
                    transport: sip_transport,
                    connection_id,
                    local_addr,
                    remote_addr,
                },
                prefix,
                inbound_tx,
                sip_connection_map,
                // TCP reaches peers through the outbound pool; the secure and
                // WebSocket transports route back over the inbound flow.
                (sip_transport == Transport::Tls).then_some(stream_connections),
                crlf_pong_tracker,
                close_tx,
            )
            .await;
        }
        StreamProtocol::WebSocket => {
            info!("{websocket_transport} accepted {remote_addr} as {connection_id:?} (mux)");
            // Replay the sniffed bytes so the upgrade handshake sees its own
            // request line.
            crate::transport::ws::handle_connection(
                PrefixedStream::new(stream, prefix),
                websocket_transport,
                connection_id,
                local_addr,
                remote_addr,
                // Hands the connection slot on; its handshake half was already
                // released above, and `handshake_done` is idempotent.
                permit,
                inbound_tx,
                websocket_connection_map,
                stream_connections,
                close_tx,
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;

    const REGISTER: &str = concat!(
        "REGISTER sip:example.com SIP/2.0\r\n",
        "Via: SIP/2.0/TCP 10.0.0.1:5060;branch=z9hG4bK776\r\n",
        "From: <sip:alice@example.com>;tag=abc123\r\n",
        "To: <sip:alice@example.com>\r\n",
        "Call-ID: mux-test@example.com\r\n",
        "CSeq: 1 REGISTER\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    struct Harness {
        addr: SocketAddr,
        inbound_rx: flume::Receiver<InboundMessage>,
        sip_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
        websocket_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    }

    /// Bind a port, release it, and start a mux listener on it.
    async fn spawn_mux(tls_config: Option<&TlsServerConfig>) -> Harness {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_sip_outbound_tx, sip_outbound_rx) = flume::unbounded::<OutboundMessage>();
        let (_ws_outbound_tx, websocket_outbound_rx) = flume::unbounded::<OutboundMessage>();
        let sip_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let websocket_connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(
            addr,
            tls_config,
            MuxChannels {
                sip_outbound_rx,
                sip_connection_map: Arc::clone(&sip_connection_map),
                websocket_outbound_rx,
                websocket_connection_map: Arc::clone(&websocket_connection_map),
            },
            inbound_tx,
            Arc::new(TransportAcl::new(vec![], vec![])),
            StreamConnections::new(),
            None,
            None,
            None,
            None,
        )
        .await;
        // listen() binds inside a spawned task.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Harness {
            addr,
            inbound_rx,
            sip_connection_map,
            websocket_connection_map,
        }
    }

    async fn next_inbound(harness: &Harness) -> InboundMessage {
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            harness.inbound_rx.recv_async(),
        )
        .await
        .expect("timed out waiting for an inbound message")
        .expect("inbound channel closed")
    }

    /// Wait for the connection to appear in `map` and hand back its sender.
    async fn sender_for(
        map: &Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
        connection_id: ConnectionId,
    ) -> mpsc::Sender<Bytes> {
        for _ in 0..100 {
            if let Some(entry) = map.get(&connection_id) {
                return entry.value().clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("connection {connection_id:?} never registered");
    }

    // --- tcp + ws -----------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_ws_mux_carries_both_protocols_on_one_socket() {
        let harness = spawn_mux(None).await;

        // A raw SIP peer.
        let mut sip_client = tokio::net::TcpStream::connect(harness.addr).await.unwrap();
        sip_client.write_all(REGISTER.as_bytes()).await.unwrap();
        let sip_message = next_inbound(&harness).await;
        assert_eq!(sip_message.transport, Transport::Tcp);
        assert_eq!(sip_message.local_addr, harness.addr);
        assert!(String::from_utf8_lossy(&sip_message.data).starts_with("REGISTER"));
        assert!(
            harness
                .sip_connection_map
                .contains_key(&sip_message.connection_id),
            "raw SIP connection must land in the SIP connection map"
        );
        assert!(
            !harness
                .websocket_connection_map
                .contains_key(&sip_message.connection_id),
            "raw SIP connection must not land in the WebSocket map"
        );

        // A WebSocket UE on the very same port (RFC 7118).
        let tcp_stream = tokio::net::TcpStream::connect(harness.addr).await.unwrap();
        let (mut websocket, _response) =
            tokio_tungstenite::client_async("ws://127.0.0.1/", tcp_stream)
                .await
                .expect("WebSocket upgrade through the mux failed");
        websocket.send(Message::text(REGISTER)).await.unwrap();
        let websocket_message = next_inbound(&harness).await;
        assert_eq!(websocket_message.transport, Transport::WebSocket);
        assert!(String::from_utf8_lossy(&websocket_message.data).starts_with("REGISTER"));
        assert!(
            harness
                .websocket_connection_map
                .contains_key(&websocket_message.connection_id),
            "WebSocket connection must land in the WebSocket connection map"
        );

        // Each half answers on its own framing: raw bytes for SIP, a text frame
        // for WebSocket.
        let sip_sender = sender_for(&harness.sip_connection_map, sip_message.connection_id).await;
        sip_sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .unwrap();
        let mut raw = vec![0u8; 18];
        sip_client.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"SIP/2.0 200 OK\r\n\r\n");

        let websocket_sender = sender_for(
            &harness.websocket_connection_map,
            websocket_message.connection_id,
        )
        .await;
        websocket_sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .unwrap();
        match websocket.next().await.unwrap().unwrap() {
            Message::Text(text) => assert_eq!(text.as_str(), "SIP/2.0 200 OK\r\n\r\n"),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_ws_mux_frames_a_message_split_across_segments() {
        // The sniff consumes the first line; the rest of the message must still
        // be framed exactly once.
        let harness = spawn_mux(None).await;
        let mut client = tokio::net::TcpStream::connect(harness.addr).await.unwrap();
        let (first_line, rest) = REGISTER.split_at(REGISTER.find("\r\n").unwrap() + 2);
        client.write_all(first_line.as_bytes()).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        client.write_all(rest.as_bytes()).await.unwrap();
        let message = next_inbound(&harness).await;
        assert_eq!(message.transport, Transport::Tcp);
        assert_eq!(String::from_utf8_lossy(&message.data), REGISTER);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_ws_mux_answers_a_crlf_keepalive_then_frames_sip() {
        // RFC 5626 §4.4.1 ping ahead of the first request: the sniff must not
        // swallow it, and must not mistake it for a WebSocket upgrade.
        let harness = spawn_mux(None).await;
        let mut client = tokio::net::TcpStream::connect(harness.addr).await.unwrap();
        client.write_all(b"\r\n\r\n").await.unwrap();
        client.write_all(REGISTER.as_bytes()).await.unwrap();
        let message = next_inbound(&harness).await;
        assert_eq!(message.transport, Transport::Tcp);
        assert_eq!(String::from_utf8_lossy(&message.data), REGISTER);
        let mut pong = [0u8; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.read_exact(&mut pong),
        )
        .await
        .expect("timed out waiting for the CRLF pong")
        .unwrap();
        assert_eq!(&pong, b"\r\n");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_ws_mux_drops_a_probe_that_is_neither_protocol() {
        let harness = spawn_mux(None).await;
        let mut client = tokio::net::TcpStream::connect(harness.addr).await.unwrap();
        client.write_all(b"HELO example.com\r\n").await.unwrap();
        // The listener closes the connection; the next read returns EOF.
        let mut buffer = [0u8; 16];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(3), client.read(&mut buffer))
                .await
                .expect("connection was not dropped");
        assert_eq!(
            read.unwrap(),
            0,
            "expected the probe's connection to be closed"
        );
        assert!(harness.inbound_rx.is_empty());
    }

    // --- tls + wss ----------------------------------------------------------

    fn test_tls_config(directory: &tempfile::TempDir) -> TlsServerConfig {
        let key_pair = rcgen::KeyPair::generate().expect("keygen");
        let params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        let certificate = params.self_signed(&key_pair).expect("self-sign");
        let certificate_path = directory.path().join("cert.pem");
        let private_key_path = directory.path().join("key.pem");
        std::fs::write(&certificate_path, certificate.pem()).unwrap();
        std::fs::write(&private_key_path, key_pair.serialize_pem()).unwrap();
        TlsServerConfig {
            certificate: certificate_path.to_str().unwrap().to_string(),
            private_key: private_key_path.to_str().unwrap().to_string(),
            certificates: vec![],
            method: crate::config::TlsMethod::Tls13,
            verify_client: false,
            client_ca: None,
            client_certificate: None,
            client_private_key: None,
        }
    }

    fn tls_connector(tls_config: &TlsServerConfig) -> tokio_rustls::TlsConnector {
        use rustls_pki_types::pem::PemObject;
        let pem = std::fs::read(&tls_config.certificate).unwrap();
        let mut cursor = std::io::Cursor::new(pem);
        let certificates: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).unwrap();
        }
        tokio_rustls::TlsConnector::from(Arc::new(
            tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    }

    async fn connect_tls(
        connector: &tokio_rustls::TlsConnector,
        addr: SocketAddr,
    ) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        connector.connect(server_name, tcp_stream).await.unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_wss_mux_carries_both_protocols_on_one_socket() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().unwrap();
        let tls_config = test_tls_config(&directory);
        let connector = tls_connector(&tls_config);
        let harness = spawn_mux(Some(&tls_config)).await;

        // A SIP trunk speaking raw SIP over TLS.
        let mut sip_client = connect_tls(&connector, harness.addr).await;
        sip_client.write_all(REGISTER.as_bytes()).await.unwrap();
        let sip_message = next_inbound(&harness).await;
        assert_eq!(sip_message.transport, Transport::Tls);
        assert!(String::from_utf8_lossy(&sip_message.data).starts_with("REGISTER"));
        assert!(harness
            .sip_connection_map
            .contains_key(&sip_message.connection_id));

        // A browser UE speaking WSS on the same port and the same certificate.
        let tls_stream = connect_tls(&connector, harness.addr).await;
        let (mut websocket, _response) =
            tokio_tungstenite::client_async("wss://localhost/", tls_stream)
                .await
                .expect("WSS upgrade through the mux failed");
        websocket.send(Message::text(REGISTER)).await.unwrap();
        let websocket_message = next_inbound(&harness).await;
        assert_eq!(websocket_message.transport, Transport::WebSocketSecure);
        assert!(harness
            .websocket_connection_map
            .contains_key(&websocket_message.connection_id));

        // Responses go back on the framing each half expects.
        let sip_sender = sender_for(&harness.sip_connection_map, sip_message.connection_id).await;
        sip_sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .unwrap();
        let mut raw = vec![0u8; 18];
        sip_client.read_exact(&mut raw).await.unwrap();
        assert_eq!(&raw, b"SIP/2.0 200 OK\r\n\r\n");

        let websocket_sender = sender_for(
            &harness.websocket_connection_map,
            websocket_message.connection_id,
        )
        .await;
        websocket_sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .unwrap();
        match websocket.next().await.unwrap().unwrap() {
            Message::Text(text) => assert_eq!(text.as_str(), "SIP/2.0 200 OK\r\n\r\n"),
            other => panic!("expected a text frame, got {other:?}"),
        }
    }
}
