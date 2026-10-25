//! Opening a pooled outbound TLS connection: the TCP connect, the handshake,
//! the reader and writer tasks, and the pool entry.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use super::{backlogged, enqueue, evict_if_current, ConnectionPool, Enqueued, PoolEntry, PoolKey};
use crate::transport::crlf_keepalive::drain_leading_crlf_keepalives;
use crate::transport::outbound_tls::resolve_server_name;
use crate::transport::send_queue;
use crate::transport::tcp::{frame_sip_message, FrameVerdict};
use crate::transport::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, Transport,
};

impl ConnectionPool {
    /// Open a TLS connection to `destination` under `key`, send `data` on it
    /// and pool it. Called from [`establish_coalesced`](Self::establish_coalesced).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn establish_tls_connection(
        &self,
        key: &PoolKey,
        listener: Option<SocketAddr>,
        destination: SocketAddr,
        server_name: Option<&str>,
        verify: bool,
        connector: Arc<TlsConnector>,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        // Create new TCP connection, then wrap with TLS handshake.
        // The default outbound path does NOT bind a specific local port — the
        // TLS listen port (5061) is for inbound only; outbound uses ephemeral.
        // A `send_socket=` egress pin (`listener = Some`) binds that listener's
        // interface IP (ephemeral port) so traffic leaves the intended NIC.
        //
        // Fail-fast on both the TCP connect and the TLS handshake: an
        // unreachable or silently-dropping peer would otherwise block the
        // calling worker indefinitely (same wedge class as the TCP path).
        let connect_future = async {
            match listener {
                Some(listener) => {
                    let source = SocketAddr::new(listener.ip(), 0);
                    let socket = if destination.is_ipv6() {
                        tokio::net::TcpSocket::new_v6()?
                    } else {
                        tokio::net::TcpSocket::new_v4()?
                    };
                    socket.set_reuseaddr(true)?;
                    socket.set_reuseport(true)?;
                    if let Some(tos) = self.tos {
                        // Family-aware, best-effort (see connect_tcp).
                        crate::transport::apply_tos(&socket2::SockRef::from(&socket), tos);
                    }
                    socket.bind(source).map_err(|error| {
                        warn!(bind_addr = %source, destination = %destination, "pool: TLS bind to requested source failed: {error}");
                        error
                    })?;
                    socket.connect(destination).await
                }
                None => tokio::net::TcpStream::connect(destination).await,
            }
        };
        let tcp_stream = match tokio::time::timeout(self.connect_timeout, connect_future).await {
            Ok(result) => result?,
            Err(_) => {
                warn!(destination = %destination, timeout = ?self.connect_timeout, "pool: TLS TCP connect timed out");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS TCP connect timed out",
                ));
            }
        };
        configure_tcp_socket(&tcp_stream, self.tos);

        // TLS handshake — SNI/certificate name from `server_name` when the relay
        // resolved a hostname; else the destination IP literal. A verified
        // connection presents the name its key verifies, which for an
        // address-routed send reusing a verified key is that key's name.
        let handshake_name =
            resolve_server_name(destination, key.verified_name.as_deref().or(server_name))?;
        let tls_stream = match tokio::time::timeout(
            self.connect_timeout,
            connector.connect(handshake_name, tcp_stream),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                // A refused certificate is the case worth naming: the request
                // fails as any connect failure does, and this line is the only
                // place that says it was the peer's identity, not its reachability.
                if verify {
                    warn!(
                        destination = %destination,
                        server_name = key.verified_name.as_deref().unwrap_or_default(),
                        %error,
                        "pool: outbound TLS server verification failed; connection refused"
                    );
                }
                return Err(error);
            }
            Err(_) => {
                warn!(destination = %destination, timeout = ?self.connect_timeout, "pool: TLS handshake timed out");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ));
            }
        };

        let connection_id = next_connection_id();
        // A pinned connection's traffic belongs to its listener, so what the
        // peer sends over it is handled as having arrived there.
        let local_addr = listener.unwrap_or_else(|| {
            let socket = tls_stream.get_ref().0;
            socket.local_addr().unwrap_or(self.local_addr)
        });
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        // Per-connection write channel
        let (write_tx, mut write_rx) =
            send_queue::channel_with_limit(Transport::Tls, connection_id, self.send_queue_bytes);

        // Register in the shared connection map
        self.connection_map.insert(connection_id, write_tx.clone());

        // Register in the stream-connection registry so the dispatcher can
        // reuse this connection for inbound routing (e.g., INVITEs to
        // registered trunks).
        match (&self.stream_connections, listener) {
            (Some(registry), Some(listener)) => {
                registry.register_on_listener(destination, Transport::Tls, connection_id, listener)
            }
            (Some(registry), None) => registry.register(destination, Transport::Tls, connection_id),
            (None, _) => {}
        }

        debug!(
            destination = %destination,
            connection_id = ?connection_id,
            "pool: opened outbound TLS connection"
        );

        // Read task — bidirectional: responses AND incoming requests come back here.
        // No idle timeout — the connection stays alive until peer close or error.
        // TCP keepalive (configured at socket level) handles dead peer detection.
        let inbound_tx = self.inbound_tx.clone();
        let conn_map = self.connection_map.clone();
        let connections = self.connections.clone();
        let stream_connections = self.stream_connections.clone();
        let key_for_cleanup = key.clone();
        let keepalive_writer = write_tx.clone();
        let crlf_pong_tracker = self.crlf_pong_tracker.clone();
        tokio::spawn(async move {
            // SIP-over-TLS framing — see the matching comment in send_tcp's
            // read task above. A raw `reader.read()` on a TLS stream can
            // return a partial SIP message or coalesce two messages into one
            // chunk; both produce parser garbage and silent call drops.
            let mut accumulator = BytesMut::with_capacity(65536);
            let mut read_buf = [0u8; 8192];
            loop {
                match reader.read(&mut read_buf).await {
                    Ok(0) => {
                        info!(
                            "pool: TLS connection {:?} to {} closed by peer",
                            connection_id, destination
                        );
                        break;
                    }
                    Ok(size) => {
                        accumulator.extend_from_slice(&read_buf[..size]);
                        loop {
                            // RFC 5626 §4.4.1 keepalive handling + RFC 3261 §7.5
                            // stray-CRLF stripping in one pass.
                            drain_leading_crlf_keepalives(
                                &mut accumulator,
                                connection_id,
                                &keepalive_writer,
                                crlf_pong_tracker.as_ref(),
                            );
                            if accumulator.is_empty() {
                                break;
                            }
                            // Same ceiling as the inbound listeners: an
                            // upstream that declares a huge Content-Length (or
                            // never terminates its header block) would
                            // otherwise grow this accumulator without bound.
                            // No 513 here — the pool reads responses, and a
                            // response is not something to answer.
                            let message_len = match frame_sip_message(
                                &accumulator,
                                crate::security::max_message_bytes(),
                            ) {
                                FrameVerdict::Complete { len } => len,
                                FrameVerdict::NeedMore => break,
                                FrameVerdict::Oversized { declared, .. } => {
                                    warn!(
                                        declared,
                                        limit = crate::security::max_message_bytes(),
                                        "pool: {} peer {} declared an oversized message; dropping connection",
                                        "TLS",
                                        destination
                                    );
                                    break;
                                }
                                FrameVerdict::Garbage => {
                                    warn!(
                                        "pool: non-SIP bytes from {} peer {}; dropping connection",
                                        "TLS", destination
                                    );
                                    break;
                                }
                            };
                            let data = accumulator.split_to(message_len).freeze();
                            let message = InboundMessage {
                                connection_id,
                                transport: Transport::Tls,
                                // Outbound connection: no front in front of it.
                                client_transport: None,
                                local_addr,
                                remote_addr: destination,
                                data,
                            };
                            if let Err(error) = inbound_tx.send_async(message).await {
                                error!("pool: TLS inbound enqueue failed: {}", error);
                                conn_map.remove(&connection_id);
                                evict_if_current(&connections, &key_for_cleanup, connection_id);
                                if let Some(ref stream_connections) = stream_connections {
                                    stream_connections.unregister(
                                        &destination,
                                        Transport::Tls,
                                        connection_id,
                                    );
                                }
                                return;
                            }
                        }
                    }
                    Err(error) => {
                        warn!("pool: TLS read error on {:?}: {}", connection_id, error);
                        break;
                    }
                }
            }
            conn_map.remove(&connection_id);
            evict_if_current(&connections, &key_for_cleanup, connection_id);
            if let Some(ref stream_connections) = stream_connections {
                stream_connections.unregister(&destination, Transport::Tls, connection_id);
            }
        });

        // Write task
        let write_timeout = self.write_timeout;
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                match tokio::time::timeout(write_timeout, writer.write_all(&data)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        warn!("pool: TLS write error on {:?}: {}", connection_id, error);
                        break;
                    }
                    // Peer is not draining the connection: drop it so
                    // callers stop queueing behind it.
                    Err(_) => {
                        write_rx.stalled(destination);
                        break;
                    }
                }
            }
        });

        // Send the initial data (never waits — see the TCP path).
        match enqueue(&write_tx, data) {
            Enqueued::Sent => {}
            Enqueued::Closed => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pooled TLS connection closed immediately",
                ));
            }
            Enqueued::Backlogged => {
                return Err(backlogged(destination, &write_tx));
            }
        }

        // Store in pool
        self.connections.insert(
            key.clone(),
            PoolEntry {
                connection_id,
                sender: write_tx,
            },
        );
        // A peer that closes straight after the first message can end the read
        // task before the insert above, and its eviction then found nothing to
        // remove. The reader leaves the connection map before it evicts, so a
        // connection already gone from it is a dead entry: drop it now rather
        // than leave it in the pool until the next send to this key trips on it.
        if !self.connection_map.contains_key(&connection_id) {
            evict_if_current(&self.connections, key, connection_id);
        }

        Ok(connection_id)
    }
}
