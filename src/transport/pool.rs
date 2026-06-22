//! Outbound TCP/TLS connection pool.
//!
//! When the proxy needs to relay a SIP message to a remote server over TCP/TLS,
//! it needs an established connection to that destination. This pool creates and
//! reuses connections, keyed by `(SocketAddr, Transport)`.
//!
//! Architecture:
//!   - Pool stores `mpsc::Sender<Bytes>` per destination (same pattern as inbound connections)
//!   - Each pooled connection has a read task that feeds responses back to the inbound channel
//!   - Idle connections are closed after `CONNECTION_IDLE_TIMEOUT`
//!   - Connections are removed on error and recreated on next use

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use crate::transport::{
    ConnectionId, InboundMessage, StreamConnections, Transport,
    configure_tcp_socket, next_connection_id,
};
use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::tcp::extract_sip_message_length;

/// Idle timeout for pooled outbound connections (shorter than inbound).
///
/// Outbound pool connections are used for probes and registrant — if no
/// response comes back within this window the connection is dead and should
/// be torn down so the next send creates a fresh one.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Fail-fast timeout for outbound TCP/TLS connection establishment.
///
/// An ESP-over-TCP IPsec MT send must leave from the fixed protected source
/// port (`pcscf_port_c`, TS 33.203 SA #3), so it can never fall back to an
/// ephemeral port.  When the UE's SA pair has been torn down (idle-liveness
/// dereg) the SYN goes nowhere and the kernel emits no RST — `connect()` would
/// otherwise block forever, stranding the PyExecutor worker that drove the
/// relay.  With work pending and zero completions for 30 s the script-executor
/// watchdog aborts the whole process (see `script/py_executor.rs`).  Bounding
/// the connect at 5 s (≥6× under the watchdog window, under SIP Timer F = 32 s)
/// turns a doomed send into a fast `Err` the caller already handles, instead of
/// a process abort.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Key for a pooled connection: destination address + transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PoolKey {
    destination: SocketAddr,
    transport: Transport,
}

/// A pooled outbound connection.
struct PoolEntry {
    connection_id: ConnectionId,
    sender: mpsc::Sender<Bytes>,
}

/// Connection pool for outbound TCP/TLS connections.
pub struct ConnectionPool {
    connections: Arc<DashMap<PoolKey, PoolEntry>>,
    /// Per-destination establishment locks.  Concurrent first-sends to the same
    /// destination must coalesce onto a single connection: an ESP-over-TCP
    /// IPsec send binds the fixed source port `pcscf_port_c`, so a second
    /// concurrent `bind`/`connect` to the same `(src, dst)` 4-tuple fails
    /// `EADDRNOTAVAIL`/`EADDRINUSE`.  The first caller establishes under the
    /// lock; the rest wait, re-check, and reuse.  Entries are pruned once no
    /// waiter remains so the map stays bounded even as a UE's `port_us` rotates
    /// each re-AKA.
    connect_locks: Arc<DashMap<PoolKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Shared connection map (same one used by inbound connections).
    /// Pooled connections are also registered here so responses can be
    /// routed back via the same connection_id.
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    /// Channel to feed inbound responses back to the dispatcher.
    inbound_tx: flume::Sender<InboundMessage>,
    /// Local address to use as source in InboundMessage.
    local_addr: SocketAddr,
    /// Pre-computed TOS byte (DSCP << 2) for DSCP/DiffServ marking.
    tos: Option<u32>,
    /// TLS connector for outbound TLS connections.
    tls_connector: TlsConnector,
    /// Unified stream-connection registry — the pool registers the outbound
    /// TLS connections it creates here (tagged `Transport::Tls`) so the
    /// dispatcher can reuse them for inbound routing (e.g., INVITEs to
    /// registered trunks). Like OpenSIPS connection reuse.
    stream_connections: Option<StreamConnections>,
    /// RFC 5626 §4.4.1 pong tracker — populated when siphon's own keepalive
    /// prober is running.  Read tasks always answer peer pings regardless
    /// (RFC contract), but only notify the tracker on pong when it's set.
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    /// Fail-fast establishment timeout (defaults to [`TCP_CONNECT_TIMEOUT`]).
    /// A field rather than a bare const so tests can drive a short value and
    /// exercise the timeout branch in milliseconds.
    connect_timeout: Duration,
}

/// Build a permissive TLS client config that accepts any server certificate.
///
/// SIP trunks and interconnect peers rarely present certificates chained to
/// public CAs, so we disable verification by default (same as OpenSIPS/Kamailio
/// `tls_verify_server = 0`).
fn build_outbound_tls_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    use tokio_rustls::rustls;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();

    Arc::new(config)
}

/// Certificate verifier that accepts any server certificate (no verification).
#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        tokio_rustls::rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ConnectionPool {
    pub fn new(
        connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
        inbound_tx: flume::Sender<InboundMessage>,
        local_addr: SocketAddr,
        tos: Option<u32>,
        stream_connections: Option<StreamConnections>,
        crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    ) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            connect_locks: Arc::new(DashMap::new()),
            connection_map,
            inbound_tx,
            local_addr,
            tos,
            tls_connector: TlsConnector::from(build_outbound_tls_config()),
            stream_connections,
            crlf_pong_tracker,
            connect_timeout: TCP_CONNECT_TIMEOUT,
        }
    }

    /// Send data to a destination, creating or reusing a pooled TCP connection.
    ///
    /// Returns the `ConnectionId` used (so responses can be correlated).
    pub async fn send_tcp(
        &self,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        // Default outbound: bind to the local IP (correct interface) but
        // an ephemeral port — see send_tcp_inner for the rationale.
        let bind_addr = SocketAddr::new(self.local_addr.ip(), 0);
        self.send_tcp_inner(bind_addr, destination, data).await
    }

    /// Send data to a destination, binding the local socket to a
    /// specific source address — used for ESP-over-TCP IPsec where
    /// the kernel egress XFRM selector for SA #3 (TS 33.203 §6.3 /
    /// §7.2) requires src=`pcscf_port_c`, dst=`ue_port_us`, and an
    /// ephemerally-bound socket would never match.
    ///
    /// Same pooling semantics as `send_tcp` — but **destinations
    /// reached this way must always use the same source**.  The pool
    /// keys connections by destination only, so mixing source-bound
    /// and ephemeral connections to the same destination would either
    /// reuse the wrong one or hit `EADDRNOTAVAIL` on rebind.  In
    /// practice IPsec destinations are exclusively source-bound and
    /// non-IPsec destinations are exclusively ephemeral; no mixing
    /// occurs at runtime.
    pub async fn send_tcp_from(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        self.send_tcp_inner(source, destination, data).await
    }

    async fn send_tcp_inner(
        &self,
        bind_addr: SocketAddr,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        let key = PoolKey {
            destination,
            transport: Transport::Tcp,
        };

        // Fast path: reuse a live pooled connection without taking the
        // per-destination establishment lock.
        if let Some(entry) = self.connections.get(&key) {
            if !entry.sender.is_closed()
                && entry.sender.send(data.clone()).await.is_ok()
            {
                return Ok(entry.connection_id);
            }
            // Connection dead — remove and create new
            drop(entry);
            self.connections.remove(&key);
        }

        // Coalesce concurrent establishment to this destination onto a single
        // connection.  A second concurrent connect from the fixed IPsec source
        // port would `bind`/`connect` the same `(src, dst)` 4-tuple and fail
        // `EADDRNOTAVAIL`/`EADDRINUSE`; instead the first caller establishes
        // under the lock while the rest wait and reuse the result.
        let connect_lock = self
            .connect_locks
            .entry(key)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let result = {
            let _establish_guard = connect_lock.lock().await;
            // Re-check: a peer may have established the connection while we
            // were waiting for the lock.
            if let Some(entry) = self.connections.get(&key) {
                if !entry.sender.is_closed()
                    && entry.sender.send(data.clone()).await.is_ok()
                {
                    Ok(entry.connection_id)
                } else {
                    drop(entry);
                    self.connections.remove(&key);
                    self.establish_tcp_connection(key, bind_addr, destination, data)
                        .await
                }
            } else {
                self.establish_tcp_connection(key, bind_addr, destination, data)
                    .await
            }
        };
        // Drop our per-destination lock once no waiter remains (map ref + our
        // local clone == 2).  Keeps `connect_locks` bounded even as a UE's
        // `port_us` rotates each re-AKA.
        self.connect_locks
            .remove_if(&key, |_, lock| Arc::strong_count(lock) <= 2);
        result
    }

    /// Establish a fresh outbound TCP connection to `destination`, bound to
    /// `bind_addr`, send `data`, and register the connection in the pool.
    /// Called by [`Self::send_tcp_inner`] while it holds the per-destination
    /// establishment lock, so concurrent sends coalesce onto one connection.
    async fn establish_tcp_connection(
        &self,
        key: PoolKey,
        bind_addr: SocketAddr,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        // Create new connection.  Default bind (`port 0`) lets the OS
        // pick an ephemeral port — required for non-IPsec destinations
        // because binding to the exact listen port causes EADDRNOTAVAIL
        // when a pooled connection in TIME_WAIT collides on the 4-tuple
        // (local:5060 → remote:6060).  IPsec callers (`send_tcp_from`)
        // bind to a specific `(pcscf_addr, pcscf_port_c)` because
        // ESP-over-TCP SA selectors require it; SO_REUSEADDR (set
        // below) lets us survive single-UE TIME_WAIT churn.
        //
        // SO_REUSEPORT is also set: the inbound TCP listener on the
        // protected ports (P-CSCF) is created with SO_REUSEPORT (see
        // transport/tcp.rs), and Linux requires every socket bound to
        // the same (addr, port) tuple to have SO_REUSEPORT set
        // consistently — otherwise our outbound bind to e.g.
        // (pcscf_addr, pcscf_port_c) collides with the listener and
        // returns EADDRINUSE.  For ephemeral binds (port 0) the flag
        // is a no-op since each socket gets its own port.
        let socket = if destination.is_ipv6() {
            tokio::net::TcpSocket::new_v6()?
        } else {
            tokio::net::TcpSocket::new_v4()?
        };
        socket.set_reuseaddr(true)?;
        socket.set_reuseport(true)?;
        if let Some(tos) = self.tos {
            let sock_ref = socket2::SockRef::from(&socket);
            sock_ref.set_tos_v4(tos)?;
        }
        socket.bind(bind_addr).map_err(|e| {
            warn!(
                bind_addr = %bind_addr,
                destination = %destination,
                "pool: TCP bind to requested source failed: {e}"
            );
            e
        })?;
        // Fail-fast: a torn-down IPsec SA gives no SYN-ACK and no RST, so an
        // un-bounded connect would block the calling worker forever (and trip
        // the script-executor watchdog → process abort).  Bound it.
        let stream = match tokio::time::timeout(self.connect_timeout, socket.connect(destination))
            .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                warn!(
                    bind_addr = %bind_addr,
                    destination = %destination,
                    "pool: TCP connect failed: {e}"
                );
                return Err(e);
            }
            Err(_) => {
                warn!(
                    bind_addr = %bind_addr,
                    destination = %destination,
                    timeout = ?self.connect_timeout,
                    "pool: TCP connect timed out — no SYN-ACK and no RST \
                     (likely a torn-down IPsec SA); failing fast so the caller \
                     is not stranded"
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TCP connect timed out",
                ));
            }
        };
        configure_tcp_socket(&stream, self.tos);

        let connection_id = next_connection_id();
        let local_addr = stream.local_addr().unwrap_or(self.local_addr);
        // Diagnostic: emit the actual `(local_addr → destination)` so
        // ESP-over-TCP issues are debuggable without a tcpdump.  The
        // kernel egress XFRM selector matches on the FULL 4-tuple, so
        // a mismatch between `bind_addr` and the resulting `local_addr`
        // (e.g. silent fallback to ephemeral on REUSE conflict) is the
        // first thing to check when SA `oseq` stays at 0.
        debug!(
            connection_id = ?connection_id,
            requested_bind = %bind_addr,
            actual_local = %local_addr,
            destination = %destination,
            "pool: opened outbound TCP connection (4-tuple)"
        );
        let (mut reader, mut writer) = stream.into_split();

        // Per-connection write channel
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);

        // Register in the shared connection map so the outbound distributor
        // can route responses back on this connection.
        self.connection_map.insert(connection_id, write_tx.clone());

        debug!(
            destination = %destination,
            connection_id = ?connection_id,
            "pool: opened outbound TCP connection"
        );

        // Read task — responses from the remote server come back here.
        //
        // SIP-over-TCP requires Content-Length-based message framing (RFC 3261
        // §18.3): each TCP read may deliver a partial message, multiple
        // messages, or any combination. Without framing, multi-message
        // arrivals were forwarded as a single InboundMessage and the parser
        // saw garbled headers — manifesting as missing 200 OKs and silent
        // call failures under any sustained TCP load.
        let inbound_tx = self.inbound_tx.clone();
        let conn_map = self.connection_map.clone();
        let connections = self.connections.clone();
        let key_for_cleanup = key;
        let keepalive_writer = write_tx.clone();
        let crlf_pong_tracker = self.crlf_pong_tracker.clone();
        tokio::spawn(async move {
            let mut accumulator = BytesMut::with_capacity(65536);
            let mut read_buf = [0u8; 8192];
            loop {
                match tokio::time::timeout(POOL_IDLE_TIMEOUT, reader.read(&mut read_buf)).await
                {
                    Ok(Ok(0)) => {
                        info!("pool: TCP connection {:?} to {} closed by peer", connection_id, destination);
                        break;
                    }
                    Ok(Ok(size)) => {
                        accumulator.extend_from_slice(&read_buf[..size]);

                        // Drain all complete messages from the accumulator.
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
                            let message_len = match extract_sip_message_length(&accumulator) {
                                Some(len) if len <= accumulator.len() => len,
                                _ => break, // incomplete — wait for more bytes
                            };
                            let data = accumulator.split_to(message_len).freeze();
                            let message = InboundMessage {
                                connection_id,
                                transport: Transport::Tcp,
                                local_addr,
                                remote_addr: destination,
                                data,
                            };
                            if let Err(error) = inbound_tx.send_async(message).await {
                                error!("pool: inbound enqueue failed: {}", error);
                                return;
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        warn!("pool: TCP read error on {:?}: {}", connection_id, error);
                        break;
                    }
                    Err(_) => {
                        info!(
                            "pool: TCP connection {:?} idle timeout ({}s)",
                            connection_id,
                            POOL_IDLE_TIMEOUT.as_secs()
                        );
                        break;
                    }
                }
            }
            conn_map.remove(&connection_id);
            connections.remove(&key_for_cleanup);
        });

        // Write task
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if let Err(error) = writer.write_all(&data).await {
                    warn!("pool: TCP write error on {:?}: {}", connection_id, error);
                    break;
                }
            }
        });

        // Send the initial data
        if write_tx.send(data).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pooled connection closed immediately",
            ));
        }

        // Store in pool
        self.connections.insert(
            key,
            PoolEntry {
                connection_id,
                sender: write_tx,
            },
        );

        Ok(connection_id)
    }

    /// Send data to a destination, creating or reusing a pooled TLS connection.
    ///
    /// Returns the `ConnectionId` used (so responses can be correlated).
    pub async fn send_tls(
        &self,
        destination: SocketAddr,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        let key = PoolKey {
            destination,
            transport: Transport::Tls,
        };

        // Try existing connection first
        if let Some(entry) = self.connections.get(&key) {
            if !entry.sender.is_closed()
                && entry.sender.send(data.clone()).await.is_ok()
            {
                return Ok(entry.connection_id);
            }
            // Connection dead — remove and create new
            drop(entry);
            self.connections.remove(&key);
        }

        // Create new TCP connection, then wrap with TLS handshake.
        // Unlike TCP pool connections we do NOT bind to a specific local port —
        // the TLS listen port (5061) is for inbound only; outbound uses ephemeral.
        //
        // Fail-fast on both the TCP connect and the TLS handshake: an
        // unreachable or silently-dropping peer would otherwise block the
        // calling worker indefinitely (same wedge class as the TCP path).
        let tcp_stream = match tokio::time::timeout(
            self.connect_timeout,
            tokio::net::TcpStream::connect(destination),
        )
        .await
        {
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

        // TLS handshake — use the destination IP as SNI
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(
            destination.ip().to_string()
        ).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let tls_stream = match tokio::time::timeout(
            self.connect_timeout,
            self.tls_connector.connect(server_name, tcp_stream),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                warn!(destination = %destination, timeout = ?self.connect_timeout, "pool: TLS handshake timed out");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "TLS handshake timed out",
                ));
            }
        };

        let connection_id = next_connection_id();
        let local_addr = tls_stream.get_ref().0.local_addr().unwrap_or(self.local_addr);
        let (mut reader, mut writer) = tokio::io::split(tls_stream);

        // Per-connection write channel
        let (write_tx, mut write_rx) = mpsc::channel::<Bytes>(64);

        // Register in the shared connection map
        self.connection_map.insert(connection_id, write_tx.clone());

        // Register in the stream-connection registry so the dispatcher can
        // reuse this connection for inbound routing (e.g., INVITEs to
        // registered trunks).
        if let Some(ref stream_connections) = self.stream_connections {
            stream_connections.register(destination, Transport::Tls, connection_id);
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
        let key_for_cleanup = key;
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
                        info!("pool: TLS connection {:?} to {} closed by peer", connection_id, destination);
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
                            let message_len = match extract_sip_message_length(&accumulator) {
                                Some(len) if len <= accumulator.len() => len,
                                _ => break,
                            };
                            let data = accumulator.split_to(message_len).freeze();
                            let message = InboundMessage {
                                connection_id,
                                transport: Transport::Tls,
                                local_addr,
                                remote_addr: destination,
                                data,
                            };
                            if let Err(error) = inbound_tx.send_async(message).await {
                                error!("pool: TLS inbound enqueue failed: {}", error);
                                conn_map.remove(&connection_id);
                                connections.remove(&key_for_cleanup);
                                if let Some(ref stream_connections) = stream_connections {
                                    stream_connections.unregister(&destination);
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
            connections.remove(&key_for_cleanup);
            if let Some(ref stream_connections) = stream_connections {
                stream_connections.unregister(&destination);
            }
        });

        // Write task
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                if let Err(error) = writer.write_all(&data).await {
                    warn!("pool: TLS write error on {:?}: {}", connection_id, error);
                    break;
                }
            }
        });

        // Send the initial data
        if write_tx.send(data).await.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pooled TLS connection closed immediately",
            ));
        }

        // Store in pool
        self.connections.insert(
            key,
            PoolEntry {
                connection_id,
                sender: write_tx,
            },
        );

        Ok(connection_id)
    }

    /// Number of active pooled connections.
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    #[tokio::test]
    async fn pool_connects_and_sends() {
        ensure_crypto_provider();
        // Start a TCP server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let size = socket.read(&mut buffer).await.unwrap();
            let received = String::from_utf8_lossy(&buffer[..size]).to_string();
            // Echo back a response
            socket.write_all(b"SIP/2.0 200 OK\r\n\r\n").await.unwrap();
            received
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map.clone(),
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        );

        // Send via pool
        let data = Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n");
        let connection_id = pool.send_tcp(server_addr, data).await.unwrap();
        assert_ne!(connection_id, ConnectionId::default());
        assert_eq!(pool.active_connections(), 1);

        // Verify server received the data
        let received = server_task.await.unwrap();
        assert!(received.contains("INVITE"));

        // Verify response comes back via inbound channel
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timeout waiting for response")
        .expect("channel closed");

        assert_eq!(response.connection_id, connection_id);
        assert_eq!(response.transport, Transport::Tcp);
        let response_text = String::from_utf8_lossy(&response.data);
        assert!(response_text.contains("200 OK"));
    }

    #[tokio::test]
    async fn pool_reuses_connection() {
        ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts one connection, reads two messages
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            // Read first message
            let _ = socket.read(&mut buffer).await.unwrap();
            // Read second message
            let _ = socket.read(&mut buffer).await.unwrap();
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        );

        let id1 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 1"))
            .await
            .unwrap();
        let id2 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 2"))
            .await
            .unwrap();

        // Same connection reused
        assert_eq!(id1, id2);
        assert_eq!(pool.active_connections(), 1);
    }

    #[tokio::test]
    async fn pool_reconnects_on_dead_connection() {
        ensure_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        // Server accepts first connection, reads one message, then closes
        let listener_arc = Arc::new(tokio::sync::Mutex::new(listener));
        let listener_clone = listener_arc.clone();
        tokio::spawn(async move {
            let listener = listener_clone.lock().await;
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
            drop(socket); // close connection
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        );

        let id1 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 1"))
            .await
            .unwrap();

        // Wait for the server to close the connection
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Accept second connection on server side
        let listener_clone2 = listener_arc.clone();
        tokio::spawn(async move {
            let listener = listener_clone2.lock().await;
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let _ = socket.read(&mut buffer).await.unwrap();
        });

        let id2 = pool
            .send_tcp(server_addr, Bytes::from_static(b"message 2"))
            .await
            .unwrap();

        // Different connection (reconnected)
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn send_tcp_from_binds_to_specified_source() {
        // ESP-over-TCP IPsec (TS 33.203 §7.2): the outbound TCP
        // socket for SA #3 must bind to (pcscf_addr, pcscf_port_c).
        // Verify that send_tcp_from honours the requested source —
        // an ephemerally-bound socket would have a random source
        // port and the kernel selector for SA #3 would never match.
        ensure_crypto_provider();

        // Pick a free local port to use as the "source"; we'll
        // assert the server sees this exact port on the inbound
        // connection.
        let bind_socket = tokio::net::TcpSocket::new_v4().unwrap();
        bind_socket.set_reuseaddr(true).unwrap();
        bind_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source_addr = bind_socket.local_addr().unwrap();
        drop(bind_socket); // release; SO_REUSEADDR lets us rebind

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (socket, peer_addr) = listener.accept().await.unwrap();
            // Keep the socket alive so the pool's read task doesn't
            // observe an EOF mid-test.
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(socket);
            peer_addr
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        );

        let connection_id = pool
            .send_tcp_from(
                source_addr,
                server_addr,
                Bytes::from_static(b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n"),
            )
            .await
            .expect("send_tcp_from must succeed");
        assert_ne!(connection_id, ConnectionId::default());

        // The server's view of the peer must match the source we
        // asked for — exact-port match is the IPsec invariant.
        let peer = server_task.await.unwrap();
        assert_eq!(
            peer.port(),
            source_addr.port(),
            "send_tcp_from must bind to the requested source port"
        );
        assert_eq!(peer.ip(), source_addr.ip());
    }

    #[tokio::test]
    async fn connect_fails_fast_to_blackhole() {
        // A torn-down IPsec SA gives a connect with no SYN-ACK and no RST.
        // The pool MUST fail fast (bounded by `connect_timeout`) instead of
        // stranding the calling worker forever — that strand is exactly what
        // trips the script-executor watchdog into aborting the process.
        ensure_crypto_provider();

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let mut pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        );
        // Short timeout so the test exercises the timeout branch in ms.
        pool.connect_timeout = Duration::from_millis(150);

        // RFC 5737 TEST-NET-1 — reserved and unrouted, so the SYN is dropped
        // (→ timeout) or rejected as unreachable.  Either way the call must
        // return `Err` quickly and never hang.
        let blackhole: SocketAddr = "192.0.2.1:5060".parse().unwrap();
        let source: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            pool.send_tcp_from(source, blackhole, Bytes::from_static(b"PING")),
        )
        .await;

        // The outer 2 s guard must NOT fire — the inner connect failed fast.
        let inner = outcome.expect("send_tcp_from hung past 2s — connect was not bounded");
        assert!(inner.is_err(), "connect to a black-hole must return Err, not succeed");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "connect must fail fast, not strand the caller"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sends_coalesce_onto_one_connection() {
        // Concurrent first-sends to the same destination from the fixed IPsec
        // source port must coalesce onto ONE connection.  Without coalescing
        // the 2nd+ concurrent connect re-binds/re-connects the identical
        // (src, dst) 4-tuple and fails EADDRNOTAVAIL/EADDRINUSE — the
        // re-REGISTER-path storm in the field report.
        use std::sync::atomic::{AtomicUsize, Ordering};
        ensure_crypto_provider();

        // Reserve a fixed source port (the role `pcscf_port_c` plays at
        // runtime); drop it so `send_tcp_from` can rebind it via SO_REUSEADDR.
        let bind_socket = tokio::net::TcpSocket::new_v4().unwrap();
        bind_socket.set_reuseaddr(true).unwrap();
        bind_socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source_addr = bind_socket.local_addr().unwrap();
        drop(bind_socket);

        // Server accepts connections and holds each open past the test window.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_clone = accepted.clone();
        tokio::spawn(async move {
            loop {
                if let Ok((socket, _)) = listener.accept().await {
                    accepted_clone.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        drop(socket);
                    });
                }
            }
        });

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = Arc::new(ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
        ));

        // Fire N concurrent sends from the same fixed source.
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                pool.send_tcp_from(source_addr, server_addr, Bytes::from(format!("PING {i}")))
                    .await
            }));
        }

        let mut ids = Vec::new();
        for handle in handles {
            let id = handle
                .await
                .unwrap()
                .expect("every coalesced send must succeed (no EADDRNOTAVAIL)");
            ids.push(id);
        }

        // All coalesced onto one connection.
        let first = ids[0];
        assert!(
            ids.iter().all(|id| *id == first),
            "all concurrent sends must share one connection_id"
        );
        assert_eq!(pool.active_connections(), 1, "exactly one pooled connection");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "server accepted more than one connection — establishment did not coalesce"
        );
    }
}
