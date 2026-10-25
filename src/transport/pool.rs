//! Outbound TCP/TLS connection pool.
//!
//! When the proxy needs to relay a SIP message to a remote server over TCP/TLS,
//! it needs an established connection to that destination. This pool creates and
//! reuses connections, keyed by `(SocketAddr, Transport)`.
//!
//! Architecture:
//!   - Pool stores `SendQueue` per destination (same pattern as inbound connections)
//!   - Each pooled connection has a read task that feeds responses back to the inbound channel
//!   - Idle connections are closed after [`POOL_IDLE_TIMEOUT`], except to a
//!     destination named in [`ConnectionPool::set_idle_exempt_destinations`]
//!     and except while a client transaction is pending on the connection
//!     ([`ConnectionPool::hold`]); a connection from a pinned local port is
//!     never closed for idleness ([`crate::transport::pool_writer`])
//!   - Connections are removed on error and recreated on next use

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::{ArcSwap, ArcSwapOption};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::AsyncReadExt;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

use crate::config::TlsMethod;
use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::hold::{ConnectionHold, ConnectionHolds};
use crate::transport::pool_writer::{pins_local_port, PoolWriter};
use crate::transport::send_queue::{self, SendQueue, TrySendError};
use crate::transport::tcp::{frame_sip_message, FrameVerdict};
use crate::transport::{
    configure_tcp_socket, next_connection_id, ConnectionId, InboundMessage, StreamConnections,
    Transport,
};

/// Connect backoff and coalescing per destination.
mod backoff;
/// Opening a pooled connection without sending on it.
mod connect;
/// Opening a pooled TLS connection.
mod tls_connect;
pub use backoff::{is_destination_down, DestinationDown};
#[cfg(test)]
pub(crate) mod fail_fast_tests;

/// Idle timeout for pooled outbound connections (shorter than inbound).
///
/// Outbound pool connections carry one-shot traffic — a gateway health probe, a
/// relay to a peer siphon holds no standing relationship with — so a connection
/// that has been silent this long is not worth an open socket and the next send
/// opens a fresh one.
///
/// A destination siphon holds a *standing* relationship with is exempt via
/// [`ConnectionPool::set_idle_exempt_destinations`] — see the rationale there.
///
/// Silent is not the same as done. A connection a client transaction is still
/// pending on (an INVITE whose callee is ringing) is kept through any amount of
/// silence, because the response is owed on it (RFC 3261 §18.2.2): see
/// [`ConnectionPool::hold`].
///
/// A connection from a pinned local port has no idle timeout: see
/// [`crate::transport::pool_writer`].
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

/// Key for a pooled connection: destination address + transport type + the
/// requested local *bind* address.
///
/// The bind address is part of the key so connections with different source
/// endpoints to the same destination stay distinct.  Without it, a
/// source-bound send (ESP-over-TCP IPsec, or a script `send_socket=` egress
/// pin) and an ephemeral send to the same destination would collide on one
/// pooled connection — reusing the wrong source, or hitting `EADDRNOTAVAIL`
/// when a rebind conflicts on the 4-tuple.  `None` means "no explicit bind"
/// (the OS picks the source — the default TLS outbound path).
///
/// `verified_name` keeps a TLS connection whose server was verified apart from
/// one that was not, and apart from one verified for another name at the same
/// address: `None` for an unverified connection (and every TCP one), else the
/// name the server's certificate was checked against. Without it a per-destination
/// `verify_server` would be bypassed by reusing whatever connection an
/// unverified send had already opened to the same address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    destination: SocketAddr,
    transport: Transport,
    bind: Option<SocketAddr>,
    verified_name: Option<Arc<str>>,
}

/// A pooled outbound connection.
struct PoolEntry {
    connection_id: ConnectionId,
    sender: SendQueue,
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
    connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    /// Channel to feed inbound responses back to the dispatcher.
    inbound_tx: flume::Sender<InboundMessage>,
    /// Local address to use as source in InboundMessage.
    local_addr: SocketAddr,
    /// Pre-computed TOS byte (DSCP << 2) for DSCP/DiffServ marking.
    tos: Option<u32>,
    /// TLS connector for outbound TLS connections. Live-swappable so a renewed
    /// outbound client certificate (mutual TLS, as carrier interconnects
    /// require) is picked up without a restart: the inbound acceptor
    /// hot-reloads via its own `ArcSwap` (see [`crate::transport::tls`]), and
    /// this is the outbound counterpart. Read once per new connection in
    /// `send_tls_inner`; replaced atomically by the client-cert watcher spawned
    /// from [`ConnectionPool::spawn_client_cert_hot_reload`].
    tls_connector: ArcSwap<TlsConnector>,
    /// The verifying twin of `tls_connector`, for a send whose destination (or
    /// `tls.verify_server`) asks for server verification. `None` until
    /// [`with_tls_configs`](Self::with_tls_configs) installs one, and a send
    /// that wants verification without it is refused, never downgraded.
    verified_tls_connector: ArcSwapOption<TlsConnector>,
    /// `tls.verify_server`: whether a send naming no policy of its own is
    /// verified. Swapped together with the connectors.
    verify_by_default: AtomicBool,
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
    /// Per-write bound in the writer tasks (defaults to
    /// `listen.stream_write_timeout_ms`, see [`send_queue::write_timeout`]).
    /// A field for the same reason as `connect_timeout`: a test needs to make a
    /// non-draining peer time out in milliseconds, not seconds.
    write_timeout: Duration,
    /// Byte bound on each connection's send queue (defaults to
    /// `listen.stream_send_queue_bytes`).  A field for the same reason.
    send_queue_bytes: usize,
    /// How long an outbound TCP connection may sit silent before its reader
    /// closes it (defaults to [`POOL_IDLE_TIMEOUT`]).  A field for the same
    /// reason as the three above: a test drives the reap in milliseconds rather
    /// than waiting 30 s for it.
    idle_timeout: Duration,
    /// Destinations whose pooled connection must survive
    /// [`idle_timeout`](Self::idle_timeout) — see
    /// [`set_idle_exempt_destinations`](Self::set_idle_exempt_destinations).
    idle_exempt: Arc<DashMap<(SocketAddr, Transport), ()>>,
    /// Connections a client transaction is pending on, which the idle timeout
    /// leaves alone until the transaction ends: see [`hold`](Self::hold).
    holds: ConnectionHolds,
    /// Local sources a pool-fallback send may bind besides the P-CSCF's
    /// protected ports: see [`pinned`].
    pinned_sources: ArcSwap<HashSet<SocketAddr>>,
    /// Destinations whose last connect failed: see [`backoff`].
    backoff: backoff::ConnectBackoff,
}

#[path = "pool_pinned.rs"]
pub(crate) mod pinned;

pub use crate::transport::outbound_tls::{
    build_outbound_tls_config, load_outbound_client_identity, OutboundClientIdentity,
};
use crate::transport::outbound_tls::{
    build_outbound_tls_configs, OutboundTlsConfigs, ServerVerification,
};

/// Outcome of the coalesced-establishment step, carried out of the
/// per-destination lock so the enqueue can happen with the guard released.
enum Coalesced {
    /// Another caller established the connection while we waited for the lock.
    Reuse((ConnectionId, SendQueue)),
    /// We established it ourselves; the message went out with the handshake.
    Established(Result<ConnectionId, std::io::Error>),
}

/// What happened when we tried to hand a message to a writer task.
enum Enqueued {
    /// The writer took it.
    Sent,
    /// The receiver is gone: the writer task exited, so the connection is dead.
    /// Evict the pool entry and establish a fresh one.
    Closed,
    /// The queue is at its byte bound.  The peer is backed up but the
    /// connection is not provably dead, so keep it — the writer's own write
    /// timeout is what decides that — and refuse this message.
    Backlogged,
}

/// Hand `data` to a connection's writer task without waiting.
///
/// The producers are SIP relays running *inside* a Python handler job, so a
/// parked producer burns a script-executor worker.  The queue is bounded by
/// bytes ([`send_queue`]), so a peer that is reading takes any burst, and one
/// that has fallen the whole bound behind is refused at once: a relayed request
/// then fails with a transport error the caller turns into a 503 or the next
/// target (RFC 3261 §8.1.3.1, §16.9), instead of waiting out Timer B/F.
fn enqueue(sender: &SendQueue, data: Bytes) -> Enqueued {
    match sender.try_send(data) {
        Ok(()) => Enqueued::Sent,
        Err(TrySendError::Closed(_)) => Enqueued::Closed,
        Err(TrySendError::Full(_)) => Enqueued::Backlogged,
    }
}

/// The error a backlogged peer produces.
///
/// `WouldBlock` rather than `BrokenPipe`: nothing is broken, the peer is not
/// draining.  Callers treat any `Err` here the same way (RFC 3261 §16.9 — a
/// transport refusal is a 503 on that branch), so this only has to be honest in
/// the log.
fn backlogged(destination: SocketAddr, sender: &SendQueue) -> std::io::Error {
    sender.log_refused(&format!("pool send to {destination}"));
    std::io::Error::new(
        std::io::ErrorKind::WouldBlock,
        "pooled connection send queue full",
    )
}

/// Drop `key`'s pool entry, but only while it is still `connection_id`.
///
/// A dead connection gets noticed by more than one party: a sender that finds
/// its channel closed, and the connection's own reader, which outlives the
/// writer and only ends with the socket (the peer closes, or the idle
/// timeout). By the time either acts, a replacement may hold the slot, and a
/// plain `remove(key)` evicts that live replacement instead. The replacement
/// is then orphaned, still open but never offered for reuse, and the next send
/// to that peer opens yet another connection.
fn evict_if_current(
    connections: &DashMap<PoolKey, PoolEntry>,
    key: &PoolKey,
    connection_id: ConnectionId,
) {
    connections.remove_if(key, |_, entry| entry.connection_id == connection_id);
}

impl ConnectionPool {
    pub fn new(
        connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
        inbound_tx: flume::Sender<InboundMessage>,
        local_addr: SocketAddr,
        tos: Option<u32>,
        stream_connections: Option<StreamConnections>,
        crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
        tls_client_config: Arc<tokio_rustls::rustls::ClientConfig>,
    ) -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            connect_locks: Arc::new(DashMap::new()),
            connection_map,
            inbound_tx,
            local_addr,
            tos,
            tls_connector: ArcSwap::from_pointee(TlsConnector::from(tls_client_config)),
            verified_tls_connector: ArcSwapOption::empty(),
            verify_by_default: AtomicBool::new(false),
            stream_connections,
            crlf_pong_tracker,
            connect_timeout: TCP_CONNECT_TIMEOUT,
            write_timeout: send_queue::write_timeout(),
            send_queue_bytes: send_queue::send_queue_bytes(),
            idle_timeout: POOL_IDLE_TIMEOUT,
            idle_exempt: Arc::new(DashMap::new()),
            holds: ConnectionHolds::new(),
            pinned_sources: ArcSwap::from_pointee(HashSet::new()),
            backoff: backoff::ConnectBackoff::new(),
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
        self.send_tcp_inner(self.default_tcp_bind(), destination, data)
            .await
    }

    /// Send data to a destination, binding the local socket to a
    /// specific source address — used for ESP-over-TCP IPsec where
    /// the kernel egress XFRM selector for SA #3 (TS 33.203 §6.3 /
    /// §7.1) requires src=`pcscf_port_c`, dst=`ue_port_us`, and an
    /// ephemerally-bound socket would never match.
    ///
    /// Same pooling semantics as `send_tcp` — and the requested `source`
    /// is part of the pool key ([`PoolKey::bind`]), so a source-bound
    /// connection and an ephemeral one to the same destination are kept
    /// distinct: they never reuse each other or collide on rebind.  Two
    /// sends that request the *same* `source` to the same destination do
    /// share a pooled connection (correct — same 4-tuple source).
    ///
    /// Used for ESP-over-TCP IPsec (a fixed `pcscf_addr:pcscf_port_c`
    /// source) and for a script `send_socket=` egress pin (a chosen
    /// interface IP with an ephemeral port).
    ///
    /// A `source` with a port is kept open through any amount of silence and
    /// reset when the pool is first to close it: see
    /// [`crate::transport::pool_writer`].
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
            bind: Some(bind_addr),
            verified_name: None,
        };

        // At most two attempts: the second exists only for the race where the
        // connection we just resolved dies before we can hand it the message,
        // which is the self-heal the pre-bounded code got from re-establishing
        // inline.  It is a bounded loop rather than recursion so the future
        // stays `Sized`.
        for _ in 0..2 {
            // Fast path: reuse a live pooled connection without taking the
            // per-destination establishment lock.
            if let Some((connection_id, sender)) = self.pooled(&key) {
                match enqueue(&sender, data.clone()) {
                    Enqueued::Sent => return Ok(connection_id),
                    Enqueued::Backlogged => return Err(backlogged(destination, &sender)),
                    // Writer task gone — drop the corpse and establish afresh.
                    Enqueued::Closed => {
                        evict_if_current(&self.connections, &key, connection_id);
                    }
                }
            }

            // Coalesce concurrent establishment to this destination onto a
            // single connection, and fail fast while it is backing off: see
            // [`backoff`].
            let coalesced = self
                .establish_coalesced(&key, || {
                    self.establish_tcp_connection(
                        key.clone(),
                        bind_addr,
                        destination,
                        Some(data.clone()),
                    )
                })
                .await;

            match coalesced {
                Coalesced::Established(result) => return result,
                Coalesced::Reuse((connection_id, sender)) => {
                    match enqueue(&sender, data.clone()) {
                        Enqueued::Sent => return Ok(connection_id),
                        Enqueued::Backlogged => return Err(backlogged(destination, &sender)),
                        // Died in the window between the re-check and the
                        // enqueue.  Evict and take the second attempt, which
                        // will establish.
                        Enqueued::Closed => {
                            evict_if_current(&self.connections, &key, connection_id);
                        }
                    }
                }
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "pooled connection closed twice while sending",
        ))
    }

    /// Snapshot a pooled connection: its id plus a *cloned* sender.
    ///
    /// Cloning the sender out — and letting the map guard die with the closure
    /// — is what lets callers await an enqueue without holding a `DashMap`
    /// shard guard across it.  Holding one blocks every insert and remove that
    /// hashes to the same shard, which is a second way to wedge the pool and
    /// the one `spawn_outbound_distributor` documents.
    fn pooled(&self, key: &PoolKey) -> Option<(ConnectionId, SendQueue)> {
        self.connections
            .get(key)
            .map(|entry| (entry.connection_id, entry.sender.clone()))
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
        data: Option<Bytes>,
    ) -> Result<ConnectionId, std::io::Error> {
        // Create new connection.  Default bind (`port 0`) lets the OS
        // pick an ephemeral port — required for non-IPsec destinations
        // because binding to the exact listen port causes EADDRNOTAVAIL
        // when a pooled connection in TIME_WAIT collides on the 4-tuple
        // (local:5060 → remote:6060).  IPsec callers (`send_tcp_from`)
        // bind to a specific `(pcscf_addr, pcscf_port_c)` because
        // ESP-over-TCP SA selectors require it.  SO_REUSEADDR (set
        // below) lets that bind succeed next to the listener and next
        // to a connection in TIME_WAIT; it does not let the connect
        // reuse a 4-tuple in TIME_WAIT, which is why such a connection
        // is kept open and reset on close (see `pool_writer`).
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
            // Family-aware, best-effort — a DSCP marking failure must not fail
            // the outbound connection.
            super::apply_tos(&socket2::SockRef::from(&socket), tos);
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
        let stream =
            match tokio::time::timeout(self.connect_timeout, socket.connect(destination)).await {
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
        let (mut reader, writer) = stream.into_split();
        let pinned = pins_local_port(bind_addr);

        // Per-connection write channel
        let (write_tx, write_rx) =
            send_queue::channel_with_limit(Transport::Tcp, connection_id, self.send_queue_bytes);

        // Register in the shared connection map so the outbound distributor
        // can route responses back on this connection.
        self.connection_map.insert(connection_id, write_tx.clone());

        debug!(
            destination = %destination,
            connection_id = ?connection_id,
            "pool: opened outbound TCP connection"
        );

        // Write task
        let mut writer = PoolWriter::spawn(
            writer,
            write_rx,
            self.write_timeout,
            connection_id,
            destination,
            pinned,
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
        let key_for_cleanup = key.clone();
        let keepalive_writer = write_tx.clone();
        let crlf_pong_tracker = self.crlf_pong_tracker.clone();
        let idle_timeout = self.idle_timeout;
        let idle_exempt = Arc::clone(&self.idle_exempt);
        let holds = self.holds.clone();
        // Reachable from outside this task, so a P-CSCF deleting a UE's
        // security associations can end the connection they carried
        // ([`crate::transport::disconnect::close_peer`]); dropped with the task.
        let closer = crate::transport::disconnect::ConnectionCloser::register_outbound(
            connection_id,
            destination,
            Transport::Tcp,
            (bind_addr.port() != 0).then_some(bind_addr.port()),
        );
        tokio::spawn(async move {
            let mut accumulator = BytesMut::with_capacity(65536);
            let mut read_buf = [0u8; 8192];
            let mut peer_closed = false;
            loop {
                let read = tokio::select! {
                    read = tokio::time::timeout(idle_timeout, reader.read(&mut read_buf)) => read,
                    // A pinned port only: its socket holds the 4-tuple the
                    // replacement needs.
                    () = writer.gave_up() => break,
                    // Closed from outside: a pinned port resets it below.
                    () = closer.closed() => break,
                };
                match read {
                    Ok(Ok(0)) => {
                        info!(
                            "pool: TCP connection {:?} to {} closed by peer",
                            connection_id, destination
                        );
                        peer_closed = true;
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
                                        "TCP",
                                        destination
                                    );
                                    break;
                                }
                                FrameVerdict::Garbage => {
                                    warn!(
                                        "pool: non-SIP bytes from {} peer {}; dropping connection",
                                        "TCP", destination
                                    );
                                    break;
                                }
                            };
                            let data = accumulator.split_to(message_len).freeze();
                            let message = InboundMessage {
                                connection_id,
                                transport: Transport::Tcp,
                                // siphon opened this connection itself, so there
                                // is no front and no client behind one.
                                client_transport: None,
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
                        // A destination siphon holds a standing relationship
                        // with keeps its connection through any amount of
                        // silence; only the peer, an error or the socket's own
                        // keepalive ends it (see
                        // `set_idle_exempt_destinations`).
                        if idle_exempt.contains_key(&(destination, Transport::Tcp)) {
                            debug!(
                                connection_id = ?connection_id,
                                destination = %destination,
                                idle = ?idle_timeout,
                                "pool: TCP connection idle but kept open (exempt destination)"
                            );
                            continue;
                        }
                        // A client transaction is still pending on this
                        // connection, and its response is owed here (RFC 3261
                        // §18.2.2).  The timer starts over, so the connection
                        // goes one idle period after the last of them ends.
                        if holds.is_held(connection_id) {
                            debug!(
                                connection_id = ?connection_id,
                                destination = %destination,
                                idle = ?idle_timeout,
                                "pool: TCP connection idle but kept open (transaction pending)"
                            );
                            continue;
                        }
                        // The next request to this peer can only leave on
                        // this 4-tuple, which cannot be opened again while the
                        // connection just closed is in TIME_WAIT.
                        if pinned {
                            debug!(
                                connection_id = ?connection_id,
                                destination = %destination,
                                idle = ?idle_timeout,
                                "pool: TCP connection idle but kept open (pinned local port)"
                            );
                            continue;
                        }
                        info!(
                            "pool: TCP connection {:?} idle timeout ({}s)",
                            connection_id,
                            idle_timeout.as_secs()
                        );
                        break;
                    }
                }
            }
            // A connection from a pinned port is closed before the pool offers
            // its slot again, and its senders see the channel close only then.
            let write_rx = writer.close(reader, peer_closed).await;
            conn_map.remove(&connection_id);
            evict_if_current(&connections, &key_for_cleanup, connection_id);
            drop(write_rx);
        });

        // Send the initial data.  Never waits, like every other enqueue: the writer
        // task above is live but a peer that never reads still backs the
        // channel up, and this runs on a script-executor worker.
        // A bare connect ([`connect_tcp_from`](Self::connect_tcp_from)) has none.
        match data.map(|data| enqueue(&write_tx, data)) {
            None | Some(Enqueued::Sent) => {}
            Some(Enqueued::Closed) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pooled connection closed immediately",
                ));
            }
            Some(Enqueued::Backlogged) => {
                return Err(backlogged(destination, &write_tx));
            }
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
    /// `server_name` is the SNI / certificate hostname to present in the TLS
    /// handshake. When `Some(host)`, that hostname is used (RFC 6066 SNI is
    /// emitted, letting a hostname-vhost front-end route the handshake, and it
    /// is the name a verified server's certificate is checked against). When
    /// `None`, the destination IP literal is used (RFC 6066 forbids SNI for IP
    /// literals, so none is sent — prior behavior).
    ///
    /// The server is verified when `tls.verify_server` says so; see
    /// [`send_tls_with_policy`](Self::send_tls_with_policy) for a destination
    /// that carries its own setting.
    ///
    /// Returns the `ConnectionId` used (so responses can be correlated).
    pub async fn send_tls(
        &self,
        destination: SocketAddr,
        server_name: Option<&str>,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        self.send_tls_inner(None, destination, server_name, None, data)
            .await
    }

    /// [`send_tls`](Self::send_tls) with the destination's own server
    /// verification setting: `Some(true)` verifies, `Some(false)` does not,
    /// `None` follows `tls.verify_server` ([`verifies`](Self::verifies)).
    pub async fn send_tls_with_policy(
        &self,
        destination: SocketAddr,
        server_name: Option<&str>,
        verify_server: Option<bool>,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        self.send_tls_inner(None, destination, server_name, verify_server, data)
            .await
    }

    /// Whether a send whose destination says `verify_server` about server
    /// verification is verified: its own setting, else `tls.verify_server`.
    pub fn verifies(&self, verify_server: Option<bool>) -> bool {
        verify_server.unwrap_or_else(|| self.verify_by_default.load(Ordering::Relaxed))
    }

    /// Send over TLS from `listener` (a script `send_socket=` egress pin): the
    /// socket binds the listener's IP with an ephemeral port (binding the TLS
    /// listen port for an outbound connection collides on the 4-tuple in
    /// `TIME_WAIT`). The listener is the pool key's source, so two listeners
    /// sharing an IP keep separate connections, and the connection is recorded
    /// as that listener's: its traffic advertises the listener's identity.
    /// `verify_server` as for [`send_tls_with_policy`](Self::send_tls_with_policy).
    pub async fn send_tls_from(
        &self,
        listener: SocketAddr,
        destination: SocketAddr,
        server_name: Option<&str>,
        verify_server: Option<bool>,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        self.send_tls_inner(
            Some(listener),
            destination,
            server_name,
            verify_server,
            data,
        )
        .await
    }

    /// The pool key a TLS send lands under.
    ///
    /// A verified send is keyed by the name it verifies, so it never picks up
    /// an unverified connection, or one verified for another name, to the same
    /// address. One that routed by address alone (no name: an in-dialog request
    /// to where the dialog's peer is, a response reconnect) takes a connection
    /// already verified to that destination under whatever name it was opened
    /// for, which is the peer the dialog was set up with. Only with none does
    /// it verify the destination's IP literal.
    fn tls_key(
        &self,
        bind: Option<SocketAddr>,
        destination: SocketAddr,
        server_name: Option<&str>,
        verify: bool,
    ) -> PoolKey {
        let key = PoolKey {
            destination,
            transport: Transport::Tls,
            bind,
            verified_name: verify.then(|| {
                Arc::from(crate::transport::outbound_tls::expected_server_name(
                    destination,
                    server_name,
                ))
            }),
        };
        if !verify || server_name.is_some() || self.connections.contains_key(&key) {
            return key;
        }
        self.connections
            .iter()
            .find(|entry| {
                let candidate = entry.key();
                candidate.destination == destination
                    && candidate.transport == Transport::Tls
                    && candidate.bind == bind
                    && candidate.verified_name.is_some()
                    && !entry.value().sender.is_closed()
            })
            .map(|entry| entry.key().clone())
            .unwrap_or(key)
    }

    async fn send_tls_inner(
        &self,
        listener: Option<SocketAddr>,
        destination: SocketAddr,
        server_name: Option<&str>,
        verify_server: Option<bool>,
        data: Bytes,
    ) -> Result<ConnectionId, std::io::Error> {
        let verify = self.verifies(verify_server);
        let key = self.tls_key(listener, destination, server_name, verify);

        // Try existing connection first.  Bounded, and with the sender cloned
        // out of the map so no shard guard is held across the await — same
        // reasoning as the TCP path.
        if let Some((connection_id, sender)) = self.pooled(&key) {
            match enqueue(&sender, data.clone()) {
                Enqueued::Sent => return Ok(connection_id),
                Enqueued::Backlogged => return Err(backlogged(destination, &sender)),
                // Connection dead — remove and create new
                Enqueued::Closed => {
                    evict_if_current(&self.connections, &key, connection_id);
                }
            }
        }

        // The connector, read once per new connection so a hot-reloaded client
        // certificate is presented on fresh handshakes (an Arc load, only on
        // establishment). Chosen before connecting: a send that wants the
        // server verified and has no verifying config is refused outright,
        // never downgraded to an unverified handshake.
        let connector = if verify {
            match self.verified_tls_connector.load_full() {
                Some(connector) => connector,
                None => {
                    error!(destination = %destination, "pool: TLS server verification requested but no verifying client config is installed; refusing the connection");
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "TLS server verification requested but not configured",
                    ));
                }
            }
        } else {
            self.tls_connector.load_full()
        };

        // One connect at a time to this destination, and none while it is
        // backing off: see [`backoff`].
        let coalesced = self
            .establish_coalesced(&key, || {
                self.establish_tls_connection(
                    &key,
                    listener,
                    destination,
                    server_name,
                    verify,
                    connector,
                    data.clone(),
                )
            })
            .await;
        match coalesced {
            Coalesced::Established(result) => result,
            Coalesced::Reuse((connection_id, sender)) => match enqueue(&sender, data) {
                Enqueued::Sent => Ok(connection_id),
                Enqueued::Backlogged => Err(backlogged(destination, &sender)),
                Enqueued::Closed => {
                    evict_if_current(&self.connections, &key, connection_id);
                    Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "pooled TLS connection closed while sending",
                    ))
                }
            },
        }
    }

    /// Number of active pooled connections.
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Whether the connection a default [`send_tcp`](Self::send_tcp) or
    /// [`send_tls`](Self::send_tls) to exactly `destination` would reuse is
    /// still open.
    ///
    /// Answers for that one connection only: another port on the same host,
    /// the other transport, a source-bound connection (IPsec, `send_socket=`)
    /// and any inbound connection the peer opened are all different
    /// connections and never count. A connection is gone once its reader has
    /// evicted it (peer close, read error, the TCP idle timeout) or its writer
    /// has stopped (write error or stall), whichever comes first. A TLS
    /// connection dropped from reuse by a client-certificate reload reads as
    /// gone too, since the next send opens a fresh one.
    ///
    /// The pool opens only TCP and TLS connections, so every other transport
    /// is `false`.
    ///
    /// A default TLS send can land under a verified or an unverified key, so
    /// for TLS any open default-source connection to `destination` counts.
    pub fn has_live(&self, destination: SocketAddr, transport: Transport) -> bool {
        match transport {
            Transport::Tcp => {
                let key = PoolKey {
                    destination,
                    transport,
                    bind: Some(self.default_tcp_bind()),
                    verified_name: None,
                };
                self.connections
                    .get(&key)
                    .is_some_and(|entry| !entry.sender.is_closed())
            }
            Transport::Tls => self.connections.iter().any(|entry| {
                let key = entry.key();
                key.destination == destination
                    && key.transport == Transport::Tls
                    && key.bind.is_none()
                    && !entry.value().sender.is_closed()
            }),
            _ => false,
        }
    }

    /// The bind address of a default outbound TCP connection: the local IP
    /// (so the right interface is used) with an ephemeral port.
    fn default_tcp_bind(&self) -> SocketAddr {
        SocketAddr::new(self.local_addr.ip(), 0)
    }

    /// Replace the set of destinations whose pooled connection must not be
    /// closed just for being idle.
    ///
    /// The pool's idle timeout suits traffic that ends when its answer arrives.
    /// It is wrong for a destination siphon holds a *standing* relationship
    /// with: an outbound registration keeps one connection to the registrar for
    /// the life of the binding, because that is the connection the registrar
    /// reaches this node over (RFC 5626 §4.1) and the one the registrant judges
    /// the trunk's liveness from. Closing it after 30 s of silence and
    /// re-opening it on the next refresh is pure churn — worse, the trunk read
    /// as dead in between, so an idle trunk re-REGISTERed roughly every 35 s
    /// instead of once per configured interval, which carriers rate-limit.
    ///
    /// Exemption removes only the *timer*, never the detection: an exempt
    /// connection is still dropped the moment the peer closes it, the read or
    /// write errors, or the socket's own keepalive gives up on a peer that
    /// vanished without a FIN (`SO_KEEPALIVE` 60 s + 3 × 10 s and
    /// `TCP_USER_TIMEOUT` 90 s, both set in
    /// [`configure_tcp_socket`](crate::transport::configure_tcp_socket)).
    ///
    /// The whole set goes in one call, and `destinations` is the set afterwards:
    /// anything not named is released, so a trunk that leaves the configuration
    /// stops exempting its destination. One owner re-states its set on a timer
    /// ([`crate::registrant::registration_loop`]); a second caller would fight
    /// it for the map.
    pub fn set_idle_exempt_destinations(
        &self,
        destinations: impl IntoIterator<Item = (SocketAddr, Transport)>,
    ) {
        let wanted: HashSet<(SocketAddr, Transport)> = destinations.into_iter().collect();
        for key in &wanted {
            self.idle_exempt.insert(*key, ());
        }
        self.idle_exempt.retain(|key, _| wanted.contains(key));
    }

    /// Whether a pooled connection to `destination` over `transport` is exempt
    /// from the idle timeout.
    pub fn is_idle_exempt(&self, destination: SocketAddr, transport: Transport) -> bool {
        self.idle_exempt.contains_key(&(destination, transport))
    }

    /// Keep `connection_id` from being closed for idleness until the returned
    /// hold is dropped.
    ///
    /// For a client transaction, taken on the connection its request left on
    /// and kept for as long as the transaction lives. The response to that
    /// request is owed on that connection (RFC 3261 §18.2.2), and a callee may
    /// take longer to answer than the idle timeout: an INVITE that rings for
    /// 35 s is silent for 35 s. The transaction layer's own timers (B, F, C)
    /// bound how long a hold can last.
    ///
    /// Only the idle *timer* is suspended, as with an exempt destination: the
    /// peer closing the connection, a read or write error and the socket's own
    /// keepalive all still end it. A dialog is not a transaction, so a
    /// connection that carried a call's INVITE idles out once the INVITE is
    /// answered, and a later request in the dialog opens a new one.
    ///
    /// Only the pool's TCP connections have an idle timer. A hold on any other
    /// connection is accepted and changes nothing.
    pub fn hold(&self, connection_id: ConnectionId) -> ConnectionHold {
        self.holds.hold(connection_id)
    }

    /// Whether a client transaction still holds `connection_id` open.
    pub fn is_held(&self, connection_id: ConnectionId) -> bool {
        self.holds.is_held(connection_id)
    }

    /// Size of the idle-exemption set, for the drains-to-baseline leak test.
    #[cfg(test)]
    pub(crate) fn idle_exempt_len(&self) -> usize {
        self.idle_exempt.len()
    }

    /// Drive a short idle timeout, so a test in another module of this crate can
    /// make the reaper fire in milliseconds.
    #[cfg(test)]
    pub(crate) fn set_idle_timeout(&mut self, idle_timeout: Duration) {
        self.idle_timeout = idle_timeout;
    }

    /// Drive a short connect timeout, so a test can make a connect to a peer
    /// that never answers the SYN time out in milliseconds.
    #[cfg(test)]
    pub(crate) fn set_connect_timeout(&mut self, connect_timeout: Duration) {
        self.connect_timeout = connect_timeout;
    }

    /// Install the verifying and non-verifying client configs and the
    /// `tls.verify_server` default, at construction.
    ///
    /// A pool built without this dials unverified only, and refuses a send
    /// that asks for verification rather than downgrade it.
    pub fn with_tls_configs(self, configs: OutboundTlsConfigs) -> Self {
        self.store_tls_configs(configs);
        self
    }

    fn store_tls_configs(&self, configs: OutboundTlsConfigs) {
        self.tls_connector
            .store(Arc::new(TlsConnector::from(configs.unverified)));
        self.verified_tls_connector
            .store(Some(Arc::new(TlsConnector::from(configs.verified))));
        self.verify_by_default
            .store(configs.verify_by_default, Ordering::Relaxed);
    }

    /// Atomically swap both outbound TLS client configs (e.g. after a renewed
    /// client certificate on disk) so subsequent outbound handshakes present
    /// the new identity, verified or not.
    ///
    /// Existing pooled `Transport::Tls` connections are dropped from the reuse
    /// map so the next outbound send re-handshakes with the fresh identity. This
    /// is non-disruptive: those connections stay live in `connection_map` /
    /// `stream_connections` and finish any in-flight exchange naturally — they
    /// are simply no longer offered for reuse. Pooled TCP connections are
    /// retained (their identity is transport-level, unaffected by the cert).
    pub fn reload_tls_client_configs(&self, configs: OutboundTlsConfigs) {
        self.store_tls_configs(configs);
        self.connections
            .retain(|key, _| key.transport != Transport::Tls);
        info!(
            "outbound TLS client certificate hot-reloaded — new outbound \
             handshakes present the updated cert"
        );
    }

    /// Spawn a watcher that rebuilds the outbound TLS client identity whenever
    /// the certificate or private-key file on disk changes, and swaps it into
    /// the pool via [`ConnectionPool::reload_tls_client_configs`]. Both client
    /// configs are rebuilt, against the same `verification`, so a renewed
    /// identity never leaves the verifying one presenting the old certificate.
    ///
    /// This is the outbound counterpart to
    /// [`crate::transport::tls::build_hot_reload_acceptor`] (which hot-reloads
    /// the inbound *server* acceptor): after a cert renewal, siphon presents the
    /// renewed identity both when it *accepts* TLS (inbound) and when it *dials*
    /// TLS (outbound mutual-TLS, as carrier interconnects require)
    /// without a restart. Same notify pattern as the acceptor watcher:
    /// parent-directory watch (so atomic rename by cert-manager/certbot is
    /// observed), 150 ms debounce for the key-then-cert write pair, and a `Weak`
    /// self-reference so the watcher exits when the pool is dropped.
    #[allow(clippy::disallowed_methods)] // dedicated cert-watcher thread, never attaches
    pub fn spawn_client_cert_hot_reload(
        pool: &Arc<ConnectionPool>,
        certificate_path: &str,
        private_key_path: &str,
        method: TlsMethod,
        verification: ServerVerification,
    ) {
        let cert_path = PathBuf::from(certificate_path);
        let key_path = PathBuf::from(private_key_path);
        let certificate_path = certificate_path.to_owned();
        let private_key_path = private_key_path.to_owned();
        // Weak ref so the watcher exits once the last strong reference (the
        // running server) is dropped — otherwise a spawned watcher would leak
        // and block runtime shutdown in tests.
        let weak = Arc::downgrade(pool);

        tokio::task::spawn_blocking(move || {
            use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
            use std::sync::mpsc;

            let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();
            let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
                Ok(watcher) => watcher,
                Err(error) => {
                    error!(%error, "outbound TLS watcher: failed to create file watcher");
                    return;
                }
            };

            // Watch the parent directories so atomic rename (cert-manager,
            // certbot) is observed — they swap the file rather than rewrite it.
            for path in [&cert_path, &key_path] {
                let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
                if let Err(error) = watcher.watch(dir, RecursiveMode::NonRecursive) {
                    warn!(%error, path = %dir.display(),
                        "outbound TLS watcher: failed to watch directory; client-cert hot-reload disabled");
                    return;
                }
            }
            info!(
                cert = %cert_path.display(),
                key = %key_path.display(),
                "outbound TLS client-cert hot-reload watcher started"
            );

            let cert_name = cert_path.file_name().map(|n| n.to_owned());
            let key_name = key_path.file_name().map(|n| n.to_owned());

            loop {
                // Poll with a 1s timeout so we can check Weak::upgrade between
                // events — when the pool drops we exit.
                let event = match receiver.recv_timeout(std::time::Duration::from_secs(1)) {
                    Ok(event) => event,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if weak.upgrade().is_none() {
                            break;
                        }
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let pool = match weak.upgrade() {
                    Some(pool) => pool,
                    None => break,
                };
                match event {
                    Ok(Event {
                        kind: EventKind::Modify(_) | EventKind::Create(_),
                        paths,
                        ..
                    }) => {
                        let touched = paths.iter().any(|p| {
                            let name = p.file_name().map(|n| n.to_owned());
                            name == cert_name || name == key_name
                        });
                        if !touched {
                            continue;
                        }
                        // Debounce — a renewal typically writes the key first,
                        // then the cert; wait for the pair to settle.
                        std::thread::sleep(std::time::Duration::from_millis(150));
                        match load_outbound_client_identity(&certificate_path, &private_key_path)
                            .and_then(|identity| {
                                build_outbound_tls_configs(Some(identity), method, &verification)
                            }) {
                            Ok(configs) => pool.reload_tls_client_configs(configs),
                            Err(error) => warn!(%error,
                                "outbound TLS client-cert hot-reload failed — keeping previous cert. Renewal half-written?"),
                        }
                    }
                    Ok(_) => {}
                    Err(error) => warn!(%error, "outbound TLS watcher: file event error"),
                }
            }
            debug!("outbound TLS watcher exiting (pool dropped)");
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::outbound_tls::resolve_server_name;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    fn test_pool() -> ConnectionPool {
        ensure_crypto_provider();
        ConnectionPool::new(
            Arc::new(DashMap::new()),
            flume::unbounded().0,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
        )
    }

    /// A peer that completes the handshake and then never reads a byte.
    ///
    /// This is the shape the field incident had: the socket stays established
    /// and the peer keeps ACKing, but its receive window closes, so our writes
    /// stop draining. `SO_KEEPALIVE` never fires against it (probes are
    /// suppressed with data in flight or in the persist state), which is why an
    /// unbounded write there is unbounded in the real sense, not the "eventually
    /// errors" sense.
    ///
    /// The small receive buffer is what keeps the test fast: the peer's window
    /// closes after a few KB instead of the megabytes autotuning would otherwise
    /// allow.
    ///
    /// Every accepted socket is handed to the test over the returned channel,
    /// never read. A socket stays open while it sits in the channel or the test
    /// holds it, so the test decides when the peer closes a connection, and
    /// awaiting `recv()` is an explicit "the peer has accepted" point: the
    /// accept loop is its own task and can lag the kernel handshake that has
    /// already let `send_tcp` return.
    async fn spawn_non_draining_peer(
    ) -> (SocketAddr, mpsc::UnboundedReceiver<tokio::net::TcpStream>) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket2::SockRef::from(&socket)
            .set_recv_buffer_size(2 * 1024)
            .unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let listener = socket.listen(16).unwrap();
        let addr = listener.local_addr().unwrap();

        let (accepted_sender, accepted) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                if accepted_sender.send(socket).is_err() {
                    return;
                }
            }
        });
        (addr, accepted)
    }

    /// The pool key a default-bound `send_tcp` to `peer` lands under.
    fn tcp_key(pool: &ConnectionPool, peer: SocketAddr) -> PoolKey {
        PoolKey {
            destination: peer,
            transport: Transport::Tcp,
            bind: Some(SocketAddr::new(pool.local_addr.ip(), 0)),
            verified_name: None,
        }
    }

    /// Keep sending until the pool refuses, bounded so the test fails by
    /// *hanging* rather than by asserting a count if the enqueue is ever
    /// unbounded again. 8 KB per message fills a closed window and then the
    /// 64-slot channel in well under a second.
    ///
    /// Returns how many sends went out before the refusal, and every
    /// connection they went out on. That is normally one, but a writer that
    /// gives up while the channel is still filling is replaced mid-round, which
    /// is the behaviour under test rather than a reason to fail.
    async fn send_until_refused(
        pool: &ConnectionPool,
        peer: SocketAddr,
    ) -> (usize, std::collections::HashSet<ConnectionId>) {
        let payload = Bytes::from(vec![b'x'; 8 * 1024]);
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut carried_on = std::collections::HashSet::new();
            for attempt in 0..2000usize {
                match pool.send_tcp(peer, payload.clone()).await {
                    Ok(connection_id) => {
                        carried_on.insert(connection_id);
                    }
                    // A refusal only says the queue got ahead of the writer.
                    // The peer is stuck once it is still refused after the
                    // writer has had time to fill the socket buffers.
                    Err(_) if writer_caught_up(pool, peer).await => {}
                    Err(_) => return (attempt, carried_on),
                }
            }
            panic!("2000 sends to a peer that never reads all reported success");
        })
        .await
        .expect(
            "send_tcp parked on a peer that accepted the connection and then \
             stopped draining it. That is the process-abort path: the write \
             never returns, the bounded channel behind it fills, is_closed() \
             still reports the connection healthy because full is not closed, \
             and every caller — each one a script-executor worker — parks \
             forever until the watchdog aborts the process.",
        )
    }

    /// Give a connection's writer time to drain its queue into the socket, and
    /// say whether it did.
    async fn writer_caught_up(pool: &ConnectionPool, peer: SocketAddr) -> bool {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let key = tcp_key(pool, peer);
        pool.pooled(&key)
            .is_some_and(|(_, sender)| sender.queued_bytes() == 0)
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
        let response =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv_async())
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
        // ESP-over-TCP IPsec (TS 33.203 §7.1): the outbound TCP
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
        assert!(
            inner.is_err(),
            "connect to a black-hole must return Err, not succeed"
        );
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
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
        assert_eq!(
            pool.active_connections(),
            1,
            "exactly one pooled connection"
        );
        // The accept count is produced by a separate task, and the kernel
        // completes a loopback handshake off the listen backlog without that
        // task having run — so reading it the instant the sends return is a
        // race, and under parallel test load it reads 0. Wait for the first
        // accept, then hold still long enough that a second one would have
        // shown up. Both halves matter: the wait alone would pass if
        // establishment stopped coalescing.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while accepted.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "establishment did not coalesce onto a single connection"
        );
    }

    // --- Outbound mutual-TLS + SNI ---------------------------------------

    /// CA-signed material for the mutual-TLS tests: a CA, a server cert
    /// (SAN `localhost` / `127.0.0.1`), and a CLIENT cert (ClientAuth EKU)
    /// both signed by that CA.
    struct MtlsCerts {
        ca_cert_der: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
        server_cert_der: tokio_rustls::rustls::pki_types::CertificateDer<'static>,
        server_key_der: tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn generate_mtls_certs() -> MtlsCerts {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose,
        };
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let ca_key = KeyPair::generate().expect("ca keygen");
        let mut ca_params =
            CertificateParams::new(vec!["siphon-test-ca".to_string()]).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca self-sign");
        let ca_cert_der = ca_cert.der().clone();
        let issuer = Issuer::new(ca_params, ca_key);

        // Server cert signed by the CA.
        let server_key = KeyPair::generate().expect("server keygen");
        let server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("server params");
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server sign");
        let server_cert_der = server_cert.der().clone();
        let server_key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

        // Client cert signed by the CA, with the ClientAuth EKU webpki wants.
        let client_key = KeyPair::generate().expect("client keygen");
        let mut client_params =
            CertificateParams::new(vec!["siphon-test-client".to_string()]).expect("client params");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client sign");

        MtlsCerts {
            ca_cert_der,
            server_cert_der,
            server_key_der,
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
        }
    }

    /// A TLS server acceptor that REQUIRES and verifies a client certificate
    /// against the CA. Pinned to TLS 1.2 so a missing client cert is rejected
    /// *during* the handshake (client `connect().await` then returns `Err`
    /// deterministically — under TLS 1.3 client-auth failure surfaces late).
    fn mtls_server_acceptor(certs: &MtlsCerts) -> tokio_rustls::TlsAcceptor {
        use tokio_rustls::rustls::server::WebPkiClientVerifier;
        use tokio_rustls::rustls::{version, RootCertStore, ServerConfig};

        let mut roots = RootCertStore::empty();
        roots
            .add(certs.ca_cert_der.clone())
            .expect("add ca to roots");
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("build client verifier");
        let server_config = ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![certs.server_cert_der.clone()],
                certs.server_key_der.clone_key(),
            )
            .expect("server config");
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
    }

    #[tokio::test]
    async fn build_outbound_tls_config_none_and_some_both_build() {
        ensure_crypto_provider();
        // No client identity — prior behavior (no client auth).
        assert!(build_outbound_tls_config(None, TlsMethod::default()).is_ok());

        // A valid client identity, loaded via the production PEM loader.
        let certs = generate_mtls_certs();
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("client.crt");
        let key_path = directory.path().join("client.key");
        std::fs::write(&cert_path, &certs.client_cert_pem).unwrap();
        std::fs::write(&key_path, &certs.client_key_pem).unwrap();
        let identity =
            load_outbound_client_identity(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("client identity must load");
        assert!(build_outbound_tls_config(Some(identity), TlsMethod::default()).is_ok());
    }

    #[test]
    fn resolve_server_name_prefers_hostname_then_ip() {
        use tokio_rustls::rustls::pki_types::ServerName;
        let destination: SocketAddr = "192.0.2.1:5061".parse().unwrap();

        // Hostname present → SNI-capable DnsName.
        let name = resolve_server_name(destination, Some("sbc.example.com"))
            .expect("hostname must resolve to a ServerName");
        match name {
            ServerName::DnsName(dns) => assert_eq!(dns.as_ref(), "sbc.example.com"),
            other => panic!("expected DnsName, got {other:?}"),
        }

        // No hostname → IP literal (rustls emits no SNI for an IP).
        let ip_name = resolve_server_name(destination, None)
            .expect("IP destination must resolve to a ServerName");
        assert!(
            matches!(ip_name, ServerName::IpAddress(_)),
            "IP destination must yield an IpAddress ServerName"
        );
    }

    /// A plain TLS server acceptor pinned to TLS 1.2 — stands in for a legacy
    /// carrier trunk that never got a 1.3 stack.
    fn tls12_only_server_acceptor(certs: &MtlsCerts) -> tokio_rustls::TlsAcceptor {
        use tokio_rustls::rustls::{version, ServerConfig};

        let server_config = ServerConfig::builder_with_protocol_versions(&[&version::TLS12])
            .with_no_client_auth()
            .with_single_cert(
                vec![certs.server_cert_der.clone()],
                certs.server_key_der.clone_key(),
            )
            .expect("server config");
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tls_method_floor_applies_to_outbound_handshakes() {
        // `tls.method` is one process-wide statement about the TLS versions
        // siphon speaks, so a 1.3 floor must also stop siphon *dialling* a TLS
        // 1.2 trunk — enforcing it only on the listener would leave the same
        // "claimed floor nothing enforces" gap on the outbound side.
        ensure_crypto_provider();
        let certs = generate_mtls_certs();

        async fn dial(
            certs: &MtlsCerts,
            method: TlsMethod,
        ) -> Result<ConnectionId, std::io::Error> {
            let acceptor = tls12_only_server_acceptor(certs);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let server_addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.expect("accept");
                let _ = acceptor.accept(tcp).await;
            });

            let client_config =
                build_outbound_tls_config(None, method).expect("outbound client config");
            let (inbound_tx, _inbound_rx) = flume::unbounded();
            let pool = ConnectionPool::new(
                Arc::new(DashMap::new()),
                inbound_tx,
                "127.0.0.1:5060".parse().unwrap(),
                None,
                None,
                None,
                client_config,
            );

            let outcome = pool
                .send_tls(
                    server_addr,
                    Some("localhost"),
                    Bytes::from_static(b"OPTIONS sip:peer@example.com SIP/2.0\r\n\r\n"),
                )
                .await;
            let _ = tokio::time::timeout(Duration::from_secs(5), server).await;
            outcome
        }

        assert!(
            dial(&certs, TlsMethod::Tls13).await.is_err(),
            "tls.method TLSv1_3 must refuse to dial a TLS 1.2-only peer"
        );
        assert!(
            dial(&certs, TlsMethod::Tls12).await.is_ok(),
            "the default TLS 1.2 floor must still dial a TLS 1.2-only peer"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_handshake_succeeds_with_client_cert_and_fails_without() {
        ensure_crypto_provider();
        let certs = generate_mtls_certs();

        // ---- (a) WITH a matching client identity: handshake succeeds ------
        let acceptor = mtls_server_acceptor(&certs);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let mut tls = acceptor
                .accept(tcp)
                .await
                .expect("server handshake with a valid client cert must succeed");
            let mut buffer = vec![0u8; 1024];
            let size = tls.read(&mut buffer).await.expect("read app data");
            String::from_utf8_lossy(&buffer[..size]).to_string()
        });

        // Load the client identity through the production PEM loader.
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("client.crt");
        let key_path = directory.path().join("client.key");
        std::fs::write(&cert_path, &certs.client_cert_pem).unwrap();
        std::fs::write(&key_path, &certs.client_key_pem).unwrap();
        let identity =
            load_outbound_client_identity(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
                .expect("client identity must load");
        let client_config =
            build_outbound_tls_config(Some(identity), TlsMethod::default()).expect("client config");

        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            client_config,
        );

        let data = Bytes::from_static(b"OPTIONS sip:peer@example.com SIP/2.0\r\n\r\n");
        let outcome = pool.send_tls(server_addr, Some("localhost"), data).await;
        assert!(
            outcome.is_ok(),
            "mTLS handshake with a valid client cert must succeed: {:?}",
            outcome.err()
        );

        let received = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server task timed out")
            .expect("server task panicked");
        assert!(
            received.contains("OPTIONS"),
            "server did not receive app data over mTLS: {received}"
        );

        // ---- (b) WITHOUT a client identity: mandatory-mTLS server rejects -
        let acceptor2 = mtls_server_acceptor(&certs);
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr2 = listener2.local_addr().unwrap();
        let server2 = tokio::spawn(async move {
            let (tcp, _) = listener2.accept().await.expect("accept");
            // Server handshake MUST fail — no client certificate presented.
            acceptor2.accept(tcp).await.is_err()
        });

        let no_auth_config =
            build_outbound_tls_config(None, TlsMethod::default()).expect("no-auth client config");
        let connection_map2 = Arc::new(DashMap::new());
        let (inbound_tx2, _inbound_rx2) = flume::unbounded();
        let pool2 = ConnectionPool::new(
            connection_map2,
            inbound_tx2,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            no_auth_config,
        );

        let outcome2 = pool2
            .send_tls(server_addr2, Some("localhost"), Bytes::from_static(b"PING"))
            .await;
        assert!(
            outcome2.is_err(),
            "a handshake without a client cert against a mandatory-mTLS server must fail"
        );

        let server_rejected = tokio::time::timeout(Duration::from_secs(5), server2)
            .await
            .expect("server2 task timed out")
            .expect("server2 task panicked");
        assert!(
            server_rejected,
            "server must reject the handshake when no client cert is presented"
        );
    }

    // --- Outbound client-certificate hot-reload --------------------------

    /// A TLS server acceptor that presents `certs`' server cert and requires NO
    /// client certificate — used to establish a plain outbound pooled TLS
    /// connection (the pool's `NoVerify` accepts any server cert).
    fn plain_server_acceptor(certs: &MtlsCerts) -> tokio_rustls::TlsAcceptor {
        use tokio_rustls::rustls::ServerConfig;
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certs.server_cert_der.clone()],
                certs.server_key_der.clone_key(),
            )
            .expect("server config");
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
    }

    /// Load an [`OutboundClientIdentity`] from in-memory PEM strings via the
    /// production loader (files are fully read, so the tempdir can drop after).
    fn identity_from_pem(cert_pem: &str, key_pem: &str) -> OutboundClientIdentity {
        let directory = tempfile::tempdir().unwrap();
        let cert_path = directory.path().join("client.crt");
        let key_path = directory.path().join("client.key");
        std::fs::write(&cert_path, cert_pem).unwrap();
        std::fs::write(&key_path, key_pem).unwrap();
        load_outbound_client_identity(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
            .expect("client identity must load")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reload_swaps_outbound_identity_for_new_connections() {
        // The client-cert-renewal path: an outbound handshake with the OLD
        // (untrusted) client identity must fail, and after
        // `reload_tls_client_configs` swaps in the renewed identity, a fresh
        // outbound handshake must succeed — proving the live swap reaches new
        // outbound connections (not just the inbound acceptor).
        ensure_crypto_provider();

        // Two independent CAs. The mTLS servers trust only CA-B.
        let certs_a = generate_mtls_certs();
        let certs_b = generate_mtls_certs();

        // Pool starts with the CA-A client identity (wrong CA for these servers).
        let identity_a = identity_from_pem(&certs_a.client_cert_pem, &certs_a.client_key_pem);
        let config_a =
            build_outbound_tls_config(Some(identity_a), TlsMethod::default()).expect("config a");
        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            connection_map,
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            config_a,
        );

        // (a) Handshake with the wrong-CA client cert must FAIL.
        let acceptor1 = mtls_server_acceptor(&certs_b);
        let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr1 = listener1.local_addr().unwrap();
        let server1 = tokio::spawn(async move {
            let (tcp, _) = listener1.accept().await.expect("accept");
            // Server MUST reject — client cert chains to CA-A, not trusted.
            acceptor1.accept(tcp).await.is_err()
        });
        let before = pool
            .send_tls(addr1, Some("localhost"), Bytes::from_static(b"PING"))
            .await;
        assert!(
            before.is_err(),
            "handshake with the pre-reload (untrusted) client cert must fail"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(5), server1)
                .await
                .expect("server1 timed out")
                .expect("server1 panicked"),
            "server must reject the untrusted client cert"
        );

        // Swap in the renewed identity signed by CA-B.
        let identity_b = identity_from_pem(&certs_b.client_cert_pem, &certs_b.client_key_pem);
        let configs_b = build_outbound_tls_configs(
            Some(identity_b),
            TlsMethod::default(),
            &ServerVerification::public_roots(false),
        )
        .expect("config b");
        pool.reload_tls_client_configs(configs_b);

        // (b) A fresh outbound handshake now SUCCEEDS with the new identity.
        let acceptor2 = mtls_server_acceptor(&certs_b);
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let server2 = tokio::spawn(async move {
            let (tcp, _) = listener2.accept().await.expect("accept");
            let mut tls = acceptor2
                .accept(tcp)
                .await
                .expect("handshake with the renewed client cert must succeed");
            let mut buffer = vec![0u8; 1024];
            let size = tls.read(&mut buffer).await.expect("read app data");
            String::from_utf8_lossy(&buffer[..size]).to_string()
        });
        let after = pool
            .send_tls(
                addr2,
                Some("localhost"),
                Bytes::from_static(b"OPTIONS sip:peer@example.com SIP/2.0\r\n\r\n"),
            )
            .await;
        assert!(
            after.is_ok(),
            "after reload, the handshake with the renewed identity must succeed: {:?}",
            after.err()
        );
        let received = tokio::time::timeout(Duration::from_secs(5), server2)
            .await
            .expect("server2 timed out")
            .expect("server2 panicked");
        assert!(
            received.contains("OPTIONS"),
            "server did not receive app data over the reloaded identity: {received}"
        );
    }

    #[tokio::test]
    async fn reload_evicts_stale_pooled_tls_connection() {
        // A reload must drop pooled TLS connections from the reuse map (so the
        // next send re-handshakes with the new cert) while leaving pooled TCP
        // connections — whose identity is transport-level — untouched.
        ensure_crypto_provider();
        let certs = generate_mtls_certs();

        // A plain TLS server (no client auth) to establish a pooled TLS conn.
        let tls_acceptor = plain_server_acceptor(&certs);
        let tls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = tls_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((tcp, _)) = tls_listener.accept().await {
                if let Ok(mut tls) = tls_acceptor.accept(tcp).await {
                    let mut buffer = vec![0u8; 1024];
                    let _ = tls.read(&mut buffer).await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        });

        // A plain TCP server to establish a pooled TCP conn that must survive.
        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut tcp, _)) = tcp_listener.accept().await {
                let mut buffer = vec![0u8; 1024];
                let _ = tcp.read(&mut buffer).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
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
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
        );

        pool.send_tls(tls_addr, Some("localhost"), Bytes::from_static(b"PING"))
            .await
            .expect("establish pooled TLS connection");
        pool.send_tcp(tcp_addr, Bytes::from_static(b"PING"))
            .await
            .expect("establish pooled TCP connection");
        assert_eq!(pool.active_connections(), 2, "both connections pooled");

        pool.reload_tls_client_configs(
            build_outbound_tls_configs(
                None,
                TlsMethod::default(),
                &ServerVerification::public_roots(false),
            )
            .expect("outbound tls config"),
        );

        assert_eq!(
            pool.active_connections(),
            1,
            "reload must evict the pooled TLS connection but keep the TCP one"
        );
    }

    // -----------------------------------------------------------------------
    // A peer that stops draining must never park the caller
    // -----------------------------------------------------------------------

    /// The unit half: the enqueue helper both the TCP and TLS paths share
    /// refuses at once on a queue at its byte bound, rather than waiting for
    /// room that a stalled writer will never make.
    #[tokio::test]
    async fn enqueue_refuses_at_once_when_the_queue_is_at_its_bound() {
        let (sender, _receiver) =
            send_queue::channel_with_limit(Transport::Tcp, ConnectionId(1), 6);
        assert!(matches!(
            enqueue(&sender, Bytes::from_static(b"one")),
            Enqueued::Sent
        ));
        assert!(matches!(
            enqueue(&sender, Bytes::from_static(b"two")),
            Enqueued::Sent
        ));
        assert!(
            matches!(
                enqueue(&sender, Bytes::from_static(b"three")),
                Enqueued::Backlogged
            ),
            "a queue at its bound must report Backlogged, not park"
        );
    }

    /// A closed queue is a dead connection, and has to stay distinguishable
    /// from a merely backed-up one: `Closed` evicts and re-establishes, whereas
    /// `Backlogged` keeps the connection (the writer's own timeout is what
    /// decides a peer is stuck).
    #[tokio::test]
    async fn enqueue_reports_closed_when_the_writer_is_gone() {
        let (sender, receiver) = send_queue::channel_with_limit(Transport::Tcp, ConnectionId(1), 6);
        drop(receiver);
        assert!(
            matches!(
                enqueue(&sender, Bytes::from_static(b"anything")),
                Enqueued::Closed
            ),
            "a dropped receiver must report Closed"
        );
    }

    /// A burst far past the old 64-message bound, to a peer that reads, all
    /// goes out on the one pooled connection, in order.
    #[tokio::test]
    async fn a_burst_of_pool_sends_to_a_reading_peer_all_arrive_in_order() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let pool = test_pool();
        const BURST: usize = 500;
        let mut connections = std::collections::HashSet::new();
        for sequence in 0..BURST {
            let frame = Bytes::from(format!("{sequence:08}\n"));
            connections.insert(pool.send_tcp(peer, frame).await.expect("never refused"));
        }
        assert_eq!(
            connections.len(),
            1,
            "one connection carries the whole burst"
        );
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut received = vec![0u8; BURST * 9];
        tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut received))
            .await
            .expect("the whole burst arrives")
            .unwrap();
        let expected: Vec<u8> = (0..BURST)
            .flat_map(|sequence| format!("{sequence:08}\n").into_bytes())
            .collect();
        assert!(received == expected, "every send arrives once, in order");
    }

    /// The regression for the process abort.
    ///
    /// Before the bound, this test does not fail — it *hangs*, which is the
    /// point: in the field the same wait was 30 s of a completely silent
    /// process, three script-executor workers gone, and then `abort()`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn send_to_a_peer_that_stops_draining_fails_instead_of_parking_the_caller() {
        let (peer, _accepted) = spawn_non_draining_peer().await;

        let mut pool = test_pool();
        pool.send_queue_bytes = 64 * 1024;
        pool.write_timeout = Duration::from_millis(200);

        let (refused_at, _) = send_until_refused(&pool, peer).await;

        assert!(
            refused_at > 0,
            "the first send should still have gone out — the peer accepts, it \
             just never reads"
        );
    }

    /// Once the writer gives up, the connection must not stay in the pool as a
    /// corpse that every later caller queues behind. The writer dropping its
    /// receiver closes the channel, which the next send sees as `Closed` and
    /// replaces — so a peer that recovers gets a fresh connection rather than
    /// permanent 503s.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_stalled_connection_is_replaced_on_the_next_send() {
        let (peer, mut accepted) = spawn_non_draining_peer().await;

        let mut pool = test_pool();
        pool.send_queue_bytes = 64 * 1024;
        pool.write_timeout = Duration::from_millis(200);
        let key = tcp_key(&pool, peer);

        let (_, carried_on) = send_until_refused(&pool, peer).await;
        let (stalled_id, stalled_sender) = pool
            .pooled(&key)
            .expect("the refused send leaves the backed-up connection pooled");

        // The writer's own timeout is what gives up on the peer, and it does so
        // by dropping its receiver. Wait for exactly that instead of sleeping
        // past the timeout and hoping the runtime has polled the writer since.
        tokio::time::timeout(Duration::from_secs(10), stalled_sender.closed())
            .await
            .expect("the writer must give up on a peer that never drains");

        // The next send must establish a *new* connection rather than error
        // forever against the wedged entry.
        let replacement_id = tokio::time::timeout(
            Duration::from_secs(10),
            pool.send_tcp(peer, Bytes::from_static(b"PING")),
        )
        .await
        .expect("a send after the writer gave up must not park either")
        .expect("a send after the writer gave up must establish a new connection");

        assert_ne!(
            replacement_id, stalled_id,
            "a stalled connection must be replaced, not kept as a corpse every \
             later caller queues behind"
        );
        assert_eq!(
            pool.pooled(&key).map(|(connection_id, _)| connection_id),
            Some(replacement_id),
            "later callers must be offered the replacement"
        );

        // And the peer really saw it: one accept for every connection the pool
        // opened, the replacement included.
        let mut held = Vec::new();
        for _ in 0..=carried_on.len() {
            let socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
                .await
                .expect("every connection the pool opened must reach the peer")
                .expect("the peer's accept loop is still running");
            held.push(socket);
        }
    }

    /// A connection's reader outlives its writer. Once the writer gives up on a
    /// peer that stopped draining, the next send replaces the pool entry while
    /// the old reader is still parked on the socket, and that reader only ends
    /// later: when the peer closes, or at the idle timeout. Its cleanup must
    /// remove the connection it belongs to, not whichever connection holds the
    /// slot by then. Evicting the replacement orphans a live connection, still
    /// open but never offered for reuse, and makes the next send to that peer
    /// open yet another one.
    ///
    /// Current-thread on purpose: the reader's cleanup drops the connection from
    /// `connection_map` and from the pool within one poll, so once this task
    /// sees the first removal the second has happened too.
    #[tokio::test]
    async fn an_old_connection_closing_does_not_evict_its_replacement() {
        let (peer, mut accepted) = spawn_non_draining_peer().await;

        let mut pool = test_pool();
        pool.send_queue_bytes = 64 * 1024;
        pool.write_timeout = Duration::from_millis(200);
        let key = tcp_key(&pool, peer);

        let (_, carried_on) = send_until_refused(&pool, peer).await;
        let (_, stalled_sender) = pool
            .pooled(&key)
            .expect("the refused send leaves the backed-up connection pooled");
        tokio::time::timeout(Duration::from_secs(10), stalled_sender.closed())
            .await
            .expect("the writer must give up on a peer that never drains");

        // The peer's end of every connection opened so far, so the test can
        // close exactly those.
        let mut old_sockets = Vec::new();
        for _ in 0..carried_on.len() {
            let socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
                .await
                .expect("every connection the pool opened must reach the peer")
                .expect("the peer's accept loop is still running");
            old_sockets.push(socket);
        }

        let replacement_id = tokio::time::timeout(
            Duration::from_secs(10),
            pool.send_tcp(peer, Bytes::from_static(b"PING")),
        )
        .await
        .expect("a send after the writer gave up must not park")
        .expect("a send after the writer gave up must establish a new connection");
        let _replacement_socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
            .await
            .expect("the replacement must reach the peer")
            .expect("the peer's accept loop is still running");

        // The peer closes the old connections, which ends their readers.
        drop(old_sockets);
        tokio::time::timeout(Duration::from_secs(10), async {
            while carried_on
                .iter()
                .any(|connection_id| pool.connection_map.contains_key(connection_id))
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the old connections' readers must see the peer close");

        assert_eq!(
            pool.pooled(&key).map(|(connection_id, _)| connection_id),
            Some(replacement_id),
            "an old connection's cleanup evicted the live connection that replaced it"
        );
    }

    /// The TLS half of `an_old_connection_closing_does_not_evict_its_replacement`,
    /// for the stream-connection registry.
    ///
    /// An outbound TLS connection also registers under its destination, which
    /// is what relays reuse. A client-certificate reload retires the pooled
    /// entry and the next send opens a replacement, whose registration takes
    /// the destination over while the old connection is still open. When the
    /// old reader then ends, its cleanup must leave the replacement registered:
    /// removing by destination alone made a live trunk connection unreachable
    /// for reuse.
    ///
    /// Current-thread on purpose: the reader's cleanup drops the connection from
    /// `connection_map` and from the registry within one poll.
    #[tokio::test]
    async fn an_old_tls_connection_closing_does_not_unregister_its_replacement() {
        ensure_crypto_provider();
        let certs = generate_mtls_certs();
        let acceptor = plain_server_acceptor(&certs);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        // Every accepted connection is handed to the test and never read, so the
        // test decides when the peer closes each one.
        let (accepted_sender, mut accepted) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let accepted_sender = accepted_sender.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = accepted_sender.send(tls);
                    }
                });
            }
        });

        let registry = StreamConnections::new();
        let connection_map = Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let pool = ConnectionPool::new(
            Arc::clone(&connection_map),
            inbound_tx,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            Some(registry.clone()),
            None,
            build_outbound_tls_config(None, TlsMethod::default()).expect("outbound tls config"),
        );
        let ping = || Bytes::from_static(b"OPTIONS sip:peer@example.com SIP/2.0\r\n\r\n");

        let old_id = pool
            .send_tls(peer, Some("localhost"), ping())
            .await
            .expect("establish the first TLS connection");
        let old_socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
            .await
            .expect("the first connection must reach the peer")
            .expect("the peer's accept loop is still running");

        pool.reload_tls_client_configs(
            build_outbound_tls_configs(
                None,
                TlsMethod::default(),
                &ServerVerification::public_roots(false),
            )
            .expect("outbound tls config"),
        );
        let replacement_id = pool
            .send_tls(peer, Some("localhost"), ping())
            .await
            .expect("a send after the reload must establish a new connection");
        assert_ne!(
            replacement_id, old_id,
            "the reload must retire the first connection"
        );
        let _replacement_socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
            .await
            .expect("the replacement must reach the peer")
            .expect("the peer's accept loop is still running");
        assert_eq!(registry.reuse(peer, Transport::Tls), Some(replacement_id));

        // The peer closes the old connection, which ends its reader.
        drop(old_socket);
        tokio::time::timeout(Duration::from_secs(10), async {
            while connection_map.contains_key(&old_id) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the old connection's reader must see the peer close");

        assert!(
            registry.is_alive(peer, Transport::Tls, replacement_id),
            "an old connection's cleanup unregistered the live connection that replaced it"
        );
    }

    /// Source-level, for the same reason the dispatcher guards its CDR wiring
    /// that way: the property is an *ordering* one, and the race that exposes it
    /// behaviourally is too tight to drive reliably.
    ///
    /// The per-destination establishment lock exists so concurrent first-sends
    /// coalesce onto one connection. It must not still be held while handing the
    /// message to the writer: one caller parked there — even for the bounded
    /// window — convoys every other caller for that destination behind it, which
    /// is how a single stuck peer became a per-destination stall.
    #[test]
    fn the_establishment_lock_is_released_before_the_message_is_enqueued() {
        let source = include_str!("pool.rs");

        let guarded = source
            .split("let _establish_guard = connect_lock.lock().await;")
            .nth(1)
            .expect("the establishment lock is still taken");
        // A closing brace followed by a semicolon, the brace escaped: the same
        // two bytes to `split`, but not an unmatched brace in the source.
        // Written literally it sent the brace walk in
        // scripts/check_file_size.py off the end of this function instead of
        // the end of the module, so every test below here counted as production
        // code.
        let guarded = guarded
            .split("\u{7d};")
            .next()
            .expect("the guarded block is still delimited");

        assert!(
            !guarded.contains("enqueue("),
            "the re-check enqueue moved back inside the establishment lock, so a \
             caller waiting on a peer that is not draining now convoys every \
             other caller to the same destination behind it. The guarded block \
             was:{guarded}"
        );
    }

    /// `has_live` answers for the one connection a default send to that exact
    /// destination and transport reuses, and for nothing else.
    #[tokio::test]
    async fn has_live_names_the_exact_destination_and_transport() {
        let pool = test_pool();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registrar = listener.local_addr().unwrap();
        let other_port = SocketAddr::new(registrar.ip(), registrar.port().wrapping_add(1));
        assert!(
            !pool.has_live(registrar, Transport::Tcp),
            "nothing pooled yet"
        );

        pool.send_tcp(registrar, Bytes::from_static(b"REGISTER"))
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();

        assert!(pool.has_live(registrar, Transport::Tcp));
        assert!(
            !pool.has_live(other_port, Transport::Tcp),
            "another port on the same host is a different connection"
        );
        assert!(
            !pool.has_live(registrar, Transport::Tls),
            "a TCP connection is not a TLS one"
        );
        for transport in [
            Transport::Udp,
            Transport::Sctp,
            Transport::WebSocket,
            Transport::WebSocketSecure,
        ] {
            assert!(
                !pool.has_live(registrar, transport),
                "the pool opens no {transport} connections"
            );
        }

        drop(accepted);
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.has_live(registrar, Transport::Tcp) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a connection the peer closed still reads as live");
    }

    /// A source-bound connection (IPsec, `send_socket=`) to the same
    /// destination is not the one a default send reuses.
    #[tokio::test]
    async fn has_live_ignores_a_source_bound_connection() {
        let pool = test_pool();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registrar = listener.local_addr().unwrap();

        pool.send_tcp_from(
            "127.0.0.2:0".parse().unwrap(),
            registrar,
            Bytes::from_static(b"REGISTER"),
        )
        .await
        .unwrap();
        let (_accepted, _) = listener.accept().await.unwrap();

        assert!(!pool.has_live(registrar, Transport::Tcp));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn has_live_sees_an_outbound_tls_connection_until_it_closes() {
        let pool = test_pool();
        let certs = generate_mtls_certs();
        let acceptor = plain_server_acceptor(&certs);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let registrar = listener.local_addr().unwrap();
        let (close_sender, close_receiver) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            let tls = acceptor.accept(tcp).await.expect("handshake");
            let _ = close_receiver.await;
            drop(tls);
        });

        pool.send_tls(
            registrar,
            Some("localhost"),
            Bytes::from_static(b"REGISTER"),
        )
        .await
        .unwrap();

        assert!(pool.has_live(registrar, Transport::Tls));
        assert!(!pool.has_live(registrar, Transport::Tcp));

        close_sender.send(()).unwrap();
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.has_live(registrar, Transport::Tls) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("a TLS connection the peer closed still reads as live");
    }

    /// A silent peer on a listening socket, for the idle-reap tests.
    async fn silent_peer() -> (tokio::net::TcpListener, SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        (listener, destination)
    }

    /// An exempt destination's connection survives the idle timeout; a
    /// destination that is not exempt still loses its connection to it.
    ///
    /// The non-exempt connection is the control: it is what proves the reaper
    /// really ran, so the survivor is an exemption rather than a test that did
    /// not wait long enough.
    #[tokio::test]
    async fn an_idle_exempt_destination_outlives_the_idle_timeout() {
        let mut pool = test_pool();
        pool.set_idle_timeout(Duration::from_millis(30));
        let (trunk_listener, trunk) = silent_peer().await;
        let (probe_listener, probe) = silent_peer().await;
        pool.set_idle_exempt_destinations([(trunk, Transport::Tcp)]);

        pool.send_tcp(trunk, Bytes::from_static(b"REGISTER"))
            .await
            .unwrap();
        let (_trunk_peer, _) = trunk_listener.accept().await.unwrap();
        pool.send_tcp(probe, Bytes::from_static(b"OPTIONS"))
            .await
            .unwrap();
        let (_probe_peer, _) = probe_listener.accept().await.unwrap();

        // Neither peer ever answers.  The trunk's window opened first, so it has
        // passed by the time the probe's does.
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.has_live(probe, Transport::Tcp) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the idle timeout never closed the connection that is not exempt");

        assert!(
            pool.has_live(trunk, Transport::Tcp),
            "an exempt destination's connection was closed for idleness"
        );
        assert_eq!(pool.active_connections(), 1);
    }

    /// Exemption drops the timer, not the detection: the peer closing still
    /// takes the connection out of the pool at once.
    #[tokio::test]
    async fn an_idle_exempt_connection_still_goes_when_the_peer_closes() {
        let mut pool = test_pool();
        pool.set_idle_timeout(Duration::from_millis(30));
        let (listener, trunk) = silent_peer().await;
        pool.set_idle_exempt_destinations([(trunk, Transport::Tcp)]);

        pool.send_tcp(trunk, Bytes::from_static(b"REGISTER"))
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        assert!(pool.has_live(trunk, Transport::Tcp));

        drop(peer);

        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.has_live(trunk, Transport::Tcp) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("an exempt connection the peer closed still reads as live");
    }

    #[test]
    fn idle_exemption_names_one_destination_and_transport() {
        let pool = test_pool();
        let trunk: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        let other: SocketAddr = "192.0.2.11:5060".parse().unwrap();
        pool.set_idle_exempt_destinations([(trunk, Transport::Tcp)]);

        assert!(pool.is_idle_exempt(trunk, Transport::Tcp));
        assert!(!pool.is_idle_exempt(trunk, Transport::Tls));
        assert!(!pool.is_idle_exempt(other, Transport::Tcp));
    }

    /// Steady state: the exemption set holds what the last call named and
    /// nothing else, and returns to its starting size once nothing is exempt.
    /// It is keyed per trunk, so an owner that restates a churning set must not
    /// grow it.
    #[test]
    fn the_idle_exemption_set_drains_to_its_starting_len() {
        let pool = test_pool();
        let baseline = pool.idle_exempt_len();

        for cycle in 0..50u16 {
            let stated: Vec<(SocketAddr, Transport)> = (0..8u16)
                .map(|index| {
                    let destination: SocketAddr = format!("192.0.2.{}:{}", index + 1, 5060 + cycle)
                        .parse()
                        .unwrap();
                    (destination, Transport::Tcp)
                })
                .collect();
            pool.set_idle_exempt_destinations(stated.iter().copied());
            assert_eq!(
                pool.idle_exempt_len(),
                stated.len(),
                "restating the set on cycle {cycle} left earlier destinations behind"
            );
        }

        pool.set_idle_exempt_destinations(std::iter::empty());
        assert_eq!(
            pool.idle_exempt_len(),
            baseline,
            "the exemption set did not drain once no destination was exempt"
        );
    }

    // --- a pending client transaction keeps its connection ------------------

    /// An INVITE over TCP as a relay puts it on the wire.
    fn ringing_invite(branch: &str) -> crate::sip::message::SipMessage {
        crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("example.org".to_string())
                    .with_user("callee".to_string()),
            )
            .via(format!("SIP/2.0/TCP 192.0.2.1:5060;branch={branch}"))
            .to("<sip:callee@example.org>".to_string())
            .from("<sip:caller@example.org>;tag=caller-tag".to_string())
            .call_id(format!("{branch}@example.org"))
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .expect("the INVITE builds")
    }

    /// Wait for the pool to stop offering its default connection to
    /// `destination`.
    async fn until_closed(pool: &ConnectionPool, destination: SocketAddr, what: &str) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while pool.has_live(destination, Transport::Tcp) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}"));
    }

    /// A connection an INVITE client transaction is pending on survives the
    /// idle timeout for as long as the callee rings, and is closed for idleness
    /// like any other once the transaction has ended.
    ///
    /// Before: the reader closed it after the idle timeout whatever was pending
    /// on it, so a call answered later than that had lost the connection its
    /// 200 was owed on (RFC 3261 §18.2.2).
    ///
    /// The control connections carry nothing pending. Each one being reaped
    /// proves a whole idle period went by, so the survivor is held rather than
    /// not yet due.
    #[tokio::test]
    async fn a_connection_with_a_pending_invite_outlives_the_idle_timeout() {
        use crate::transaction::state::IctEvent;
        use crate::transaction::{ClientEvent, TransactionManager};

        let mut pool = test_pool();
        pool.set_idle_timeout(Duration::from_millis(30));
        let transactions = TransactionManager::default();
        let (callee_listener, callee) = silent_peer().await;

        let invite = ringing_invite("z9hG4bK-pool-ringing");
        let wire = Bytes::from(invite.to_bytes());
        let (key, _) = transactions
            .new_client_transaction(
                &invite,
                wire.clone(),
                crate::transaction::state::Transport::Reliable,
            )
            .expect("the client transaction starts");
        let connection_id = pool.send_tcp(callee, wire).await.unwrap();
        transactions.hold_client_connection(&key, pool.hold(connection_id));
        let (_callee_peer, _) = callee_listener.accept().await.unwrap();
        assert!(pool.is_held(connection_id));

        // The callee rings: nothing is read on the connection for several idle
        // periods, each one witnessed by a control connection being reaped.
        for round in 0..3 {
            let (control_listener, control) = silent_peer().await;
            pool.send_tcp(control, Bytes::from_static(b"OPTIONS"))
                .await
                .unwrap();
            let (_control_peer, _) = control_listener.accept().await.unwrap();
            until_closed(
                &pool,
                control,
                "the idle timeout never closed a connection with nothing pending",
            )
            .await;
            assert!(
                pool.has_live(callee, Transport::Tcp),
                "the connection of a ringing INVITE was closed for idleness (round {round})"
            );
        }
        // Still the same connection, not a replacement.
        assert_eq!(
            pool.send_tcp(callee, Bytes::from_static(b"\r\n"))
                .await
                .unwrap(),
            connection_id
        );

        // Answered: the transaction ends and takes its hold with it.
        let answer = crate::sip::builder::SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK-pool-ringing".to_string())
            .to("<sip:callee@example.org>;tag=callee-tag".to_string())
            .from("<sip:caller@example.org>;tag=caller-tag".to_string())
            .call_id("z9hG4bK-pool-ringing@example.org".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .expect("the 200 builds");
        transactions
            .process_client_event(&key, ClientEvent::Ict(IctEvent::Response2xx(answer)))
            .expect("the 200 is taken");
        assert!(!pool.is_held(connection_id));

        until_closed(
            &pool,
            callee,
            "a connection whose transaction had ended was never closed for idleness",
        )
        .await;
        assert_eq!(pool.active_connections(), 0);
    }

    /// A hold suspends the idle timer and nothing else: the peer closing the
    /// connection still takes it out of the pool at once.
    #[tokio::test]
    async fn a_held_connection_still_goes_when_the_peer_closes() {
        let mut pool = test_pool();
        pool.set_idle_timeout(Duration::from_millis(30));
        let (listener, destination) = silent_peer().await;

        let connection_id = pool
            .send_tcp(destination, Bytes::from_static(b"INVITE"))
            .await
            .unwrap();
        let _hold = pool.hold(connection_id);
        let (peer, _) = listener.accept().await.unwrap();
        drop(peer);

        until_closed(
            &pool,
            destination,
            "a held connection the peer closed still reads as live",
        )
        .await;
    }

    /// Holds are per connection: one on a connection does not keep another
    /// connection open, and a hold on an id the pool never issued is inert.
    #[tokio::test]
    async fn a_hold_keeps_only_its_own_connection() {
        let mut pool = test_pool();
        pool.set_idle_timeout(Duration::from_millis(30));
        let (held_listener, held) = silent_peer().await;
        let (other_listener, other) = silent_peer().await;

        let held_id = pool
            .send_tcp(held, Bytes::from_static(b"INVITE"))
            .await
            .unwrap();
        let _hold = pool.hold(held_id);
        let _unknown = pool.hold(ConnectionId(u64::MAX));
        let (_held_peer, _) = held_listener.accept().await.unwrap();
        pool.send_tcp(other, Bytes::from_static(b"OPTIONS"))
            .await
            .unwrap();
        let (_other_peer, _) = other_listener.accept().await.unwrap();

        until_closed(&pool, other, "the connection with no hold was never closed").await;
        assert!(pool.has_live(held, Transport::Tcp));
    }

    // --- a connection from a pinned local port -------------------------------

    /// A connection whose local port the caller chose, as an IPsec protected
    /// port is chosen (TS 33.203 §7.1).
    ///
    /// What Linux does with a connect on a 4-tuple it has just closed depends
    /// on TCP timestamps. With them, a connect from a bound port takes over
    /// the connection in TIME-WAIT. With a peer that negotiates none it fails
    /// with `EADDRNOTAVAIL` for the whole of TIME-WAIT, and `SO_REUSEADDR` does
    /// not change that. Loopback negotiates timestamps, so to see the second
    /// case run these in a network namespace with `net.ipv4.tcp_timestamps=0`.
    mod pinned_port {
        use super::*;

        /// A free local port to pin, standing in for a protected client port.
        /// `SO_REUSEADDR` lets the pool bind it once it is released here.
        fn protected_source() -> SocketAddr {
            let reserve = tokio::net::TcpSocket::new_v4().unwrap();
            reserve.set_reuseaddr(true).unwrap();
            reserve.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            reserve.local_addr().unwrap()
        }

        fn pinned_key(source: SocketAddr, destination: SocketAddr) -> PoolKey {
            PoolKey {
                destination,
                transport: Transport::Tcp,
                bind: Some(source),
                verified_name: None,
            }
        }

        /// Wait for the pool to stop offering the connection under `key`.
        async fn until_released(pool: &ConnectionPool, key: &PoolKey, what: &str) {
            tokio::time::timeout(Duration::from_secs(5), async {
                while pool.pooled(key).is_some() {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("{what}"));
        }

        /// A connection from a pinned port is not closed for idleness, and the
        /// next request to the same peer goes out on it.
        ///
        /// Before: the reader closed it after the idle timeout like any other.
        /// The request that followed had to connect again from the same local
        /// port to the same remote port, while the connection just closed was
        /// still in TIME-WAIT on that 4-tuple, and failed with `EADDRNOTAVAIL`
        /// against a peer without TCP timestamps.
        ///
        /// The control connections are what prove whole idle periods went by.
        /// The peer closes when the pool does, as a peer does, which is what
        /// put the pool's end in TIME-WAIT.
        #[tokio::test]
        async fn a_connection_outlives_the_idle_timeout_and_carries_the_next_request() {
            let mut pool = test_pool();
            pool.set_idle_timeout(Duration::from_millis(30));
            let source = protected_source();
            let (listener, destination) = silent_peer().await;

            let first = pool
                .send_tcp_from(source, destination, Bytes::from_static(b"INVITE"))
                .await
                .unwrap();
            let (mut peer, from) = listener.accept().await.unwrap();
            assert_eq!(from, source);
            let (seen_sender, mut seen) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                let mut scratch = [0u8; 64];
                while let Ok(size) = peer.read(&mut scratch).await {
                    if size == 0 || seen_sender.send(scratch[..size].to_vec()).is_err() {
                        return;
                    }
                }
            });

            for _ in 0..3 {
                let (control_listener, control) = silent_peer().await;
                pool.send_tcp(control, Bytes::from_static(b"OPTIONS"))
                    .await
                    .unwrap();
                let (_control_peer, _) = control_listener.accept().await.unwrap();
                until_closed(
                    &pool,
                    control,
                    "the idle timeout never closed a connection from an ephemeral port",
                )
                .await;
            }

            let second = pool
                .send_tcp_from(source, destination, Bytes::from_static(b"BYE"))
                .await
                .expect("a request after the idle period could not be sent from the pinned port");
            assert_eq!(
                second, first,
                "the connection from a pinned port was closed for idleness and replaced"
            );
            let mut received = Vec::new();
            while received.len() < b"INVITEBYE".len() {
                let chunk = tokio::time::timeout(Duration::from_secs(5), seen.recv())
                    .await
                    .expect("the peer never received both requests")
                    .expect("the peer lost the connection both requests were owed on");
                received.extend(chunk);
            }
            assert_eq!(received, b"INVITEBYE");
        }

        /// Only a pinned port is kept: a source-bound connection on an
        /// ephemeral port (a `send_socket=` egress pin) idles out as before.
        #[tokio::test]
        async fn a_source_bound_connection_on_an_ephemeral_port_still_idles_out() {
            let mut pool = test_pool();
            pool.set_idle_timeout(Duration::from_millis(30));
            let source: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let (listener, destination) = silent_peer().await;

            pool.send_tcp_from(source, destination, Bytes::from_static(b"OPTIONS"))
                .await
                .unwrap();
            let (_peer, _) = listener.accept().await.unwrap();

            until_released(
                &pool,
                &pinned_key(source, destination),
                "the idle timeout never closed a source-bound connection on an ephemeral port",
            )
            .await;
        }

        /// A pinned connection is ended from outside its task when its peer is
        /// closed (a P-CSCF deleting the UE's security associations), with a
        /// reset, and the pool stops offering it.
        ///
        /// Before: nothing outside the task could end it, so it stayed up until
        /// the peer closed it or keepalive gave up, retransmitting toward an
        /// address with no association behind it.
        #[tokio::test]
        async fn closing_its_peer_resets_a_pinned_connection() {
            let pool = test_pool();
            let source = protected_source();
            let (listener, destination) = silent_peer().await;
            let key = pinned_key(source, destination);

            pool.send_tcp_from(source, destination, Bytes::from_static(b"NOTIFY"))
                .await
                .unwrap();
            let (mut peer, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 16];
            let size = peer.read(&mut scratch).await.unwrap();
            assert_eq!(&scratch[..size], b"NOTIFY");

            assert_eq!(
                crate::transport::disconnect::close_peer(destination, "a test signal"),
                1
            );
            let ended = tokio::time::timeout(Duration::from_secs(5), peer.read(&mut scratch))
                .await
                .expect("the connection was never closed");
            assert_eq!(
                ended.map_err(|error| error.kind()),
                Err(std::io::ErrorKind::ConnectionReset),
                "a pinned connection closed from outside must end with a reset"
            );
            until_released(
                &pool,
                &key,
                "a closed connection is still offered for reuse",
            )
            .await;
        }

        /// A peer that closes first leaves nothing behind on the pool's side:
        /// the connection is gone from both maps and the next request connects
        /// from the same port.
        #[tokio::test]
        async fn a_connection_the_peer_closes_is_replaced_from_the_same_port() {
            let mut pool = test_pool();
            pool.set_idle_timeout(Duration::from_millis(30));
            let source = protected_source();
            let (listener, destination) = silent_peer().await;
            let key = pinned_key(source, destination);

            let first = pool
                .send_tcp_from(source, destination, Bytes::from_static(b"INVITE"))
                .await
                .unwrap();
            let (peer, _) = listener.accept().await.unwrap();
            drop(peer);
            until_released(
                &pool,
                &key,
                "a connection the peer closed is still offered for reuse",
            )
            .await;
            assert_eq!(pool.active_connections(), 0);
            assert!(pool.connection_map.is_empty());

            let second = pool
                .send_tcp_from(source, destination, Bytes::from_static(b"BYE"))
                .await
                .expect("no connect from the pinned port after the peer closed its connection");
            assert_ne!(second, first);
            let (_replacement, from) = listener.accept().await.unwrap();
            assert_eq!(from, source);
        }

        /// A writer that gives up on a peer that stopped draining takes the
        /// whole connection with it, so the replacement can leave from the same
        /// port.
        ///
        /// Before: the reader stayed parked on the socket after the writer had
        /// gone, the 4-tuple stayed taken, and every connect from the pinned
        /// port failed with `EADDRNOTAVAIL` until the reader ended as well.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn a_connection_whose_writer_gave_up_frees_its_port_at_once() {
            let (destination, mut accepted) = spawn_non_draining_peer().await;
            let mut pool = test_pool();
            pool.send_queue_bytes = 64 * 1024;
            pool.write_timeout = Duration::from_millis(200);
            let source = protected_source();
            let key = pinned_key(source, destination);

            let payload = Bytes::from(vec![b'x'; 8 * 1024]);
            let mut carried_on = std::collections::HashSet::new();
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match pool
                        .send_tcp_from(source, destination, payload.clone())
                        .await
                    {
                        Ok(connection_id) => {
                            carried_on.insert(connection_id);
                        }
                        // Refused while the writer was only behind, not stuck.
                        Err(_) => {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            let caught_up = pool
                                .pooled(&key)
                                .is_some_and(|(_, sender)| sender.queued_bytes() == 0);
                            if !caught_up {
                                break;
                            }
                        }
                    }
                }
            })
            .await
            .expect("a send to a peer that never reads must be refused, not parked");
            let (stalled_id, stalled_sender) = pool
                .pooled(&key)
                .expect("the refused send leaves the backed-up connection pooled");
            tokio::time::timeout(Duration::from_secs(10), stalled_sender.closed())
                .await
                .expect("the writer must give up on a peer that never drains");

            let replacement_id = tokio::time::timeout(
                Duration::from_secs(10),
                pool.send_tcp_from(source, destination, Bytes::from_static(b"PING")),
            )
            .await
            .expect("a send after the writer gave up must not park")
            .expect("no connect from the pinned port after the writer gave up");
            assert_ne!(replacement_id, stalled_id);

            // One accept for every connection the pool opened.  The last is the
            // replacement, the only one not reset by now, and it came from the
            // pinned port.
            let mut held = Vec::new();
            for _ in 0..=carried_on.len() {
                let socket = tokio::time::timeout(Duration::from_secs(10), accepted.recv())
                    .await
                    .expect("every connection the pool opened must reach the peer")
                    .expect("the peer's accept loop is still running");
                held.push(socket);
            }
            let replacement = held.last().expect("the pool opened a connection");
            assert_eq!(replacement.peer_addr().unwrap(), source);
        }
    }
}
