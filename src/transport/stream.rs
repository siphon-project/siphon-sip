//! Shared plumbing for the connection-oriented (stream) transports: TCP, TLS,
//! WS and WSS.
//!
//! Three pieces live here, all of them previously duplicated between
//! [`super::tcp`], [`super::tls`] and [`super::ws`]:
//!
//! * [`spawn_outbound_distributor`] — the single task per listener that fans
//!   outbound messages out to per-connection senders (with the optional
//!   [`ConnectionPool`] fallback when no inbound connection matches).
//! * [`serve_sip_stream`] — the per-connection read/write pair that frames
//!   inbound bytes into SIP messages (RFC 3261 §18.3), answers RFC 5626 §4.4.1
//!   CRLF keepalives, and cleans up both registries on close.
//! * [`sniff_stream`] / [`PrefixedStream`] — first-line protocol detection, so
//!   one listening socket can carry raw SIP *and* SIP-over-WebSocket
//!   (RFC 7118). See [`super::mux`] for the listener that uses them.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::transport::crlf_keepalive::{drain_leading_crlf_keepalives, CrlfPongTracker};
use crate::transport::pool::ConnectionPool;
use crate::transport::tcp::{frame_sip_message, FrameVerdict};
use crate::transport::{
    ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport,
    CONNECTION_IDLE_TIMEOUT, WRITE_TIMEOUT,
};

/// Create a listening TCP socket with `SO_REUSEADDR`/`SO_REUSEPORT` and the
/// optional DSCP marking applied *before* bind.
///
/// `SO_REUSEPORT` lets the outbound connection pool bind the same address, so
/// siphon can originate connections from its well-known SIP port. Note that it
/// also means two listeners on one address both bind successfully and the
/// kernel load-balances accepts between them — which is why sharing a port
/// between protocols goes through [`super::mux`] rather than two listeners.
pub(crate) fn bind_tcp_listener(
    local_addr: SocketAddr,
    tos: Option<u32>,
) -> io::Result<tokio::net::TcpListener> {
    let socket = if local_addr.is_ipv6() {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;
    // DSCP / DiffServ marking (RFC 4594) — family-aware (IP_TOS on v4,
    // IPV6_TCLASS on v6), best-effort so it never fails the listener.
    if let Some(tos) = tos {
        super::apply_tos(&socket2::SockRef::from(&socket), tos);
    }
    socket.bind(local_addr)?;
    socket.listen(1024)
}

/// Per-connection coordinates carried through the stream helpers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamContext {
    /// Transport this connection speaks — stamped on every `InboundMessage`
    /// and used to key the [`StreamConnections`] registry.
    pub transport: Transport,
    pub connection_id: ConnectionId,
    /// Local (listener) address the connection arrived on.
    pub local_addr: SocketAddr,
    /// Peer address.
    pub remote_addr: SocketAddr,
}

/// The source a pool-fallback TCP connect must bind, if any.
///
/// Only an IPsec-protected P-CSCF port.  An ESP-over-TCP SA selector keys on
/// the P-CSCF's exact source port, so a connect toward a UE whose captured flow
/// has closed has to leave from that port, or it matches no SA and never
/// arrives (3GPP TS 33.203).  Everything else stays ephemeral, as the pool has
/// always bound it: `source_local_addr` is stamped on responses too (the
/// listener they arrived on), and a reconnect from a listen port fails with
/// EADDRNOTAVAIL while an earlier connection to a peer that negotiated no TCP
/// timestamps sits in TIME_WAIT on the same 4-tuple (see
/// `ConnectionPool::establish_tcp_connection`).  A source of the other address
/// family can never be bound for the connect.
fn pool_tcp_source(
    source_local_addr: Option<SocketAddr>,
    destination: SocketAddr,
    is_protected: fn(u16) -> bool,
) -> Option<SocketAddr> {
    source_local_addr
        .filter(|source| source.is_ipv4() == destination.is_ipv4() && is_protected(source.port()))
}

/// A pool-fallback send: carries one [`OutboundMessage`] that has no live
/// connection out through the [`ConnectionPool`], connecting if it must.
/// Injected so tests can stand in a destination whose connect never completes.
type FallbackSend =
    Arc<dyn Fn(OutboundMessage) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The production [`FallbackSend`]: [`send_via_pool`] for `transport`.
fn pool_fallback_send(
    pool: Arc<ConnectionPool>,
    transport: Transport,
    is_protected: fn(u16) -> bool,
) -> FallbackSend {
    Arc::new(move |outbound: OutboundMessage| {
        let pool = Arc::clone(&pool);
        Box::pin(async move { send_via_pool(&pool, transport, is_protected, outbound).await })
    })
}

/// Send one message through the pool, its frames in order on the one
/// connection the pool coalesces to for the destination.  TCP binds the
/// protected source where [`pool_tcp_source`] requires one.
async fn send_via_pool(
    pool: &ConnectionPool,
    transport: Transport,
    is_protected: fn(u16) -> bool,
    outbound: OutboundMessage,
) {
    let destination = outbound.destination;
    let server_name = outbound.server_name.clone();
    let requested_connection_id = outbound.connection_id;
    let source = pool_tcp_source(outbound.source_local_addr, destination, is_protected);
    for frame in outbound.into_frames() {
        let sent = match transport {
            Transport::Tls => {
                pool.send_tls(destination, server_name.as_deref(), frame)
                    .await
            }
            Transport::Tcp => match source {
                Some(source) => pool.send_tcp_from(source, destination, frame).await,
                None => pool.send_tcp(destination, frame).await,
            },
            // WS/WSS are client-initiated (RFC 7118 §5): there is no
            // outbound-connect path, so a miss here is a dead UE.
            other => {
                warn!(
                    destination = %destination,
                    connection_id = ?requested_connection_id,
                    "{other} outbound dropped: no live connection and no outbound-connect path for this transport"
                );
                return;
            }
        };
        match sent {
            Ok(connection_id) => {
                debug!(
                    destination = %destination,
                    connection_id = ?connection_id,
                    "{transport} outbound: sent via pool"
                );
            }
            Err(error) => {
                warn!(
                    destination = %destination,
                    connection_id = ?requested_connection_id,
                    "{transport} outbound pool connect failed: {error}"
                );
                return;
            }
        }
    }
}

/// Queue depth of one fallback lane: the same bound a live connection's
/// channel has, and shed the same way when a peer cannot keep up.
const FALLBACK_LANE_CAPACITY: usize = 64;

/// How long an empty fallback lane waits for another message before it retires.
const FALLBACK_LANE_IDLE: Duration = Duration::from_secs(1);

/// Pool-fallback sends, each destination on its own serial lane, so the
/// distributor never waits on a connect.
///
/// A fallback send may have to connect, and a connect to a UE that died with its
/// SA still installed gets neither SYN-ACK nor RST, so it runs the pool's full
/// connect timeout.  Awaited on the distributor, that parked every other send
/// the distributor carries — live connections included — behind one dead peer,
/// and the registrar-liveness sweep sends to likely-dead peers by design.  A
/// lane is a task that sends one destination's messages in arrival order, so a
/// dead peer stalls only its own lane.
///
/// Lanes retire once idle.  A lane removes itself from the map only while it
/// holds the map lock and has seen its queue empty, and [`dispatch`] enqueues
/// under the same lock, so no message can land in a lane that is leaving: the
/// store drains to empty, and a destination never has two lanes running at once
/// (which could reorder its messages).
///
/// [`dispatch`]: FallbackLanes::dispatch
struct FallbackLanes {
    lanes: Arc<std::sync::Mutex<HashMap<SocketAddr, FallbackLane>>>,
    send: FallbackSend,
    idle: Duration,
    next_id: u64,
}

struct FallbackLane {
    /// Tells this lane apart from a later one for the same destination, so a
    /// retiring lane only ever removes itself.
    id: u64,
    sender: mpsc::Sender<OutboundMessage>,
}

impl FallbackLanes {
    fn new(send: FallbackSend, idle: Duration) -> Self {
        Self {
            lanes: Arc::new(std::sync::Mutex::new(HashMap::new())),
            send,
            idle,
            next_id: 0,
        }
    }

    /// Queue `outbound` behind any earlier fallback send to the same
    /// destination.  Never awaits.  Returns `false` when the message was shed
    /// because that destination already has a full lane.
    fn dispatch(&mut self, outbound: OutboundMessage) -> bool {
        let destination = outbound.destination;
        let mut lanes = lock_lanes(&self.lanes);
        let outbound = match lanes.get(&destination) {
            Some(lane) => match lane.sender.try_send(outbound) {
                Ok(()) => return true,
                Err(mpsc::error::TrySendError::Full(outbound)) => {
                    warn!(
                        destination = %destination,
                        connection_id = ?outbound.connection_id,
                        "outbound dropped: {FALLBACK_LANE_CAPACITY} sends already queued behind a pool connect to this destination (slow/stuck peer)"
                    );
                    return false;
                }
                // The lane's task ended without retiring, which only a panic
                // can do: replace it.
                Err(mpsc::error::TrySendError::Closed(outbound)) => outbound,
            },
            None => outbound,
        };
        let (sender, receiver) = mpsc::channel(FALLBACK_LANE_CAPACITY);
        if sender.try_send(outbound).is_err() {
            error!(
                destination = %destination,
                "outbound dropped: a new pool-fallback lane refused its first send"
            );
            return false;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        lanes.insert(destination, FallbackLane { id, sender });
        drop(lanes);
        tokio::spawn(run_fallback_lane(
            Arc::clone(&self.lanes),
            destination,
            id,
            receiver,
            Arc::clone(&self.send),
            self.idle,
        ));
        true
    }

    /// Lanes currently running, for the drain-to-empty leak test.
    #[cfg(test)]
    fn len(&self) -> usize {
        lock_lanes(&self.lanes).len()
    }
}

/// Lock the lane map.  Nothing panics while holding it, and a poisoned lock
/// still guards a consistent map, so recover it rather than lose every lane.
fn lock_lanes(
    lanes: &std::sync::Mutex<HashMap<SocketAddr, FallbackLane>>,
) -> std::sync::MutexGuard<'_, HashMap<SocketAddr, FallbackLane>> {
    lanes
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// One destination's lane: send its messages in arrival order, and retire once
/// it has sat empty for `idle`.  [`FallbackLanes`] explains why retiring can
/// neither lose nor reorder a message.
async fn run_fallback_lane(
    lanes: Arc<std::sync::Mutex<HashMap<SocketAddr, FallbackLane>>>,
    destination: SocketAddr,
    id: u64,
    mut receiver: mpsc::Receiver<OutboundMessage>,
    send: FallbackSend,
    idle: Duration,
) {
    loop {
        match tokio::time::timeout(idle, receiver.recv()).await {
            Ok(Some(outbound)) => send(outbound).await,
            // Every sender is gone, so nothing more can arrive.
            Ok(None) => return,
            Err(_) => {
                if retire_fallback_lane(&lanes, destination, id, &receiver) {
                    return;
                }
                // A send landed as the idle timer fired: keep going.
            }
        }
    }
}

/// Remove lane `id` from the map if its queue is empty, under the map lock that
/// [`FallbackLanes::dispatch`] enqueues under.  `true` once it has retired.
fn retire_fallback_lane(
    lanes: &std::sync::Mutex<HashMap<SocketAddr, FallbackLane>>,
    destination: SocketAddr,
    id: u64,
    receiver: &mpsc::Receiver<OutboundMessage>,
) -> bool {
    let mut lanes = lock_lanes(lanes);
    if !receiver.is_empty() {
        return false;
    }
    if lanes.get(&destination).is_some_and(|lane| lane.id == id) {
        lanes.remove(&destination);
    }
    true
}

/// Spawn the outbound distributor for one stream listener.
///
/// Routes each [`OutboundMessage`] to its connection's bounded sender; when no
/// live connection matches (a fire-and-forget send with
/// `ConnectionId::default()`, or a connection that has since closed) it falls
/// back to the outbound [`ConnectionPool`] where one is supplied, on a lane per
/// destination ([`FallbackLanes`]) so a connect never stalls the distributor.
pub(crate) fn spawn_outbound_distributor(
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    transport: Transport,
    pool: Option<Arc<ConnectionPool>>,
) {
    let fallback = pool.map(|pool| {
        pool_fallback_send(
            pool,
            transport,
            crate::script::api::ipsec::is_protected_local_port,
        )
    });
    spawn_outbound_distributor_with(outbound_rx, connection_map, transport, fallback);
}

/// [`spawn_outbound_distributor`] with the pool fallback injected, so tests do
/// not depend on a real pool or the process-wide IPsec config.
fn spawn_outbound_distributor_with(
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    transport: Transport,
    fallback: Option<FallbackSend>,
) {
    let mut lanes = fallback.map(|send| FallbackLanes::new(send, FALLBACK_LANE_IDLE));
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here. This task is
                // the single outbound distributor and it holds the
                // `connection_map` shard read guard for the whole `if let`. A
                // non-reading peer fills its bounded channel; an awaiting send
                // would then park holding the guard — stalling outbound for
                // every connection (head-of-line) and blocking the accept
                // loop's `insert` on the same shard (accept stops, backlog
                // fills, engine wedges). `try_send` keeps the guard for only
                // the synchronous send and sheds for a backed-up (stuck) peer —
                // it will retransmit or its connection will close.
                let connection_id = outbound.connection_id;
                // Frames of one message keep their relative order: they enter
                // the same per-connection channel back to back, and this is the
                // only distributor task feeding it.
                for frame in outbound.into_frames() {
                    match sender.try_send(frame) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            warn!("{transport} outbound dropped: connection {connection_id:?} send buffer full (slow/stuck peer)");
                            break;
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            warn!(
                                "{transport} outbound dropped: connection {connection_id:?} closed"
                            );
                            break;
                        }
                    }
                }
            } else if let Some(lanes) = lanes.as_mut() {
                // Never awaited here: a connect can run the pool's full timeout,
                // and this task carries every other send too.
                lanes.dispatch(outbound);
            } else {
                debug!(
                    "{transport} outbound: connection {:?} not found (may have closed)",
                    outbound.connection_id
                );
            }
        }
    });
}

/// Drive one accepted stream connection for its whole lifetime: frame inbound
/// SIP messages out of the byte stream, write outbound frames back, and clean
/// up both registries when either half ends.
///
/// `seed` carries bytes already consumed from the stream (the protocol sniff in
/// [`super::mux`]); it is framed before the first read, so a complete message
/// that arrived inside the sniff window is never lost. Callers with nothing
/// pre-read pass an empty buffer.
///
/// `stream_connections` is `Some` for the transports that support MT routing
/// back over the inbound flow (TLS, WS, WSS) and `None` for TCP, which reaches
/// peers through the outbound [`ConnectionPool`] instead.
pub(crate) async fn serve_sip_stream<R, W>(
    reader: R,
    mut writer: W,
    context: StreamContext,
    seed: BytesMut,
    inbound_tx: flume::Sender<InboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    stream_connections: Option<StreamConnections>,
    crlf_pong_tracker: Option<Arc<CrlfPongTracker>>,
    close_tx: Option<flume::Sender<u64>>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let StreamContext {
        transport,
        connection_id,
        local_addr,
        remote_addr,
    } = context;

    // Counts this connection in `siphon_connections_active{transport}` until the
    // guard drops at the end of this function — which covers the cancellation
    // path too, unlike a decrement written next to the cleanup below.
    //
    // Taken here rather than off `connection_map`/`StreamConnections`: the TCP
    // and TLS maps are shared with the outbound pool so their length mixes both
    // directions, and the registry deliberately omits TCP entirely.
    let _connection_gauge = crate::transport::ConnectionGauge::register(transport);

    // Per-connection outbound channel. Cloned for the read task so it can write
    // RFC 5626 §4.4.1 pong (`\r\n`) responses back over the same connection.
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
    connection_map.insert(connection_id, outbound_tx.clone());
    if let Some(registry) = stream_connections.as_ref() {
        registry.register(remote_addr, transport, connection_id);
    }
    let keepalive_writer = outbound_tx;

    // Read task: SIP stream framing (RFC 3261 §18.3) with an idle timeout.
    let read_task = tokio::spawn(async move {
        let mut reader = reader;
        let mut accumulator = seed;
        let mut read_buf = [0u8; 8192];
        loop {
            // Extract every complete message currently buffered. Runs before
            // the first read so a seeded buffer is framed immediately.
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
                let message_len = match frame_sip_message(
                    &accumulator,
                    crate::security::max_message_bytes(),
                ) {
                    FrameVerdict::Complete { len } => len,
                    // Still arriving (or header block done, body in flight).
                    FrameVerdict::NeedMore => break,
                    // RFC 3261 §21.4.11 — the peer declared more than we will
                    // buffer. The header block is already complete, so answer
                    // 513 rather than resetting the connection out from under
                    // a peer that would otherwise have no idea why: a legit
                    // oversized body (large SIPREC metadata, say) is then an
                    // obvious configuration problem instead of a mystery RST.
                    // The connection still closes, because the body we refuse
                    // to buffer is exactly what we would have to read to find
                    // the next message boundary.
                    FrameVerdict::Oversized {
                        declared,
                        header_len,
                    } => {
                        warn!(
                            declared,
                            limit = crate::security::max_message_bytes(),
                            "message from {remote_addr} on {transport} {connection_id:?} exceeds \
                             security.max_message_bytes; answering 513 and dropping connection"
                        );
                        if let Ok(request) =
                            crate::sip::parser::parse_sip_headers_only(&accumulator[..header_len])
                        {
                            if request.is_request() {
                                let reject = crate::sip::builder::build_response_skeleton(
                                    &request,
                                    513,
                                    "Message Too Large",
                                );
                                let _ = keepalive_writer.send(Bytes::from(reject.to_bytes())).await;
                            }
                        }
                        crate::security::record_malformed_message(
                            remote_addr.ip(),
                            &transport.to_string(),
                        );
                        return; // close the connection
                    }
                    FrameVerdict::Garbage => {
                        warn!("non-SIP bytes from {remote_addr} on {transport} {connection_id:?}; dropping connection");
                        crate::security::record_malformed_message(
                            remote_addr.ip(),
                            &transport.to_string(),
                        );
                        return; // close the connection
                    }
                };
                let data = accumulator.split_to(message_len).freeze();
                let message = InboundMessage {
                    connection_id,
                    transport,
                    local_addr,
                    remote_addr,
                    data,
                };
                if let Err(error) = inbound_tx.send_async(message).await {
                    error!("{transport} inbound enqueue failed: {error}");
                    return;
                }
            }

            match tokio::time::timeout(CONNECTION_IDLE_TIMEOUT, reader.read(&mut read_buf)).await {
                Ok(Ok(0)) => {
                    debug!("{transport} connection {connection_id:?} closed by peer");
                    break;
                }
                Ok(Ok(size)) => accumulator.extend_from_slice(&read_buf[..size]),
                // A peer that disappears without a TLS close_notify (rustls
                // reports it as `UnexpectedEof`) is ordinary internet
                // behaviour — scanners and browsers do it constantly, and it
                // says nothing an operator can act on. Every other read error
                // still warns.
                Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    debug!(
                        "{transport} connection {connection_id:?} from {remote_addr} closed without close_notify"
                    );
                    break;
                }
                Ok(Err(error)) => {
                    warn!(
                        "{transport} read error on {connection_id:?} from {remote_addr}: {error}"
                    );
                    break;
                }
                Err(_) => {
                    debug!(
                        "{transport} connection {connection_id:?} idle timeout ({}s)",
                        CONNECTION_IDLE_TIMEOUT.as_secs()
                    );
                    break;
                }
            }
        }
    });

    // Write task.
    let mut write_task = tokio::spawn(async move {
        while let Some(data) = outbound_rx.recv().await {
            match tokio::time::timeout(WRITE_TIMEOUT, writer.write_all(&data)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    warn!("{transport} write error on {connection_id:?}: {error}");
                    break;
                }
                Err(_) => {
                    warn!(
                        "{transport} write stalled on {connection_id:?} after \
                         {WRITE_TIMEOUT:?} — peer is not draining the connection \
                         (zero receive window); closing it"
                    );
                    break;
                }
            }
        }
    });

    // Wait for either half to close, then clean up.
    tokio::select! {
        _ = read_task => {
            // The read half can queue a final response on its way out — a 513
            // for an oversized declaration, say. Dropping the write half here
            // would discard it and the peer would see a bare connection reset
            // with no idea why, so instead close the channel (the read half's
            // sender went with the task; this drops the map's copy) and give
            // the writer a bounded window to flush what is already queued.
            connection_map.remove(&connection_id);
            let _ = tokio::time::timeout(FINAL_WRITE_GRACE, &mut write_task).await;
        }
        _ = &mut write_task => {}
    }

    connection_map.remove(&connection_id);
    if let Some(registry) = stream_connections.as_ref() {
        registry.unregister(&remote_addr);
    }
    // RFC 5626 §4.2.2 flow failure: notify the registrar so it can deregister
    // any binding that arrived on this connection. Best-effort.
    if let Some(close_tx) = &close_tx {
        let _ = close_tx.send(connection_id.0);
    }
    debug!("{transport} connection {connection_id:?} cleaned up");
}

// ---------------------------------------------------------------------------
// Protocol sniffing — raw SIP vs SIP-over-WebSocket on one socket
// ---------------------------------------------------------------------------

/// How long the write half may take to flush a response the read half queued
/// immediately before closing the connection. Bounded so a peer that has
/// stopped reading cannot pin the task open, but generous enough for one small
/// response on a live socket.
const FINAL_WRITE_GRACE: Duration = Duration::from_secs(1);

/// How long a freshly accepted connection may stay silent before it is assumed
/// to be raw SIP.
///
/// A WebSocket client always sends its `GET` immediately (the upgrade is
/// client-driven, RFC 6455 §4.1), so only a raw-SIP peer holding a connection
/// open for reuse (RFC 5923) ever reaches this timeout. Until the sniff
/// resolves the connection is not yet in the connection map, so a short budget
/// keeps the window in which siphon would open a second connection to that
/// peer instead of reusing this one.
pub(crate) const SNIFF_TIMEOUT: Duration = Duration::from_secs(2);

/// Bytes of first line tolerated before the sniff gives up. A SIP request line
/// and a WebSocket `GET` line are both far shorter; anything longer is a probe.
const MAX_SNIFF_BYTES: usize = 4096;

/// What a listening socket found on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamProtocol {
    /// Raw SIP over the stream (RFC 3261 §18.3 framing).
    Sip,
    /// An HTTP request line — a SIP-over-WebSocket upgrade (RFC 7118 §5).
    WebSocket,
}

/// Verdict of [`sniff_first_line`] on the bytes seen so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sniff {
    /// First line not complete yet — read more.
    NeedMore,
    /// Protocol determined.
    Decided(StreamProtocol),
    /// Neither SIP nor HTTP — a scanner probe or binary garbage.
    Garbage,
}

/// Classify a connection from its first line.
///
/// SIP and the WebSocket upgrade are unambiguous at the first line: a SIP
/// request line ends with ` SIP/2.0` and a status line starts with `SIP/2.0 `
/// (RFC 3261 §7.1/§7.2), while the upgrade is an HTTP request line ending in
/// ` HTTP/1.1` (RFC 6455 §4.1). No SIP method is a valid HTTP method and vice
/// versa, so no message is ever ambiguous.
///
/// Leading CRLFs (RFC 5626 §4.4.1 keepalives, RFC 3261 §7.5 stray CRLF) are
/// skipped for the decision but left in the buffer — the SIP read loop still
/// sees them and answers the ping.
pub(crate) fn sniff_first_line(buffer: &[u8]) -> Sniff {
    // A C0 control byte (other than CR/LF/HT) never appears in a SIP start-line
    // or an HTTP request line — catches binary probes (a TLS ClientHello on the
    // plaintext port, random bytes) before a CRLF is even seen.
    let head = &buffer[..buffer.len().min(512)];
    if head
        .iter()
        .any(|&byte| byte < 0x20 && byte != b'\r' && byte != b'\n' && byte != b'\t')
    {
        return Sniff::Garbage;
    }
    // Skip leading CRLF keepalives to find the start of the first real line.
    let start = buffer
        .iter()
        .position(|&byte| byte != b'\r' && byte != b'\n')
        .unwrap_or(buffer.len());
    let rest = &buffer[start..];
    let Some(line_end) = rest.windows(2).position(|window| window == b"\r\n") else {
        // First line still arriving. Bound it so a peer that never sends a CRLF
        // cannot pin the connection (the sniff timeout also covers this).
        return if buffer.len() > MAX_SNIFF_BYTES {
            Sniff::Garbage
        } else {
            Sniff::NeedMore
        };
    };
    let line = &rest[..line_end];
    if line.starts_with(b"SIP/2.0 ") || line.ends_with(b" SIP/2.0") {
        Sniff::Decided(StreamProtocol::Sip)
    } else if line.ends_with(b" HTTP/1.1") || line.ends_with(b" HTTP/1.0") {
        // Any HTTP request line, not just GET: tungstenite answers a non-GET
        // or a non-upgrade request with a proper HTTP error, which is a better
        // diagnostic for an operator who points a browser at the port than a
        // silent connection reset.
        Sniff::Decided(StreamProtocol::WebSocket)
    } else {
        Sniff::Garbage
    }
}

/// Read from `stream` until its protocol is known.
///
/// Returns the verdict plus every byte consumed while deciding, which the
/// caller must replay: seed it into [`serve_sip_stream`] for SIP, or wrap the
/// stream in [`PrefixedStream`] for WebSocket.
///
/// A peer that sends nothing within [`SNIFF_TIMEOUT`] is taken to be raw SIP
/// (a WebSocket client always sends its upgrade immediately), so a silent
/// connection held open for reuse is never dropped.
pub(crate) async fn sniff_stream<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> io::Result<(StreamProtocol, BytesMut)> {
    let mut buffer = BytesMut::with_capacity(1024);
    let mut read_buf = [0u8; 1024];
    let deadline = tokio::time::Instant::now() + SNIFF_TIMEOUT;

    loop {
        match sniff_first_line(&buffer) {
            Sniff::Decided(protocol) => return Ok((protocol, buffer)),
            Sniff::Garbage => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "neither SIP nor an HTTP upgrade",
                ))
            }
            Sniff::NeedMore => {}
        }
        match tokio::time::timeout_at(deadline, stream.read(&mut read_buf)).await {
            Ok(Ok(0)) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed before sending a first line",
                ))
            }
            Ok(Ok(size)) => buffer.extend_from_slice(&read_buf[..size]),
            Ok(Err(error)) => return Err(error),
            // Silent (or still mid-line) peer: assume raw SIP and let the SIP
            // read loop apply its own framing, garbage and idle rules.
            Err(_) => return Ok((StreamProtocol::Sip, buffer)),
        }
    }
}

/// What a raw-SIP-only listener should do with a freshly accepted connection.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SipOnlyVerdict {
    /// Speaks SIP. The bytes the decision consumed seed the framer.
    Serve(BytesMut),
    /// Not SIP, and the peer chose to send it: drop the connection and count a
    /// strong auto-ban signal. The string names the shape for the log.
    Abuse(&'static str),
    /// Ended before a first line arrived. Drop, but count nothing: an L4 health
    /// check (connect, then close, no data) is indistinguishable from this.
    Gone,
}

/// Classify a connection accepted on a listener that speaks only raw SIP.
///
/// A listener that is not half of a mux has no WebSocket side to hand an HTTP
/// request line to, so an upgrade line is as much "not SIP" here as random
/// bytes are — both are [`SipOnlyVerdict::Abuse`].
///
/// Framing alone never catches the HTTP case. A complete HTTP header block
/// satisfies [`extract_sip_message_length`] — it looks for `\r\n\r\n` and a
/// `Content-Length`, and an HTTP request has the first and defaults the second
/// to zero — so the probe frames as a "message", reaches the dispatcher, and is
/// rejected only by the parser, which has no connection to close and no source
/// to record. A vulnerability scanner walking `/phpinfo.php`, `/info.php`, …
/// over TLS on the SIP port could therefore probe indefinitely. Deciding here,
/// from the first line, closes the connection on the first probe and bans the
/// source on the fourth (weight 3 against the default threshold of 10).
pub(crate) async fn classify_sip_only<S: AsyncRead + Unpin>(stream: &mut S) -> SipOnlyVerdict {
    match sniff_stream(stream).await {
        Ok((StreamProtocol::Sip, prefix)) => SipOnlyVerdict::Serve(prefix),
        Ok((StreamProtocol::WebSocket, _)) => SipOnlyVerdict::Abuse("an HTTP request line"),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            SipOnlyVerdict::Abuse("non-SIP bytes")
        }
        Err(_) => SipOnlyVerdict::Gone,
    }
}

/// Run [`classify_sip_only`] and act on it: log, feed the auto-ban store, and
/// return the framer seed only when the connection may proceed.
///
/// `None` means the caller must stop. An abusive connection is dropped without
/// a reply — a SIP port that answers a probe fingerprints itself, which is why
/// every other drop on this path is silent too.
///
/// Cost is one classification per *connection*, on the first read the framer
/// would have made anyway. Nothing is added to the per-message path.
pub(crate) async fn sniff_sip_or_drop<S: AsyncRead + Unpin>(
    stream: &mut S,
    remote_addr: SocketAddr,
    transport: Transport,
) -> Option<BytesMut> {
    match classify_sip_only(stream).await {
        SipOnlyVerdict::Serve(prefix) => Some(prefix),
        SipOnlyVerdict::Abuse(shape) => {
            warn!("{shape} from {remote_addr} on the SIP-only {transport} listener; dropping connection");
            crate::security::record_malformed_message(remote_addr.ip(), &transport.to_string());
            None
        }
        SipOnlyVerdict::Gone => {
            debug!("{transport} connection from {remote_addr} ended before its first line");
            None
        }
    }
}

/// A stream with bytes already read from it pushed back in front.
///
/// Wraps the socket after [`sniff_stream`] so the WebSocket handshake sees the
/// `GET` line the sniff consumed. Reads drain the prefix first, then delegate;
/// writes always delegate.
pub(crate) struct PrefixedStream<S> {
    inner: S,
    prefix: BytesMut,
}

impl<S> PrefixedStream<S> {
    pub(crate) fn new(inner: S, prefix: BytesMut) -> Self {
        Self { inner, prefix }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.prefix.is_empty() {
            let take = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix.split_to(take));
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tcp::extract_sip_message_length;

    // --- pool fallback: protected source binding ---------------------------

    fn ensure_crypto_provider() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    }

    #[test]
    fn pool_tcp_source_binds_only_a_protected_same_family_source() {
        let protected: fn(u16) -> bool = |port| port == 5064;
        let destination: SocketAddr = "198.51.100.20:50002".parse().unwrap();
        // An IPsec SA's own port: the only source its selector matches.
        let pcscf_port_c: SocketAddr = "192.0.2.10:5064".parse().unwrap();
        assert_eq!(
            pool_tcp_source(Some(pcscf_port_c), destination, protected),
            Some(pcscf_port_c)
        );
        // Any other listener stays ephemeral, as the pool always bound it, so a
        // reconnect to a peer without TCP timestamps never lands on our
        // TIME_WAIT 4-tuple on the listen port.
        let plain: SocketAddr = "192.0.2.10:5060".parse().unwrap();
        assert_eq!(pool_tcp_source(Some(plain), destination, protected), None);
        // A v6 listener cannot be bound for a v4 connect.
        let v6: SocketAddr = "[2001:db8::10]:5064".parse().unwrap();
        assert_eq!(pool_tcp_source(Some(v6), destination, protected), None);
        assert_eq!(pool_tcp_source(None, destination, protected), None);
    }

    #[tokio::test]
    async fn tcp_pool_fallback_leaves_from_a_protected_source() {
        // What a closed flow leaves behind: a send with no live connection (the
        // default id) that names the protected port it has to leave from.
        ensure_crypto_provider();
        // Reserve a port to stand in for pcscf_port_c; SO_REUSEADDR lets the
        // pool rebind it once it is released.
        let reserve = tokio::net::TcpSocket::new_v4().unwrap();
        reserve.set_reuseaddr(true).unwrap();
        reserve.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let source = reserve.local_addr().unwrap();
        drop(reserve);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            // Hold the socket so the pool's reader sees no EOF mid-send.
            tokio::time::sleep(Duration::from_millis(50)).await;
            drop(socket);
            peer
        });

        let pool = Arc::new(ConnectionPool::new(
            Arc::new(DashMap::new()),
            flume::unbounded().0,
            "127.0.0.1:5060".parse().unwrap(),
            None,
            None,
            None,
            crate::transport::pool::build_outbound_tls_config(
                None,
                crate::config::TlsMethod::default(),
            )
            .expect("outbound tls config"),
        ));
        let (outbound_tx, outbound_rx) = flume::unbounded();
        spawn_outbound_distributor_with(
            outbound_rx,
            Arc::new(DashMap::new()),
            Transport::Tcp,
            Some(pool_fallback_send(pool, Transport::Tcp, |_| true)),
        );
        outbound_tx
            .send(OutboundMessage {
                connection_id: ConnectionId::default(),
                transport: Transport::Tcp,
                destination: server,
                data: Bytes::from_static(b"OPTIONS sip:ue.example.invalid SIP/2.0\r\n\r\n"),
                source_local_addr: Some(source),
                server_name: None,
                followups: None,
            })
            .unwrap();

        let peer = tokio::time::timeout(Duration::from_secs(2), accepted)
            .await
            .expect("the pool fallback must connect within 2 s")
            .unwrap();
        assert_eq!(
            peer, source,
            "the pool fallback must leave from the protected source, not an ephemeral port"
        );
    }

    /// A send with no live connection, bound for `destination`.
    fn fallback_message(destination: SocketAddr) -> OutboundMessage {
        OutboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Tcp,
            destination,
            data: Bytes::from_static(b"OPTIONS sip:ue.example.invalid SIP/2.0\r\n\r\n"),
            source_local_addr: None,
            server_name: None,
            followups: None,
        }
    }

    #[tokio::test]
    async fn a_hung_pool_fallback_does_not_stall_the_distributor() {
        // A UE that died with its SA still installed answers neither SYN nor
        // RST, so a fallback connect to it runs the full connect timeout.  The
        // registrar-liveness sweep sends exactly those.  It must hold up
        // neither a live connection's traffic nor a fallback send to anyone
        // else.
        let hung: SocketAddr = "198.51.100.1:5060".parse().unwrap();
        let other: SocketAddr = "198.51.100.2:5060".parse().unwrap();
        let (sent_tx, mut sent_rx) = mpsc::unbounded_channel::<SocketAddr>();
        let fallback: FallbackSend = Arc::new(move |outbound: OutboundMessage| {
            let sent_tx = sent_tx.clone();
            Box::pin(async move {
                if outbound.destination == hung {
                    std::future::pending::<()>().await;
                }
                let _ = sent_tx.send(outbound.destination);
            })
        });
        let connection_map = Arc::new(DashMap::new());
        let live = ConnectionId(42);
        let (live_tx, mut live_rx) = mpsc::channel::<Bytes>(4);
        connection_map.insert(live, live_tx);
        let (outbound_tx, outbound_rx) = flume::unbounded();
        spawn_outbound_distributor_with(
            outbound_rx,
            connection_map,
            Transport::Tcp,
            Some(fallback),
        );

        outbound_tx.send(fallback_message(hung)).unwrap();
        outbound_tx
            .send(OutboundMessage {
                connection_id: live,
                ..fallback_message(other)
            })
            .unwrap();
        outbound_tx.send(fallback_message(other)).unwrap();

        tokio::time::timeout(Duration::from_secs(2), live_rx.recv())
            .await
            .expect("a live connection's frame must not wait behind a hung fallback connect")
            .expect("the live frame is delivered");
        let reached = tokio::time::timeout(Duration::from_secs(2), sent_rx.recv())
            .await
            .expect("a fallback send to another destination must not wait behind a hung one");
        assert_eq!(reached, Some(other));
    }

    /// A fallback send that records each message's body, in the order sent.
    fn recording_send(
        delay_first: Option<Duration>,
    ) -> (FallbackSend, mpsc::UnboundedReceiver<(SocketAddr, Bytes)>) {
        let (sent_tx, sent_rx) = mpsc::unbounded_channel();
        let first = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let send: FallbackSend = Arc::new(move |outbound: OutboundMessage| {
            let sent_tx = sent_tx.clone();
            let is_first = first.swap(false, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if let (true, Some(delay)) = (is_first, delay_first) {
                    tokio::time::sleep(delay).await;
                }
                let _ = sent_tx.send((outbound.destination, outbound.data.clone()));
            })
        });
        (send, sent_rx)
    }

    fn message_with_body(destination: SocketAddr, body: &'static [u8]) -> OutboundMessage {
        OutboundMessage {
            data: Bytes::from_static(body),
            ..fallback_message(destination)
        }
    }

    #[tokio::test]
    async fn a_fallback_lane_keeps_one_destinations_messages_in_order() {
        // The first send is slow (a connect in flight); the second must still
        // go after it, since reordering, say, a 180 behind a 200 breaks the call.
        let destination: SocketAddr = "198.51.100.3:5060".parse().unwrap();
        let (send, mut sent_rx) = recording_send(Some(Duration::from_millis(200)));
        let mut lanes = FallbackLanes::new(send, Duration::from_millis(50));
        assert!(lanes.dispatch(message_with_body(destination, b"first")));
        assert!(lanes.dispatch(message_with_body(destination, b"second")));

        let mut order = Vec::new();
        for _ in 0..2 {
            let (_, body) = tokio::time::timeout(Duration::from_secs(2), sent_rx.recv())
                .await
                .expect("both sends complete")
                .expect("the recorder stays open");
            order.push(body);
        }
        assert_eq!(
            order,
            vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]
        );
    }

    #[tokio::test]
    async fn fallback_lanes_drain_to_empty_once_idle() {
        // Per-module leak gate: a lane exists per destination while it has work
        // and must be gone once that work is done, or the store grows by one
        // entry per peer the pool ever had to connect to.
        let (send, mut sent_rx) = recording_send(None);
        let mut lanes = FallbackLanes::new(send, Duration::from_millis(50));
        for batch in 0..2 {
            for index in 0..200u16 {
                let destination =
                    SocketAddr::new("198.51.100.10".parse().unwrap(), 5060 + index % 20);
                assert!(lanes.dispatch(fallback_message(destination)));
            }
            for _ in 0..200 {
                tokio::time::timeout(Duration::from_secs(2), sent_rx.recv())
                    .await
                    .expect("every send completes")
                    .expect("the recorder stays open");
            }
            let drained = tokio::time::timeout(Duration::from_secs(2), async {
                while lanes.len() != 0 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                drained.is_ok(),
                "batch {batch}: {} lane(s) still held after every send completed",
                lanes.len()
            );
        }
    }

    #[tokio::test]
    async fn a_full_fallback_lane_sheds_rather_than_grows() {
        // A dead peer keeps its lane busy on the first connect; everything
        // behind it queues, up to the same bound a live connection has, and
        // the next send is shed rather than held without limit.
        let destination: SocketAddr = "198.51.100.4:5060".parse().unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let send: FallbackSend = {
            let started = Arc::clone(&started);
            Arc::new(move |_outbound: OutboundMessage| {
                let started = Arc::clone(&started);
                Box::pin(async move {
                    started.notify_one();
                    std::future::pending::<()>().await;
                })
            })
        };
        let mut lanes = FallbackLanes::new(send, Duration::from_millis(50));
        assert!(lanes.dispatch(fallback_message(destination)));
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("the lane picks up its first send");
        for _ in 0..FALLBACK_LANE_CAPACITY {
            assert!(lanes.dispatch(fallback_message(destination)));
        }
        assert!(
            !lanes.dispatch(fallback_message(destination)),
            "a send past the lane's bound must be shed"
        );
    }

    const INVITE: &[u8] = concat!(
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
        "Via: SIP/2.0/TCP pc33.atlanta.com;branch=z9hG4bK776\r\n",
        "From: <sip:alice@atlanta.com>;tag=1928301774\r\n",
        "To: <sip:bob@biloxi.com>\r\n",
        "Call-ID: a84b4c76e66710\r\n",
        "CSeq: 314159 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
    .as_bytes();

    const UPGRADE: &[u8] = concat!(
        "GET / HTTP/1.1\r\n",
        "Host: proxy.example.com\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Protocol: sip\r\n",
        "\r\n",
    )
    .as_bytes();

    fn context() -> StreamContext {
        StreamContext {
            transport: Transport::Tcp,
            connection_id: ConnectionId(42),
            local_addr: "127.0.0.1:5060".parse().unwrap(),
            remote_addr: "127.0.0.1:41234".parse().unwrap(),
        }
    }

    // --- a peer that stops reading ------------------------------------------

    /// A write half that never completes a write — what a peer whose receive
    /// window has closed looks like from up here. Not an error, not a close:
    /// simply no progress, ever.
    struct NeverDrains;

    impl tokio::io::AsyncWrite for NeverDrains {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// A read half that never delivers anything, so the *write* half is the only
    /// thing that can end the connection.
    struct NeverSpeaks;

    impl tokio::io::AsyncRead for NeverSpeaks {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// An unbounded write to a peer that has stopped reading pins the writer
    /// task, the connection and its `connection_map` entry for the life of the
    /// process — the peer never errors and never closes, so nothing else ever
    /// ends it.
    ///
    /// Time is paused, so this asserts the *write* timeout fired: it completes
    /// long before `CONNECTION_IDLE_TIMEOUT` would have reaped the connection
    /// from the read side, which would otherwise let the test pass for the wrong
    /// reason.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stops_reading_is_disconnected_rather_than_pinned_forever() {
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        let (inbound_tx, _inbound_rx) = flume::unbounded();

        let served = tokio::spawn(serve_sip_stream(
            NeverSpeaks,
            NeverDrains,
            context(),
            BytesMut::new(),
            inbound_tx,
            Arc::clone(&connection_map),
            None,
            None,
            None,
        ));

        // Queue one response for the peer that will never read it.
        let sender = loop {
            if let Some(entry) = connection_map.get(&ConnectionId(42)) {
                break entry.clone();
            }
            tokio::task::yield_now().await;
        };
        sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .expect("the writer task is live");

        let started = tokio::time::Instant::now();
        tokio::time::timeout(CONNECTION_IDLE_TIMEOUT * 2, served)
            .await
            .expect(
                "serve_sip_stream never returned — an unbounded write to a peer \
                 that stopped reading pins the writer task, the connection and \
                 its connection_map entry for the life of the process",
            )
            .expect("the connection task did not panic");

        assert!(
            started.elapsed() < CONNECTION_IDLE_TIMEOUT,
            "the connection outlived the write timeout and was reaped by the \
             read-side idle timer instead — the write half is not bounded"
        );
        assert!(
            connection_map.is_empty(),
            "cleanup must drop the connection_map entry so nothing routes to a \
             connection that is gone"
        );
    }

    // --- sniff_first_line ---------------------------------------------------

    #[test]
    fn sniffs_sip_request_line() {
        assert_eq!(
            sniff_first_line(INVITE),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniffs_sip_status_line() {
        assert_eq!(
            sniff_first_line(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniffs_extension_method_as_sip() {
        // RFC 3261 §7.1 permits extension methods — the sniff keys on the
        // ` SIP/2.0` tail, never on a known-method list.
        assert_eq!(
            sniff_first_line(b"FROBNICATE sip:bob@biloxi.com SIP/2.0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniffs_websocket_upgrade() {
        assert_eq!(
            sniff_first_line(UPGRADE),
            Sniff::Decided(StreamProtocol::WebSocket)
        );
    }

    #[test]
    fn sniffs_http_1_0_request_line() {
        assert_eq!(
            sniff_first_line(b"GET /health HTTP/1.0\r\n\r\n"),
            Sniff::Decided(StreamProtocol::WebSocket)
        );
    }

    #[test]
    fn sniffs_sip_behind_leading_crlf_keepalives() {
        // RFC 5626 §4.4.1 ping before the first request must not confuse the
        // decision, and must stay in the buffer for the pong.
        let mut buffer = Vec::from(&b"\r\n\r\n"[..]);
        buffer.extend_from_slice(INVITE);
        assert_eq!(
            sniff_first_line(&buffer),
            Sniff::Decided(StreamProtocol::Sip)
        );
    }

    #[test]
    fn sniff_needs_more_on_partial_first_line() {
        assert_eq!(sniff_first_line(b""), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"\r\n"), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"INVITE sip:bob@bilo"), Sniff::NeedMore);
        assert_eq!(sniff_first_line(b"GET / HTT"), Sniff::NeedMore);
    }

    #[test]
    fn sniff_rejects_binary_probe() {
        // A TLS ClientHello arriving on a plaintext port.
        assert_eq!(
            sniff_first_line(&[0x16, 0x03, 0x01, 0x00, 0x9c]),
            Sniff::Garbage
        );
    }

    #[test]
    fn sniff_rejects_complete_non_sip_non_http_line() {
        assert_eq!(sniff_first_line(b"HELO example.com\r\n"), Sniff::Garbage);
    }

    #[test]
    fn sniff_rejects_overlong_first_line() {
        let flood = vec![b'A'; MAX_SNIFF_BYTES + 1];
        assert_eq!(sniff_first_line(&flood), Sniff::Garbage);
    }

    // --- sniff_stream -------------------------------------------------------

    #[tokio::test]
    async fn sniff_stream_returns_sip_and_consumed_prefix() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(INVITE).await.unwrap();
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::Sip);
        assert_eq!(
            &prefix[..],
            INVITE,
            "every consumed byte must be returned for replay"
        );
    }

    #[tokio::test]
    async fn sniff_stream_returns_websocket_and_consumed_prefix() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(UPGRADE).await.unwrap();
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::WebSocket);
        assert_eq!(&prefix[..], UPGRADE);
    }

    #[tokio::test]
    async fn sniff_stream_reassembles_a_split_first_line() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let sniff = tokio::spawn(async move { sniff_stream(&mut server).await.map(|(p, _)| p) });
        client.write_all(b"GET / HT").await.unwrap();
        client
            .write_all(b"TP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(sniff.await.unwrap().unwrap(), StreamProtocol::WebSocket);
    }

    #[tokio::test(start_paused = true)]
    async fn sniff_stream_defaults_to_sip_when_peer_stays_silent() {
        // RFC 5923 connection reuse: a peer may open a connection and wait for
        // siphon to send the first request. It must not be dropped.
        let (_client, mut server) = tokio::io::duplex(4096);
        let (protocol, prefix) = sniff_stream(&mut server).await.unwrap();
        assert_eq!(protocol, StreamProtocol::Sip);
        assert!(prefix.is_empty());
    }

    #[tokio::test]
    async fn sniff_stream_rejects_garbage() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\x16\x03\x01hello").await.unwrap();
        let error = sniff_stream(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn sniff_stream_reports_eof() {
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        let error = sniff_stream(&mut server).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    // --- PrefixedStream -----------------------------------------------------

    #[tokio::test]
    async fn prefixed_stream_replays_prefix_then_inner() {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"world").await.unwrap();
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"hello "[..]));
        let mut out = [0u8; 11];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello world");
    }

    #[tokio::test]
    async fn prefixed_stream_writes_pass_through() {
        let (mut client, server) = tokio::io::duplex(4096);
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"unread"[..]));
        stream.write_all(b"pong").await.unwrap();
        let mut out = [0u8; 4];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong");
    }

    #[tokio::test]
    async fn prefixed_stream_handles_short_reads_of_the_prefix() {
        let (_client, server) = tokio::io::duplex(4096);
        let mut stream = PrefixedStream::new(server, BytesMut::from(&b"abcdef"[..]));
        let mut out = [0u8; 2];
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"ab");
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"cd");
    }

    // --- serve_sip_stream ---------------------------------------------------

    #[tokio::test]
    async fn serve_frames_a_seeded_message_before_reading() {
        let (_client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::from(INVITE),
            inbound_tx,
            connection_map,
            None,
            None,
            None,
        ));
        let message = inbound_rx.recv_async().await.unwrap();
        assert_eq!(&message.data[..], INVITE);
        assert_eq!(message.transport, Transport::Tcp);
        assert_eq!(message.connection_id, ConnectionId(42));
    }

    #[tokio::test]
    async fn serve_frames_two_messages_coalesced_in_one_segment() {
        let (mut client, server) = tokio::io::duplex(8192);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map,
            None,
            None,
            None,
        ));
        let mut both = Vec::from(INVITE);
        both.extend_from_slice(INVITE);
        client.write_all(&both).await.unwrap();
        assert_eq!(&inbound_rx.recv_async().await.unwrap().data[..], INVITE);
        assert_eq!(&inbound_rx.recv_async().await.unwrap().data[..], INVITE);
    }

    #[tokio::test]
    async fn serve_registers_and_deregisters_the_flow_registry() {
        let (client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        let registry = StreamConnections::new();
        let context = StreamContext {
            transport: Transport::Tls,
            ..context()
        };
        let (close_tx, close_rx) = flume::unbounded();
        let served = tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context,
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            Some(registry.clone()),
            None,
            Some(close_tx),
        ));
        // Wait for registration to land, then close the peer.
        while registry.get(&context.remote_addr).is_none() {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            registry.get(&context.remote_addr),
            Some((Transport::Tls, ConnectionId(42)))
        );
        assert!(connection_map.contains_key(&ConnectionId(42)));

        drop(client);
        served.await.unwrap();
        assert!(
            registry.get(&context.remote_addr).is_none(),
            "flow must be unregistered on close"
        );
        assert!(!connection_map.contains_key(&ConnectionId(42)));
        // RFC 5626 §4.2.2 flow failure is reported to the registrar.
        assert_eq!(close_rx.recv_async().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn serve_writes_outbound_frames_to_the_peer() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());
        tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            None,
            None,
            None,
        ));
        let sender = loop {
            if let Some(entry) = connection_map.get(&ConnectionId(42)) {
                break entry.value().clone();
            }
            tokio::task::yield_now().await;
        };
        sender
            .send(Bytes::from_static(b"SIP/2.0 200 OK\r\n\r\n"))
            .await
            .unwrap();
        let mut out = vec![0u8; 18];
        client.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"SIP/2.0 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn serve_drops_the_connection_on_non_sip_bytes() {
        let (mut client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let (inbound_tx, _inbound_rx) = flume::unbounded();
        let connection_map = Arc::new(DashMap::new());
        let served = tokio::spawn(serve_sip_stream(
            reader,
            writer,
            context(),
            BytesMut::new(),
            inbound_tx,
            connection_map.clone(),
            None,
            None,
            None,
        ));
        client.write_all(b"HELO example.com\r\n").await.unwrap();
        served.await.unwrap();
        assert!(!connection_map.contains_key(&ConnectionId(42)));
    }

    // --- classify_sip_only (listeners that are not half of a mux) -----------

    /// The probe that motivated the classifier: a complete, well-formed HTTP
    /// request, as a vulnerability scanner sends it to a TLS SIP port.
    const HTTP_PROBE: &[u8] = concat!(
        "GET /phpinfo.php HTTP/1.1\r\n",
        "Host: proxy.example.com\r\n",
        "User-Agent: Mozilla/5.0\r\n",
        "\r\n",
    )
    .as_bytes();

    #[tokio::test]
    async fn classify_sip_only_serves_sip_and_keeps_the_consumed_prefix() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(INVITE).await.unwrap();
        match classify_sip_only(&mut server).await {
            SipOnlyVerdict::Serve(prefix) => assert_eq!(
                &prefix[..],
                INVITE,
                "consumed bytes must be handed back to seed the framer"
            ),
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn classify_sip_only_rejects_a_complete_http_probe() {
        // Why the classifier has to exist: framing alone reports this probe as
        // a complete message (an HTTP header block ends in \r\n\r\n and has no
        // Content-Length, so the length is the header block), which is how it
        // used to reach the parser with the connection still open and the
        // source never counted.
        assert_eq!(
            extract_sip_message_length(HTTP_PROBE),
            Some(HTTP_PROBE.len()),
            "precondition: framing cannot tell this from a SIP message"
        );

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(HTTP_PROBE).await.unwrap();
        assert_eq!(
            classify_sip_only(&mut server).await,
            SipOnlyVerdict::Abuse("an HTTP request line")
        );
    }

    #[tokio::test]
    async fn classify_sip_only_rejects_a_websocket_upgrade() {
        // Valid on a wss listener or a tls+wss mux, abuse on a SIP-only one:
        // there is no WebSocket half here to hand it to.
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(UPGRADE).await.unwrap();
        assert_eq!(
            classify_sip_only(&mut server).await,
            SipOnlyVerdict::Abuse("an HTTP request line")
        );
    }

    #[tokio::test]
    async fn classify_sip_only_rejects_binary_garbage() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(b"\x16\x03\x01\x00\x9c").await.unwrap();
        assert_eq!(
            classify_sip_only(&mut server).await,
            SipOnlyVerdict::Abuse("non-SIP bytes")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn classify_sip_only_keeps_a_silent_peer() {
        // RFC 5923 connection reuse: a peer may open a connection and wait for
        // siphon to send the first request. Never mistaken for a probe.
        let (_client, mut server) = tokio::io::duplex(4096);
        assert_eq!(
            classify_sip_only(&mut server).await,
            SipOnlyVerdict::Serve(BytesMut::new())
        );
    }

    #[tokio::test]
    async fn classify_sip_only_does_not_count_a_connect_and_close() {
        // An L4 health check (an AWS NLB target check, say) connects and closes
        // without sending anything. Dropped, but never an auto-ban signal —
        // banning it would take siphon out of its own load balancer.
        let (client, mut server) = tokio::io::duplex(4096);
        drop(client);
        assert_eq!(classify_sip_only(&mut server).await, SipOnlyVerdict::Gone);
    }

    #[tokio::test]
    async fn sniff_sip_or_drop_returns_a_seed_only_for_sip() {
        let scanner = "203.0.113.9:41000".parse().unwrap();

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(INVITE).await.unwrap();
        let seed = sniff_sip_or_drop(&mut server, scanner, Transport::Tls)
            .await
            .expect("SIP must be served");
        assert_eq!(&seed[..], INVITE);

        let (mut client, mut server) = tokio::io::duplex(4096);
        client.write_all(HTTP_PROBE).await.unwrap();
        assert!(
            sniff_sip_or_drop(&mut server, scanner, Transport::Tls)
                .await
                .is_none(),
            "an HTTP probe must not reach the framer"
        );
    }
}
