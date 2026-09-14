//! UDP transport with SO_REUSEPORT — one socket per CPU worker for parallel recv.
//!
//! Each worker:
//!   1. Receives a datagram (heap-allocated Bytes, not a fixed stack buffer)
//!   2. Sends an InboundMessage to the core via `inbound_tx`
//!   3. Sends what its own outbound channel carries — [`UdpOutbound`] routes
//!      every destination to one worker, so a peer's messages leave in the order
//!      they were enqueued
//!
//! Connection IDs for UDP are derived by hashing (local_addr, remote_addr) so
//! that responses can always be routed back to the right socket.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use bytes::BytesMut;
use socket2::SockAddr;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::transport::acl::TransportAcl;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport};

/// The outbound side of one UDP listener: one channel per worker, with every
/// destination always routed to the same one.
///
/// Each worker owns its own `SO_REUSEPORT` socket. Were they all to drain one
/// shared channel, two messages enqueued back to back for one peer would be
/// picked up by two workers and race to the wire: a BYE ahead of the ACK that
/// confirms its dialog, a 487 ahead of the 200 to its CANCEL, a 200 ahead of the
/// 183 before it. Routing by destination keeps each peer's traffic on one worker,
/// in the order it was enqueued, from every call site at once, while distinct
/// peers still spread across all the workers.
#[derive(Clone, Debug)]
pub struct UdpOutbound {
    shards: Arc<[flume::Sender<OutboundMessage>]>,
}

impl UdpOutbound {
    /// A listener's outbound channels, one per worker (at least one), and the
    /// receivers to hand to [`listen`].
    pub fn channels(workers: usize) -> (Self, Vec<flume::Receiver<OutboundMessage>>) {
        let (senders, receivers): (Vec<_>, Vec<_>) =
            (0..workers.max(1)).map(|_| flume::unbounded()).unzip();
        (
            Self {
                shards: senders.into(),
            },
            receivers,
        )
    }

    /// Enqueue `message` on the channel of the worker that owns its destination.
    // flume's `SendError<T>` hands the message back by design; see
    // `OutboundRouter::send`.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, message: OutboundMessage) -> Result<(), flume::SendError<OutboundMessage>> {
        let shard = shard_for(message.destination, self.shards.len());
        match self.shards.get(shard) {
            Some(sender) => sender.send(message),
            // `shard_for` stays below the channel count, and there is always at
            // least one channel, so this is never taken.
            None => Err(flume::SendError(message)),
        }
    }
}

impl From<flume::Sender<OutboundMessage>> for UdpOutbound {
    /// A single channel: one worker's worth, or a test reading what was sent.
    fn from(sender: flume::Sender<OutboundMessage>) -> Self {
        Self {
            shards: Arc::from([sender]),
        }
    }
}

/// Which of `shards` channels carries traffic to `destination`.
///
/// FNV-1a over the address and port, with the high half folded into the low
/// bits the modulo keeps: deterministic, so a peer always lands on the same
/// worker, and a few nanoseconds per datagram.
fn shard_for(destination: SocketAddr, shards: usize) -> usize {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    if shards <= 1 {
        return 0;
    }
    let mut hash = FNV_OFFSET_BASIS;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
    };
    match destination.ip() {
        IpAddr::V4(ip) => mix(&ip.octets()),
        IpAddr::V6(ip) => mix(&ip.octets()),
    }
    mix(&destination.port().to_be_bytes());
    let folded = hash ^ (hash >> 32);
    (folded % shards as u64) as usize
}

/// Spawn one UDP listener worker per channel in `outbound_rx`, all sharing the
/// same port via SO_REUSEPORT. Each worker sends inbound messages to
/// `inbound_tx` and sends what its own channel carries (see [`UdpOutbound`]).
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: Vec<flume::Receiver<OutboundMessage>>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    recv_buffer_bytes: usize,
) {
    let worker_count = outbound_rx.len();
    info!("Starting {} UDP workers on {}", worker_count, local_addr);

    let sockets: Vec<Option<Arc<UdpSocket>>> = (0..worker_count)
        .map(
            |worker_index| match create_reusable_udp_socket(local_addr, tos, recv_buffer_bytes) {
                Ok(socket) => Some(Arc::new(socket)),
                Err(error) => {
                    error!(
                        "[udp-worker-{}] failed to create socket: {}",
                        worker_index, error
                    );
                    None
                }
            },
        )
        .collect();
    let Some(fallback) = sockets.iter().flatten().next().cloned() else {
        error!(
            "[udp {}] no worker could open a socket — nothing is sent or received on this listener",
            local_addr
        );
        return;
    };

    for (worker_index, (socket, outbound_rx)) in sockets.into_iter().zip(outbound_rx).enumerate() {
        match socket {
            Some(socket) => {
                tokio::spawn(run_worker(
                    worker_index,
                    local_addr,
                    socket,
                    inbound_tx.clone(),
                    outbound_rx,
                    Arc::clone(&acl),
                ));
            }
            // The destinations routed to this channel stay routed to it, so a
            // worker with no socket must not leave it undrained: those messages
            // would queue for good. They leave another worker's socket instead,
            // still in the order they were enqueued.
            None => {
                tokio::spawn(drain_outbound(
                    worker_index,
                    Arc::clone(&fallback),
                    outbound_rx,
                ));
            }
        }
    }
}

/// One listener worker: receive on `socket`, and send what `outbound_rx` carries.
async fn run_worker(
    worker_index: usize,
    local_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    acl: Arc<TransportAcl>,
) {
    loop {
        // Use a reasonably large initial buffer; we'll grow it if needed.
        // SIP messages with SDP can exceed 1500 bytes easily.
        let mut buffer = BytesMut::zeroed(8192);

        tokio::select! {
            recv_result = socket.recv_from(&mut buffer) => {
                match recv_result {
                    Ok((size, remote_addr)) => {
                        if !acl.is_allowed(remote_addr.ip()) {
                            continue;
                        }
                        if size == buffer.len() {
                            // `recv_from` reports the bytes it copied, not the
                            // datagram's length, so a datagram that exactly fills
                            // the buffer is indistinguishable from one the kernel
                            // truncated. Say so rather than leaving an operator to
                            // work backwards from a parse error: RFC 3261 §18.1.1
                            // requires a UAC to move to a congestion-controlled
                            // transport well below this size, so either way the
                            // peer is doing something it should not. The message
                            // is still processed — a genuinely truncated one is
                            // refused by the parser's Content-Length check
                            // (RFC 4475 §3.1.2.2) rather than acted on.
                            warn!(
                                remote = %remote_addr,
                                bytes = size,
                                "UDP datagram filled the receive buffer — it may have been \
                                 truncated by the kernel; the peer should be using TCP \
                                 (RFC 3261 §18.1.1)"
                            );
                            if let Some(metrics) = crate::metrics::try_metrics() {
                                metrics.udp_datagrams_at_buffer_limit_total.inc();
                            }
                        }
                        buffer.truncate(size);
                        let data = buffer.freeze();

                        let connection_id = udp_connection_id(local_addr, remote_addr);

                        let message = InboundMessage {
                            connection_id,
                            transport: Transport::Udp,
                            local_addr,
                            remote_addr,
                            data,
                        };

                        if let Err(e) = inbound_tx.send_async(message).await {
                            error!("[udp-worker-{}] Failed to enqueue inbound message: {}", worker_index, e);
                        }
                    }
                    Err(e) => {
                        error!("[udp-worker-{}] recv_from error: {}", worker_index, e);
                    }
                }
            }

            outbound_result = outbound_rx.recv_async() => {
                match outbound_result {
                    Ok(outbound) => send_frames(worker_index, &socket, &outbound).await,
                    // Outbound channel closed — clean shutdown
                    Err(_) => break,
                }
            }
        }
    }
}

/// Send every frame of `outbound` from `socket`, in order, before the caller
/// takes anything else off its channel.
async fn send_frames(worker_index: usize, socket: &UdpSocket, outbound: &OutboundMessage) {
    let dest = SockAddr::from(outbound.destination);
    let Some(dest_addr) = dest.as_socket() else {
        warn!(
            "[udp-worker-{}] invalid destination: {}",
            worker_index, outbound.destination
        );
        return;
    };
    for frame in outbound.frames() {
        if let Err(e) = socket.send_to(frame, &dest_addr).await {
            warn!(
                "[udp-worker-{}] send_to {} failed: {}",
                worker_index, outbound.destination, e
            );
            break;
        }
    }
}

/// Drain the channel of a worker that could not open its socket, sending from a
/// working worker's socket instead.
async fn drain_outbound(
    worker_index: usize,
    socket: Arc<UdpSocket>,
    outbound_rx: flume::Receiver<OutboundMessage>,
) {
    while let Ok(outbound) = outbound_rx.recv_async().await {
        send_frames(worker_index, &socket, &outbound).await;
    }
}

/// Compute a stable ConnectionId for a UDP (local, remote) pair.
pub(crate) fn udp_connection_id(local: SocketAddr, remote: SocketAddr) -> ConnectionId {
    let mut hasher = DefaultHasher::new();
    local.hash(&mut hasher);
    remote.hash(&mut hasher);
    ConnectionId(hasher.finish())
}

fn create_reusable_udp_socket(
    local_addr: SocketAddr,
    tos: Option<u32>,
    recv_buffer_bytes: usize,
) -> std::io::Result<UdpSocket> {
    let socket = match local_addr {
        SocketAddr::V4(_) => socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ),
        SocketAddr::V6(_) => socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ),
    }?;

    socket.set_reuse_address(true)?;
    #[cfg(not(target_os = "windows"))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;

    // DSCP / DiffServ marking (RFC 4594) — family-aware, best-effort (a marking
    // failure must not stop the listener coming up).
    if let Some(tos) = tos {
        super::apply_tos(&socket2::SockRef::from(&socket), tos);
    }

    apply_recv_buffer(&socket, local_addr, recv_buffer_bytes);

    socket.bind(&SockAddr::from(local_addr))?;

    UdpSocket::from_std(socket.into())
}

/// Raise `SO_RCVBUF` to at least `requested` and report what the kernel granted.
///
/// The configured size is a **floor, not a target**: a host already tuned above
/// it keeps its larger buffer. Without that check the knob silently *shrinks*
/// the queue on a tuned host, because the two sides of the comparison are not
/// measured the same way — an untouched socket carries `net.core.rmem_default`
/// verbatim, while an explicit `setsockopt` is doubled by the kernel. Asking
/// for 1 MiB on a host defaulting to 4 MiB therefore lands at 2 MiB, and since
/// nothing was clamped the read-back warning below stays quiet, so the operator
/// has no way to notice the loss.
///
/// Best-effort throughout: a listener that cannot get the buffer it asked for
/// is still a working listener, so a failure here warns rather than aborting
/// the bind.
///
/// Linux returns roughly double the requested size from `getsockopt` (the extra
/// is bookkeeping overhead), so "at least what we asked for" is the honest
/// check — anything less means `net.core.rmem_max` clamped us, which is the
/// case worth telling an operator about, because the symptom otherwise is
/// silent datagram drops that look like peer retransmissions.
fn apply_recv_buffer(socket: &socket2::Socket, local_addr: SocketAddr, requested: usize) {
    if requested == 0 {
        return;
    }
    // Compare against the raw size the socket already carries. Deliberately
    // conservative about the kernel's doubling: this can decline to raise a
    // buffer that is already within 2x of the floor, but it can never lower
    // one, which is the failure worth avoiding.
    match socket.recv_buffer_size() {
        Ok(existing) if existing >= requested => {
            debug!(
                "[udp {}] leaving SO_RCVBUF at the kernel's {} bytes — already at or above the \
                 configured {} byte floor",
                local_addr, existing, requested
            );
            return;
        }
        Ok(_) => {}
        // Unreadable: fall through and ask anyway, which is what siphon did
        // before the floor existed.
        Err(error) => debug!(
            "[udp {}] could not read the current SO_RCVBUF ({}) — requesting {} bytes anyway",
            local_addr, error, requested
        ),
    }
    if let Err(error) = socket.set_recv_buffer_size(requested) {
        warn!(
            "[udp {}] could not set SO_RCVBUF to {} bytes: {} — continuing with the kernel default",
            local_addr, requested, error
        );
        return;
    }
    match socket.recv_buffer_size() {
        Ok(granted) if granted < requested => warn!(
            "[udp {}] SO_RCVBUF clamped to {} bytes (asked for {}) — raise net.core.rmem_max, \
             or inbound bursts will be dropped by the kernel and look like peer retransmissions",
            local_addr, granted, requested
        ),
        Ok(granted) => debug!("[udp {}] SO_RCVBUF granted {} bytes", local_addr, granted),
        Err(error) => debug!(
            "[udp {}] could not read back SO_RCVBUF: {}",
            local_addr, error
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A listener ends up with at least the configured floor, whether that
    /// took a `setsockopt` or the host already gave it that much.
    ///
    /// Linux reports back roughly double an explicit request, so "no less than
    /// asked" is the honest assertion, and it is exactly the condition
    /// `apply_recv_buffer` warns about when `net.core.rmem_max` clamps it.
    ///
    /// Uses a modest size so the test passes under a conservative `rmem_max`.
    #[tokio::test]
    async fn listener_socket_honours_the_configured_recv_buffer() {
        const REQUESTED: usize = 256 * 1024;

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");
        let socket =
            create_reusable_udp_socket(addr, None, REQUESTED).expect("listener socket binds");

        let granted = socket2::SockRef::from(&socket)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");
        assert!(
            granted >= REQUESTED,
            "kernel granted {granted} B for a {REQUESTED} B request — if this fails on a \
             developer box, net.core.rmem_max is set below the request"
        );
    }

    /// `0` is the documented "leave the kernel default alone" escape hatch, so
    /// it must not fail the bind and must leave the socket exactly where one
    /// siphon never touched sits.
    #[tokio::test]
    async fn zero_recv_buffer_leaves_the_kernel_default() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");

        let untouched = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("bare socket");
        let untouched_size = untouched.recv_buffer_size().expect("SO_RCVBUF reads back");

        let defaulted = create_reusable_udp_socket(addr, None, 0).expect("binds with 0");
        let default_size = socket2::SockRef::from(&defaulted)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        assert_eq!(
            default_size, untouched_size,
            "0 must leave SO_RCVBUF at the kernel default"
        );
    }

    /// A floor above what the host gives by default is a real lift.
    ///
    /// Derived from the observed default rather than hardcoded: `SO_RCVBUF` is
    /// clamped to `net.core.rmem_max` and then doubled, so on a host whose
    /// `net.core.rmem_default` is already large a fixed constant asserts
    /// nothing.
    #[tokio::test]
    async fn a_floor_above_the_kernel_default_raises_the_buffer() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");

        let defaulted = create_reusable_udp_socket(addr, None, 0).expect("binds with 0");
        let default_size = socket2::SockRef::from(&defaulted)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        let raised = create_reusable_udp_socket(addr, None, default_size * 2)
            .expect("binds with an explicit size");
        let raised_size = socket2::SockRef::from(&raised)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        assert!(
            raised_size > default_size,
            "a {} B floor on a host defaulting to {default_size} B should raise the buffer, \
             got {raised_size} B",
            default_size * 2
        );
    }

    /// Regression: the configured size is a floor, not a target — a host tuned
    /// above it keeps its larger buffer.
    ///
    /// siphon used to call `setsockopt` unconditionally. Because an untouched
    /// socket reports `net.core.rmem_default` raw while an explicit request
    /// comes back doubled, the 1 MiB default *halved* the receive queue on any
    /// host tuned above 512 KiB, and did it silently: nothing was clamped, so
    /// the read-back warning stayed quiet.
    #[tokio::test]
    async fn a_floor_below_the_kernel_default_does_not_shrink_the_buffer() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");

        let defaulted = create_reusable_udp_socket(addr, None, 0).expect("binds with 0");
        let default_size = socket2::SockRef::from(&defaulted)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        let floor = default_size / 4;
        let floored =
            create_reusable_udp_socket(addr, None, floor).expect("binds with a low floor");
        let floored_size = socket2::SockRef::from(&floored)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        assert_eq!(
            floored_size,
            default_size,
            "a {floor} B floor on a host already giving {default_size} B must leave the socket \
             alone; requesting it would have landed at about {} B",
            floor * 2
        );
    }

    use bytes::Bytes;

    #[test]
    fn udp_connection_id_is_deterministic() {
        let local: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let remote: SocketAddr = "192.168.1.100:50123".parse().unwrap();
        let id1 = udp_connection_id(local, remote);
        let id2 = udp_connection_id(local, remote);
        assert_eq!(id1, id2);
    }

    #[test]
    fn udp_connection_id_differs_for_different_remotes() {
        let local: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let remote1: SocketAddr = "192.168.1.100:50123".parse().unwrap();
        let remote2: SocketAddr = "192.168.1.101:50123".parse().unwrap();
        assert_ne!(
            udp_connection_id(local, remote1),
            udp_connection_id(local, remote2)
        );
    }

    #[test]
    fn udp_connection_id_differs_for_different_ports() {
        let local: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let remote1: SocketAddr = "192.168.1.100:50123".parse().unwrap();
        let remote2: SocketAddr = "192.168.1.100:50124".parse().unwrap();
        assert_ne!(
            udp_connection_id(local, remote1),
            udp_connection_id(local, remote2)
        );
    }

    /// Frames of one `OutboundMessage` must reach the peer in the order they
    /// were queued, however many workers the listener runs.
    ///
    /// This is the regression guard for the REFER `202`/`NOTIFY` inversion
    /// (RFC 3515 §2.4.4 requires the 202 first): a worker sends every frame of
    /// one message before it takes the next message off its channel. Separately
    /// enqueued messages to one peer are ordered too, by destination routing;
    /// see `separately_enqueued_messages_to_one_peer_keep_their_order`.
    ///
    /// Many groups are driven through so a within-group inversion has room to
    /// show up rather than passing by luck on one attempt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ordered_frames_are_not_reordered_across_workers() {
        const GROUPS: usize = 100;
        const FRAMES: usize = 3;

        // Generous receive buffer + a reader running before anything is sent:
        // the workers can burst faster than one recv loop drains, and a dropped
        // datagram here would look like a failure without being one.
        let peer = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        peer.set_recv_buffer_size(4 * 1024 * 1024).unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.bind(&SockAddr::from(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
        let peer = tokio::net::UdpSocket::from_std(peer.into()).unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let mut received = Vec::with_capacity(GROUPS * FRAMES);
            let mut buffer = [0u8; 2048];
            while received.len() < GROUPS * FRAMES {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    peer.recv_from(&mut buffer),
                )
                .await
                {
                    Ok(Ok((size, _))) => {
                        received.push(String::from_utf8_lossy(&buffer[..size]).to_string())
                    }
                    Ok(Err(error)) => panic!("recv failed: {error}"),
                    Err(_) => break,
                }
            }
            received
        });

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (inbound_tx, _inbound_rx) = flume::unbounded::<InboundMessage>();
        let (outbound, outbound_rx) = UdpOutbound::channels(8);

        listen(
            listen_addr,
            inbound_tx,
            outbound_rx,
            Arc::new(TransportAcl::new(vec![], vec![])),
            None,
            0,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        for group in 0..GROUPS {
            outbound
                .send(OutboundMessage {
                    connection_id: ConnectionId::default(),
                    transport: Transport::Udp,
                    destination: peer_addr,
                    data: Bytes::from(format!("{group}:0")),
                    source_local_addr: None,
                    server_name: None,
                    followups: Some(vec![
                        Bytes::from(format!("{group}:1")),
                        Bytes::from(format!("{group}:2")),
                    ]),
                })
                .unwrap();
        }

        let received = reader.await.unwrap();
        assert_eq!(
            received.len(),
            GROUPS * FRAMES,
            "expected every frame to arrive; got {}",
            received.len()
        );

        // Within each group, frame N must arrive before frame N+1.
        let mut next_expected = vec![0usize; GROUPS];
        for (arrival, payload) in received.iter().enumerate() {
            let (group, frame) = payload.split_once(':').expect("malformed payload");
            let group: usize = group.parse().expect("group id");
            let frame: usize = frame.parse().expect("frame id");
            assert_eq!(
                frame, next_expected[group],
                "group {group} frame {frame} arrived at position {arrival} but \
                 frame {} was still outstanding — frames of one message were reordered",
                next_expected[group]
            );
            next_expected[group] += 1;
        }
    }

    /// Messages enqueued separately to one peer reach it in the order they were
    /// enqueued, however many workers the listener runs.
    ///
    /// Two messages siphon sends back to back to one peer are often only right in
    /// that order: the ACK that confirms a dialog and the BYE that ends it, the
    /// 200 to a CANCEL and the 487 to its INVITE, a 183 and the 200 after it.
    /// Grouping a pair into one message (`OutboundMessage::followups`) covers
    /// only the call sites that remember to; this holds for all of them.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn separately_enqueued_messages_to_one_peer_keep_their_order() {
        const MESSAGES: usize = 400;

        let peer = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        peer.set_recv_buffer_size(4 * 1024 * 1024).unwrap();
        peer.set_nonblocking(true).unwrap();
        peer.bind(&SockAddr::from(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap();
        let peer = tokio::net::UdpSocket::from_std(peer.into()).unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let reader = tokio::spawn(async move {
            let mut received = Vec::with_capacity(MESSAGES);
            let mut buffer = [0u8; 64];
            while received.len() < MESSAGES {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    peer.recv_from(&mut buffer),
                )
                .await
                {
                    Ok(Ok((size, _))) => received.push(
                        String::from_utf8_lossy(&buffer[..size])
                            .parse::<usize>()
                            .expect("message index"),
                    ),
                    Ok(Err(error)) => panic!("recv failed: {error}"),
                    Err(_) => break,
                }
            }
            received
        });

        let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (inbound_tx, _inbound_rx) = flume::unbounded::<InboundMessage>();
        let (outbound, outbound_rx) = UdpOutbound::channels(8);

        listen(
            listen_addr,
            inbound_tx,
            outbound_rx,
            Arc::new(TransportAcl::new(vec![], vec![])),
            None,
            0,
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        for index in 0..MESSAGES {
            outbound
                .send(OutboundMessage {
                    connection_id: ConnectionId::default(),
                    transport: Transport::Udp,
                    destination: peer_addr,
                    data: Bytes::from(index.to_string()),
                    source_local_addr: None,
                    server_name: None,
                    followups: None,
                })
                .unwrap();
        }

        let received = reader.await.unwrap();
        assert_eq!(
            received.len(),
            MESSAGES,
            "expected every message to arrive; got {}",
            received.len()
        );
        if let Some(position) = received.windows(2).position(|pair| pair[0] > pair[1]) {
            panic!(
                "message {} arrived after message {} — separately enqueued messages to one \
                 peer were reordered",
                received[position + 1],
                received[position]
            );
        }
    }

    fn message_to(destination: SocketAddr) -> OutboundMessage {
        OutboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            destination,
            data: Bytes::from_static(b"OPTIONS"),
            source_local_addr: None,
            server_name: None,
            followups: None,
        }
    }

    /// A destination always maps to the same worker, so all its messages share
    /// one queue, while distinct peers still spread across the workers.
    #[test]
    fn a_destination_always_maps_to_one_worker_and_peers_spread() {
        let peer: SocketAddr = "198.51.100.7:5060".parse().unwrap();
        let first = shard_for(peer, 8);
        assert!(first < 8);
        for _ in 0..100 {
            assert_eq!(shard_for(peer, 8), first);
        }
        assert_eq!(shard_for(peer, 1), 0);
        assert_eq!(shard_for(peer, 0), 0);
        let v6: SocketAddr = "[2001:db8::1]:5060".parse().unwrap();
        assert!(shard_for(v6, 8) < 8);

        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let used: std::collections::HashSet<usize> = (0..64u16)
            .map(|offset| shard_for(SocketAddr::new(loopback, 5061 + offset), 8))
            .collect();
        assert!(
            used.len() >= 6,
            "64 peers landed on only {} of 8 workers",
            used.len()
        );
    }

    /// Sends go to the channel of the worker that owns the destination, and a
    /// single sender converts into a one-channel outbound.
    #[test]
    fn udp_outbound_sends_each_destination_down_its_own_channel() {
        let (outbound, receivers) = UdpOutbound::channels(4);
        assert_eq!(receivers.len(), 4);
        let peer: SocketAddr = "198.51.100.7:5060".parse().unwrap();
        for _ in 0..3 {
            outbound.send(message_to(peer)).unwrap();
        }
        assert_eq!(receivers[shard_for(peer, 4)].len(), 3);
        assert_eq!(receivers.iter().map(flume::Receiver::len).sum::<usize>(), 3);

        assert_eq!(UdpOutbound::channels(0).1.len(), 1);

        let (sender, receiver) = flume::unbounded();
        let single = UdpOutbound::from(sender);
        single.send(message_to(peer)).unwrap();
        assert_eq!(receiver.len(), 1);
    }

    /// The channel of a worker that could not open its socket is still drained,
    /// through another worker's socket.
    #[tokio::test]
    async fn an_orphaned_worker_channel_is_drained_through_another_socket() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (sender, receiver) = flume::unbounded();
        tokio::spawn(drain_outbound(3, socket, receiver));

        sender.send(message_to(peer_addr)).unwrap();

        let mut buffer = [0u8; 64];
        let (size, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer.recv_from(&mut buffer),
        )
        .await
        .expect("the orphaned channel was never drained")
        .unwrap();
        assert_eq!(&buffer[..size], b"OPTIONS");
    }
}
