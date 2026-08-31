//! UDP transport with SO_REUSEPORT — one socket per CPU worker for parallel recv.
//!
//! Each worker:
//!   1. Receives a datagram (heap-allocated Bytes, not a fixed stack buffer)
//!   2. Sends an InboundMessage to the core via `inbound_tx`
//!   3. Checks `outbound_rx` for any pending replies and sends them
//!
//! Connection IDs for UDP are derived by hashing (local_addr, remote_addr) so
//! that responses can always be routed back to the right socket.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use socket2::SockAddr;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport};
use crate::transport::acl::TransportAcl;

/// Spawn `num_cpus::get()` UDP listener workers, all sharing the same port
/// via SO_REUSEPORT. Each worker sends inbound messages to `inbound_tx` and
/// drains `outbound_rx` to send replies.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    acl: Arc<TransportAcl>,
    tos: Option<u32>,
    recv_buffer_bytes: usize,
) {
    let worker_count = num_cpus::get();
    info!("Starting {} UDP workers on {}", worker_count, local_addr);

    for worker_index in 0..worker_count {
        let inbound_tx = inbound_tx.clone();
        let outbound_rx = outbound_rx.clone();
        let acl = Arc::clone(&acl);

        tokio::spawn(async move {
            let socket = match create_reusable_udp_socket(local_addr, tos, recv_buffer_bytes) {
                Ok(socket) => Arc::new(socket),
                Err(error) => {
                    error!("[udp-worker-{}] failed to create socket: {}", worker_index, error);
                    return;
                }
            };

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
                            Ok(outbound) => {
                                let dest = SockAddr::from(outbound.destination);
                                let Some(dest_addr) = dest.as_socket() else {
                                    warn!("[udp-worker-{}] invalid destination: {}", worker_index, outbound.destination);
                                    continue;
                                };
                                // Every frame of this message goes out from THIS
                                // worker's socket, in order, before the worker
                                // takes another message off the shared channel.
                                // That is the only ordering guarantee available
                                // on UDP here: workers share the receiver
                                // MPMC-style, so two separately-enqueued
                                // messages can leave from two sockets in either
                                // order (see `OutboundMessage::followups`).
                                for frame in outbound.frames() {
                                    if let Err(e) = socket.send_to(frame, &dest_addr).await {
                                        warn!("[udp-worker-{}] send_to {} failed: {}", worker_index, outbound.destination, e);
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                // Outbound channel closed — clean shutdown
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Compute a stable ConnectionId for a UDP (local, remote) pair.
fn udp_connection_id(local: SocketAddr, remote: SocketAddr) -> ConnectionId {
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

/// Request `SO_RCVBUF` and report what the kernel actually granted.
///
/// Best-effort: a listener that cannot get the buffer it asked for is still a
/// working listener, so a failure here warns rather than aborting the bind.
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
        Err(error) => debug!("[udp {}] could not read back SO_RCVBUF: {}", local_addr, error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A listener asks the kernel for the configured `SO_RCVBUF` and gets at
    /// least that much. Linux reports back roughly double the request, so the
    /// assertion is "no less than asked", which is exactly the condition
    /// `apply_recv_buffer` warns about when `net.core.rmem_max` clamps it.
    ///
    /// Uses a modest size so the test passes under a conservative `rmem_max`.
    #[tokio::test]
    async fn listener_socket_honours_the_configured_recv_buffer() {
        const REQUESTED: usize = 256 * 1024;

        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");
        let socket = create_reusable_udp_socket(addr, None, REQUESTED)
            .expect("listener socket binds");

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
    /// it must not fail the bind and must not raise the buffer.
    #[tokio::test]
    async fn zero_recv_buffer_leaves_the_kernel_default() {
        let addr: SocketAddr = "127.0.0.1:0".parse().expect("addr parses");

        let defaulted = create_reusable_udp_socket(addr, None, 0).expect("binds with 0");
        let default_size = socket2::SockRef::from(&defaulted)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        let raised = create_reusable_udp_socket(addr, None, 4 * 1024 * 1024)
            .expect("binds with an explicit size");
        let raised_size = socket2::SockRef::from(&raised)
            .recv_buffer_size()
            .expect("SO_RCVBUF reads back");

        assert!(
            raised_size > default_size,
            "an explicit request ({raised_size} B) should exceed the untouched default \
             ({default_size} B)"
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
        assert_ne!(udp_connection_id(local, remote1), udp_connection_id(local, remote2));
    }

    #[test]
    fn udp_connection_id_differs_for_different_ports() {
        let local: SocketAddr = "127.0.0.1:5060".parse().unwrap();
        let remote1: SocketAddr = "192.168.1.100:50123".parse().unwrap();
        let remote2: SocketAddr = "192.168.1.100:50124".parse().unwrap();
        assert_ne!(udp_connection_id(local, remote1), udp_connection_id(local, remote2));
    }

    /// Frames of one `OutboundMessage` must reach the peer in the order they
    /// were queued, however many workers are draining the shared channel.
    ///
    /// This is the regression guard for the REFER `202`/`NOTIFY` inversion:
    /// every worker clones the same outbound receiver and owns its own
    /// `SO_REUSEPORT` socket, so two *separately enqueued* messages race and can
    /// land inverted (RFC 3515 §2.4.4 requires the 202 first). Grouping them
    /// into one message pins them to a single worker, which sends them in
    /// sequence.
    ///
    /// The guarantee is per-group ordering, NOT adjacency on the wire: another
    /// worker may be sending a different group concurrently, so groups legitimately
    /// interleave with each other. Many groups are driven through so a within-group
    /// inversion has room to show up rather than passing by luck on one attempt.
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
        peer.bind(&SockAddr::from("127.0.0.1:0".parse::<SocketAddr>().unwrap()))
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
        let (outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();

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
            outbound_tx
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
}
