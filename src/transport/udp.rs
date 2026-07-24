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
use tracing::{error, info, warn};

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
) {
    let worker_count = num_cpus::get();
    info!("Starting {} UDP workers on {}", worker_count, local_addr);

    for worker_index in 0..worker_count {
        let inbound_tx = inbound_tx.clone();
        let outbound_rx = outbound_rx.clone();
        let acl = Arc::clone(&acl);

        tokio::spawn(async move {
            let socket = match create_reusable_udp_socket(local_addr, tos) {
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
                                if let Err(e) = socket.send_to(&outbound.data, &dest_addr).await {
                                    warn!("[udp-worker-{}] send_to {} failed: {}", worker_index, outbound.destination, e);
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

fn create_reusable_udp_socket(local_addr: SocketAddr, tos: Option<u32>) -> std::io::Result<UdpSocket> {
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

    socket.bind(&SockAddr::from(local_addr))?;

    UdpSocket::from_std(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
