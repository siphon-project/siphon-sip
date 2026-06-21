//! SCTP transport — RFC 4168 (SIP over SCTP).
//!
//! Uses one-to-one style SCTP sockets via `tokio-sctp`. SCTP is
//! message-oriented — each `recvmsg` delivers one complete SIP message
//! without the TCP stream-reassembly problem.
//!
//! Linux only. Requires `libsctp-dev` (lksctp-tools) installed.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use tokio::sync::mpsc;
use tokio_sctp::{SctpListener, SendOptions};
use tracing::{debug, error, info, warn};

use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport, next_connection_id};
use crate::transport::acl::TransportAcl;

/// Spawn an SCTP listener.
pub async fn listen(
    local_addr: SocketAddr,
    inbound_tx: flume::Sender<InboundMessage>,
    outbound_rx: flume::Receiver<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    acl: Arc<TransportAcl>,
    _tos: Option<u32>,
) {
    // Spawn outbound dispatcher
    let connection_map_clone = connection_map.clone();
    tokio::spawn(async move {
        while let Ok(outbound) = outbound_rx.recv_async().await {
            if let Some(sender) = connection_map_clone.get(&outbound.connection_id) {
                // Non-blocking: NEVER park in `send().await` here (see tcp.rs for
                // the full rationale). Awaiting a send to a non-reading peer's full
                // bounded channel would park this single distributor while holding
                // the `connection_map` shard guard — stalling all outbound and
                // blocking accept's `insert` on the same shard. `try_send` sheds
                // for a backed-up (stuck) peer instead.
                match sender.try_send(outbound.data) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        warn!("SCTP outbound dropped: connection {:?} send buffer full (slow/stuck peer)", outbound.connection_id);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("SCTP outbound dropped: connection {:?} closed", outbound.connection_id);
                    }
                }
            } else {
                debug!("SCTP outbound: connection {:?} not found (may have closed)", outbound.connection_id);
            }
        }
    });

    // SctpListener::bind is synchronous
    let listener = match SctpListener::bind(local_addr) {
        Ok(listener) => listener,
        Err(error) => {
            error!("failed to bind SCTP listener on {local_addr}: {error}");
            return;
        }
    };
    info!("SCTP listener on {}", local_addr);

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sctp_stream, remote_addr)) => {
                    if !acl.is_allowed(remote_addr.ip()) {
                        continue;
                    }
                    let connection_id = next_connection_id();
                    let inbound_tx = inbound_tx.clone();
                    let connection_map = connection_map.clone();

                    info!("SCTP accepted {} as {:?}", remote_addr, connection_id);

                    tokio::spawn(async move {
                        let local = sctp_stream.local_addr().unwrap_or(local_addr);
                        let (mut reader, mut writer) = sctp_stream.into_split();

                        // Per-connection outbound channel
                        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Bytes>(64);
                        connection_map.insert(connection_id, outbound_tx);

                        // Read task — message-oriented: each recvmsg returns one SIP message
                        let inbound_tx_clone = inbound_tx.clone();
                        let read_task = tokio::spawn(async move {
                            loop {
                                let mut buffer = BytesMut::with_capacity(65536);
                                match reader.recvmsg_buf(&mut buffer).await {
                                    Ok((0, _, _)) => {
                                        info!("SCTP connection {:?} closed by peer", connection_id);
                                        break;
                                    }
                                    Ok((size, _recv_info, _flags)) => {
                                        let data = buffer.split_to(size).freeze();
                                        let message = InboundMessage {
                                            connection_id,
                                            transport: Transport::Sctp,
                                            local_addr: local,
                                            remote_addr,
                                            data,
                                        };
                                        if let Err(error) = inbound_tx_clone.send_async(message).await {
                                            error!("SCTP inbound enqueue failed: {}", error);
                                            break;
                                        }
                                    }
                                    Err(error) => {
                                        warn!("SCTP read error on {:?}: {}", connection_id, error);
                                        break;
                                    }
                                }
                            }
                        });

                        // Write task
                        let write_task = tokio::spawn(async move {
                            let options = SendOptions::default();
                            while let Some(data) = outbound_rx.recv().await {
                                if let Err(error) = writer.sendmsg(&data, None, &options).await {
                                    warn!("SCTP write error on {:?}: {}", connection_id, error);
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
                        info!("SCTP connection {:?} cleaned up", connection_id);
                    });
                }
                Err(error) => {
                    error!("SCTP accept error: {}", error);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio_sctp::SctpStream;

    fn test_acl() -> Arc<TransportAcl> {
        Arc::new(TransportAcl::new(vec![], vec![]))
    }

    /// Helper: find a free port by binding and releasing.
    fn free_port() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    #[tokio::test]
    async fn sctp_connection_lifecycle() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect as an SCTP client
        let client = SctpStream::connect(addr).await.expect("SCTP connect failed");

        // Send a SIP message
        let sip_message = concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/SCTP 10.0.0.1:5060;branch=z9hG4bK778\r\n",
            "From: <sip:alice@example.com>;tag=sctp123\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: test-sctp-lifecycle@example.com\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let options = SendOptions::default();
        client.sendmsg(sip_message.as_bytes(), None, &options).await.unwrap();

        // Receive the inbound message
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .expect("timed out waiting for inbound message")
        .expect("inbound channel closed");

        assert_eq!(message.transport, Transport::Sctp);
        let data_str = String::from_utf8_lossy(&message.data);
        assert!(data_str.contains("REGISTER"), "expected REGISTER in data: {}", data_str);
        assert!(connection_map.contains_key(&message.connection_id));
    }

    #[tokio::test]
    async fn sctp_connection_cleanup() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = SctpStream::connect(addr).await.expect("SCTP connect failed");
        let options = SendOptions::default();
        client.sendmsg(b"OPTIONS sip:test SIP/2.0\r\n\r\n", None, &options).await.unwrap();

        let message = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let connection_id = message.connection_id;
        assert!(connection_map.contains_key(&connection_id));

        // Drop the client
        drop(client);

        // Wait for cleanup
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        assert!(
            !connection_map.contains_key(&connection_id),
            "connection should have been cleaned up after client drop"
        );
    }

    #[tokio::test]
    async fn sctp_message_boundaries() {
        let addr = free_port();
        let (inbound_tx, inbound_rx) = flume::unbounded();
        let (_outbound_tx, outbound_rx) = flume::unbounded::<OutboundMessage>();
        let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> =
            Arc::new(DashMap::new());

        listen(addr, inbound_tx, outbound_rx, Arc::clone(&connection_map), test_acl(), None).await;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let client = SctpStream::connect(addr).await.expect("SCTP connect failed");
        let options = SendOptions::default();

        // Send two messages back-to-back
        let message1 = "REGISTER sip:a SIP/2.0\r\n\r\n";
        let message2 = "OPTIONS sip:b SIP/2.0\r\n\r\n";
        client.sendmsg(message1.as_bytes(), None, &options).await.unwrap();
        client.sendmsg(message2.as_bytes(), None, &options).await.unwrap();

        // Both should arrive as separate InboundMessages (not coalesced)
        let received1 = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let received2 = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            inbound_rx.recv_async(),
        )
        .await
        .unwrap()
        .unwrap();

        let data1 = String::from_utf8_lossy(&received1.data);
        let data2 = String::from_utf8_lossy(&received2.data);

        // Each message should be separate — not merged
        assert!(
            (data1.contains("REGISTER") && data2.contains("OPTIONS"))
                || (data1.contains("OPTIONS") && data2.contains("REGISTER")),
            "messages should arrive separately: msg1='{}', msg2='{}'",
            data1,
            data2,
        );
    }
}
