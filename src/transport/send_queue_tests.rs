//! Backpressure on the per-connection send queue of the stream transports.
//!
//! A burst bigger than a connection's queue used to be shed on a peer that was
//! reading normally: the bound was 64 messages, and the outbound distributor
//! fills it far faster than the writer task gets scheduled to drain it. These
//! tests drive a real TCP listener, its distributor and a raw peer socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::transport::acl::TransportAcl;
use crate::transport::send_queue::SendQueue;
use crate::transport::{
    ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport,
};

type ConnectionMap = Arc<DashMap<ConnectionId, SendQueue>>;

/// A TCP listener with its outbound distributor and no pool, so a message for
/// a connection that is gone goes nowhere rather than to a fresh connection.
struct Listener {
    addr: SocketAddr,
    inbound: flume::Receiver<InboundMessage>,
    outbound: flume::Sender<OutboundMessage>,
    connection_map: ConnectionMap,
}

async fn listener() -> Listener {
    let (inbound_tx, inbound) = flume::unbounded();
    let (outbound, outbound_rx) = flume::unbounded();
    let connection_map: ConnectionMap = Arc::new(DashMap::new());
    let addr = crate::transport::tcp::listen(
        "127.0.0.1:0".parse().expect("a literal address"),
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        Arc::new(TransportAcl::new(vec![], vec![])),
        StreamConnections::new(),
        None,
        None,
        None,
        None,
        None,
    )
    .await
    .expect("the TCP listener binds");
    Listener {
        addr,
        inbound,
        outbound,
        connection_map,
    }
}

/// One numbered SIP message, so the peer can check every one arrived in order.
fn numbered(sequence: usize) -> Bytes {
    Bytes::from(format!(
        "OPTIONS sip:peer@127.0.0.1 SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-{sequence}\r\n\
         CSeq: {sequence} OPTIONS\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

const HELLO: &[u8] = b"OPTIONS sip:node@127.0.0.1 SIP/2.0\r\n\
    Via: SIP/2.0/TCP 127.0.0.1:1;branch=z9hG4bK-hello\r\n\
    CSeq: 1 OPTIONS\r\n\
    Content-Length: 0\r\n\r\n";

impl Listener {
    /// Connect a peer and announce it with one message, returning the socket
    /// and the connection the listener filed it under.
    async fn connect(&self) -> (TcpStream, InboundMessage) {
        let mut peer = TcpStream::connect(self.addr)
            .await
            .expect("the peer connects");
        peer.write_all(HELLO).await.expect("the peer writes");
        let hello = tokio::time::timeout(Duration::from_secs(5), self.inbound.recv_async())
            .await
            .expect("the listener frames the peer's message")
            .expect("the inbound queue is open");
        (peer, hello)
    }

    fn send(&self, on: &InboundMessage, data: Bytes) {
        self.outbound
            .send(OutboundMessage {
                followups: None,
                connection_id: on.connection_id,
                transport: Transport::Tcp,
                destination: on.remote_addr,
                data,
                source_local_addr: None,
                server_name: None,
                verify_server: None,
            })
            .expect("the distributor is running");
    }
}

/// Read until `expected` bytes have arrived, or fail after `within`.
async fn read_exactly(peer: &mut TcpStream, expected: usize, within: Duration) -> Vec<u8> {
    let mut received = Vec::with_capacity(expected);
    let mut buffer = vec![0u8; 64 * 1024];
    let outcome = tokio::time::timeout(within, async {
        while received.len() < expected {
            let read = peer.read(&mut buffer).await.expect("the peer reads");
            assert_ne!(
                read,
                0,
                "the connection closed after {} bytes",
                received.len()
            );
            received.extend_from_slice(&buffer[..read]);
        }
    })
    .await;
    assert!(
        outcome.is_ok(),
        "only {} of {expected} bytes arrived: the rest were dropped",
        received.len()
    );
    received
}

/// The regression: a burst of more than 64 messages queued at once, to a peer
/// that reads normally, must arrive whole and in order.
///
/// Current-thread on purpose: the distributor routes the whole burst before
/// the connection's writer task is polled once, which is exactly what a busy
/// runtime does to it at a few hundred messages a second.
#[tokio::test]
async fn a_burst_larger_than_64_messages_reaches_a_reading_peer_in_order() {
    let node = listener().await;
    let (mut peer, hello) = node.connect().await;

    const BURST: usize = 500;
    let expected: Vec<u8> = (0..BURST).flat_map(|n| numbered(n).to_vec()).collect();
    for sequence in 0..BURST {
        node.send(&hello, numbered(sequence));
    }

    let received = read_exactly(&mut peer, expected.len(), Duration::from_secs(10)).await;
    assert!(
        received == expected,
        "every message must arrive once, in the order it was sent"
    );
}

/// A connection whose peer has stopped reading must not hold up any other:
/// the distributor never waits on one connection's queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_stops_reading_does_not_hold_up_another_connection() {
    let node = listener().await;
    let (_stuck_peer, stuck) = node.connect().await;
    let (mut live_peer, live) = node.connect().await;

    // Far more than the stuck peer's socket buffers hold, so its writer parks
    // and its queue fills up to the byte bound and past it.
    let filler = Bytes::from(vec![b'x'; 64 * 1024]);
    for _ in 0..256 {
        node.send(&stuck, filler.clone());
    }

    const BURST: usize = 200;
    let expected: Vec<u8> = (0..BURST).flat_map(|n| numbered(n).to_vec()).collect();
    for sequence in 0..BURST {
        node.send(&live, numbered(sequence));
    }
    let received = read_exactly(&mut live_peer, expected.len(), Duration::from_secs(2)).await;
    assert!(
        received == expected,
        "the live connection must keep flowing, in order, while the other is stuck"
    );
    assert!(
        node.connection_map.contains_key(&live.connection_id),
        "the live connection must stay up"
    );
}

/// A peer that stops reading altogether is closed once a write has made no
/// progress for the write timeout, and from then on its queue refuses at once:
/// nothing more is accepted for a connection that cannot carry it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_stops_reading_is_closed_and_its_queue_fails_fast() {
    let node = listener().await;
    let (_stuck_peer, stuck) = node.connect().await;
    let queue = node
        .connection_map
        .get(&stuck.connection_id)
        .map(|entry| entry.value().clone())
        .expect("the connection is registered");

    let filler = Bytes::from(vec![b'x'; 64 * 1024]);
    for _ in 0..256 {
        node.send(&stuck, filler.clone());
    }

    let within = crate::transport::send_queue::write_timeout() + Duration::from_secs(5);
    tokio::time::timeout(within, queue.closed())
        .await
        .expect("the writer must give up on a peer that never reads");
    tokio::time::timeout(Duration::from_secs(2), async {
        while node.connection_map.contains_key(&stuck.connection_id) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a stuck connection leaves the connection map");
    assert_eq!(
        queue.queued_bytes(),
        0,
        "what was still queued is discarded and released"
    );
    assert!(
        matches!(
            queue.try_send(Bytes::from_static(b"late")),
            Err(crate::transport::send_queue::TrySendError::Closed(_))
        ),
        "a send after the close fails at once"
    );
}
