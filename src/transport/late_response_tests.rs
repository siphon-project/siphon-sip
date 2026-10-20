//! A final response that comes later than the outbound pool's idle timeout
//! still reaches the node that sent the request.
//!
//! Two things have to hold for a request relayed over TCP whose answer is slow
//! (a callee that rings for longer than the idle timeout, or a downstream
//! node's own 408 at its transaction timeout):
//!
//! * the sender keeps the connection open while its client transaction is
//!   pending on it, since the response is owed there (RFC 3261 §18.2.2);
//! * a node that has to answer over a connection that is gone all the same
//!   opens one to the port in the sent-by of the Via, not to the source port
//!   the request came from (§18.2.2 again): that port was ephemeral and
//!   nothing listens on it.
//!
//! Both are driven with two nodes, each a real TCP listener, an outbound
//! distributor and a connection pool, exchanging real bytes; the second also
//! against the distributor alone. The idle timeout is the pool's own, set to
//! milliseconds.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::{Method, SipMessage};
use crate::sip::uri::SipUri;
use crate::transaction::state::IctEvent;
use crate::transaction::{ClientEvent, TransactionManager};
use crate::transport::acl::TransportAcl;
use crate::transport::pool::{build_outbound_tls_config, ConnectionPool};
use crate::transport::stream::spawn_outbound_distributor;
use crate::transport::{
    ConnectionId, InboundMessage, OutboundMessage, StreamConnections, Transport,
};

/// The pool's idle timeout in these tests, in place of its 30 s.
const IDLE: Duration = Duration::from_millis(40);

fn pool_with(
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    inbound_tx: flume::Sender<InboundMessage>,
) -> ConnectionPool {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let mut pool = ConnectionPool::new(
        connection_map,
        inbound_tx,
        "127.0.0.1:5060".parse().expect("a literal address"),
        None,
        None,
        None,
        build_outbound_tls_config(None, crate::config::TlsMethod::default())
            .expect("an outbound TLS config"),
    );
    pool.set_idle_timeout(IDLE);
    pool
}

/// One node: a TCP listener, its outbound distributor and its connection pool,
/// sharing one connection map and one inbound queue as a running server does.
struct Node {
    /// Where it listens: what it writes in the sent-by of its Via.
    addr: SocketAddr,
    inbound: flume::Receiver<InboundMessage>,
    outbound: flume::Sender<OutboundMessage>,
    pool: Arc<ConnectionPool>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
}

async fn node() -> Node {
    let (inbound_tx, inbound) = flume::unbounded();
    let (outbound, outbound_rx) = flume::unbounded();
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let pool = Arc::new(pool_with(Arc::clone(&connection_map), inbound_tx.clone()));
    let addr = crate::transport::tcp::listen(
        "127.0.0.1:0".parse().expect("a literal address"),
        inbound_tx,
        outbound_rx,
        Arc::clone(&connection_map),
        Arc::new(TransportAcl::new(vec![], vec![])),
        StreamConnections::new(),
        None,
        Some(Arc::clone(&pool)),
        None,
        None,
        None,
    )
    .await
    .expect("the TCP listener binds");
    Node {
        addr,
        inbound,
        outbound,
        pool,
        connection_map,
    }
}

impl Node {
    async fn next_inbound(&self, what: &str) -> InboundMessage {
        tokio::time::timeout(Duration::from_secs(5), self.inbound.recv_async())
            .await
            .unwrap_or_else(|_| panic!("{what}"))
            .expect("the inbound queue is open")
    }

    /// Answer `request` the way the dispatcher does: on the connection it
    /// arrived on, addressed to where it came from.
    fn answer(&self, request: &InboundMessage, response: &SipMessage) {
        self.outbound
            .send(OutboundMessage {
                connection_id: request.connection_id,
                transport: Transport::Tcp,
                destination: request.remote_addr,
                data: Bytes::from(response.to_bytes()),
                source_local_addr: Some(request.local_addr),
                server_name: None,
                verify_server: None,
                followups: None,
            })
            .expect("the outbound queue is open");
    }
}

/// An INVITE as the node listening on `sender` relays it: its own Via on top,
/// naming the port it listens on.
fn invite(sender: SocketAddr, branch: &str) -> SipMessage {
    SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("example.org".to_string()).with_user("callee".to_string()),
        )
        .via(format!("SIP/2.0/TCP {sender};branch={branch}"))
        .to("<sip:callee@example.org>".to_string())
        .from("<sip:caller@example.org>;tag=caller-tag".to_string())
        .call_id(format!("{branch}@example.org"))
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .expect("the INVITE builds")
}

/// A final response to an INVITE whose top Via is `via`.
fn response_with_via(status_code: u16, reason: &str, via: &str, branch: &str) -> SipMessage {
    SipMessageBuilder::new()
        .response(status_code, reason.to_string())
        .via(via.to_string())
        .to("<sip:callee@example.org>;tag=callee-tag".to_string())
        .from("<sip:caller@example.org>;tag=caller-tag".to_string())
        .call_id(format!("{branch}@example.org"))
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .expect("the response builds")
}

fn response(status_code: u16, reason: &str, sender: SocketAddr, branch: &str) -> SipMessage {
    response_with_via(
        status_code,
        reason,
        &format!("SIP/2.0/TCP {sender};branch={branch}"),
        branch,
    )
}

/// Let one whole idle period of `pool` go by, witnessed rather than slept: a
/// connection with nothing pending is opened and waited on until the pool has
/// closed it for idleness.
async fn one_idle_period(pool: &ConnectionPool) {
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener binds");
    let destination = silent.local_addr().expect("a bound address");
    pool.send_tcp(destination, Bytes::from_static(b"\r\n\r\n"))
        .await
        .expect("the control connection opens");
    let (_peer, _) = silent.accept().await.expect("the control connection");
    until("the idle timeout never closed an idle connection", || {
        !pool.has_live(destination, Transport::Tcp)
    })
    .await;
}

async fn until(what: &str, condition: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what}"));
}

// ---------------------------------------------------------------------------
// Two nodes: the sender keeps the connection while its transaction is pending
// ---------------------------------------------------------------------------

/// `upstream` relays an INVITE to `downstream` over TCP and holds the
/// connection for its client transaction; `downstream` answers with
/// `status_code` several idle periods later. The answer comes back on the
/// connection the INVITE went out on.
async fn a_late_final_response_arrives_on_the_connection_of_its_request(
    status_code: u16,
    reason: &str,
) {
    let upstream = node().await;
    let downstream = node().await;
    let transactions = TransactionManager::default();
    let branch = format!("z9hG4bK-held-{status_code}");

    let relayed = invite(upstream.addr, &branch);
    let wire = Bytes::from(relayed.to_bytes());
    let (key, _) = transactions
        .new_client_transaction(
            &relayed,
            wire.clone(),
            crate::transaction::state::Transport::Reliable,
        )
        .expect("the client transaction starts");
    let connection_id = upstream
        .pool
        .send_tcp(downstream.addr, wire.clone())
        .await
        .expect("the INVITE is sent");
    transactions.hold_client_connection(&key, upstream.pool.hold(connection_id));

    let arrived = downstream
        .next_inbound("the INVITE never reached the downstream node")
        .await;
    assert_eq!(arrived.data, wire);
    assert_ne!(
        arrived.remote_addr.port(),
        upstream.addr.port(),
        "precondition: the INVITE came from an ephemeral port, not the listening one"
    );

    // The callee rings (or the downstream transaction runs to its timeout).
    for _ in 0..3 {
        one_idle_period(&upstream.pool).await;
    }
    assert!(
        upstream.pool.has_live(downstream.addr, Transport::Tcp),
        "the connection of a pending INVITE was closed for idleness"
    );

    let final_response = response(status_code, reason, upstream.addr, &branch);
    downstream.answer(&arrived, &final_response);

    let answered = upstream
        .next_inbound("the final response never reached the node that sent the INVITE")
        .await;
    assert_eq!(answered.data, Bytes::from(final_response.to_bytes()));
    assert_eq!(
        answered.connection_id, connection_id,
        "the response did not come back on the connection the INVITE went out on"
    );

    // The transaction ends, and the connection is free to idle out again.
    let event = if status_code < 300 {
        IctEvent::Response2xx(final_response)
    } else {
        IctEvent::ResponseNon2xx(final_response)
    };
    transactions
        .process_client_event(&key, ClientEvent::Ict(event))
        .expect("the final response is taken");
    if transactions.contains(&key) {
        transactions
            .process_client_event(&key, ClientEvent::Ict(IctEvent::TimerD))
            .expect("Timer D is taken");
    }
    assert!(!upstream.pool.is_held(connection_id));
    until(
        "the connection was never closed once its transaction had ended",
        || !upstream.pool.has_live(downstream.addr, Transport::Tcp),
    )
    .await;
}

#[tokio::test]
async fn a_call_answered_after_the_idle_timeout_is_delivered() {
    a_late_final_response_arrives_on_the_connection_of_its_request(200, "OK").await;
}

#[tokio::test]
async fn a_downstream_timeout_after_the_idle_timeout_is_delivered() {
    a_late_final_response_arrives_on_the_connection_of_its_request(408, "Request Timeout").await;
}

// ---------------------------------------------------------------------------
// Two nodes: the connection is gone, the response is sent to the sent-by port
// ---------------------------------------------------------------------------

/// The sender holds nothing, as a peer that closes idle connections regardless
/// does, so the connection the INVITE came on is closed by the time
/// `downstream` answers. The answer still arrives: on a new connection to the
/// port `upstream` listens on.
async fn a_response_whose_connection_is_gone_is_sent_to_the_sent_by_port(
    status_code: u16,
    reason: &str,
) {
    let upstream = node().await;
    let downstream = node().await;
    let branch = format!("z9hG4bK-gone-{status_code}");

    let relayed = invite(upstream.addr, &branch);
    let connection_id = upstream
        .pool
        .send_tcp(downstream.addr, Bytes::from(relayed.to_bytes()))
        .await
        .expect("the INVITE is sent");
    let arrived = downstream
        .next_inbound("the INVITE never reached the downstream node")
        .await;

    until("the sender never closed its idle connection", || {
        !upstream.pool.has_live(downstream.addr, Transport::Tcp)
    })
    .await;
    until("the downstream node never saw the connection close", || {
        !downstream
            .connection_map
            .contains_key(&arrived.connection_id)
    })
    .await;

    let final_response = response(status_code, reason, upstream.addr, &branch);
    downstream.answer(&arrived, &final_response);

    let answered = upstream
        .next_inbound("a response whose connection had closed was never delivered")
        .await;
    assert_eq!(answered.data, Bytes::from(final_response.to_bytes()));
    assert_eq!(
        answered.local_addr, upstream.addr,
        "the response did not arrive on the port named in the sent-by"
    );
    assert_ne!(answered.connection_id, connection_id);
    assert!(
        downstream.pool.has_live(upstream.addr, Transport::Tcp),
        "the downstream node holds no connection to the sent-by port"
    );
    assert!(
        !downstream
            .pool
            .has_live(arrived.remote_addr, Transport::Tcp),
        "the downstream node connected to the source port of the request"
    );
}

#[tokio::test]
async fn a_late_answer_reaches_a_sender_that_closed_its_connection() {
    a_response_whose_connection_is_gone_is_sent_to_the_sent_by_port(200, "OK").await;
}

#[tokio::test]
async fn a_late_timeout_reaches_a_sender_that_closed_its_connection() {
    a_response_whose_connection_is_gone_is_sent_to_the_sent_by_port(408, "Request Timeout").await;
}

// ---------------------------------------------------------------------------
// The distributor: where a message with no live connection is sent
// ---------------------------------------------------------------------------

/// A distributor with a pool behind it and no connection of its own, plus two
/// listeners: `sent_by`, the port a peer names in its Via, and `source`,
/// standing for the port the request came from. `source` accepts connections
/// here, which is what makes a wrong connect visible: on a real peer that port
/// is closed and the connect is refused.
struct Fallback {
    outbound: flume::Sender<OutboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>>,
    sent_by: tokio::net::TcpListener,
    source: tokio::net::TcpListener,
}

async fn fallback() -> Fallback {
    let connection_map: Arc<DashMap<ConnectionId, mpsc::Sender<Bytes>>> = Arc::new(DashMap::new());
    let pool = Arc::new(pool_with(Arc::new(DashMap::new()), flume::unbounded().0));
    let (outbound, outbound_rx) = flume::unbounded();
    spawn_outbound_distributor(
        outbound_rx,
        Arc::clone(&connection_map),
        Transport::Tcp,
        Some(pool),
    );
    Fallback {
        outbound,
        connection_map,
        sent_by: tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a listener binds"),
        source: tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a listener binds"),
    }
}

impl Fallback {
    fn sent_by_port(&self) -> u16 {
        self.sent_by.local_addr().expect("a bound address").port()
    }

    /// Send `data` on a connection that does not exist, addressed to the
    /// source port.
    fn send(&self, connection_id: ConnectionId, data: Vec<u8>) {
        self.outbound
            .send(OutboundMessage {
                connection_id,
                transport: Transport::Tcp,
                destination: self.source.local_addr().expect("a bound address"),
                data: Bytes::from(data),
                source_local_addr: None,
                server_name: None,
                verify_server: None,
                followups: None,
            })
            .expect("the outbound queue is open");
    }
}

/// The bytes the next connection to `listener` delivers, or `None` when
/// nothing connects within `wait`.
async fn delivered_to(
    listener: &tokio::net::TcpListener,
    expected: usize,
    wait: Duration,
) -> Option<Vec<u8>> {
    let (mut socket, _) = tokio::time::timeout(wait, listener.accept())
        .await
        .ok()?
        .expect("accept");
    let mut received = vec![0u8; expected];
    tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut received))
        .await
        .expect("the connection delivers the message")
        .expect("read");
    Some(received)
}

async fn assert_goes_to_the_sent_by_port(fallback: &Fallback, data: Vec<u8>) {
    let delivered = delivered_to(&fallback.sent_by, data.len(), Duration::from_secs(5)).await;
    assert_eq!(
        delivered.as_deref(),
        Some(data.as_slice()),
        "the response did not reach the port in the sent-by"
    );
    assert!(
        delivered_to(&fallback.source, 1, Duration::from_millis(200))
            .await
            .is_none(),
        "a connection was opened to the source port of the request"
    );
}

#[tokio::test]
async fn a_response_without_its_connection_goes_to_the_sent_by_port() {
    let fallback = fallback().await;
    let branch = "z9hG4bK-fallback-sent-by";
    let data = response_with_via(
        200,
        "OK",
        &format!(
            "SIP/2.0/TCP 127.0.0.1:{};branch={branch}",
            fallback.sent_by_port()
        ),
        branch,
    )
    .to_bytes();

    fallback.send(ConnectionId(4242), data.clone());
    assert_goes_to_the_sent_by_port(&fallback, data).await;
}

/// With `received` in the Via, and a sent-by host that is a name: the address
/// the request was received from, at the sent-by port.
#[tokio::test]
async fn a_response_with_received_goes_to_that_address_at_the_sent_by_port() {
    let fallback = fallback().await;
    let branch = "z9hG4bK-fallback-received";
    let data = response_with_via(
        408,
        "Request Timeout",
        &format!(
            "SIP/2.0/TCP proxy.example.org:{};branch={branch};received=127.0.0.1",
            fallback.sent_by_port()
        ),
        branch,
    )
    .to_bytes();

    fallback.send(ConnectionId(4242), data.clone());
    assert_goes_to_the_sent_by_port(&fallback, data).await;
}

/// `rport` carries the source port of the request. Over TCP it is not a port
/// to connect to, with a value or without.
#[tokio::test]
async fn a_response_with_rport_still_goes_to_the_sent_by_port() {
    let fallback = fallback().await;
    let branch = "z9hG4bK-fallback-rport";
    let source_port = fallback
        .source
        .local_addr()
        .expect("a bound address")
        .port();
    let data = response_with_via(
        200,
        "OK",
        &format!(
            "SIP/2.0/TCP 127.0.0.1:{};branch={branch};received=127.0.0.1;rport={source_port}",
            fallback.sent_by_port()
        ),
        branch,
    )
    .to_bytes();

    fallback.send(ConnectionId(4242), data.clone());
    assert_goes_to_the_sent_by_port(&fallback, data).await;
}

/// The mirror case: the connection is still in the map, but its writer has
/// ended (the peer closed it, or a write failed) and the entry has not been
/// removed yet. That is a connection that is gone, not a response to drop.
#[tokio::test]
async fn a_response_for_a_connection_that_just_closed_goes_to_the_sent_by_port() {
    let fallback = fallback().await;
    let branch = "z9hG4bK-fallback-closing";
    let closing = ConnectionId(4243);
    let (sender, receiver) = mpsc::channel::<Bytes>(1);
    drop(receiver);
    fallback.connection_map.insert(closing, sender);
    let data = response_with_via(
        200,
        "OK",
        &format!(
            "SIP/2.0/TCP 127.0.0.1:{};branch={branch}",
            fallback.sent_by_port()
        ),
        branch,
    )
    .to_bytes();

    fallback.send(closing, data.clone());
    assert_goes_to_the_sent_by_port(&fallback, data).await;
}

/// A request with no live connection goes where it was addressed: its
/// destination was resolved from its Request-URI or a Route, and its top Via
/// is this node's own.
#[tokio::test]
async fn a_request_without_a_connection_keeps_its_destination() {
    let fallback = fallback().await;
    let data = invite(
        "127.0.0.1:5060".parse().expect("a literal address"),
        "z9hG4bK-fallback-request",
    )
    .to_bytes();

    fallback.send(ConnectionId::default(), data.clone());
    let delivered = delivered_to(&fallback.source, data.len(), Duration::from_secs(5)).await;
    assert_eq!(delivered.as_deref(), Some(data.as_slice()));
}
