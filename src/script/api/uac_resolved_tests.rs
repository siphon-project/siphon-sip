//! A request siphon originates to a resolved next hop moves from UDP to TCP
//! when it is over `listen.mtu` (RFC 3261 §18.1.1), read off the egress
//! channels and off real loopback sockets.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::uac_resolved::ResolvedEgress;
use crate::dns::SipResolver;
use crate::gateway::tests::{test_uac_over_mtu, TestUac};
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_sip_message_bytes;
use crate::transport::mtu::{upgrade_metrics, OverMtuPath};
use crate::transport::pool::ConnectionPool;
use crate::transport::send_queue::SendQueue;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, Transport};
use crate::uac::UacResult;

/// A next hop on loopback: a UDP socket, and on the same port either a TCP
/// listener or a TCP socket that refuses.
pub(crate) struct Peer {
    pub(crate) addr: SocketAddr,
    pub(crate) udp: tokio::net::UdpSocket,
    tcp: Option<tokio::net::TcpListener>,
    _refusing: Option<socket2::Socket>,
}

impl Peer {
    /// A next hop that listens for TCP where it receives UDP (RFC 3261
    /// §18.2.1).
    pub(crate) async fn listening() -> Self {
        Self::bound(true).await
    }

    /// A next hop with no TCP listener: a connect to it is refused.
    pub(crate) async fn udp_only() -> Self {
        Self::bound(false).await
    }

    async fn bound(listening: bool) -> Self {
        for _ in 0..50 {
            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("a UDP port");
            let addr = udp.local_addr().expect("bound");
            let (tcp, refusing) = if listening {
                match tokio::net::TcpListener::bind(addr).await {
                    Ok(listener) => (Some(listener), None),
                    // The TCP port of that number is taken: another pair.
                    Err(_) => continue,
                }
            } else {
                // Bound and not listening: the kernel answers a SYN with a
                // reset, and nothing else can listen there meanwhile.
                let socket =
                    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                        .expect("a socket");
                if socket.bind(&addr.into()).is_err() {
                    continue;
                }
                (None, Some(socket))
            };
            // The port may be one another test saw refuse within the window.
            crate::dispatcher::forget_tcp_probe(addr);
            return Self {
                addr,
                udp,
                tcp,
                _refusing: refusing,
            };
        }
        panic!("no free UDP and TCP port pair on loopback");
    }

    pub(crate) async fn accept(&self) -> tokio::net::TcpStream {
        let listener = self.tcp.as_ref().expect("a listening next hop");
        tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a connection within 5 s")
            .expect("accepted")
            .0
    }

    /// The next connection that carries bytes: the reachability probe's own
    /// connection is closed with nothing on it, the request's is not.
    pub(crate) async fn accept_request(&self) -> tokio::net::TcpStream {
        loop {
            let stream = self.accept().await;
            let mut first = [0u8; 1];
            match tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut first)).await {
                Ok(Ok(read)) if read > 0 => return stream,
                _ => continue,
            }
        }
    }

    /// Whether a TCP connection reaches the next hop within a moment.
    pub(crate) async fn sees_connection(&self) -> bool {
        match &self.tcp {
            Some(listener) => tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_ok(),
            None => false,
        }
    }

    /// The next datagram the next hop receives.
    pub(crate) async fn datagram(&self) -> Vec<u8> {
        let mut buffer = vec![0u8; 65_535];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), self.udp.recv_from(&mut buffer))
                .await
                .expect("a datagram within 5 s")
                .expect("received");
        buffer.truncate(length);
        buffer
    }

    pub(crate) fn uri(&self) -> String {
        format!("sip:as@{}", self.addr)
    }
}

/// A UAC sender with `listen.mtu` set, its pool, and what the pool reads.
pub(crate) struct Node {
    pub(crate) uac: TestUac,
    pub(crate) resolver: Arc<SipResolver>,
    pub(crate) pool: Arc<ConnectionPool>,
    pub(crate) connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    pub(crate) inbound: flume::Receiver<InboundMessage>,
}

impl Node {
    /// A node whose egress stays on its channels, for a test that reads what
    /// was handed to each transport.
    pub(crate) fn new(mtu: u16) -> Self {
        let (inbound_tx, inbound) = flume::unbounded();
        let connection_map: Arc<DashMap<ConnectionId, SendQueue>> = Arc::new(DashMap::new());
        let pool = Arc::new(ConnectionPool::for_tests(
            Arc::clone(&connection_map),
            inbound_tx,
        ));
        Self {
            uac: test_uac_over_mtu(Some((Arc::clone(&pool), mtu))),
            resolver: Arc::new(SipResolver::from_system().expect("a system resolver")),
            pool,
            connection_map,
            inbound,
        }
    }

    /// A node whose egress reaches the wire: the TCP channel through the
    /// outbound distributor and the pool, as a running node's does, and the
    /// UDP channel through a socket.
    pub(crate) async fn on_the_wire(mtu: u16) -> Self {
        let node = Self::new(mtu);
        crate::transport::stream::spawn_outbound_distributor(
            node.uac.tcp.clone(),
            Arc::clone(&node.connection_map),
            Transport::Tcp,
            Some(Arc::clone(&node.pool)),
        );
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a UDP socket");
        let udp = node.uac.udp.clone();
        tokio::spawn(async move {
            while let Ok(outbound) = udp.recv_async().await {
                let _ = socket.send_to(&outbound.data, outbound.destination).await;
            }
        });
        node
    }

    /// What was handed to a transport next, and whether to TCP.
    pub(crate) async fn sent(&self) -> (bool, OutboundMessage) {
        tokio::select! {
            sent = self.uac.tcp.recv_async() => (true, sent.expect("open")),
            sent = self.uac.udp.recv_async() => (false, sent.expect("open")),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("nothing was sent"),
        }
    }
}

/// A MESSAGE as `proxy.send_request` builds one for UDP, with a `body` byte
/// body.
pub(crate) fn message(branch: &str, body: usize) -> SipMessage {
    let head = format!(
        concat!(
            "MESSAGE sip:001010000000001@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-uac-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:as@example.com>;tag=a1\r\n",
            "To: <sip:001010000000001@example.com>\r\n",
            "Call-ID: resolved-{branch}\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: {body}\r\n",
            "\r\n",
        ),
        branch = branch,
        body = body
    );
    let mut bytes = head.into_bytes();
    bytes.extend(vec![b'x'; body]);
    parse_sip_message_bytes(&bytes).expect("a message")
}

pub(crate) fn via_of(data: &[u8]) -> String {
    parse_sip_message_bytes(data)
        .expect("a message")
        .headers
        .get("Via")
        .cloned()
        .expect("a Via")
}

/// Read one SIP message off `stream`: its head and its Content-Length body.
async fn read_message(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                return buffer;
            }
        }
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("the request within 5 s")
            .expect("a read");
        assert!(read > 0, "the connection closed before the whole request");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

fn counted(path: OverMtuPath) -> u64 {
    upgrade_metrics::init_for_tests();
    upgrade_metrics::count(path)
}

/// RFC 3261 §18.1.1 with `listen.mtu: 1500`: a 1500-byte body is over the
/// threshold and goes over TCP with a TCP top Via; a 900-byte one stays UDP.
#[tokio::test]
async fn a_1500_byte_request_goes_tcp_and_a_900_byte_one_stays_udp() {
    let peer = Peer::listening().await;
    let node = Node::new(1500);
    let uri = peer.uri();
    let egress = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp);
    let before = counted(OverMtuPath::Script);

    let _receiver = egress
        .send(&node.uac.sender, &node.resolver, message("big", 1500))
        .await;
    let (over_tcp, sent) = node.sent().await;
    assert!(over_tcp, "over the threshold: TCP");
    assert_eq!(sent.transport, Transport::Tcp);
    assert_eq!(sent.destination, peer.addr, "the same address, over TCP");
    assert_eq!(sent.connection_id, ConnectionId::default());
    assert_eq!(
        via_of(&sent.data),
        "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-uac-big",
        "the top Via names the transport used, the branch is kept"
    );
    assert!(sent.data.len() > 1500, "the whole request");
    assert!(node.uac.udp.try_recv().is_err(), "and not over UDP as well");
    assert!(counted(OverMtuPath::Script) > before, "counted");

    let _receiver = egress
        .send(&node.uac.sender, &node.resolver, message("small", 900))
        .await;
    let (over_tcp, sent) = node.sent().await;
    assert!(!over_tcp, "under the threshold: UDP");
    assert_eq!(sent.destination, peer.addr);
    assert!(via_of(&sent.data).starts_with("SIP/2.0/UDP "));
}

/// The threshold is the relay's: exactly `mtu - 200` is not over, one byte
/// more is.
#[tokio::test]
async fn the_threshold_is_mtu_minus_200() {
    let peer = Peer::listening().await;
    let uri = peer.uri();
    let length = message("edge", 1500).to_bytes().len();
    let at = |len: usize| u16::try_from(len + 200).expect("an MTU");
    for (mtu, expect_tcp) in [(at(length), false), (at(length - 1), true)] {
        let node = Node::new(mtu);
        ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp)
            .send_and_forget(&node.uac.sender, &node.resolver, message("edge", 1500))
            .await;
        assert_eq!(
            node.sent().await.0,
            expect_tcp,
            "mtu {mtu}, length {length}"
        );
    }
}

/// A target URI that names `transport=udp` keeps UDP whatever the size, and
/// nothing is opened toward the next hop.
#[tokio::test]
async fn an_explicit_udp_transport_parameter_keeps_udp() {
    let peer = Peer::listening().await;
    let node = Node::new(1500);
    let uri = format!("sip:as@{};transport=udp", peer.addr);

    ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp)
        .send_and_forget(&node.uac.sender, &node.resolver, message("pinned", 1500))
        .await;

    let (over_tcp, sent) = node.sent().await;
    assert!(!over_tcp, "transport=udp is honoured");
    assert!(via_of(&sent.data).starts_with("SIP/2.0/UDP "));
    assert!(sent.data.len() > 1500, "the whole request");
    assert!(!peer.sees_connection().await, "no probe either");
}

/// A request already on a stream transport is not touched, and without
/// `listen.mtu` nothing switches.
#[tokio::test]
async fn a_stream_request_and_a_node_without_an_mtu_are_unchanged() {
    let peer = Peer::listening().await;
    let uri = peer.uri();

    let node = Node::new(1500);
    let mut big = message("tls", 1500);
    big.headers.set(
        "Via",
        "SIP/2.0/TLS 127.0.0.1:5061;branch=z9hG4bK-uac-tls".to_string(),
    );
    let routed = ResolvedEgress::resolved(&uri, peer.addr, Transport::Tls)
        .route(&node.uac.sender, &node.resolver, big)
        .await;
    assert_eq!(routed.transport, Transport::Tls);
    assert!(via_of(&routed.message.to_bytes()).starts_with("SIP/2.0/TLS "));

    let plain = test_uac_over_mtu(None);
    let routed = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp)
        .route(&plain.sender, &node.resolver, message("no-mtu", 1500))
        .await;
    assert_eq!(routed.transport, Transport::Udp);
    assert!(!peer.sees_connection().await, "nothing probed");
}

/// With no TCP listener at the next hop the request goes over UDP as it would
/// have (RFC 3261 §18.1.1), and later requests there do not probe again inside
/// the window.
#[tokio::test]
async fn a_next_hop_without_tcp_gets_the_request_over_udp() {
    let peer = Peer::udp_only().await;
    let node = Node::new(1500);
    let uri = peer.uri();
    let egress = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp);
    let before = counted(OverMtuPath::Script);

    for index in 0..3 {
        egress
            .send_and_forget(
                &node.uac.sender,
                &node.resolver,
                message(&format!("refused{index}"), 1500),
            )
            .await;
        let (over_tcp, sent) = node.sent().await;
        assert!(!over_tcp, "request {index}: the UDP fallback");
        assert!(via_of(&sent.data).starts_with("SIP/2.0/UDP "));
        assert!(sent.data.len() > 1500, "the whole request");
    }
    assert_eq!(counted(OverMtuPath::Script), before, "not counted as moved");
    crate::dispatcher::forget_tcp_probe(peer.addr);
}

/// In a dialog learned over UDP with no route set, the peer is probed at the
/// address it sent from, where it listens for TCP too (RFC 3261 §18.2.1): its
/// Contact need not resolve. A Contact that names `transport=udp` keeps UDP.
#[tokio::test]
async fn a_dialog_learned_over_udp_switches_at_the_address_it_was_learned_from() {
    let peer = Peer::listening().await;
    let node = Node::new(1500);

    ResolvedEgress::learned("sip:watcher@host.invalid", peer.addr, Transport::Udp)
        .send_and_forget(&node.uac.sender, &node.resolver, message("learned", 1500))
        .await;
    let (over_tcp, sent) = node.sent().await;
    assert!(over_tcp, "the learned address is probed, not the Contact");
    assert_eq!(sent.destination, peer.addr);

    ResolvedEgress::learned(
        "sip:watcher@host.invalid;transport=udp",
        peer.addr,
        Transport::Udp,
    )
    .send_and_forget(&node.uac.sender, &node.resolver, message("pinned", 1500))
    .await;
    assert!(!node.sent().await.0, "the Contact asked for UDP");
}

/// With a TCP listener of its own, the node names that listener in the Via of
/// a request it moves to TCP; a Via the script wrote keeps its sent-by.
#[tokio::test]
async fn the_via_names_the_nodes_tcp_listener_when_it_has_one() {
    let peer = Peer::listening().await;
    let pool = Arc::new(ConnectionPool::for_tests(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
    ));
    let (udp_tx, _udp) = flume::unbounded();
    let (tcp_tx, tcp) = flume::unbounded();
    let (other_tx, _other) = flume::unbounded();
    let router = Arc::new(crate::transport::OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: tcp_tx,
        tls: other_tx.clone(),
        ws: other_tx.clone(),
        wss: other_tx,
        sctp: None,
    });
    let listen: std::collections::HashMap<Transport, SocketAddr> = [
        (
            Transport::Udp,
            "127.0.0.1:5060".parse().expect("an address"),
        ),
        (
            Transport::Tcp,
            "127.0.0.1:5070".parse().expect("an address"),
        ),
    ]
    .into();
    let uac = crate::uac::UacSender::new(
        router,
        "127.0.0.1:5060".parse().expect("an address"),
        listen,
        std::collections::HashMap::new(),
        None,
        None,
        crate::config::IdentityHeaders::default().shared(),
    )
    .with_over_mtu(pool, Some(1500));
    let resolver = SipResolver::from_system().expect("a system resolver");
    let uri = peer.uri();
    let egress = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp);

    egress
        .send_and_forget(&uac, &resolver, message("listener", 1500))
        .await;
    let sent = tcp.try_recv().expect("over TCP");
    assert_eq!(
        via_of(&sent.data),
        "SIP/2.0/TCP 127.0.0.1:5070;branch=z9hG4bK-uac-listener"
    );

    let mut scripted = message("scripted", 1500);
    scripted.headers.set(
        "Via",
        "SIP/2.0/UDP edge.example.com:5080;branch=z9hG4bK-uac-scripted".to_string(),
    );
    egress.send_and_forget(&uac, &resolver, scripted).await;
    let sent = tcp.try_recv().expect("over TCP");
    assert_eq!(
        via_of(&sent.data),
        "SIP/2.0/TCP edge.example.com:5080;branch=z9hG4bK-uac-scripted"
    );
}

/// On the wire: a next hop listening for TCP receives the whole request over
/// one connection, and its response, sent back on that connection (RFC 3261
/// §18.2.2), resolves the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tcp_listener_at_the_next_hop_receives_the_whole_request() {
    let peer = Peer::listening().await;
    let node = Node::on_the_wire(1500).await;
    let uri = peer.uri();
    let request = message("wire", 1500);
    let expected_body = request.body.clone();

    let mut receiver = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp)
        .send(&node.uac.sender, &node.resolver, request)
        .await;

    let mut stream = peer.accept_request().await;
    let received = read_message(&mut stream).await;
    let parsed = parse_sip_message_bytes(&received).expect("the request parses");
    assert_eq!(
        parsed.method().map(|method| method.as_str()),
        Some("MESSAGE")
    );
    assert_eq!(parsed.body, expected_body, "the whole 1500-byte body");
    let via = parsed.headers.get("Via").cloned().expect("a Via");
    assert!(via.starts_with("SIP/2.0/TCP "), "{via}");

    let response = format!(
        concat!(
            "SIP/2.0 202 Accepted\r\n",
            "Via: {via}\r\n",
            "From: <sip:as@example.com>;tag=a1\r\n",
            "To: <sip:001010000000001@example.com>;tag=p1\r\n",
            "Call-ID: resolved-wire\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        via = via
    );
    stream
        .write_all(response.as_bytes())
        .await
        .expect("the answer is written");
    let inbound = tokio::time::timeout(Duration::from_secs(5), node.inbound.recv_async())
        .await
        .expect("the answer is read off the connection")
        .expect("open");
    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(inbound.remote_addr, peer.addr);
    let answer = parse_sip_message_bytes(&inbound.data).expect("a response");
    assert!(node.uac.sender.match_response(&answer));
    match tokio::time::timeout(Duration::from_secs(2), &mut receiver).await {
        Ok(Ok(UacResult::Response(response))) => assert_eq!(response.status_code(), Some(202)),
        other => panic!("no response delivered: {other:?}"),
    }
    // Nothing went over UDP.
    let mut buffer = [0u8; 16];
    let datagram =
        tokio::time::timeout(Duration::from_millis(200), peer.udp.recv_from(&mut buffer)).await;
    assert!(datagram.is_err(), "nothing over UDP");
}

/// On the wire: with no TCP listener at the next hop the whole request
/// arrives over UDP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_tcp_listener_the_request_arrives_over_udp() {
    let peer = Peer::udp_only().await;
    let node = Node::on_the_wire(1500).await;
    let uri = peer.uri();
    let request = message("fallback", 1500);
    let expected = request.to_bytes();

    ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp)
        .send_and_forget(&node.uac.sender, &node.resolver, request)
        .await;

    let datagram = peer.datagram().await;
    assert_eq!(datagram, expected, "the request as built for UDP, whole");
    assert!(via_of(&datagram).starts_with("SIP/2.0/UDP "));
    crate::dispatcher::forget_tcp_probe(peer.addr);
}

/// Leak gate: requests moved to TCP and answered, over and over, share one
/// pooled connection and leave no pending entry; once the next hop closes,
/// the pool and the connection map are back to empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answered_requests_over_tcp_leave_nothing_behind() {
    let peer = Peer::listening().await;
    let node = Node::on_the_wire(1500).await;
    let uri = peer.uri();
    let egress = ResolvedEgress::resolved(&uri, peer.addr, Transport::Udp);
    assert_eq!(node.uac.sender.pending_count(), 0);

    let mut connection: Option<tokio::net::TcpStream> = None;
    for cycle in 0..20 {
        let mut receiver = egress
            .send(
                &node.uac.sender,
                &node.resolver,
                message(&format!("cycle{cycle}"), 1500),
            )
            .await;
        let stream = match connection.as_mut() {
            Some(stream) => stream,
            None => connection.insert(peer.accept_request().await),
        };
        let received = read_message(stream).await;
        let via = via_of(&received);
        let response = format!(
            "SIP/2.0 200 OK\r\nVia: {via}\r\nFrom: <sip:as@example.com>;tag=a1\r\n\
             To: <sip:001010000000001@example.com>;tag=p1\r\nCall-ID: resolved-cycle{cycle}\r\n\
             CSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n"
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("written");
        let inbound = tokio::time::timeout(Duration::from_secs(5), node.inbound.recv_async())
            .await
            .expect("the answer")
            .expect("open");
        let answer = parse_sip_message_bytes(&inbound.data).expect("a response");
        assert!(node.uac.sender.match_response(&answer), "cycle {cycle}");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), &mut receiver).await,
            Ok(Ok(UacResult::Response(_)))
        ));
        assert_eq!(
            node.pool.active_connections(),
            1,
            "cycle {cycle}: one connection"
        );
    }
    assert_eq!(node.uac.sender.pending_count(), 0, "no pending entry left");

    drop(connection);
    for _ in 0..300 {
        if node.pool.active_connections() == 0 && node.connection_map.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(node.pool.active_connections(), 0);
    assert!(node.connection_map.is_empty());
}
