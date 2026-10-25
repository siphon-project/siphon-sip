use super::*;
use crate::transport::ue_sockets::UeSockets;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    sockets: UeSockets,
    inbound: flume::Receiver<InboundMessage>,
    connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    pool: Arc<ConnectionPool>,
}

fn fixture() -> Fixture {
    let (inbound_tx, inbound) = flume::unbounded();
    let connection_map: Arc<DashMap<ConnectionId, SendQueue>> = Arc::new(DashMap::new());
    let pool = Arc::new(ConnectionPool::for_tests(
        Arc::clone(&connection_map),
        inbound_tx.clone(),
    ));
    let sockets = UeSockets::new(
        inbound_tx,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    );
    assert!(sockets.attach_tcp(UeTcpContext {
        connection_map: Arc::clone(&connection_map),
        stream_connections: StreamConnections::new(),
        pool: Arc::clone(&pool),
        crlf_pong_tracker: None,
        static_addrs: HashSet::new(),
    }));
    Fixture {
        sockets,
        inbound,
        connection_map,
        pool,
    }
}

/// A free TCP port on loopback, released before returning.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("a free port")
}

fn listening(addrs: &[SocketAddr]) -> UeTcpPlan {
    UeTcpPlan {
        listeners: addrs.iter().copied().collect(),
        ..UeTcpPlan::default()
    }
}

/// An exclusive bind (no SO_REUSEADDR/SO_REUSEPORT) succeeds only once no
/// socket holds the address, so it proves the listener closed.
fn exclusively_bindable(addr: SocketAddr) -> bool {
    std::net::TcpListener::bind(addr).is_ok()
}

async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

/// What the P-CSCF does: connect to the UE's protected server port from its
/// protected client port (TS 24.229 5.2.2.2 1A b), here a port on 127.0.0.1.
async fn pcscf_connects(ue_server: SocketAddr) -> (tokio::net::TcpStream, SocketAddr) {
    let socket = tokio::net::TcpSocket::new_v4().expect("a socket");
    socket.set_reuseaddr(true).expect("SO_REUSEADDR");
    socket
        .bind("127.0.0.1:0".parse().expect("an address"))
        .expect("a client port");
    let pcscf_client = socket.local_addr().expect("its address");
    let stream = socket.connect(ue_server).await.expect("connected");
    (stream, pcscf_client)
}

const OPTIONS: &[u8] = concat!(
    "OPTIONS sip:001010000000001@127.0.0.2 SIP/2.0\r\n",
    "Via: SIP/2.0/TCP 127.0.0.1:5066;branch=z9hG4bK-pcscf-1\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=p1\r\n",
    "To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n",
    "Call-ID: tcp-ue-listener@example.test\r\n",
    "CSeq: 1 OPTIONS\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
)
.as_bytes();

#[tokio::test]
async fn the_same_port_listens_on_two_addresses() {
    let fixture = fixture();
    let port = free_port();
    let first = SocketAddr::from(([127, 0, 0, 2], port));
    let second = SocketAddr::from(([127, 0, 0, 3], port));

    let outcome = fixture.sockets.reconcile_tcp(&listening(&[first, second]));
    assert_eq!(outcome.opened, 2, "{outcome:?}");
    assert!(outcome.failed.is_empty());
    assert!(fixture.sockets.contains_tcp(&first) && fixture.sockets.contains_tcp(&second));
    assert!(fixture.sockets.contains_any(&first));
    assert!(!fixture.sockets.contains(&first), "not a UDP socket");
    assert!(fixture.sockets.contains_ip(first.ip()));
    assert_eq!(fixture.sockets.tcp_len(), (2, 0));

    let again = fixture.sockets.reconcile_tcp(&listening(&[first, second]));
    assert_eq!(
        again,
        ReconcileOutcome::default(),
        "a restated plan changes nothing"
    );

    let outcome = fixture.sockets.reconcile_tcp(&listening(&[first]));
    assert_eq!(outcome.closed, 1);
    assert!(!fixture.sockets.contains_tcp(&second));
    assert!(!fixture.sockets.contains_ip(second.ip()));
    assert!(
        wait_until(|| exclusively_bindable(second)).await,
        "the listener closed"
    );
}

#[tokio::test]
async fn without_the_tcp_half_attached_every_listener_fails() {
    let (inbound_tx, _inbound) = flume::unbounded();
    let sockets = UeSockets::new(
        inbound_tx,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    );
    let wanted = SocketAddr::from(([127, 0, 0, 2], free_port()));
    let outcome = sockets.reconcile_tcp(&listening(&[wanted]));
    assert_eq!(outcome.failed, [wanted].into_iter().collect());
    assert!(!sockets.contains_tcp(&wanted));
}

#[tokio::test]
async fn a_configured_listener_is_left_to_serve_its_address() {
    let (inbound_tx, _inbound) = flume::unbounded();
    let connection_map = Arc::new(DashMap::new());
    let sockets = UeSockets::new(
        inbound_tx.clone(),
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    );
    let port = free_port();
    sockets.attach_tcp(UeTcpContext {
        connection_map: Arc::clone(&connection_map),
        stream_connections: StreamConnections::new(),
        pool: Arc::new(ConnectionPool::for_tests(connection_map, inbound_tx)),
        crlf_pong_tracker: None,
        static_addrs: [SocketAddr::from(([0, 0, 0, 0], port))]
            .into_iter()
            .collect(),
    });
    let outcome = sockets.reconcile_tcp(&listening(&[SocketAddr::from(([127, 0, 0, 2], port))]));
    assert_eq!(outcome, ReconcileOutcome::default());
    assert_eq!(sockets.tcp_len(), (0, 0));
}

/// The P-CSCF's connection to the UE's protected server port is accepted, its
/// request reaches the dispatcher as arriving on that port, and the answer
/// goes back on the same connection.
#[tokio::test]
async fn a_pcscf_connection_is_accepted_and_answered_on() {
    let fixture = fixture();
    let ue_server = SocketAddr::from(([127, 0, 0, 2], free_port()));
    fixture.sockets.reconcile_tcp(&listening(&[ue_server]));

    let (mut pcscf, pcscf_client) = pcscf_connects(ue_server).await;
    pcscf
        .write_all(OPTIONS)
        .await
        .expect("the request is written");
    let inbound = tokio::time::timeout(Duration::from_secs(2), fixture.inbound.recv_async())
        .await
        .expect("the request arrives")
        .expect("the channel is open");
    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(inbound.local_addr, ue_server);
    assert_eq!(inbound.remote_addr, pcscf_client);
    assert_eq!(&inbound.data[..], OPTIONS);
    assert_eq!(fixture.sockets.tcp_len(), (1, 1));

    let response = b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n";
    fixture
        .connection_map
        .get(&inbound.connection_id)
        .expect("the connection is in the map")
        .try_send(bytes::Bytes::from_static(response))
        .expect("queued");
    let mut answer = vec![0u8; response.len()];
    tokio::time::timeout(Duration::from_secs(2), pcscf.read_exact(&mut answer))
        .await
        .expect("the answer arrives")
        .expect("read");
    assert_eq!(&answer, response);
}

/// Closing a listener closes the connections it accepted, and both stores
/// drain: the per-UE analogue of `siphon_proxy_dialog_sessions` reaching zero.
#[tokio::test]
async fn closing_a_listener_closes_what_it_accepted() {
    let fixture = fixture();
    let ue_server = SocketAddr::from(([127, 0, 0, 2], free_port()));
    fixture.sockets.reconcile_tcp(&listening(&[ue_server]));
    let (mut pcscf, _) = pcscf_connects(ue_server).await;
    pcscf.write_all(OPTIONS).await.expect("written");
    assert!(wait_until(|| fixture.sockets.tcp_len() == (1, 1)).await);

    fixture.sockets.reconcile_tcp(&UeTcpPlan::default());
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), pcscf.read(&mut buffer))
        .await
        .expect("the connection ends");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(wait_until(|| fixture.sockets.tcp_len() == (0, 0)).await);
    assert!(wait_until(|| fixture.connection_map.is_empty()).await);
}

/// Leak gate: cycles of a UE that listens, is connected to, connects out from
/// its own address and goes away leave no listener, no accepted connection, no
/// pool connection from its address and no connection-map entry behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_ue_cycles_return_every_store_to_baseline() {
    let fixture = fixture();
    let pcscf_server = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    let pcscf_address = pcscf_server.local_addr().expect("its address");
    let ue_ip: IpAddr = "127.0.0.3".parse().expect("an address");
    // Held open, so only the reconcile can end the UE's own connections.
    let mut held = Vec::new();
    for cycle in 0..20 {
        let ue_server = SocketAddr::new(ue_ip, free_port());
        let ue_client = SocketAddr::new(ue_ip, free_port());
        let plan = UeTcpPlan {
            listeners: [ue_server].into_iter().collect(),
            sources: [ue_client].into_iter().collect(),
            keep: [ue_client].into_iter().collect(),
        };
        fixture.sockets.reconcile_tcp(&plan);
        // The UE's own connection, from its client port.
        fixture
            .pool
            .send_tcp_from(
                ue_client,
                pcscf_address,
                bytes::Bytes::from_static(b"\r\n\r\n"),
            )
            .await
            .expect("the UE connects from its client port");
        let (accepted, from) = pcscf_server.accept().await.expect("an accept");
        assert_eq!(from, ue_client, "cycle {cycle}");
        held.push(accepted);
        // The P-CSCF's connection to it.
        let (mut pcscf, _) = pcscf_connects(ue_server).await;
        pcscf.write_all(OPTIONS).await.expect("written");
        assert!(
            wait_until(|| fixture.sockets.tcp_len() == (1, 1)).await,
            "cycle {cycle}"
        );
        let _ = fixture.inbound.drain();

        fixture.sockets.reconcile_tcp(&UeTcpPlan::default());
        assert!(
            wait_until(|| fixture.sockets.tcp_len() == (0, 0)
                && fixture.pool.connections_bound_on(ue_ip) == 0)
            .await,
            "cycle {cycle}: listeners/accepted {:?}, pool {}",
            fixture.sockets.tcp_len(),
            fixture.pool.connections_bound_on(ue_ip)
        );
    }
    assert!(wait_until(|| fixture.connection_map.is_empty()).await);
    assert!(!fixture.pool.binds_source(SocketAddr::new(ue_ip, 1)));
}

/// A listener closed after it accepted a connection but before that
/// connection's task served it still closes it, with no later reconcile to
/// sweep it up. The P-CSCF keeps its side open, so nothing else would end it.
///
/// Before: the close went through the connection-closer registry, which the
/// task joined only once it started serving; a close sent earlier was lost,
/// and the connection lived until the peer closed it (the leak gate below
/// failed on loaded runners with "listeners/accepted (0, 1)").
#[tokio::test]
async fn a_connection_accepted_just_before_its_listener_closes_is_closed() {
    let fixture = fixture();
    let hold = Arc::new(tokio::sync::Semaphore::new(0));
    fixture.sockets.hold_tcp_serving(Arc::clone(&hold));
    let ue_server = SocketAddr::from(([127, 0, 0, 4], free_port()));
    fixture.sockets.reconcile_tcp(&listening(&[ue_server]));
    let (mut pcscf, _) = pcscf_connects(ue_server).await;
    assert!(
        wait_until(|| fixture.sockets.tcp_len() == (1, 1)).await,
        "accepted"
    );

    // Closed while the connection's task has not served it yet.
    fixture.sockets.reconcile_tcp(&UeTcpPlan::default());
    hold.add_permits(1);

    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), pcscf.read(&mut buffer)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the connection must end without the peer closing it: {read:?}"
    );
    assert!(wait_until(|| fixture.sockets.tcp_len() == (0, 0)).await);
}
