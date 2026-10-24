use super::*;
use crate::registrant::test_support::{self, impu, trunk, ue};
use crate::transport::acl::TransportAcl;
use std::collections::HashSet;

fn router() -> (Arc<OutboundRouter>, flume::Receiver<OutboundMessage>) {
    router_with(None)
}

fn router_with(
    dynamic: Option<Arc<UeSockets>>,
) -> (Arc<OutboundRouter>, flume::Receiver<OutboundMessage>) {
    let (udp_tx, udp_rx) = flume::unbounded();
    let (tcp, _) = flume::unbounded();
    let (tls, _) = flume::unbounded();
    let (ws, _) = flume::unbounded();
    let (wss, _) = flume::unbounded();
    (
        Arc::new(OutboundRouter {
            udp: udp_tx.into(),
            udp_by_local: HashMap::new(),
            udp_dynamic: dynamic,
            tcp,
            tls,
            ws,
            wss,
            sctp: None,
        }),
        udp_rx,
    )
}

fn pool() -> Arc<ConnectionPool> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    Arc::new(ConnectionPool::new(
        Arc::new(dashmap::DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("addr"),
        None,
        None,
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("a TLS config"),
    ))
}

fn context(
    outbound: Arc<OutboundRouter>,
    ue_sockets: Option<Arc<UeSockets>>,
    listen_port: u16,
) -> RegistrationLoopContext {
    RegistrationLoopContext {
        outbound,
        local_addr: SocketAddr::from(([127, 0, 0, 1], listen_port)),
        listen_addrs: HashMap::from([(
            Transport::Udp,
            SocketAddr::from(([127, 0, 0, 1], listen_port)),
        )]),
        advertised_addrs: HashMap::new(),
        advertised_address: None,
        hep_sender: None,
        connection_pool: pool(),
        ue_sockets,
        ipsec_manager: None,
    }
}

fn install(manager: &RegistrantManager, context: &RegistrationLoopContext) {
    manager.set_egress(RegistrantEgress {
        local_addr: context.local_addr,
        listen_addrs: context.listen_addrs.clone(),
        advertised_addrs: HashMap::new(),
        advertised_address: None,
        hep_sender: None,
    });
}

fn ue_sockets() -> Arc<UeSockets> {
    Arc::new(UeSockets::new(
        flume::unbounded().0,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    ))
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .expect("a free port")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

/// Several UEs on loopback addresses of their own: the tick opens their
/// sockets (plain + both protected ports each) and sends every initial
/// REGISTER pinned to its own address.
#[tokio::test]
async fn a_tick_opens_each_ues_sockets_and_registers_it_from_them() {
    let manager = test_support::manager();
    let sockets = ue_sockets();
    let (outbound, _default) = router_with(Some(Arc::clone(&sockets)));
    let port = free_port();
    let context = context(outbound, Some(Arc::clone(&sockets)), port);
    install(&manager, &context);
    for index in 2..5u32 {
        manager
            .try_add(ue(index, Some(ip(&format!("127.0.0.{index}")))))
            .expect("added");
    }
    // One plain entry on the process address, unaffected.
    manager.add(trunk("sip:trunk@carrier.example"));

    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );

    assert_eq!(
        sockets.len(),
        15,
        "plain + the three rotating client ports + port_s for three UEs"
    );
    for index in 2..5u32 {
        let own = ip(&format!("127.0.0.{index}"));
        for socket_port in [port, 6100, 6102, 6103, 6101] {
            assert!(sockets.contains(&SocketAddr::new(own, socket_port)));
        }
        assert_eq!(
            manager.state(&impu(index)),
            Some(RegistrantState::Registering)
        );
    }

    // Moving one closes its old sockets on the next tick.
    manager
        .set_local_addr(&impu(2), Some(ip("127.0.0.9")))
        .expect("moved");
    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );
    assert!(!sockets.contains_ip(ip("127.0.0.2")));
    assert!(sockets.contains(&SocketAddr::new(ip("127.0.0.9"), 6101)));

    // Removing every UE releases every socket.
    for index in 2..5u32 {
        manager.remove(&impu(index));
    }
    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );
    assert!(sockets.is_empty());
}

/// The REGISTER of an entry with its own address is handed to the transport
/// pinned to that address; a process-address entry keeps the first listener.
#[tokio::test]
async fn each_register_leaves_pinned_to_its_entrys_address() {
    let manager = test_support::manager();
    let (outbound, sent) = router();
    let context = context(outbound, None, 5070);
    install(&manager, &context);
    manager.add(trunk("sip:trunk@carrier.example"));
    manager
        .try_add(trunk("sip:own@carrier.example").with_local_addr(ip("192.0.2.40")))
        .expect("added");

    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );

    let mut sources: Vec<Option<SocketAddr>> = sent
        .try_iter()
        .map(|message| message.source_local_addr)
        .collect();
    sources.sort();
    // Without per-UE socket support the entry with an address cannot bind,
    // so only the process-address entry went out.
    assert_eq!(sources, [Some("127.0.0.1:5070".parse().expect("addr"))]);
    assert_eq!(
        manager.state("sip:own@carrier.example"),
        Some(RegistrantState::Unregistered),
        "an entry that cannot bind waits"
    );
}

#[tokio::test]
async fn an_entry_whose_socket_cannot_bind_sits_the_tick_out() {
    let manager = test_support::manager();
    let sockets = ue_sockets();
    let (outbound, _sent) = router_with(Some(Arc::clone(&sockets)));
    let port = free_port();
    let context = context(outbound, Some(Arc::clone(&sockets)), port);
    install(&manager, &context);
    let blocked = SocketAddr::new(ip("127.0.0.7"), port);
    let holder = std::net::UdpSocket::bind(blocked).expect("held by someone else");
    manager
        .try_add(trunk("sip:blocked@carrier.example").with_local_addr(blocked.ip()))
        .expect("added");

    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );
    assert_eq!(
        manager.state("sip:blocked@carrier.example"),
        Some(RegistrantState::Unregistered)
    );

    drop(holder);
    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );
    assert_eq!(
        manager.state("sip:blocked@carrier.example"),
        Some(RegistrantState::Registering)
    );
}

/// Five consecutive free UDP ports on loopback, released before returning.
fn free_port_run() -> u16 {
    for _ in 0..200 {
        let base = free_port();
        if base > u16::MAX - 5 {
            continue;
        }
        let held: Vec<std::net::UdpSocket> = (0..5)
            .filter_map(|offset| std::net::UdpSocket::bind(("127.0.0.1", base + offset)).ok())
            .collect();
        if held.len() == 5 {
            return base;
        }
    }
    panic!("no run of five free ports");
}

/// A rotation port of a process-address IMS UE that another socket holds no
/// longer stalls the entry: the tick moves it to a free port, binds that, and
/// the entry registers.
#[tokio::test]
async fn a_process_ue_whose_rotation_port_is_taken_registers_anyway() {
    let manager = test_support::manager();
    let sockets = ue_sockets();
    let (outbound, sent) = router_with(Some(Arc::clone(&sockets)));
    let context = context(outbound, Some(Arc::clone(&sockets)), free_port());
    install(&manager, &context);
    let base = free_port_run();
    let mut entry = ue(1, None);
    entry.ue_ipsec = Some(crate::registrant::UeIpsec::new(
        base,
        base + 1,
        crate::ipsec::IntegrityAlgorithm::HmacSha1,
        crate::ipsec::EncryptionAlgorithm::Null,
    ));
    manager.try_add(entry).expect("added");
    let taken = SocketAddr::new(ip("127.0.0.1"), base + 2);
    let _holder = std::net::UdpSocket::bind(taken).expect("held by someone else");

    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );

    assert_eq!(manager.state(&impu(1)), Some(RegistrantState::Registering));
    let moved = SocketAddr::new(ip("127.0.0.1"), base + 4);
    assert!(sockets.contains(&moved), "the replacement port is bound");
    assert!(!sockets.contains(&taken));
    let register = sent.try_recv().expect("the REGISTER");
    assert!(String::from_utf8_lossy(&register.data).contains(&format!("port-c={base};")));
}

#[tokio::test]
async fn a_removed_entry_is_de_registered_from_its_own_address() {
    let manager = test_support::manager();
    let (outbound, sent) = router();
    let context = context(outbound, None, 5070);
    install(&manager, &context);
    manager
        .try_add(trunk("sip:own@carrier.example").with_local_addr(ip("192.0.2.40")))
        .expect("added");
    manager.handle_success("sip:own@carrier.example", 3600);
    manager.remove("sip:own@carrier.example");

    run_tick(
        &manager,
        &context,
        manager.egress.get().expect("egress"),
        None,
    );

    let message = sent.try_recv().expect("the de-REGISTER");
    assert_eq!(
        message.source_local_addr,
        Some("192.0.2.40:5070".parse().expect("addr"))
    );
    assert!(String::from_utf8_lossy(&message.data).contains("Expires: 0"));
}

#[tokio::test]
async fn deregister_all_sends_each_binding_from_its_own_address() {
    let manager = test_support::manager();
    let (outbound, sent) = router();
    let context = context(Arc::clone(&outbound), None, 5070);
    install(&manager, &context);
    manager.add(trunk("sip:process@carrier.example"));
    manager
        .try_add(trunk("sip:own@carrier.example").with_local_addr(ip("192.0.2.40")))
        .expect("added");
    manager.handle_success("sip:process@carrier.example", 3600);
    manager.handle_success("sip:own@carrier.example", 3600);

    assert_eq!(deregister_all(&manager, &outbound), 2);
    let sources: HashSet<Option<SocketAddr>> = sent
        .try_iter()
        .map(|message| message.source_local_addr)
        .collect();
    assert_eq!(
        sources,
        HashSet::from([
            Some("192.0.2.40:5070".parse().expect("addr")),
            Some("127.0.0.1:5070".parse().expect("addr")),
        ])
    );
}

/// The start-rate cap under paused time: never more than the cap in any one
/// second, the longest-overdue entries first, and every entry started in the
/// end.
#[tokio::test(start_paused = true)]
async fn the_loop_ramps_at_the_capped_rate_oldest_first() {
    const CAP: u32 = 10;
    const ENTRIES: u32 = 45;
    let manager = Arc::new(test_support::manager().with_max_registers_per_sec(Some(CAP)));
    let now = std::time::Instant::now();
    for index in 0..ENTRIES {
        let mut entry = trunk(&format!("sip:t{index}@carrier.example"));
        // t0 is the longest overdue.
        entry.next_attempt = now - std::time::Duration::from_secs(u64::from(ENTRIES - index));
        manager.add(entry);
    }
    let (outbound, sent) = router();
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(registration_loop(
        Arc::clone(&manager),
        context(outbound, None, 5070),
    ));

    let mut arrivals: Vec<(tokio::time::Instant, String)> = Vec::new();
    for _ in 0..(10 * 7) {
        tokio::time::advance(std::time::Duration::from_millis(100)).await;
        tokio::task::yield_now().await;
        for message in sent.try_iter() {
            let raw = String::from_utf8_lossy(&message.data).into_owned();
            let aor = raw
                .lines()
                .find_map(|line| line.strip_prefix("To: <"))
                .and_then(|rest| rest.strip_suffix('>'))
                .expect("a To")
                .to_string();
            arrivals.push((tokio::time::Instant::now(), aor));
        }
    }
    task.abort();

    assert_eq!(arrivals.len(), ENTRIES as usize, "every entry started");
    for (index, (at, _)) in arrivals.iter().enumerate() {
        let in_second = arrivals[index..]
            .iter()
            .take_while(|(later, _)| later.duration_since(*at) < std::time::Duration::from_secs(1))
            .count();
        assert!(
            in_second <= CAP as usize,
            "{in_second} starts within one second"
        );
    }
    let order: Vec<String> = arrivals.into_iter().map(|(_, aor)| aor).collect();
    let expected: Vec<String> = (0..ENTRIES)
        .map(|index| format!("sip:t{index}@carrier.example"))
        .collect();
    assert_eq!(order, expected, "longest overdue first");
    assert!(
        tokio::time::Instant::now().duration_since(started) >= std::time::Duration::from_secs(4)
    );
}

// --- over TCP ----------------------------------------------------------------

/// A registration loop wired as the server wires it for TCP: the router's TCP
/// channel drained by the stream distributor into one pool, and the per-UE
/// sockets' TCP half attached to the same pool and connection map.
struct TcpLoop {
    context: RegistrationLoopContext,
    sockets: Arc<UeSockets>,
    pool: Arc<ConnectionPool>,
    connection_map: Arc<
        dashmap::DashMap<crate::transport::ConnectionId, crate::transport::send_queue::SendQueue>,
    >,
    inbound: flume::Receiver<crate::transport::InboundMessage>,
}

fn tcp_loop(plain_port: u16) -> TcpLoop {
    let (inbound_tx, inbound) = flume::unbounded();
    let connection_map = Arc::new(dashmap::DashMap::new());
    let pool = Arc::new(ConnectionPool::for_tests(
        Arc::clone(&connection_map),
        inbound_tx.clone(),
    ));
    let sockets = Arc::new(UeSockets::new(
        inbound_tx,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    ));
    sockets.attach_tcp(crate::transport::ue_streams::UeTcpContext {
        connection_map: Arc::clone(&connection_map),
        stream_connections: crate::transport::StreamConnections::new(),
        pool: Arc::clone(&pool),
        crlf_pong_tracker: None,
        static_addrs: HashSet::new(),
    });
    let (udp_tx, _udp_rx) = flume::unbounded();
    let (tcp_tx, tcp_rx) = flume::unbounded();
    crate::transport::stream::spawn_outbound_distributor(
        tcp_rx,
        Arc::clone(&connection_map),
        Transport::Tcp,
        Some(Arc::clone(&pool)),
    );
    let outbound = Arc::new(OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: HashMap::new(),
        udp_dynamic: Some(Arc::clone(&sockets)),
        tcp: tcp_tx,
        tls: flume::unbounded().0,
        ws: flume::unbounded().0,
        wss: flume::unbounded().0,
        sctp: None,
    });
    let mut context = context(outbound, Some(Arc::clone(&sockets)), plain_port);
    context.connection_pool = Arc::clone(&pool);
    TcpLoop {
        context,
        sockets,
        pool,
        connection_map,
        inbound,
    }
}

fn tick(manager: &RegistrantManager, context: &RegistrationLoopContext) {
    run_tick(
        manager,
        context,
        manager.egress.get().expect("egress"),
        None,
    );
}

async fn eventually(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if condition() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    condition()
}

/// Read one SIP message (headers, no body) off `stream`.
async fn read_message(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut received = Vec::new();
    let mut buffer = [0u8; 4096];
    while !received.windows(4).any(|window| window == b"\r\n\r\n") {
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buffer))
                .await
                .expect("a message within 3 s")
                .expect("read");
        assert_ne!(read, 0, "closed before a message");
        received.extend_from_slice(&buffer[..read]);
    }
    String::from_utf8_lossy(&received).into_owned()
}

/// Two UEs over TCP, each on a loopback address of its own and the same
/// ports: the tick opens a listener on each one's protected server port, and
/// each initial REGISTER reaches the P-CSCF on a connection from that UE's own
/// address and plain port. The P-CSCF's connection to a UE's protected server
/// port is accepted, its request arrives as received on that port, and the
/// answer, routed by connection id as the dispatcher routes it, goes back on
/// that connection. Removing the UEs closes everything they held.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_ues_register_from_their_own_address_and_take_the_pcscf_connection() {
    use tokio::io::AsyncWriteExt;
    let plain_port = free_port();
    let harness = tcp_loop(plain_port);
    let pcscf = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a P-CSCF");
    let pcscf_address = pcscf.local_addr().expect("its address");
    let manager = test_support::manager();
    install(&manager, &harness.context);
    let addresses = [ip("127.0.0.71"), ip("127.0.0.72")];
    for (index, address) in (1u32..).zip(addresses) {
        let mut entry = ue(index, Some(address));
        entry.transport = Transport::Tcp;
        entry.destination = pcscf_address;
        manager.try_add(entry).expect("a TCP UE");
    }

    tick(&manager, &harness.context);
    for address in addresses {
        assert!(harness
            .sockets
            .contains_tcp(&SocketAddr::new(address, 6101)));
        assert!(
            !harness.sockets.contains(&SocketAddr::new(address, 6101)),
            "no UDP socket"
        );
    }

    // Each REGISTER on its own connection, from its own plain port.
    let mut registered_from = HashSet::new();
    let mut held = Vec::new();
    for _ in addresses {
        let (mut connection, peer) =
            tokio::time::timeout(std::time::Duration::from_secs(3), pcscf.accept())
                .await
                .expect("a connection within 3 s")
                .expect("accepted");
        let register = read_message(&mut connection).await;
        assert!(register.starts_with("REGISTER "), "{register}");
        assert!(
            register.contains(&format!("Via: SIP/2.0/TCP {peer};")),
            "Via names the source: {register}"
        );
        assert!(register.contains(";transport=tcp"), "{register}");
        registered_from.insert(peer);
        held.push(connection);
    }
    let expected: HashSet<SocketAddr> = addresses
        .iter()
        .map(|address| SocketAddr::new(*address, plain_port))
        .collect();
    assert_eq!(registered_from, expected);

    // The P-CSCF's connection to UE 1's protected server port.
    let ue_server = SocketAddr::new(addresses[0], 6101);
    let mut towards_ue = tokio::net::TcpStream::connect(ue_server)
        .await
        .expect("the UE listens");
    let request = concat!(
        "OPTIONS sip:001010000000001@127.0.0.71:6101 SIP/2.0\r\n",
        "Via: SIP/2.0/TCP 127.0.0.1:5066;branch=z9hG4bK-mt-1\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=p1\r\n",
        "To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n",
        "Call-ID: tcp-mt@example.test\r\n",
        "CSeq: 1 OPTIONS\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    towards_ue
        .write_all(request.as_bytes())
        .await
        .expect("written");
    let inbound = loop {
        let message = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            harness.inbound.recv_async(),
        )
        .await
        .expect("the request arrives")
        .expect("open");
        if message.local_addr == ue_server {
            break message;
        }
    };
    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(
        manager.find_by_local(crate::registrant::address::LocalAddrQuery::Socket(
            ue_server
        )),
        Some(impu(1))
    );
    harness
        .context
        .outbound
        .send(OutboundMessage {
            connection_id: inbound.connection_id,
            transport: Transport::Tcp,
            destination: inbound.remote_addr,
            data: bytes::Bytes::from_static(b"SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
            source_local_addr: Some(ue_server),
            server_name: None,
            verify_server: None,
            followups: None,
        })
        .expect("sent");
    let answer = read_message(&mut towards_ue).await;
    assert!(answer.starts_with("SIP/2.0 200 OK"), "{answer}");

    // Removed: the next tick closes the listeners, the accepted connection
    // and the UEs' own connections.
    for index in 1..=2u32 {
        manager.remove(&impu(index));
    }
    tick(&manager, &harness.context);
    assert!(
        eventually(|| harness.sockets.tcp_len() == (0, 0)
            && addresses
                .iter()
                .all(|address| harness.pool.connections_bound_on(*address) == 0))
        .await,
        "listeners/accepted {:?}",
        harness.sockets.tcp_len()
    );
    assert!(eventually(|| harness.connection_map.is_empty()).await);
}
