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

    assert_eq!(sockets.len(), 9, "plain + port_c + port_s for three UEs");
    for index in 2..5u32 {
        let own = ip(&format!("127.0.0.{index}"));
        for socket_port in [port, 6100, 6101] {
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
