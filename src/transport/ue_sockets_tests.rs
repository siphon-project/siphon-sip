use super::*;
use crate::transport::{ConnectionId, OutboundRouter, Transport};
use std::time::Duration;

fn sockets(static_addrs: Vec<SocketAddr>) -> (UeSockets, flume::Receiver<InboundMessage>) {
    let (inbound_tx, inbound_rx) = flume::unbounded();
    (
        UeSockets::new(
            inbound_tx,
            Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
            None,
            0,
            static_addrs,
        ),
        inbound_rx,
    )
}

/// A free UDP port on loopback, released before returning.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .expect("a free port")
}

fn set(addrs: &[SocketAddr]) -> HashSet<SocketAddr> {
    addrs.iter().copied().collect()
}

fn datagram(source: SocketAddr, destination: SocketAddr, body: &'static [u8]) -> OutboundMessage {
    OutboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        destination,
        data: bytes::Bytes::from_static(body),
        source_local_addr: Some(source),
        server_name: None,
        verify_server: None,
        followups: None,
    }
}

/// An exclusive bind (no SO_REUSEADDR) succeeds only when no socket holds the
/// address any more, so it proves the descriptor closed.
fn exclusively_bindable(addr: SocketAddr) -> bool {
    std::net::UdpSocket::bind(addr).is_ok()
}

async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

#[tokio::test]
async fn the_same_port_binds_on_two_addresses() {
    let (sockets, _inbound) = sockets(Vec::new());
    let port = free_port();
    let first = SocketAddr::from(([127, 0, 0, 2], port));
    let second = SocketAddr::from(([127, 0, 0, 3], port));

    let outcome = sockets.reconcile(&set(&[first, second]));

    assert_eq!(outcome.opened, 2, "{outcome:?}");
    assert!(outcome.failed.is_empty());
    assert!(sockets.contains(&first) && sockets.contains(&second));
    assert!(sockets.contains_ip(first.ip()));
    assert_eq!(sockets.len(), 2);
}

#[tokio::test]
async fn reconcile_is_idempotent_and_closes_what_is_no_longer_wanted() {
    let (sockets, _inbound) = sockets(Vec::new());
    let port = free_port();
    let kept = SocketAddr::from(([127, 0, 0, 2], port));
    let dropped = SocketAddr::from(([127, 0, 0, 3], port));

    sockets.reconcile(&set(&[kept, dropped]));
    let again = sockets.reconcile(&set(&[kept, dropped]));
    assert_eq!(
        again,
        ReconcileOutcome::default(),
        "a restated set changes nothing"
    );

    let outcome = sockets.reconcile(&set(&[kept]));
    assert_eq!(outcome.closed, 1);
    assert!(!sockets.contains(&dropped));
    assert!(!sockets.contains_ip(dropped.ip()));
    assert!(sockets.contains(&kept));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn freebind_binds_an_address_the_host_does_not_have() {
    // TEST-NET-1 (RFC 5737): never configured on a test host.
    let absent = SocketAddr::from(([192, 0, 2, 77], free_port()));
    let nonlocal_bind_allowed = std::fs::read_to_string("/proc/sys/net/ipv4/ip_nonlocal_bind")
        .is_ok_and(|value| value.trim() == "1");
    if !nonlocal_bind_allowed {
        assert!(
            std::net::UdpSocket::bind(absent).is_err(),
            "without IP_FREEBIND the bind must fail on an absent address"
        );
    }

    let (sockets, _inbound) = sockets(Vec::new());
    let outcome = sockets.reconcile(&set(&[absent]));
    assert_eq!(outcome.opened, 1, "{outcome:?}");
    assert!(sockets.contains(&absent));
}

/// What happens when a per-UE address leaves the host: the socket stays
/// bound, but the kernel refuses to send from a source it does not own, so
/// nothing leaves with a spoofed address. The registration then times out.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_send_from_an_absent_address_fails_instead_of_leaving() {
    let absent = SocketAddr::from(([192, 0, 2, 78], free_port()));
    let socket = super::super::udp::tests_support::freebind_socket(absent).expect("binds");
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("peer");
    let sent = socket
        .send_to(b"OPTIONS", peer.local_addr().expect("peer addr"))
        .await;
    let mut buffer = [0u8; 16];
    let received =
        tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buffer)).await;
    let received: std::io::Result<()> = match received {
        Ok(Ok(_)) => Ok(()),
        _ => Err(std::io::Error::from(std::io::ErrorKind::TimedOut)),
    };
    assert!(
        sent.is_err() || received.is_err(),
        "a datagram left from an address the host does not have"
    );
}

#[tokio::test]
async fn a_static_listener_address_is_never_opened_here() {
    let port = free_port();
    let configured = SocketAddr::from(([127, 0, 0, 2], port));
    let (sockets, _inbound) = sockets(vec![configured]);

    let outcome = sockets.reconcile(&set(&[configured]));

    assert_eq!(outcome, ReconcileOutcome::default());
    assert!(!sockets.contains(&configured));
    assert!(sockets.is_static(&configured));
}

#[tokio::test]
async fn an_unbindable_address_is_reported_failed_and_retried() {
    let port = free_port();
    let taken = SocketAddr::from(([127, 0, 0, 2], port));
    // Held exclusively by someone else.
    let holder = std::net::UdpSocket::bind(taken).expect("holder binds");
    let (sockets, _inbound) = sockets(Vec::new());

    let first = sockets.reconcile(&set(&[taken]));
    assert!(first.failed.contains(&taken), "{first:?}");
    assert!(!sockets.contains(&taken));

    drop(holder);
    let second = sockets.reconcile(&set(&[taken]));
    assert_eq!(second.opened, 1, "the next tick binds it: {second:?}");
}

#[tokio::test]
async fn a_port_zero_or_wildcard_address_is_refused() {
    let (sockets, _inbound) = sockets(Vec::new());
    let outcome = sockets.reconcile(&set(&[
        SocketAddr::from(([127, 0, 0, 2], 0)),
        SocketAddr::from(([0, 0, 0, 0], 5060)),
    ]));
    assert_eq!(outcome.failed.len(), 2);
    assert!(sockets.is_empty());
}

#[tokio::test]
async fn a_dynamic_socket_receives_and_reports_its_own_local_address() {
    let (sockets, inbound) = sockets(Vec::new());
    let addr = SocketAddr::from(([127, 0, 0, 2], free_port()));
    sockets.reconcile(&set(&[addr]));

    let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer");
    peer.send_to(b"OPTIONS sip:x SIP/2.0\r\n\r\n", addr)
        .expect("send");
    let message = tokio::time::timeout(Duration::from_secs(2), inbound.recv_async())
        .await
        .expect("received in time")
        .expect("channel open");
    assert_eq!(message.local_addr, addr);
}

fn router_with(
    dynamic: Option<Arc<UeSockets>>,
) -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp_tx, udp_rx) = flume::unbounded();
    let (tcp, _) = flume::unbounded();
    let (tls, _) = flume::unbounded();
    let (ws, _) = flume::unbounded();
    let (wss, _) = flume::unbounded();
    (
        OutboundRouter {
            udp: udp_tx.into(),
            udp_by_local: std::collections::HashMap::new(),
            udp_dynamic: dynamic,
            tcp,
            tls,
            ws,
            wss,
            sctp: None,
        },
        udp_rx,
    )
}

#[tokio::test]
async fn the_router_falls_back_to_a_dynamic_socket_for_its_address() {
    let (sockets, _inbound) = sockets(Vec::new());
    let sockets = Arc::new(sockets);
    let source = SocketAddr::from(([127, 0, 0, 2], free_port()));
    sockets.reconcile(&set(&[source]));
    let (router, default_rx) = router_with(Some(Arc::clone(&sockets)));

    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("peer");
    router
        .send(datagram(source, peer.local_addr().expect("peer"), b"PING"))
        .expect("routed");

    let mut buffer = [0u8; 16];
    let (size, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .expect("in time")
        .expect("datagram arrives");
    assert_eq!(&buffer[..size], b"PING");
    assert_eq!(from, source, "it left from the dynamic socket");
    assert!(default_rx.try_recv().is_err(), "not the default channel");

    // An address no socket holds still takes the default path.
    let other = SocketAddr::from(([127, 0, 0, 9], 5060));
    router
        .send(datagram(other, peer.local_addr().expect("peer"), b"X"))
        .expect("routed");
    assert!(default_rx.try_recv().is_ok());
}

#[tokio::test]
async fn a_router_without_dynamic_sockets_routes_as_before() {
    let (router, default_rx) = router_with(None);
    let source = SocketAddr::from(([127, 0, 0, 2], 5060));
    router
        .send(datagram(
            source,
            "127.0.0.1:5999".parse().expect("addr"),
            b"X",
        ))
        .expect("routed");
    let message = default_rx.try_recv().expect("on the default channel");
    assert_eq!(message.source_local_addr, Some(source));
}

#[tokio::test]
async fn the_registry_names_a_dynamic_socket_by_its_own_address() {
    let (sockets, _inbound) = sockets(Vec::new());
    let sockets = Arc::new(sockets);
    let ue = SocketAddr::from(([127, 0, 0, 2], free_port()));
    sockets.reconcile(&set(&[ue]));
    let registry = crate::transport::ListenerRegistry::from_entries(vec![(
        Transport::Udp,
        "127.0.0.1:5060".parse().expect("addr"),
        None,
    )])
    .with_global_advertised(Some("203.0.113.50"))
    .with_dynamic_udp(Some(Arc::clone(&sockets)));

    assert_eq!(
        registry.identity(Transport::Udp, ue),
        Some(("127.0.0.2".to_string(), ue.port())),
        "not the global advertised address"
    );
    assert_eq!(registry.identity_port(Transport::Udp, ue), Some(ue.port()));
    assert!(registry.matches_local(&ue));
    // The configured listener keeps the global identity.
    assert_eq!(
        registry.identity(Transport::Udp, "127.0.0.1:5060".parse().expect("addr")),
        Some(("203.0.113.50".to_string(), 5060))
    );
    // Not a TCP listener.
    assert_eq!(registry.identity(Transport::Tcp, ue), None);

    let mut identity = crate::proxy::core::SelfIdentity::new();
    identity.set_dynamic_udp(registry.dynamic_udp().cloned());
    assert!(identity.matches("127.0.0.2", Some(ue.port())));
    assert!(identity.matches("127.0.0.2", None));
    assert!(!identity.matches("127.0.0.2", Some(1)));
    assert!(!identity.matches("192.0.2.1", None));

    sockets.reconcile(&HashSet::new());
    assert_eq!(
        registry.identity(Transport::Udp, ue),
        None,
        "closed: no longer ours"
    );
    assert!(!identity.matches("127.0.0.2", None));
}

#[cfg(target_os = "linux")]
fn read_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
}

#[cfg(not(target_os = "linux"))]
fn read_rss_kb() -> Option<u64> {
    None
}

async fn cycle(sockets: &UeSockets, addrs: &HashSet<SocketAddr>, cycles: usize) {
    let empty = HashSet::new();
    for _ in 0..cycles {
        let opened = sockets.reconcile(addrs);
        assert!(opened.failed.is_empty(), "{opened:?}");
        sockets.reconcile(&empty);
        // Let the closed workers run to their exit.
        tokio::task::yield_now().await;
    }
}

/// Leak gate: a socket per address, opened and closed over and over, leaves
/// the store at its baseline, closes every descriptor (the port binds
/// exclusively again) and keeps the resident set flat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opening_and_closing_sockets_returns_to_baseline() {
    let (sockets, _inbound) = sockets(Vec::new());
    let port = free_port();
    let addrs: HashSet<SocketAddr> = (2..6u8)
        .map(|last| SocketAddr::from(([127, 0, 0, last], port)))
        .collect();

    cycle(&sockets, &addrs, 250).await;
    let warm = read_rss_kb();
    cycle(&sockets, &addrs, 750).await;
    let steady = read_rss_kb();

    assert_eq!(sockets.len(), 0, "a closed socket stayed in the store");
    assert!(sockets.ips.is_empty(), "an IP count stayed behind");
    for addr in &addrs {
        assert!(
            wait_until(|| exclusively_bindable(*addr)).await,
            "{addr} still held: a worker kept its descriptor"
        );
    }
    if let (Some(warm), Some(steady)) = (warm, steady) {
        // 3000 opens; a leak of even one socket's buffers each would show.
        assert!(
            steady <= warm + 8 * 1024,
            "RSS grew from {warm} kB to {steady} kB over 3000 socket cycles"
        );
    }
}

#[test]
fn the_debug_form_names_counts_not_internals() {
    let (inbound_tx, _inbound_rx) = flume::unbounded();
    let sockets = UeSockets::new(
        inbound_tx,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    );
    assert_eq!(
        format!("{sockets:?}"),
        "UeSockets { sockets: 0, static_addrs: 0 }"
    );
}
