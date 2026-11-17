//! The over-MTU decision for a request siphon originates, against real
//! loopback sockets: the relay's threshold, probe and negative cache, awaited.

use std::net::SocketAddr;
use std::sync::Arc;

use dashmap::DashMap;

use super::*;
use crate::log_capture::LogBuffer;

const MTU: u16 = 1500;
const FORCED_UDP: &str = "forced UDP over-MTU send (no reachable TCP path)";

fn pool() -> Arc<ConnectionPool> {
    Arc::new(ConnectionPool::for_tests(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
    ))
}

fn resolver() -> SipResolver {
    SipResolver::from_system().expect("a system resolver")
}

/// A next hop that refuses TCP: a bound socket that does not listen, held so
/// nothing else takes the port.
fn refusing_peer() -> (SocketAddr, socket2::Socket) {
    let socket =
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).expect("a socket");
    let address: SocketAddr = "127.0.0.1:0".parse().expect("an address");
    socket.bind(&address.into()).expect("a free port");
    let peer = socket
        .local_addr()
        .expect("bound")
        .as_socket()
        .expect("an inet address");
    (peer, socket)
}

async fn listening_peer() -> (SocketAddr, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener");
    (listener.local_addr().expect("bound"), listener)
}

#[tokio::test]
async fn a_request_over_the_threshold_goes_tcp_to_a_next_hop_that_listens() {
    let (peer, _listener) = listening_peer().await;
    let (pool, resolver) = (pool(), resolver());
    let decision = OriginatedOverMtu {
        mtu: MTU,
        pool: &pool,
        ipsec: None,
        resolver: &resolver,
    };
    let uri = format!("sip:as@{peer}");
    assert_eq!(
        decision.upgrade(1301, &uri, peer).await,
        Some(OriginatedTcp {
            destination: peer,
            protected: false,
        }),
        "one byte over mtu - 200"
    );
    // A bare address names the same host.
    assert!(decision
        .upgrade(1900, &peer.to_string(), peer)
        .await
        .is_some());
}

#[tokio::test]
async fn a_request_at_or_under_the_threshold_is_not_probed() {
    let (peer, listener) = listening_peer().await;
    let (pool, resolver) = (pool(), resolver());
    let decision = OriginatedOverMtu {
        mtu: MTU,
        pool: &pool,
        ipsec: None,
        resolver: &resolver,
    };
    let before = probe_cache().probes_started(peer);
    let uri = format!("sip:as@{peer}");
    assert_eq!(decision.upgrade(1300, &uri, peer).await, None);
    assert_eq!(decision.upgrade(900, &uri, peer).await, None);
    assert_eq!(probe_cache().probes_started(peer), before, "no probe");
    let accepted =
        tokio::time::timeout(std::time::Duration::from_millis(200), listener.accept()).await;
    assert!(accepted.is_err(), "nothing connected");
}

/// RFC 3261 §18.1.1: when the connection attempt fails the request goes over
/// UDP. The next hop is probed once per window and the warning logged once,
/// as for a relayed request.
#[tokio::test]
async fn a_next_hop_that_refuses_tcp_keeps_udp_and_is_probed_once() {
    let (peer, _held) = refusing_peer();
    probe_cache().forget(peer);
    let (pool, resolver) = (pool(), resolver());
    let decision = OriginatedOverMtu {
        mtu: MTU,
        pool: &pool,
        ipsec: None,
        resolver: &resolver,
    };
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let before = probe_cache().probes_started(peer);
    let uri = format!("sip:as@{peer}");
    for _ in 0..50 {
        assert_eq!(decision.upgrade(1900, &uri, peer).await, None);
    }
    drop(guard);
    assert_eq!(
        probe_cache().probes_started(peer),
        before + 1,
        "one probe per window"
    );
    assert_eq!(
        log.rendered().matches(FORCED_UDP).count(),
        1,
        "one warning per window:\n{}",
        log.rendered()
    );
    probe_cache().forget(peer);
}

/// The blocking decision and the awaited one share the cache: a next hop the
/// relay found unreachable is not probed again by a script's request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relays_failed_probe_spares_an_originated_request_its_own() {
    let (peer, _held) = refusing_peer();
    probe_cache().forget(peer);
    let (pool, resolver) = (pool(), resolver());
    let before = probe_cache().probes_started(peer);
    assert_eq!(
        mtu_tcp_upgrade(
            Some(MTU),
            Transport::Udp,
            1900,
            &peer.to_string(),
            peer,
            &resolver
        ),
        None
    );
    let decision = OriginatedOverMtu {
        mtu: MTU,
        pool: &pool,
        ipsec: None,
        resolver: &resolver,
    };
    assert_eq!(decision.upgrade(1900, &peer.to_string(), peer).await, None);
    assert_eq!(probe_cache().probes_started(peer), before + 1);
    probe_cache().forget(peer);
}

/// Leak gate: a probe abandoned mid-connect (its request's future dropped)
/// leaves no entry behind, so the next request probes.
#[tokio::test]
async fn an_abandoned_probe_leaves_the_cache_as_it_found_it() {
    let (peer, _listener) = listening_peer().await;
    probe_cache().forget(peer);
    let (pool, resolver) = (pool(), resolver());
    let decision = OriginatedOverMtu {
        mtu: MTU,
        pool: &pool,
        ipsec: None,
        resolver: &resolver,
    };
    for _ in 0..20 {
        let uri = peer.to_string();
        let upgrade = decision.upgrade(1900, &uri, peer);
        // Polled once, to the connect, then dropped.
        let _ = tokio::time::timeout(std::time::Duration::ZERO, upgrade).await;
    }
    assert!(
        decision
            .upgrade(1900, &peer.to_string(), peer)
            .await
            .is_some(),
        "not left marked as being probed"
    );
    // A reachable next hop is not remembered: the cache holds nothing for it.
    assert!(
        probe_cache().claim(peer, std::time::Instant::now()).is_ok(),
        "no entry left for the next hop"
    );
}
