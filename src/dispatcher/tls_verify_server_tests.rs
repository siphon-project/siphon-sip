//! A gateway's or a dial target's `verify_server` reaches the connection pool.
//!
//! The pool's own tests prove a verified handshake checks what it should. These
//! prove the setting gets there: from a gateway destination through RFC 3263
//! resolution and `send_to_target`, from a B-leg dial through
//! `b2bua_send_b_leg_invite`, and that `send_to_target` does not route a
//! verified send over a connection it found in the stream registry, which
//! would skip the check entirely.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::transport::outbound_tls::tests::{
    dns, ip, leaf, spawn_peer, test_ca, trusting, Peer, ROUTED_HOST,
};
use crate::transport::outbound_tls::{build_outbound_tls_configs, ServerVerification};

const CALLER: &str = "192.0.2.10:5060";

/// A dispatcher whose pool trusts `verification`'s roots.
fn dispatcher_trusting(verification: &ServerVerification) -> TestDispatcher {
    let mut dispatcher = test_dispatcher();
    let configs =
        build_outbound_tls_configs(None, crate::config::TlsMethod::default(), verification)
            .expect("outbound tls configs");
    dispatcher.state.connection_pool = Arc::new(
        ConnectionPool::new(
            Arc::new(DashMap::new()),
            flume::unbounded().0,
            "127.0.0.1:5060".parse().expect("addr"),
            None,
            Some(dispatcher.state.stream_connections.clone()),
            None,
            Arc::clone(&configs.unverified),
        )
        .with_tls_configs(configs),
    );
    dispatcher
}

fn options() -> Bytes {
    Bytes::from_static(b"OPTIONS sip:gw.example.net SIP/2.0\r\nContent-Length: 0\r\n\r\n")
}

fn tls_target(peer: &Peer, server_name: Option<&str>, verify_server: Option<bool>) -> RelayTarget {
    RelayTarget {
        address: peer.address,
        transport: Some(Transport::Tls),
        server_name: server_name.map(str::to_string),
        verify_server,
    }
}

fn send(dispatcher: &TestDispatcher, target: &RelayTarget) -> SendOutcome {
    send_to_target(
        options(),
        target,
        Transport::Tls,
        ConnectionId::default(),
        None,
        &dispatcher.state,
    )
}

/// Wait until the peer has completed `count` handshakes, or fail.
async fn handshakes_reach(peer: &Peer, count: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while peer.handshakes.load(Ordering::SeqCst) < count {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer saw {} handshakes, expected {count}",
            peer.handshakes.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn send_to_target_verifies_when_the_target_asks_and_not_otherwise() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let dispatcher = dispatcher_trusting(&verification);

    let verified = send(
        &dispatcher,
        &tls_target(&peer, Some(ROUTED_HOST), Some(true)),
    );
    assert!(
        verified.delivery_failed,
        "a certificate from an untrusted CA must fail the send the way a refused connect does"
    );

    let unverified = send(&dispatcher, &tls_target(&peer, Some(ROUTED_HOST), None));
    assert!(
        !unverified.delivery_failed,
        "verification is off by default"
    );
    handshakes_reach(&peer, 1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verified_send_never_rides_a_connection_from_the_stream_registry() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![dns(ROUTED_HOST)]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let dispatcher = dispatcher_trusting(&verification);

    // An unverified send opens a connection the registry now offers for reuse.
    assert!(!send(&dispatcher, &tls_target(&peer, Some(ROUTED_HOST), None)).delivery_failed);
    assert!(dispatcher
        .state
        .stream_connections
        .reuse(peer.address, Transport::Tls)
        .is_some());

    // Riding it would have succeeded without a check.
    assert!(
        send(
            &dispatcher,
            &tls_target(&peer, Some(ROUTED_HOST), Some(true))
        )
        .delivery_failed,
        "a verified send must open its own connection, not reuse an unverified one"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gateway_verify_server_wires_through_resolution_to_the_pool() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![ip("127.0.0.1")]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);
    let dispatcher = dispatcher_trusting(&verification);

    let gateway_uri = format!("sip:{};transport=tls", peer.address);
    let manager = crate::gateway::DispatcherManager::new();
    manager.add_group(crate::gateway::DispatcherGroup::new(
        "trunks".to_string(),
        crate::gateway::Algorithm::Weighted,
        vec![crate::gateway::Destination::new(
            gateway_uri.clone(),
            peer.address,
            Transport::Tls,
            1,
            1,
        )
        .with_verify_server(Some(true))],
    ));

    let targets =
        resolve_candidates_inner(&gateway_uri, &dispatcher.state.dns_resolver, Some(&manager));
    let target = targets
        .into_iter()
        .next()
        .expect("the gateway URI resolves");
    assert_eq!(
        target.verify_server,
        Some(true),
        "the gateway's setting rides the target"
    );
    assert_eq!(target.transport, Some(Transport::Tls));
    assert!(
        send(&dispatcher, &target).delivery_failed,
        "the gateway's verify_server must reach the pool"
    );
    assert_eq!(peer.handshakes.load(Ordering::SeqCst), 0);

    // Not a gateway: the same address resolves with no setting of its own.
    let bare = resolve_candidates_inner(&gateway_uri, &dispatcher.state.dns_resolver, None);
    assert_eq!(bare.first().and_then(|target| target.verify_server), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dial_branch_verify_server_reaches_the_pool() {
    let issuing = test_ca("issuing-ca");
    let trusted = test_ca("some-other-ca");
    let peer = spawn_peer(&leaf(&issuing, vec![ip("127.0.0.1")]), None, false).await;
    let (_directory, verification) = trusting(&trusted, false);

    let dial = |verify_server: Option<bool>| {
        let dispatcher = dispatcher_trusting(&verification);
        let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
            format!("verify-{verify_server:?}@192.0.2.10"),
            "caller-tag".to_string(),
            "z9hG4bK-verify".to_string(),
            LegTransport {
                remote_addr: CALLER.parse().expect("addr"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        let caller_invite = parse_sip_message_bytes(
            concat!(
                "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-verify\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>\r\n",
                "Call-ID: verify@192.0.2.10\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.10:5060>\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("the caller INVITE parses");
        b2bua_send_b_leg_invite(
            &call_id,
            &format!("sip:15550100042@{};transport=tls", peer.address),
            None,
            None,
            &[],
            None,
            None,
            &caller_invite,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            verify_server,
            &[],
            &dispatcher.state,
        )
    };

    // Verified against an untrusted CA: no handshake completes.
    let _ = dial(Some(true));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        peer.handshakes.load(Ordering::SeqCst),
        0,
        "the branch's verify_server must reach the pool and refuse the peer"
    );

    // The same branch without it connects, as before.
    let _ = dial(None);
    handshakes_reach(&peer, 1).await;
}
