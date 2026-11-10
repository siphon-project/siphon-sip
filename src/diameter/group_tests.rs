use super::*;
use crate::config::{DiameterApplication, DiameterConfig};
use crate::diameter::peer::{DiameterPeer, PeerConfig, PeerState};
use std::sync::Arc;

fn register(manager: &DiameterManager, name: &str, tenant: Option<&str>) -> Arc<DiameterClient> {
    let config = PeerConfig {
        host: "127.0.0.1".into(),
        port: 3868,
        origin_host: "node.example.net".into(),
        origin_realm: "example.net".into(),
        destination_host: None,
        destination_realm: "example.net".into(),
        local_ip: "127.0.0.1".parse().unwrap(),
        application_ids: vec![],
        watchdog_interval: 30,
        reconnect_delay: 5,
        source_address: None,
        lifecycle: Default::default(),
        product_name: "test".into(),
        firmware_revision: 1,
    };
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let client = Arc::new(DiameterClient::new(Arc::new(DiameterPeer::new_for_test(
        config, tx,
    ))));
    if let Some(tenant) = tenant {
        manager.register_backend(tenant, name, client.clone());
    } else {
        manager.register(name.into(), client.clone());
    }
    client
}

#[test]
fn diameter_group_config() {
    let defaults: DiameterConfig = serde_saphyr::from_str("{}").unwrap();
    assert_eq!(defaults.resolve_interval, 30);
    let config: DiameterConfig = serde_saphyr::from_str("resolve_interval: 7\npeers:\n- {name: a, host: example.net, destination_realm: example.net}\n- {name: b, host: example.net, destination_realm: example.net, all_addresses: true}\nservers:\n- {name: a, host: example.net}\n- {name: b, host: example.net, all_addresses: true}\ntenants:\n  t:\n    identity: {}\n    servers:\n    - {name: c, host: example.net, all_addresses: true}\n").unwrap();
    assert_eq!(config.resolve_interval, 7);
    assert!(!config.peers[0].all_addresses);
    assert!(config.peers[1].all_addresses);
    assert!(!config.servers[0].all_addresses);
    assert!(config.servers[1].all_addresses);
    assert!(config.tenants["t"].servers[0].all_addresses);
}

#[test]
fn diameter_group_routes_expand_and_skip_closed() {
    let config: DiameterConfig =
        serde_saphyr::from_str("routes:\n- {application: cx, peers: [dra]}").unwrap();
    let manager = DiameterManager::with_routes(&config.routes);
    manager.set_group(
        None,
        "dra",
        vec!["dra@192.0.2.1".into(), "dra@192.0.2.2".into()],
    );
    let a = register(&manager, "dra@192.0.2.1", None);
    let b = register(&manager, "dra@192.0.2.2", None);
    assert!(Arc::ptr_eq(
        &manager
            .route_client(&DiameterApplication::Cx, None)
            .unwrap(),
        &a
    ));
    assert!(Arc::ptr_eq(
        &manager
            .route_client(&DiameterApplication::Cx, None)
            .unwrap(),
        &b
    ));
    assert_eq!(manager.route_clients(&DiameterApplication::Cx).len(), 2);
    a.peer().set_state_for_test(PeerState::Closed);
    assert!(Arc::ptr_eq(&manager.client("dra").unwrap(), &b));
    assert_eq!(manager.route_clients(&DiameterApplication::Cx).len(), 1);
    b.peer().set_state_for_test(PeerState::Closed);
    assert!(manager.live_client("dra").is_none());
    assert!(manager
        .route_client(&DiameterApplication::Cx, None)
        .is_none());
}

#[test]
fn diameter_group_pool_binds_member_and_rebinds() {
    let manager = Arc::new(DiameterManager::new());
    manager.set_group(
        Some("t"),
        "dra",
        vec!["dra@192.0.2.1".into(), "dra@192.0.2.2".into()],
    );
    register(&manager, "dra@192.0.2.1", Some("t"));
    register(&manager, "dra@192.0.2.2", Some("t"));
    let pool = pool::PeerPool::new("t", manager.clone(), vec!["dra".into()]);
    assert_eq!(pool.live_count(), 2);
    let ttl = std::time::Duration::from_secs(60);
    let (name, client) = pool.pick_sticky_named("session", ttl).unwrap();
    assert!(name.starts_with("dra@"));
    for _ in 0..4 {
        assert_eq!(pool.pick_sticky_named("session", ttl).unwrap().0, name);
    }
    client.peer().set_state_for_test(PeerState::Closed);
    assert_ne!(pool.pick_sticky_named("session", ttl).unwrap().0, name);
    assert!(pool
        .pick_weighted(&std::collections::HashMap::new())
        .is_some());
    assert!(manager.live_backend("other", "dra").is_none());
    manager
        .live_backend("t", "dra")
        .unwrap()
        .peer()
        .set_state_for_test(PeerState::Closed);
    assert_eq!(pool.live_count(), 0);
    assert!(pool.pick_round_robin().is_none());
    assert!(pool
        .pick_weighted(&std::collections::HashMap::new())
        .is_none());
    assert!(pool.pick_sticky("session", ttl).is_none());
}

struct Resolver(
    std::sync::Mutex<std::collections::VecDeque<std::io::Result<Vec<std::net::SocketAddr>>>>,
);
impl group::Resolver for Resolver {
    fn resolve<'a>(&'a self, _host: &'a str, _port: u16) -> group::Resolution<'a> {
        Box::pin(async { self.0.lock().unwrap().pop_front().unwrap() })
    }
}

#[tokio::test]
async fn diameter_group_reconciles_dns_and_preserves_members_on_error() {
    let a = "127.0.0.1:3868".parse().unwrap();
    let b = "127.0.0.2:3868".parse().unwrap();
    let resolver = Resolver(std::sync::Mutex::new(std::collections::VecDeque::from([
        Ok(vec![a]),
        Ok(vec![a, b, b]),
        Err(std::io::Error::other("DNS unavailable")),
        Ok(vec![b]),
        Ok(vec![]),
    ])));
    let manager = Arc::new(DiameterManager::new());
    let mut supervisor = group::Supervisor::new(manager.clone(), None, "dra".into());
    let tasks = std::sync::Mutex::new(Vec::new());
    let spawn = |name: String, _address| {
        register(&manager, &name, None);
        let task = tokio::spawn(std::future::pending());
        tasks.lock().unwrap().push(task.abort_handle());
        task
    };
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    assert_eq!(manager.peer_count(), 1);
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    assert_eq!(manager.peer_count(), 2);
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    assert_eq!(manager.peer_count(), 2);
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    assert_eq!(manager.peer_count(), 1);
    assert!(manager.client("dra@127.0.0.1").is_none());
    assert!(tasks.lock().unwrap()[0].is_finished());
    assert!(!tasks.lock().unwrap()[1].is_finished());
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    assert!(tasks.lock().unwrap()[1].is_finished());
    drop(supervisor);
    assert_eq!(manager.peer_count(), 0);
}

#[tokio::test]
async fn diameter_group_two_listeners_receive_requests_and_removal_closes_connection() {
    use std::time::Duration;
    let manager = Arc::new(DiameterManager::new());
    let template = register(&manager, "template", None).peer().config().clone();
    manager.deregister("template");
    let mut addresses = Vec::new();
    let mut accepts = Vec::new();
    for _ in 0..2 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        addresses.push(listener.local_addr().unwrap());
        let config = template.clone();
        accepts.push(tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            peer::accept(stream.into(), config).await.unwrap()
        }));
    }
    let resolver = Resolver(std::sync::Mutex::new(std::collections::VecDeque::from([
        Ok(addresses.clone()),
        Ok(vec![addresses[1]]),
    ])));
    let mut supervisor = group::Supervisor::new(manager.clone(), None, "dra".into());
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let spawn = |name, address: std::net::SocketAddr| {
        let mut config = template.clone();
        config.host = address.ip().to_string();
        config.port = address.port();
        client_connection::spawn(name, config, manager.clone(), tx.clone())
    };
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    let mut remote_peers = Vec::new();
    let mut responses = Vec::new();
    for accept in accepts {
        let (peer, mut incoming) = tokio::time::timeout(Duration::from_secs(5), accept)
            .await
            .unwrap()
            .unwrap();
        remote_peers.push(peer.clone());
        responses.push(tokio::spawn(async move {
            let request = incoming.recv().await.unwrap();
            let answer = codec::encode_diameter_message(
                0,
                request.command_code,
                request.application_id,
                request.hop_by_hop,
                request.end_to_end,
                &codec::encode_avp_u32(dictionary::avp::RESULT_CODE, 2001),
            );
            peer.send_response(answer).await.unwrap();
        }));
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while manager.open_members(None, "dra").len() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for id in 1..=2 {
        let client = manager.live_client("dra").unwrap();
        let request = codec::encode_diameter_message(codec::FLAG_REQUEST, 300, 0, id, id, &[]);
        tokio::time::timeout(Duration::from_secs(5), client.peer().send_request(request))
            .await
            .unwrap()
            .unwrap();
    }
    for response in responses {
        response.await.unwrap();
    }
    supervisor
        .refresh(&resolver, "example.net", 3868, &spawn)
        .await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while remote_peers[0].is_open() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(manager.peer_count(), 1);
    // The member that left the group was told why (RFC 6733 section 5.4.3:
    // DO_NOT_WANT_TO_TALK_TO_YOU), not just dropped.
    assert_eq!(remote_peers[0].remote_disconnect_cause(), Some(2));
    assert_eq!(remote_peers[1].remote_disconnect_cause(), None);
}

#[test]
fn diameter_group_route_algorithm_and_group_cursors_are_independent() {
    let config: DiameterConfig = serde_saphyr::from_str(
        "routes:\n- {application: cx, peers: [dra, other], algorithm: round_robin}",
    )
    .unwrap();
    let manager = DiameterManager::with_routes(&config.routes);
    manager.set_group(
        None,
        "dra",
        vec!["dra@192.0.2.1".into(), "dra@192.0.2.2".into()],
    );
    let a = register(&manager, "dra@192.0.2.1", None);
    let b = register(&manager, "dra@192.0.2.2", None);
    let other = register(&manager, "other", None);
    for expected in [&a, &other, &b, &other, &a] {
        assert!(Arc::ptr_eq(
            &manager
                .route_client(&DiameterApplication::Cx, None)
                .unwrap(),
            expected
        ));
    }
}

#[test]
fn diameter_group_pool_weights_apply_to_groups_and_rotate_members() {
    let manager = Arc::new(DiameterManager::new());
    manager.set_group(
        Some("t"),
        "dra",
        vec!["dra@192.0.2.1".into(), "dra@192.0.2.2".into()],
    );
    register(&manager, "dra@192.0.2.1", Some("t"));
    register(&manager, "dra@192.0.2.2", Some("t"));
    register(&manager, "other", Some("t"));
    let pool = pool::PeerPool::new("t", manager, vec!["dra".into(), "other".into()]);
    let weights = std::collections::HashMap::from([("dra".into(), 2), ("other".into(), 1)]);
    let picks: Vec<_> = (0..6)
        .map(|_| pool.pick_weighted_named(&weights).unwrap().0)
        .collect();
    assert_eq!(
        picks,
        [
            "dra@192.0.2.1",
            "dra@192.0.2.2",
            "other",
            "dra@192.0.2.1",
            "dra@192.0.2.2",
            "other"
        ]
    );
    let first = pool.pick_round_robin_named().unwrap().0;
    assert!(first.starts_with("dra@"));
    assert_eq!(pool.pick_round_robin_named().unwrap().0, "other");
    assert_ne!(pool.pick_round_robin_named().unwrap().0, first);
}
