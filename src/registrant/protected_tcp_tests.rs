use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::super::address::LocalAddrQuery;
use super::super::test_support;
use super::*;
use crate::transport::acl::TransportAcl;
use crate::transport::pool::ConnectionPool;
use crate::transport::send_queue::SendQueue;
use crate::transport::ue_sockets::UeSockets;
use crate::transport::ue_streams::UeTcpContext;
use crate::transport::{ConnectionId, InboundMessage, StreamConnections};

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .expect("a free port")
}

/// A UDP IMS UE on `ue_ip` whose protected server port is `port_s` (client
/// port `port_c` and the two ports above the higher of the two).
fn udp_ue(index: u32, ue_ip: IpAddr, port_c: u16, port_s: u16) -> RegistrantEntry {
    let mut entry = test_support::ue(index, Some(ue_ip));
    entry.ue_ipsec = Some(super::super::UeIpsec::new(
        port_c,
        port_s,
        crate::ipsec::IntegrityAlgorithm::HmacSha1,
        crate::ipsec::EncryptionAlgorithm::Null,
    ));
    entry
}

fn plan_of(manager: &RegistrantManager, process_ue_ip: Option<IpAddr>) -> UeTcpPlan {
    manager.ue_stream_plan_with(5060, process_ue_ip, true).0
}

#[test]
fn a_udp_entry_listens_for_tcp_once_it_holds_an_sa_set() {
    let manager = test_support::manager();
    let ue_ip = ip("192.0.2.77");
    let aor = test_support::impu(1);
    manager.add(test_support::ue(1, Some(ue_ip)));
    let before = plan_of(&manager, None);
    assert_eq!(
        before.listeners,
        HashSet::new(),
        "no set yet: the P-CSCF has nothing to connect to"
    );
    assert_eq!(
        before.sources.len(),
        3,
        "the client ports are bindable from the first REGISTER on"
    );
    assert!(before.keep.is_empty());
    // Without an MTU the UE opens no connection of its own: no sources.
    let (without_mtu, _) = manager.ue_stream_plan_with(5060, None, false);
    assert!(without_mtu.sources.is_empty());

    super::super::rotate_sa_set(&manager, &aor);
    let plan = plan_of(&manager, None);
    let addr = |text: &str| -> SocketAddr { text.parse().expect("addr") };
    assert_eq!(plan.listeners, [addr("192.0.2.77:6101")].into());
    // The UE's own TCP connection (over-MTU REGISTER) leaves from a client
    // port: the three it rotates through are bindable, the held set's kept.
    assert_eq!(
        plan.sources,
        [
            addr("192.0.2.77:6100"),
            addr("192.0.2.77:6102"),
            addr("192.0.2.77:6103"),
        ]
        .into()
    );
    let held = manager.ue_egress(&aor, ue_ip).expect("a set").local;
    assert_eq!(plan.keep, [held].into());
}

#[test]
fn the_listener_stays_through_a_rotation_and_goes_with_the_entry() {
    let manager = test_support::manager();
    let ue_ip = ip("192.0.2.77");
    let aor = test_support::impu(1);
    manager.add(test_support::ue(1, Some(ue_ip)));
    super::super::rotate_sa_set(&manager, &aor);
    let before = plan_of(&manager, None);
    let first = manager.ue_egress(&aor, ue_ip).expect("a set").local;

    // TS 33.203 7.4.0: only the client port moves, the server port stays.
    super::super::rotate_sa_set(&manager, &aor);
    let after = plan_of(&manager, None);
    let second = manager.ue_egress(&aor, ue_ip).expect("the new set").local;
    assert_ne!(first, second);
    assert_eq!(after.listeners, before.listeners);
    assert!(after.keep.contains(&second));

    manager.remove(&aor);
    assert_eq!(plan_of(&manager, None).listeners, HashSet::new());
}

#[test]
fn an_entry_on_the_process_address_listens_there_unless_it_needs_its_own() {
    let manager = test_support::manager();
    let process = ip("192.0.2.1");
    let aor = test_support::impu(1);
    manager.add(test_support::ue(1, None));
    super::super::rotate_sa_set(&manager, &aor);
    let listeners = plan_of(&manager, Some(process)).listeners;
    assert_eq!(
        listeners,
        ["192.0.2.1:6101".parse().expect("addr")].into(),
        "the process's UE address"
    );
    assert_eq!(
        plan_of(&manager, None).listeners,
        HashSet::new(),
        "no process address known"
    );
    assert_eq!(
        plan_of(&manager, Some(ip("0.0.0.0"))).listeners,
        HashSet::new(),
        "a wildcard is no address to listen on"
    );
    manager.remove(&aor);

    let waiting = test_support::manager();
    waiting.add(test_support::ue(2, None).requiring_local_addr());
    super::super::rotate_sa_set(&waiting, &test_support::impu(2));
    assert_eq!(plan_of(&waiting, Some(process)).listeners, HashSet::new());
}

#[test]
fn a_digest_entry_and_a_tcp_entry_add_nothing_here() {
    let manager = test_support::manager();
    manager.add(test_support::trunk("sip:trunk@carrier.example"));
    let mut tcp = test_support::ue(1, Some(ip("192.0.2.78")));
    tcp.transport = Transport::Tcp;
    manager.add(tcp);
    let mut plan = UeTcpPlan::default();
    for entry in manager.entries.iter() {
        RegistrantManager::plan_protected_tcp(&entry, Some(ip("192.0.2.1")), true, &mut plan);
    }
    assert_eq!(plan, UeTcpPlan::default());
}

// --- the over-MTU switch of a REGISTER ---

fn refresh_of(manager: &RegistrantManager, aor: &str) -> super::super::BuiltRegister {
    let listen =
        std::collections::HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().unwrap())]);
    let defaults = super::super::EgressDefaults::new("192.0.2.1:5060".parse().unwrap(), &listen);
    manager
        .build_register(aor, defaults, 600000)
        .expect("a REGISTER")
}

fn with_body(mut entry: RegistrantEntry, length: usize) -> RegistrantEntry {
    entry = entry.with_register_extras(
        super::super::register_extras::RegisterExtras::new(
            Some(("text/plain".to_string(), vec![b'x'; length])),
            Vec::new(),
        )
        .expect("extras"),
    );
    entry
}

#[test]
fn a_register_over_its_set_over_the_threshold_takes_tcp_and_says_so_in_its_via() {
    let manager = test_support::manager();
    let ue_ip = ip("192.0.2.77");
    let aor = test_support::impu(1);
    manager.add(with_body(test_support::ue(1, Some(ue_ip)), 1500));
    super::super::rotate_sa_set(&manager, &aor);
    let held = manager.ue_egress(&aor, ue_ip).expect("a set");

    let built = refresh_of(&manager, &aor);
    assert!(built.over_sa_set && built.protected);
    let serialized = built.message.to_bytes().len();
    assert!(serialized > 1500, "{serialized}");
    let path = built.over_mtu_tcp(Some(1280)).expect("over the threshold");
    assert_eq!(path.source, held.local, "from the protected client port");
    assert_eq!(
        path.destination, held.destination,
        "to the P-CSCF's port_ps"
    );
    assert_eq!(built.over_mtu_tcp(None), None, "no MTU, no switch");

    let branch = built.branch.clone();
    let tcp = built.over_tcp(&path);
    assert_eq!(tcp.transport, Transport::Tcp);
    assert_eq!(
        tcp.message.headers.get("Via"),
        Some(&format!(
            "SIP/2.0/TCP 192.0.2.77:6101;branch={branch};rport"
        )),
        "RFC 3261 18.1.1: the top Via follows the transport; sent-by stays port_us"
    );
    assert_eq!(
        tcp.message.headers.get("Call-ID"),
        Some(&manager_call_id(&manager, &aor))
    );
    // Already over a stream transport: nothing to switch.
    assert_eq!(tcp.over_mtu_tcp(Some(1280)), None);
}

fn manager_call_id(manager: &RegistrantManager, aor: &str) -> String {
    manager.entries.get(aor).expect("entry").call_id.clone()
}

#[test]
fn the_threshold_is_the_relays_not_a_copy() {
    // Exactly `mtu - 200` is not over, one byte more is (RFC 3261 18.1.1).
    let manager = test_support::manager();
    let aor = test_support::impu(1);
    manager.add(test_support::ue(1, Some(ip("192.0.2.77"))));
    super::super::rotate_sa_set(&manager, &aor);
    let built = refresh_of(&manager, &aor);
    let length = built.message.to_bytes().len();
    let mtu_at = |len: usize| u16::try_from(len + 200).expect("an MTU");
    assert_eq!(
        built.over_mtu_tcp(Some(mtu_at(length))),
        None,
        "at the boundary"
    );
    assert!(
        built.over_mtu_tcp(Some(mtu_at(length - 1))).is_some(),
        "one over"
    );
}

#[test]
fn only_a_register_over_a_set_is_switched() {
    let manager = test_support::manager();
    let aor = test_support::impu(1);
    manager.add(with_body(test_support::ue(1, Some(ip("192.0.2.77"))), 1500));
    // The initial REGISTER goes to the plain port, protected by nothing.
    let initial = refresh_of(&manager, &aor);
    assert!(!initial.over_sa_set);
    assert_eq!(initial.over_mtu_tcp(Some(1280)), None);
    // A digest trunk is no UE.
    let trunk = test_support::manager();
    trunk.add(test_support::trunk("sip:trunk@carrier.example"));
    assert_eq!(
        refresh_of(&trunk, "sip:trunk@carrier.example").over_mtu_tcp(Some(576)),
        None
    );
}

// --- on real sockets ---

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

async fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

/// What the P-CSCF does for a request over the MTU: a TCP connection to the
/// UE's protected server port from its own protected client port.
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

const NOTIFY: &[u8] = concat!(
    "NOTIFY sip:001010000000001@127.0.0.5:6101 SIP/2.0\r\n",
    "Via: SIP/2.0/TCP 127.0.0.1:5066;branch=z9hG4bK-pcscf-notify\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org>;tag=p1\r\n",
    "To: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=u1\r\n",
    "Call-ID: reg-event@example.test\r\n",
    "CSeq: 7 NOTIFY\r\n",
    "Event: reg\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
)
.as_bytes();

/// The P-CSCF's over-MTU connection to a UDP entry's protected server port is
/// accepted (before: connection refused), the request reaches the dispatcher
/// attributed to the entry by the address and port it arrived on, exactly as
/// one on the protected UDP port, and the answer goes back on the connection.
/// Closing follows the SA set: the entry's removal closes listener and
/// connection.
#[tokio::test]
async fn a_pcscf_connection_to_a_udp_entry_is_accepted_answered_and_closed_with_its_sas() {
    let fixture = fixture();
    let manager = test_support::manager();
    let ue_ip = ip("127.0.0.5");
    let (port_c, port_s) = (free_port(), free_port());
    let aor = test_support::impu(1);
    manager.add(udp_ue(1, ue_ip, port_c, port_s));
    super::super::rotate_sa_set(&manager, &aor);
    let ue_server = SocketAddr::new(ue_ip, port_s);
    assert!(!fixture.sockets.contains_tcp(&ue_server));

    fixture.sockets.reconcile_tcp(&plan_of(&manager, None));
    assert!(fixture.sockets.contains_tcp(&ue_server));

    let (mut pcscf, pcscf_client) = pcscf_connects(ue_server).await;
    pcscf
        .write_all(NOTIFY)
        .await
        .expect("the request is written");
    let inbound = tokio::time::timeout(Duration::from_secs(2), fixture.inbound.recv_async())
        .await
        .expect("the request arrives")
        .expect("the channel is open");
    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(inbound.local_addr, ue_server);
    assert_eq!(inbound.remote_addr, pcscf_client);
    assert_eq!(&inbound.data[..], NOTIFY);
    // The same attribution as a request on the protected UDP port: the entry
    // is found by the address and port the message arrived on.
    assert_eq!(
        manager.find_by_local(LocalAddrQuery::Socket(inbound.local_addr)),
        Some(aor.clone())
    );

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
    assert_eq!(&answer, response, "answered over the connection");

    // A re-authentication moves the client port, not the server port: the
    // connection is undisturbed.
    super::super::rotate_sa_set(&manager, &aor);
    fixture.sockets.reconcile_tcp(&plan_of(&manager, None));
    assert_eq!(fixture.sockets.tcp_len(), (1, 1));

    // De-registration ends the entry and its SA sets: the listener and the
    // connection it accepted go.
    manager.remove(&aor);
    fixture.sockets.reconcile_tcp(&plan_of(&manager, None));
    let mut buffer = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(2), pcscf.read(&mut buffer))
        .await
        .expect("the connection ends");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(wait_until(|| fixture.sockets.tcp_len() == (0, 0)).await);
    assert!(!fixture.sockets.contains_tcp(&ue_server));
}

/// Leak gate: register, be connected to, re-authenticate and de-register, over
/// and over: no listener, no accepted connection, no pool connection from the
/// UE's address and no connection-map entry is left behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn register_and_de_register_cycles_return_every_store_to_baseline() {
    let fixture = fixture();
    let manager = test_support::manager();
    let ue_ip = ip("127.0.0.6");
    let aor = test_support::impu(1);
    let mut held = Vec::new();
    for cycle in 0..20 {
        let (port_c, port_s) = (free_port(), free_port());
        manager.add(udp_ue(1, ue_ip, port_c, port_s));
        super::super::rotate_sa_set(&manager, &aor);
        fixture.sockets.reconcile_tcp(&plan_of(&manager, None));

        let ue_server = SocketAddr::new(ue_ip, port_s);
        let (mut pcscf, _) = pcscf_connects(ue_server).await;
        pcscf.write_all(NOTIFY).await.expect("written");
        assert!(
            wait_until(|| fixture.sockets.tcp_len() == (1, 1)).await,
            "cycle {cycle}: {:?}",
            fixture.sockets.tcp_len()
        );
        let _ = fixture.inbound.drain();

        super::super::rotate_sa_set(&manager, &aor);
        fixture.sockets.reconcile_tcp(&plan_of(&manager, None));
        assert_eq!(fixture.sockets.tcp_len(), (1, 1), "cycle {cycle}: rotation");

        manager.remove(&aor);
        fixture.sockets.reconcile_tcp(&plan_of(&manager, None));
        assert!(
            wait_until(|| fixture.sockets.tcp_len() == (0, 0)
                && fixture.pool.connections_bound_on(ue_ip) == 0)
            .await,
            "cycle {cycle}: listeners/accepted {:?}, pool {}",
            fixture.sockets.tcp_len(),
            fixture.pool.connections_bound_on(ue_ip)
        );
        // The P-CSCF keeps its end open: only the listener closing ends it.
        held.push(pcscf);
    }
    assert!(wait_until(|| fixture.connection_map.is_empty()).await);
}
