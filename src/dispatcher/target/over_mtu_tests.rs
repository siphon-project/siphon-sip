//! An over-MTU request a P-CSCF relays to a UE that registered over UDP and
//! has a security association: it goes over TCP on the P-CSCF's connection from
//! its protected client port to the UE's protected server port, and the UE's
//! answer comes back on it, instead of fragmenting over UDP after a TCP probe
//! at the UE's client port that can never succeed. When that connection cannot
//! be opened the request stays on UDP and the reason is logged.
//!
//! Loopback stands in for the access network: the P-CSCF is 127.0.0.1, the UE
//! 127.0.0.6x with a real TCP listener on its protected server port.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::dispatcher::test_dispatcher::{test_dispatcher, TestDispatcher};
use crate::ipsec::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair,
};
use crate::log_capture::LogBuffer;

const PCSCF: &str = "127.0.0.1";
/// The P-CSCF's protected server port, which its Via names.
const PORT_PS: u16 = 5066;
const UE_PORT_C: u16 = 6100;
/// The S-CSCF the NOTIFY comes from.
const CORE: &str = "198.51.100.12:5060";
const MTU: u16 = 1300;
const FORCED_UDP: &str = "forced UDP over-MTU send";

fn pcscf_ip() -> IpAddr {
    PCSCF.parse().expect("an address")
}

fn free_port(ip: IpAddr) -> u16 {
    std::net::TcpListener::bind((ip, 0))
        .expect("a free port")
        .local_addr()
        .expect("bound")
        .port()
}

/// Abort the test binary if a test wedges, rather than hanging CI. Drop the
/// returned sender when the test is done.
fn watchdog(name: &'static str) -> std::sync::mpsc::Sender<()> {
    let (done, finished) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            finished.recv_timeout(Duration::from_secs(60))
        {
            eprintln!("{name}: wedged for 60 s, aborting");
            std::process::abort();
        }
    });
    done
}

/// A P-CSCF dispatcher with an MTU, a mock-kernel IPsec manager and a pool
/// whose inbound side the test reads.
fn p_cscf() -> (
    TestDispatcher,
    Arc<IpsecManager>,
    flume::Receiver<InboundMessage>,
) {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.mtu = Some(MTU);
    let manager = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&manager));
    let (inbound_tx, inbound) = flume::unbounded();
    dispatcher.state.connection_pool = Arc::new(ConnectionPool::new(
        Arc::new(DashMap::new()),
        inbound_tx,
        SocketAddr::new(pcscf_ip(), 5060),
        None,
        None,
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("an outbound TLS config"),
    ));
    (dispatcher, manager, inbound)
}

async fn install(manager: &IpsecManager, ue: IpAddr, port_us: u16, port_pc: u16) {
    install_with_client_port(manager, ue, UE_PORT_C, port_us, port_pc).await;
}

/// [`install`] with the UE's protected client port `port_uc`.
async fn install_with_client_port(
    manager: &IpsecManager,
    ue: IpAddr,
    port_uc: u16,
    port_us: u16,
    port_pc: u16,
) {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    let sa = SecurityAssociationPair {
        ue_addr: ue,
        pcscf_addr: pcscf_ip(),
        ue_port_c: port_uc,
        ue_port_s: port_us,
        pcscf_port_c: port_pc,
        pcscf_port_s: PORT_PS,
        spi_uc: 71_000 + u32::from(port_uc),
        spi_us: 81_000 + u32::from(port_uc),
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: std::time::Instant::now(),
        created_at: std::time::Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    };
    manager.create_sa_pair(sa).await.expect("installed");
}

/// A reg-event NOTIFY over the MTU, in the UE's dialog, to the UE's protected
/// client port (the Contact rewritten to the source of its UDP REGISTER).
fn notify(ue: IpAddr, call_id: &str) -> SipMessage {
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<reginfo state=\"full\" version=\"1\">{}</reginfo>\r\n",
        "<registration aor=\"sip:001010000000001@ims.example.invalid\" state=\"active\"/>"
            .repeat(18)
    );
    let raw = format!(
        concat!(
            "NOTIFY sip:001010000000001@{ue}:{port_c} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {core};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=core-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 NOTIFY\r\n",
            "Event: reg\r\n",
            "Subscription-State: active;expires=600000\r\n",
            "Contact: <sip:scscf@{core}>\r\n",
            "Content-Type: application/reginfo+xml\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        ue = ue,
        port_c = UE_PORT_C,
        core = CORE,
        call_id = call_id,
        length = body.len(),
        body = body,
    );
    assert!(raw.len() > 1400, "over the MTU: {}", raw.len());
    parse_sip_message_bytes(raw.as_bytes()).expect("the request parses")
}

fn relay(dispatcher: &TestDispatcher, message: &SipMessage) {
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: SocketAddr::new(pcscf_ip(), 5060),
        remote_addr: CORE.parse().expect("an address"),
        data: Bytes::from(message.to_bytes()),
    };
    let server_key = TransactionKey::new(
        message
            .headers
            .get("Via")
            .and_then(|via| via.split("branch=").nth(1))
            .expect("a branch")
            .to_string(),
        message.method().expect("a request").clone(),
        CORE.to_string(),
    );
    tokio::task::block_in_place(|| {
        relay_request(
            message,
            None,
            false,
            &inbound,
            Some(&server_key),
            &dispatcher.state,
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
            None,
        )
    });
}

/// Relay `message` with the log captured on this thread.
fn relay_logged(dispatcher: &TestDispatcher, message: &SipMessage) -> String {
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    relay(dispatcher, message);
    drop(guard);
    log.rendered()
}

/// Read one SIP message off `stream` (headers plus Content-Length body).
async fn read_message(stream: &mut tokio::net::TcpStream) -> String {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&buffer).into_owned();
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length: "))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if buffer.len() >= end + 4 + length {
                return text;
            }
        }
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("the NOTIFY within 5 s")
            .expect("a read");
        assert!(read > 0, "the P-CSCF closed the connection");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// The 200 a UE answers `request` with: its Via, From, To, Call-ID and CSeq.
fn ok_for(request: &str) -> String {
    let mut response = String::from("SIP/2.0 200 OK\r\n");
    for line in request.lines() {
        if ["Via:", "From:", "To:", "Call-ID:", "CSeq:"]
            .iter()
            .any(|name| line.starts_with(name))
        {
            response.push_str(line);
            response.push_str("\r\n");
        }
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    response
}

#[tokio::test(flavor = "multi_thread")]
async fn an_over_mtu_notify_to_a_protected_udp_ue_goes_on_the_p_cscf_tcp_connection() {
    let _watchdog = watchdog("over-MTU NOTIFY over TCP");
    let (dispatcher, manager, inbound) = p_cscf();
    let ue: IpAddr = "127.0.0.61".parse().expect("an address");
    let port_pc = free_port(pcscf_ip());
    let listener = tokio::net::TcpListener::bind((ue, 0))
        .await
        .expect("the UE's protected server port");
    let port_us = listener.local_addr().expect("bound").port();
    install(&manager, ue, port_us, port_pc).await;

    let log = relay_logged(&dispatcher, &notify(ue, "reg-event-61"));
    assert!(!log.contains(FORCED_UDP), "no forced UDP send:\n{log}");

    let (mut stream, peer) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the P-CSCF connects within 5 s")
        .expect("an accepted connection");
    assert_eq!(
        peer,
        SocketAddr::new(pcscf_ip(), port_pc),
        "from the P-CSCF's protected client port"
    );
    let received = read_message(&mut stream).await;
    assert!(received.starts_with("NOTIFY "), "{received}");
    let via = received
        .lines()
        .find(|line| line.starts_with("Via:"))
        .expect("a Via");
    assert!(
        via.contains(&format!("SIP/2.0/TCP {PCSCF}:{PORT_PS}")),
        "the Via names the protected server port over TCP: {via}"
    );
    assert!(
        !dispatcher
            .udp
            .try_iter()
            .any(|sent| sent.destination.ip() == ue),
        "nothing to the UE over UDP"
    );

    // The UE answers on the connection; the answer is read into the inbound
    // path and relayed to the core, so the subscription is not ended by a 408.
    stream
        .write_all(ok_for(&received).as_bytes())
        .await
        .expect("the UE answers");
    let answer = tokio::time::timeout(Duration::from_secs(5), inbound.recv_async())
        .await
        .expect("the answer within 5 s")
        .expect("the pool's inbound channel");
    assert_eq!(answer.remote_addr, SocketAddr::new(ue, port_us));
    assert_eq!(answer.transport, Transport::Tcp);
    let message = parse_sip_message_bytes(&answer.data).expect("the 200 parses");
    tokio::task::block_in_place(|| {
        crate::dispatcher::response::handle_response(answer, message, 200, &dispatcher.state)
    });
    let upstream: Vec<OutboundMessage> = dispatcher.udp.try_iter().collect();
    assert!(
        upstream.iter().any(|sent| {
            sent.destination == CORE.parse::<SocketAddr>().expect("an address")
                && sent.data.starts_with(b"SIP/2.0 200")
        }),
        "the 200 is relayed to the core"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_p_cscf_tcp_connection_the_notify_stays_on_udp_with_the_reason() {
    let _watchdog = watchdog("over-MTU NOTIFY UDP fallback");
    let (dispatcher, manager, _inbound) = p_cscf();
    let ue: IpAddr = "127.0.0.62".parse().expect("an address");
    let port_pc = free_port(pcscf_ip());
    // Nothing listens on the UE's protected server port: the connect is refused.
    let port_us = free_port(ue);
    install(&manager, ue, port_us, port_pc).await;

    let log = relay_logged(&dispatcher, &notify(ue, "reg-event-62"));
    assert!(
        log.contains(FORCED_UDP) && log.contains("could not be opened"),
        "the fallback says why:\n{log}"
    );
    let sent: Vec<OutboundMessage> = dispatcher.udp.try_iter().collect();
    let to_ue: Vec<&OutboundMessage> = sent
        .iter()
        .filter(|sent| sent.destination.ip() == ue && sent.data.starts_with(b"NOTIFY"))
        .collect();
    assert_eq!(to_ue.len(), 1, "the NOTIFY still goes, over UDP");
    assert_eq!(to_ue[0].transport, Transport::Udp);
}

/// No connection reaches `listener` within a moment: nothing was opened to it.
async fn assert_never_connected(listener: &tokio::net::TcpListener) {
    let accepted = tokio::time::timeout(Duration::from_millis(500), listener.accept()).await;
    assert!(
        accepted.is_err(),
        "a TCP connection was opened to the UE: {:?}",
        accepted.map(|result| result.map(|(_, peer)| peer))
    );
}

/// A UE that just de-registered (TS 24.229 clause 5.2.5.1): its pair is kept
/// only for the transactions still pending on it, and the UE has dropped its
/// own. An over-MTU request to it opens no TCP connection over the old set.
///
/// Before: the switch took any pair the destination matched, so it connected
/// from the protected client port to the UE's protected server port, which the
/// UE no longer serves.
#[tokio::test(flavor = "multi_thread")]
async fn an_over_mtu_request_over_a_pair_being_retired_opens_no_tcp_connection() {
    let _watchdog = watchdog("over-MTU NOTIFY over a retiring pair");
    let (dispatcher, manager, _inbound) = p_cscf();
    let ue: IpAddr = "127.0.0.63".parse().expect("an address");
    let port_pc = free_port(pcscf_ip());
    let listener = tokio::net::TcpListener::bind((ue, 0))
        .await
        .expect("the UE's protected server port");
    let port_us = listener.local_addr().expect("bound").port();
    install(&manager, ue, port_us, port_pc).await;
    assert!(manager.retire_pair(
        ue,
        UE_PORT_C,
        Duration::from_secs(30),
        crate::ipsec::retire::RetireCondition::Unregistered,
        "de-registered",
    ));

    let log = relay_logged(&dispatcher, &notify(ue, "reg-event-63"));
    assert!(log.contains("not in use"), "the reason is logged:\n{log}");
    assert_never_connected(&listener).await;
    let sent: Vec<OutboundMessage> = dispatcher.udp.try_iter().collect();
    assert!(
        sent.iter()
            .any(|sent| sent.destination.ip() == ue && sent.data.starts_with(b"NOTIFY")),
        "the NOTIFY still goes, over UDP"
    );
}

/// The destination is the client port of a pair an authentication still in
/// progress set up beside the set in use: the UE may not hold it yet, so
/// nothing is opened over it.
#[tokio::test(flavor = "multi_thread")]
async fn an_over_mtu_request_to_a_pending_pairs_flow_opens_no_tcp_connection() {
    let _watchdog = watchdog("over-MTU NOTIFY to a pending pair");
    let (dispatcher, manager, _inbound) = p_cscf();
    let ue: IpAddr = "127.0.0.64".parse().expect("an address");
    let port_pc = free_port(pcscf_ip());
    let listener = tokio::net::TcpListener::bind((ue, 0))
        .await
        .expect("the UE's protected server port");
    let port_us = listener.local_addr().expect("bound").port();
    install_with_client_port(&manager, ue, 6200, port_us, port_pc).await;
    install(&manager, ue, port_us, port_pc).await;
    assert!(
        manager.is_pending(&ue, UE_PORT_C),
        "the new pair is pending"
    );

    relay_logged(&dispatcher, &notify(ue, "reg-event-64"));
    assert_never_connected(&listener).await;
}

/// The UE's pair is gone and only its binding still names its protected
/// ports: no TCP path is taken to them, over the association or probed in
/// clear. The request itself is refused at egress, as any request in clear to
/// such a port is.
#[tokio::test(flavor = "multi_thread")]
async fn an_over_mtu_request_to_the_ports_of_a_deleted_pair_opens_no_tcp_connection() {
    let _watchdog = watchdog("over-MTU NOTIFY to a deleted pair");
    let (dispatcher, manager, _inbound) = p_cscf();
    let ue: IpAddr = "127.0.0.65".parse().expect("an address");
    let port_pc = free_port(pcscf_ip());
    // The request goes to the client port the binding names; a listener there
    // answers the unbound reachability probe.
    let listener = tokio::net::TcpListener::bind((ue, UE_PORT_C))
        .await
        .expect("the UE's protected client port");
    let port_us = free_port(ue);
    install(&manager, ue, port_us, port_pc).await;
    manager
        .delete_sa_pair(&ue, UE_PORT_C)
        .await
        .expect("deleted");

    relay_logged(&dispatcher, &notify(ue, "reg-event-65"));
    assert_never_connected(&listener).await;
}
