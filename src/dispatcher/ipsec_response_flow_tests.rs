//! A P-CSCF answering a UE over IPsec on UDP: every response to a request the
//! UE sent from its protected client port goes from the P-CSCF's protected
//! client port to the UE's protected server port (3GPP TS 33.203 clause 7.1,
//! UDP case; TS 24.229 clause 5.2.2.2 NOTE 3), whether siphon answered it
//! itself, relayed it, rejected the request, or retransmitted it. Over TCP the
//! response stays on the connection the request came in on.
//!
//! The harness listens on 192.0.2.1:5060, made the protected server port here,
//! with 5064 the protected client port.

use std::net::SocketAddr;
use std::time::Duration;

use super::ipsec_lifecycle_tests::{install, p_cscf, ANSWER, REGISTRAR, RELAY};
use super::proxy_dialog_state_tests::{inbound, response_to, Proxy};
use super::*;
use crate::ipsec::{IpsecManager, SaProtocol};

/// The P-CSCF's protected client port: where every UDP response leaves from.
const PORT_PC: &str = "192.0.2.1:5064";
/// The P-CSCF's protected server port: where the UE's requests arrive.
const PORT_PS: &str = "192.0.2.1:5060";

/// One outbound message as the transport would have been handed it.
struct Sent {
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    transport: Transport,
    connection_id: ConnectionId,
    status_code: Option<u16>,
}

fn drain(receiver: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = receiver.try_recv() {
        for frame in outbound.frames() {
            let message =
                parse_sip_message_bytes(frame).expect("siphon sent a message that parses");
            sent.push(Sent {
                destination: outbound.destination,
                source_local_addr: outbound.source_local_addr,
                transport: outbound.transport,
                connection_id: outbound.connection_id,
                status_code: message.status_code(),
            });
        }
    }
    sent
}

/// The responses among `sent` that went to the UE at `ue_ip`.
fn responses_to_ue(sent: &[Sent], ue_ip: std::net::IpAddr) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.status_code.is_some() && sent.destination.ip() == ue_ip)
        .collect()
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address literal")
}

/// A request from the UE's client port, its Via naming the UE's protected
/// server port as TS 24.229 clause 5.1.1.2 has the UE do.
fn options(ue: SocketAddr, branch: &str, max_forwards: u32, transport: &str) -> String {
    format!(
        concat!(
            "OPTIONS sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/{transport} {host}:{port_s};branch=z9hG4bK-{branch};rport\r\n",
            "Max-Forwards: {max_forwards}\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "To: <sip:ims.example.invalid>\r\n",
            "Call-ID: {branch}@ue\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        transport = transport,
        host = ue.ip(),
        port_s = ue.port() + 1,
        branch = branch,
        max_forwards = max_forwards,
    )
}

fn send(proxy: &Proxy, ue: SocketAddr, raw: &str) {
    proxy.request(&ue.to_string(), raw);
}

/// Assert that every response in `sent` for the UE went over SA #3.
fn assert_over_port_pc_to_port_us(sent: &[Sent], ue: SocketAddr, expected: &[u16]) {
    let responses = responses_to_ue(sent, ue.ip());
    let codes: Vec<u16> = responses
        .iter()
        .filter_map(|sent| sent.status_code)
        .collect();
    assert_eq!(codes, expected, "the UE is answered");
    for response in responses {
        assert_eq!(
            response.destination,
            SocketAddr::new(ue.ip(), ue.port() + 1),
            "a UDP response goes to the UE's protected server port"
        );
        assert_eq!(
            response.source_local_addr,
            Some(addr(PORT_PC)),
            "a UDP response leaves from the P-CSCF's protected client port"
        );
        assert_eq!(response.transport, Transport::Udp);
    }
}

/// A response siphon builds itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_locally_answered_udp_request_is_answered_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.110:6100");
    install(&manager, ue).await;

    send(&proxy, ue, &options(ue, "local-110", 70, "UDP"));
    assert_over_port_pc_to_port_us(&drain(&proxy.udp), ue, &[200]);
}

/// A retransmitted request is answered from the server transaction's cache,
/// and that copy goes the same way as the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_answer_goes_from_port_pc_to_port_us_too() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.111:6100");
    install(&manager, ue).await;

    let raw = options(ue, "retransmit-111", 70, "UDP");
    send(&proxy, ue, &raw);
    send(&proxy, ue, &raw);
    assert_over_port_pc_to_port_us(&drain(&proxy.udp), ue, &[200, 200]);
}

/// A response relayed from the core.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_response_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue = addr("198.51.100.112:6100");
    install(&manager, ue).await;

    send(&proxy, ue, &options(ue, "relay-112", 70, "UDP"));
    let relayed = proxy
        .wire()
        .into_iter()
        .find(|sent| sent.destination == REGISTRAR)
        .expect("the request is relayed");
    proxy.response(
        REGISTRAR,
        response_to(
            &relayed.message,
            200,
            "OK",
            "core",
            "sip:core@198.51.100.12",
            "",
        ),
    );
    assert_over_port_pc_to_port_us(&drain(&proxy.udp), ue, &[200]);
}

/// A request siphon refuses before relaying it (RFC 3261 clause 16.3 step 3).
#[tokio::test(flavor = "multi_thread")]
async fn an_error_response_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue = addr("198.51.100.113:6100");
    install(&manager, ue).await;

    send(&proxy, ue, &options(ue, "hops-113", 0, "UDP"));
    let sent = drain(&proxy.udp);
    let responses = responses_to_ue(&sent, ue.ip());
    assert_eq!(responses.len(), 1, "the request is refused");
    assert_ne!(responses[0].status_code, Some(200));
    let code = responses[0].status_code.expect("a response");
    assert_over_port_pc_to_port_us(&sent, ue, &[code]);
}

/// A peer with no pair is answered where its request came from, as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_unprotected_peer_is_answered_at_its_source() {
    let (proxy, _manager) = p_cscf(ANSWER);
    let peer = addr("198.51.100.114:6100");

    send(&proxy, peer, &options(peer, "plain-114", 70, "UDP"));
    let sent = drain(&proxy.udp);
    let responses = responses_to_ue(&sent, peer.ip());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].destination, peer);
    assert_eq!(responses[0].source_local_addr, Some(addr(PORT_PS)));
}

/// A pair whose selector admits TCP only cannot carry the UDP response; it
/// still goes out (never dropped silently), where it went before.
#[tokio::test(flavor = "multi_thread")]
async fn a_tcp_only_pair_leaves_the_udp_response_where_it_was() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.115:6100");
    let mut sa = install_unconfigured(ue);
    sa.protocol = SaProtocol::Tcp;
    manager.create_sa_pair(sa).await.expect("installed");

    send(&proxy, ue, &options(ue, "tcp-only-115", 70, "UDP"));
    let sent = drain(&proxy.udp);
    let responses = responses_to_ue(&sent, ue.ip());
    assert_eq!(responses.len(), 1, "the response is still sent");
    assert_eq!(responses[0].destination, ue);
    assert_eq!(responses[0].source_local_addr, Some(addr(PORT_PS)));
}

/// Over TCP the response goes on the connection the request arrived on.
#[tokio::test(flavor = "multi_thread")]
async fn a_tcp_request_is_answered_on_its_connection() {
    let (proxy, manager) = p_cscf(ANSWER);
    let (stream_sender, stream) = flume::unbounded();
    let proxy = with_stream_egress(proxy, stream_sender);
    let ue = addr("198.51.100.116:6100");
    install(&manager, ue).await;

    let raw = options(ue, "tcp-116", 70, "TCP");
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let mut from_ue = inbound(&ue.to_string(), &raw);
    from_ue.transport = Transport::Tcp;
    from_ue.connection_id = ConnectionId(116);
    tokio::task::block_in_place(|| {
        handle_request(from_ue, message, "OPTIONS".to_string(), &proxy.state)
    });

    let sent = drain(&stream);
    let responses = responses_to_ue(&sent, ue.ip());
    assert_eq!(responses.len(), 1);
    assert_eq!(responses[0].transport, Transport::Tcp);
    assert_eq!(responses[0].destination, ue);
    assert_eq!(responses[0].connection_id, ConnectionId(116));
    assert_eq!(responses[0].source_local_addr, Some(addr(PORT_PS)));
}

/// An A-leg 2xx resent by its retransmission task (RFC 3261 clause
/// 13.3.1.4) takes the same flow as the first copy.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_retransmission_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.117:6100");
    install(&manager, ue).await;

    let raw = options(ue, "2xx-117", 70, "UDP");
    let request = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let answer = response_to(&request, 200, "OK", "as", "sip:as@192.0.2.1", "");
    super::b2bua::arm_b2bua_2xx_retransmit(
        "2xx-117@ue",
        answer,
        Transport::Udp,
        ue,
        ConnectionId::default(),
        Some(addr(PORT_PS)),
        &proxy.state,
    );
    // The first retransmission follows T1 (500 ms).
    tokio::time::sleep(Duration::from_millis(700)).await;
    if let Some(unacked) = proxy.state.uas_2xx_retransmits.get("2xx-117@ue") {
        unacked.cancel.notify_waiters();
    }

    let sent = drain(&proxy.udp);
    let codes = responses_to_ue(&sent, ue.ip()).len();
    assert!(codes >= 1, "at least one retransmission went out");
    assert_over_port_pc_to_port_us(&sent, ue, &vec![200; codes]);
}

/// A pair for `ue` as [`install`] builds it, not yet in the manager.
fn install_unconfigured(ue: SocketAddr) -> crate::ipsec::SecurityAssociationPair {
    let manager = IpsecManager::with_test_kernel();
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    crate::ipsec::SecurityAssociationPair {
        ue_addr: ue.ip(),
        pcscf_addr: "192.0.2.1".parse().expect("an address"),
        ue_port_c: ue.port(),
        ue_port_s: ue.port() + 1,
        pcscf_port_c: 5064,
        pcscf_port_s: 5060,
        spi_uc: 80_000 + u32::from(ue.port()),
        spi_us: 90_000 + u32::from(ue.port()),
        spi_pc,
        spi_ps,
        ealg: crate::ipsec::EncryptionAlgorithm::Null,
        aalg: crate::ipsec::IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: std::time::Instant::now(),
        created_at: std::time::Instant::now(),
        role: crate::ipsec::SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

/// `proxy` with its stream egress readable through `stream_sender`'s receiver.
fn with_stream_egress(proxy: Proxy, stream_sender: flume::Sender<OutboundMessage>) -> Proxy {
    let Proxy { state, udp } = proxy;
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("the only handle"));
    let (udp_sender, udp_receiver) = flume::unbounded();
    drop(udp);
    state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender.clone(),
        sctp: Some(stream_sender),
    });
    Proxy {
        state: Arc::new(state),
        udp: udp_receiver,
    }
}
