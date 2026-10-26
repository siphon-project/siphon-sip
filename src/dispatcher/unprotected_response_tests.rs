//! A response follows its request's own Via (RFC 3261 clause 18.2.2, RFC
//! 3581): a challenge to an initial REGISTER a UE sent unprotected, to the
//! P-CSCF's plain port, goes back unprotected over UDP to the source of that
//! REGISTER, from the plain listener, whatever its size, even while the pair
//! of the UE's previous registration is still being retired and a new pair
//! is pending. Nothing is moved to the protected ports of a security
//! association or to TCP. A challenge to a REGISTER that came over the
//! association still goes back over it (TS 33.203 clause 7.1, TS 24.229
//! clause 5.2.2.2).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::ipsec_lifecycle_tests::{REGISTRAR, RELAY};
use super::proxy_dialog_state_tests::{response_to, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::ipsec::retire::RetireCondition;
use crate::ipsec::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair,
};
use crate::log_capture::LogBuffer;
use crate::transaction::timer::TimerConfig;

const PCSCF: &str = "192.0.2.1";
/// The plain listener an initial REGISTER arrives on.
const PLAIN: &str = "192.0.2.1:5060";
const PORT_PS: u16 = 5066;
const PORT_PC: u16 = 5064;
/// The previous registration's pair: the UE's protected client and server
/// ports.
const UE_PORT_C: u16 = 6100;
const UE_PORT_S: u16 = 6101;
const MTU: u16 = 1300;

struct Harness {
    proxy: Proxy,
    manager: Arc<IpsecManager>,
    /// Everything handed to a stream transport.
    streams: flume::Receiver<OutboundMessage>,
}

/// A P-CSCF with a plain listener on 5060, the protected ports 5064/5066, an
/// MTU, and a script that relays everything to the registrar.
fn p_cscf() -> Harness {
    let mut dispatcher = test_dispatcher_with_script(RELAY);
    let timers = TimerConfig::new(
        Duration::from_millis(2),
        Duration::from_millis(8),
        Duration::from_millis(10),
    );
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    dispatcher.state.mtu = Some(MTU);
    let manager = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&manager));
    dispatcher.state.ipsec_config = Some(
        crate::config::yaml::from_str(&format!("pcscf_port_s: {PORT_PS}\npcscf_port_c: {PORT_PC}"))
            .expect("an ipsec block"),
    );
    let (udp_sender, udp) = flume::unbounded();
    let (stream_sender, streams) = flume::unbounded();
    dispatcher.state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: HashMap::new(),
        udp_dynamic: None,
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender.clone(),
        sctp: Some(stream_sender),
    });
    Harness {
        proxy: Proxy {
            state: Arc::new(dispatcher.state),
            udp,
        },
        manager,
        streams,
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address literal")
}

async fn install(manager: &IpsecManager, ue: IpAddr, ue_port_c: u16) {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    let sa = SecurityAssociationPair {
        ue_addr: ue,
        pcscf_addr: PCSCF.parse().expect("an address"),
        ue_port_c,
        ue_port_s: UE_PORT_S,
        pcscf_port_c: PORT_PC,
        pcscf_port_s: PORT_PS,
        spi_uc: 70_000 + u32::from(ue_port_c),
        spi_us: 80_000 + u32::from(ue_port_c),
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

/// A REGISTER from `ue`, its Contact naming the protected server port the UE
/// offers (TS 24.229 clause 5.1.1.2.1).
fn register(ue: SocketAddr, call_id: &str) -> String {
    format!(
        concat!(
            "REGISTER sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {ue};branch=z9hG4bK-{call_id};rport\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Contact: <sip:001010000000001@{host}:{port_s}>\r\n",
            "Security-Client: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;",
            "spi-c=1111;spi-s=2222;port-c=6200;port-s={port_s}\r\n",
            "Expires: 600000\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ue = ue,
        host = ue.ip(),
        port_s = UE_PORT_S,
        call_id = call_id,
    )
}

fn inbound(source: SocketAddr, local: SocketAddr, raw: &[u8]) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: local,
        remote_addr: source,
        data: Bytes::copy_from_slice(raw),
    }
}

/// One message to the UE: `(status, destination, local socket, transport)`.
type ToUe = (u16, SocketAddr, Option<SocketAddr>, Transport);

/// The UE at `ue` sends a REGISTER to `local`; the registrar answers the
/// relayed copy with a 401 over the MTU. Returns what the UE was sent and the
/// log of the whole exchange.
fn challenged(
    harness: &Harness,
    ue: SocketAddr,
    local: SocketAddr,
    call_id: &str,
) -> (Vec<ToUe>, String) {
    let log = LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);

    let raw = register(ue, call_id);
    let request = parse_sip_message_bytes(raw.as_bytes()).expect("the REGISTER parses");
    let state = &harness.proxy.state;
    tokio::task::block_in_place(|| {
        handle_request(
            inbound(ue, local, raw.as_bytes()),
            request,
            "REGISTER".to_string(),
            state,
        )
    });
    let relayed: Vec<SipMessage> = harness
        .proxy
        .wire()
        .into_iter()
        .filter(|sent| sent.destination == REGISTRAR)
        .map(|sent| sent.message)
        .collect();
    assert_eq!(relayed.len(), 1, "the REGISTER is relayed");
    let challenge_header = format!(
        "WWW-Authenticate: Digest realm=\"ims.example.invalid\",nonce=\"{}\",algorithm=AKAv1-MD5,qop=\"auth\"\r\n",
        "a".repeat(1500)
    );
    let challenge = response_to(
        &relayed[0],
        401,
        "Unauthorized",
        "scscf",
        "sip:scscf@198.51.100.12",
        &challenge_header,
    );
    let challenge_bytes = challenge.to_bytes();
    assert!(
        challenge_bytes.len() > usize::from(MTU),
        "the 401 is over the MTU: {}",
        challenge_bytes.len()
    );
    tokio::task::block_in_place(|| {
        handle_response(
            inbound(addr(REGISTRAR), addr(PLAIN), &challenge_bytes),
            challenge,
            401,
            state,
        )
    });
    drop(guard);

    let mut sent = Vec::new();
    let receivers = [&harness.proxy.udp, &harness.streams];
    for receiver in receivers {
        while let Ok(outbound) = receiver.try_recv() {
            if outbound.destination.ip() != ue.ip() {
                continue;
            }
            for frame in outbound.frames() {
                let message =
                    parse_sip_message_bytes(frame).expect("siphon sent a message that parses");
                if let Some(code) = message.status_code() {
                    sent.push((
                        code,
                        outbound.destination,
                        outbound.source_local_addr,
                        outbound.transport,
                    ));
                }
            }
        }
    }
    (sent, log.rendered())
}

/// The UE's previous pair, being retired after its de-registration, and the
/// pair the new challenge set up, pending beside it on the same protected
/// server port.
async fn de_registered_and_challenged_again(manager: &Arc<IpsecManager>, ue: IpAddr) {
    install(manager, ue, UE_PORT_C).await;
    assert!(manager.retire_pair(
        ue,
        UE_PORT_C,
        Duration::from_secs(30),
        RetireCondition::Unregistered,
        "de-registered",
    ));
    install(manager, ue, 6200).await;
}

fn assert_unprotected_to_source(sent: &[ToUe], ue: SocketAddr, log: &str) {
    assert_eq!(
        sent,
        &[(401, ue, Some(addr(PLAIN)), Transport::Udp)],
        "the 401 goes over UDP to the REGISTER's source, from the plain listener"
    );
    assert!(
        !log.contains("TCP connect") && !log.contains("over-MTU"),
        "no TCP connection is tried for the response:\n{log}"
    );
}

/// The UE was registered over a pair (port_us 6101), de-registered, and sends
/// a fresh initial REGISTER unprotected from 5060 to the plain port, while the
/// old pair is still being retired and the new challenge's pair is pending.
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_to_an_unprotected_register_goes_back_unprotected_to_its_source() {
    let harness = p_cscf();
    let ue = addr("198.51.100.150:5060");
    de_registered_and_challenged_again(&harness.manager, ue.ip()).await;

    let (sent, log) = challenged(&harness, ue, addr(PLAIN), "fresh-150");
    assert_unprotected_to_source(&sent, ue, &log);
}

/// The same, once the old pair is gone and only its ports are remembered.
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_to_an_unprotected_register_after_the_pair_is_gone_goes_to_its_source() {
    let harness = p_cscf();
    let ue = addr("198.51.100.151:5060");
    install(&harness.manager, ue.ip(), UE_PORT_C).await;
    harness
        .manager
        .delete_sa_pair(&ue.ip(), UE_PORT_C)
        .await
        .expect("deleted");

    let (sent, log) = challenged(&harness, ue, addr(PLAIN), "fresh-151");
    assert_unprotected_to_source(&sent, ue, &log);
}

/// An unprotected REGISTER sent from the very port that was the old pair's
/// protected client port is still answered at that port, unprotected: the
/// flow it came in on is the plain listener's, not the association's.
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_to_an_unprotected_register_from_the_old_client_port_stays_unprotected() {
    let harness = p_cscf();
    let ue = SocketAddr::new("198.51.100.152".parse().expect("an address"), UE_PORT_C);
    de_registered_and_challenged_again(&harness.manager, ue.ip()).await;

    let (sent, log) = challenged(&harness, ue, addr(PLAIN), "fresh-152");
    assert_unprotected_to_source(&sent, ue, &log);
}

/// A re-REGISTER over the pair in use is challenged over that pair, as before:
/// from the P-CSCF's protected client port to the UE's protected server port
/// (TS 33.203 clause 7.1, UDP case), over UDP even over the MTU.
#[tokio::test(flavor = "multi_thread")]
async fn a_challenge_to_a_protected_re_register_still_leaves_over_the_pair() {
    let harness = p_cscf();
    let ue = SocketAddr::new("198.51.100.153".parse().expect("an address"), UE_PORT_C);
    install(&harness.manager, ue.ip(), UE_PORT_C).await;
    let port_ps = SocketAddr::new(PCSCF.parse().expect("an address"), PORT_PS);

    let (sent, log) = challenged(&harness, ue, port_ps, "reauth-153");
    assert_eq!(
        sent,
        [(
            401,
            SocketAddr::new(ue.ip(), UE_PORT_S),
            Some(SocketAddr::new(PCSCF.parse().expect("an address"), PORT_PC)),
            Transport::Udp,
        )],
        "the 401 goes from port_pc to port_us"
    );
    assert!(!log.contains("TCP connect"), "{log}");
}
