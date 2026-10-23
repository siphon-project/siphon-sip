//! A P-CSCF sending its own requests to a UE over IPsec on UDP: an MT request
//! relayed over the UE's captured flow, an in-dialog request, and the
//! registrar-liveness OPTIONS all leave from the P-CSCF's protected client port
//! to the UE's protected server port (3GPP TS 24.229 clause 5.2.2.2 1A a,
//! TS 33.203 clause 7.1, UDP case). The captured flow is the one the UE sends
//! on, from its protected client port to the P-CSCF's protected server port.
//! The Via keeps naming the protected server port, where the P-CSCF receives
//! the UE's responses, also on a request routed by its Contact to the UE's
//! protected server port. Over TCP the request goes on the connection the
//! P-CSCF opens to the UE's protected server port (clause 5.2.2.2 1A b).
//! Toward a peer with no security association nothing changes.
//!
//! The harness listens on 192.0.2.1:5060, made the protected server port, with
//! 5064 the protected client port.

use std::collections::HashMap;
use std::net::SocketAddr;

use super::ipsec_lifecycle_tests::{install, p_cscf, ANSWER};
use super::proxy_dialog_state_tests::Proxy;
use super::*;

const PORT_PC: &str = "192.0.2.1:5064";
const PORT_PS: &str = "192.0.2.1:5060";
/// The S-CSCF the terminating request comes from.
const CORE: &str = "198.51.100.12:5060";

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address literal")
}

/// One message as the transport would have been handed it.
#[derive(Debug)]
struct Sent {
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    transport: Transport,
    message: SipMessage,
}

fn drain(receiver: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = receiver.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination,
                source_local_addr: outbound.source_local_addr,
                transport: outbound.transport,
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

fn requests_to_ue(sent: Vec<Sent>, ue: SocketAddr) -> Vec<Sent> {
    sent.into_iter()
        .filter(|sent| sent.message.status_code().is_none() && sent.destination.ip() == ue.ip())
        .collect()
}

/// The UE's captured flow: its protected client port, seen on the listener
/// the REGISTER landed on.
fn flow(ue: SocketAddr, transport: &str) -> crate::script::api::registrar::PyFlow {
    crate::script::api::registrar::PyFlow {
        transport: transport.to_string(),
        source_addr: ue,
        local_addr: addr(PORT_PS),
        connection_id: 0,
        kind: crate::script::api::registrar::FlowKind::Inbound,
    }
}

fn terminating(method: &str, ue: SocketAddr, call_id: &str, to_tag: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "{method} sip:001010000000001@{ue_ip}:{port_s} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {core};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:caller@ims.example.invalid>;tag=core-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>{to_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 {method}\r\n",
            "Contact: <sip:caller@{core}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        ue_ip = ue.ip(),
        port_s = ue.port() + 1,
        core = CORE,
        call_id = call_id,
        to_tag = to_tag,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the request parses")
}

fn from_core(message: &SipMessage) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: addr(PORT_PS),
        remote_addr: addr(CORE),
        data: Bytes::from(message.to_bytes()),
    }
}

/// Relay `message` from the core to the UE, over `flow` when given.
fn relay(
    proxy: &Proxy,
    message: &SipMessage,
    flow: Option<&crate::script::api::registrar::PyFlow>,
) {
    let inbound = from_core(message);
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
            &proxy.state,
            None,
            None,
            None,
            None,
            flow,
            None,
            &[],
        )
    });
}

/// The one request that went to the UE took SA #3 and still names the
/// protected server port in its Via.
fn assert_over_port_pc_to_port_us(sent: Vec<Sent>, ue: SocketAddr, method: Method) {
    let requests = requests_to_ue(sent, ue);
    assert_eq!(requests.len(), 1, "one request to the UE: {requests:?}");
    let request = &requests[0];
    assert_eq!(request.message.method(), Some(&method));
    assert_eq!(request.transport, Transport::Udp);
    assert_eq!(
        request.destination,
        SocketAddr::new(ue.ip(), ue.port() + 1),
        "to the UE's protected server port"
    );
    assert_eq!(
        request.source_local_addr,
        Some(addr(PORT_PC)),
        "from the P-CSCF's protected client port"
    );
    let via = request.message.headers.get("Via").expect("a Via");
    assert!(
        via.contains(PORT_PS),
        "the Via names where the P-CSCF receives the UE's responses: {via}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mt_invite_relayed_over_the_ue_flow_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.120:6100");
    install(&manager, ue).await;

    let invite = terminating("INVITE", ue, "mt-120", "");
    relay(&proxy, &invite, Some(&flow(ue, "udp")));
    assert_over_port_pc_to_port_us(drain(&proxy.udp), ue, Method::Invite);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_in_dialog_request_over_the_ue_flow_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.121:6100");
    install(&manager, ue).await;

    let bye = terminating("BYE", ue, "bye-121", ";tag=ue-tag");
    relay(&proxy, &bye, Some(&flow(ue, "udp")));
    assert_over_port_pc_to_port_us(drain(&proxy.udp), ue, Method::Bye);
}

/// A request routed by address to the UE's protected client port (a Contact
/// rewritten to the source) takes the same flow.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_routed_to_the_ue_client_port_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.122:6100");
    install(&manager, ue).await;

    let raw = String::from_utf8(terminating("BYE", ue, "uri-122", ";tag=ue-tag").to_bytes())
        .expect("UTF-8")
        .replace(&format!("{}:6101", ue.ip()), &ue.to_string());
    let bye = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    relay(&proxy, &bye, None);
    let requests = requests_to_ue(drain(&proxy.udp), ue);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].destination, SocketAddr::new(ue.ip(), 6101));
    assert_eq!(requests[0].source_local_addr, Some(addr(PORT_PC)));
}

/// The registrar-liveness OPTIONS goes over the binding's flow through the
/// UAC sender, which applies the same rule.
#[tokio::test(flavor = "multi_thread")]
async fn a_liveness_options_over_the_ue_flow_goes_from_port_pc_to_port_us() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.123:6100");
    install(&manager, ue).await;
    let uac = UacSender::new(
        Arc::clone(&proxy.state.outbound),
        addr(PORT_PS),
        HashMap::new(),
        HashMap::new(),
        None,
        None,
        crate::config::IdentityHeaders::default().shared(),
    )
    .with_ipsec_egress(Some(manager), Some(5060));

    let flow = flow(ue, "udp");
    let _answer = uac.send_options_over_flow(
        flow.source_addr,
        flow.local_addr,
        Transport::Udp,
        ConnectionId(flow.connection_id),
        crate::sip::parser::parse_uri_standalone(&format!("sip:001010000000001@{}:6101", ue.ip()))
            .expect("a URI"),
    );
    assert_over_port_pc_to_port_us(drain(&proxy.udp), ue, Method::Options);
}

/// Over TCP the dispatcher hands the request down on the UE's own connection
/// (port_uc -> port_ps), and the outbound router's rule takes it onto the
/// connection the P-CSCF opens from port_pc to port_us, with no connection id
/// so the pool opens or reuses that one (TS 24.229 clause 5.2.2.2 1A b). The
/// Via names the protected server port.
#[tokio::test(flavor = "multi_thread")]
async fn a_tcp_request_over_the_ue_flow_goes_on_the_p_cscf_connection() {
    let (proxy, manager) = p_cscf(ANSWER);
    let (stream_sender, stream) = flume::unbounded();
    let proxy = super::ipsec_response_flow_tests::with_stream_egress(proxy, stream_sender);
    let ue = addr("198.51.100.124:6100");
    install(&manager, ue).await;

    let mut tcp = flow(ue, "tcp");
    tcp.connection_id = 124;
    let invite = terminating("INVITE", ue, "tcp-124", "");
    relay(&proxy, &invite, Some(&tcp));
    let mut handed_down = Vec::new();
    while let Ok(outbound) = stream.try_recv() {
        handed_down.push(outbound);
    }
    assert_eq!(handed_down.len(), 1, "one request to the UE");
    let outbound = handed_down.remove(0);
    assert_eq!(
        (
            outbound.destination,
            outbound.source_local_addr,
            outbound.connection_id
        ),
        (ue, Some(addr(PORT_PS)), ConnectionId(124)),
        "the dispatcher addresses the UE's flow"
    );
    let moved = crate::ipsec::pcscf_tcp_request_egress(&manager, 5060, outbound);
    assert_eq!(moved.transport, Transport::Tcp);
    assert_eq!(moved.destination, SocketAddr::new(ue.ip(), 6101));
    assert_eq!(moved.source_local_addr, Some(addr(PORT_PC)));
    assert_eq!(moved.connection_id, ConnectionId::default());
    let message = parse_sip_message_bytes(&moved.data).expect("parses");
    let via = message.headers.get("Via").expect("a Via");
    assert!(via.contains(PORT_PS), "{via}");
}

/// A request routed by its Contact to the UE's protected server port, with no
/// flow, leaves from the protected client port but its Via names the
/// protected server port, where the UE's response comes back (TS 24.229
/// clause 5.2.6.4.3 step 6, 5.2.6.4.5 step 1; TS 33.203 clause 7.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_request_routed_to_the_ue_server_port_names_port_ps_in_its_via() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.126:6100");
    install(&manager, ue).await;

    let bye = terminating("BYE", ue, "contact-126", ";tag=ue-tag");
    relay(&proxy, &bye, None);
    let requests = requests_to_ue(drain(&proxy.udp), ue);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].destination, SocketAddr::new(ue.ip(), 6101));
    assert_eq!(requests[0].source_local_addr, Some(addr(PORT_PC)));
    let via = requests[0].message.headers.get("Via").expect("a Via");
    assert!(
        via.contains(PORT_PS) && !via.contains("5064"),
        "the Via names the protected server port, not the client port: {via}"
    );
}

/// A flow with no security association goes where it was captured.
#[tokio::test(flavor = "multi_thread")]
async fn an_unprotected_flow_is_left_alone() {
    let (proxy, _manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.125:6100");

    let invite = terminating("INVITE", ue, "plain-125", "");
    relay(&proxy, &invite, Some(&flow(ue, "udp")));
    let requests = requests_to_ue(drain(&proxy.udp), ue);
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert_eq!(requests[0].destination, ue);
    assert_eq!(requests[0].source_local_addr, Some(addr(PORT_PS)));
}
