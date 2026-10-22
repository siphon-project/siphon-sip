//! Two listeners of one transport, two identities.
//!
//! The shape: a TLS listener phones register on, advertising nothing (or an
//! IP), and a second TLS listener a trunk peer reaches, advertising an FQDN
//! the peer insists on. Each message siphon sends has to carry the identity of
//! the listener it leaves on, never the other one's: a phone handed the trunk
//! listener's FQDN reconnects to the wrong listener, and a trunk handed the
//! phone listener's address refuses the request.
//!
//! Driven through `handle_request` on a test dispatcher with a real script, and
//! read back off the TLS / UDP egress, so the assertions are on the bytes a
//! peer would get.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::transport::AdvertisedAddress;

/// The phone-facing TLS listener: no `advertise`.
const PHONES: &str = "192.0.2.10:5061";
/// The trunk-facing TLS listener, behind a front that publishes port 5068.
const TRUNK: &str = "192.0.2.10:15068";
const TRUNK_NAME: &str = "sbc.example.test";
/// A phone registered over a connection to the phone listener.
const PHONE_A: &str = "198.51.100.20:40000";
const PHONE_B: &str = "198.51.100.21:40001";
/// The trunk peer, connected to the trunk listener.
const TRUNK_PEER: &str = "203.0.113.30:5061";

fn addr(value: &str) -> SocketAddr {
    value.parse().expect("a literal address")
}

/// A dispatcher with both TLS listeners, wired the way the server wires them
/// (the per-transport maps hold the first advertising listener, as they
/// always have), and its TLS and UDP egress readable.
struct TwoListeners {
    state: Arc<DispatcherState>,
    tls: flume::Receiver<OutboundMessage>,
}

fn two_tls_listeners(script: &str) -> TwoListeners {
    let TestDispatcher { mut state, .. } = test_dispatcher_with_script(script);
    let (udp_sender, _udp) = flume::unbounded();
    let (tls_sender, tls) = flume::unbounded();
    let (other_sender, _other) = flume::unbounded();
    state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: other_sender.clone(),
        tls: tls_sender,
        ws: other_sender.clone(),
        wss: other_sender.clone(),
        sctp: Some(other_sender),
    });
    state.listen_addrs = std::collections::HashMap::from([(Transport::Tls, addr(PHONES))]);
    state.advertised_addrs =
        std::collections::HashMap::from([(Transport::Tls, TRUNK_NAME.to_string())]);
    state.advertised_ports = std::collections::HashMap::from([(Transport::Tls, 5068)]);
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (Transport::Tls, addr(PHONES), None),
        (
            Transport::Tls,
            addr(TRUNK),
            Some(AdvertisedAddress::parse("sbc.example.test:5068").expect("valid")),
        ),
    ]);
    // The phones' and the trunk's live connections, each on its own listener.
    let connections = &state.stream_connections;
    connections.register_on_listener(
        addr(PHONE_A),
        Transport::Tls,
        ConnectionId(901),
        addr(PHONES),
    );
    connections.register_on_listener(
        addr(PHONE_B),
        Transport::Tls,
        ConnectionId(902),
        addr(PHONES),
    );
    connections.register_on_listener(
        addr(TRUNK_PEER),
        Transport::Tls,
        ConnectionId(903),
        addr(TRUNK),
    );
    TwoListeners {
        state: Arc::new(state),
        tls,
    }
}

fn request(
    raw: &str,
    from: &str,
    connection_id: u64,
    listener: &str,
    state: &Arc<DispatcherState>,
) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str().to_string(),
        StartLine::Response(_) => panic!("a request"),
    };
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId(connection_id),
            transport: Transport::Tls,
            local_addr: addr(listener),
            remote_addr: addr(from),
            data: Bytes::from(raw.to_string()),
        },
        message,
        method,
        state,
    );
}

fn invite(ruri: &str, from: &str, call_id: &str) -> String {
    format!(
        concat!(
            "INVITE {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/TLS {from};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@example.test>;tag=caller\r\n",
            "To: <sip:bob@example.test>\r\n",
            "Call-ID: {call_id}@example.test\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:alice@{from};transport=tls>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ruri = ruri,
        from = from,
        call_id = call_id,
    )
}

/// The first message sent to `destination`, skipping anything else.
fn sent_to(egress: &flume::Receiver<OutboundMessage>, destination: &str) -> SipMessage {
    let destination = addr(destination);
    while let Ok(sent) = egress.try_recv() {
        if sent.destination == destination {
            return parse_sip_message_bytes(&sent.data).expect("what siphon sent parses");
        }
    }
    panic!("nothing was sent to {destination}");
}

fn top_via(message: &SipMessage) -> String {
    message
        .headers
        .get_all("Via")
        .and_then(|vias| vias.first().cloned())
        .expect("a Via")
}

fn record_routes(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Record-Route")
        .cloned()
        .unwrap_or_default()
}

const PROXY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"INVITE\")\n",
    "def route(request):\n",
    "    request.record_route()\n",
    "    request.relay()\n",
);

// Multi-thread: target resolution runs under block_in_place.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_between_two_phones_names_the_phone_listener_only() {
    let TwoListeners { state, tls } = two_tls_listeners(PROXY);

    request(
        &invite(
            "sip:bob@198.51.100.21:40001;transport=tls",
            PHONE_A,
            "phones",
        ),
        PHONE_A,
        901,
        PHONES,
        &state,
    );

    let relayed = sent_to(&tls, PHONE_B);
    let via = top_via(&relayed);
    assert!(
        via.starts_with("SIP/2.0/TLS 192.0.2.10:5061;"),
        "the INVITE leaves on the phone listener's connection and must say so: {via}"
    );
    assert_eq!(
        record_routes(&relayed),
        vec!["<sip:192.0.2.10:5061;transport=tls;lr>".to_string()],
        "one listener crossed, one Record-Route, and never the trunk FQDN"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_from_the_trunk_to_a_phone_record_routes_each_listener() {
    let TwoListeners { state, tls } = two_tls_listeners(PROXY);

    request(
        &invite(
            "sip:bob@198.51.100.21:40001;transport=tls",
            TRUNK_PEER,
            "inbound",
        ),
        TRUNK_PEER,
        903,
        TRUNK,
        &state,
    );

    let relayed = sent_to(&tls, PHONE_B);
    assert!(
        top_via(&relayed).starts_with("SIP/2.0/TLS 192.0.2.10:5061;"),
        "toward the phone, the phone listener"
    );
    // RFC 5658: each entry names the listener facing its peer. The topmost is
    // the one the phone (the UAS) reaches first.
    assert_eq!(
        record_routes(&relayed),
        vec![
            "<sip:192.0.2.10:5061;transport=tls;lr>".to_string(),
            "<sip:sbc.example.test:5068;transport=tls;lr>".to_string(),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_from_a_phone_to_the_trunk_names_the_trunk_listener_toward_it() {
    let TwoListeners { state, tls } = two_tls_listeners(PROXY);

    request(
        &invite(
            "sip:+15550100@203.0.113.30:5061;transport=tls",
            PHONE_A,
            "outbound",
        ),
        PHONE_A,
        901,
        PHONES,
        &state,
    );

    let relayed = sent_to(&tls, TRUNK_PEER);
    assert!(
        top_via(&relayed).starts_with("SIP/2.0/TLS sbc.example.test:5068;"),
        "toward the trunk, the trunk listener: {}",
        top_via(&relayed)
    );
    // Topmost the entry the trunk (the UAS) reaches first, its own listener.
    assert_eq!(
        record_routes(&relayed),
        vec![
            "<sip:sbc.example.test:5068;transport=tls;lr>".to_string(),
            "<sip:192.0.2.10:5061;transport=tls;lr>".to_string(),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_options_answer_names_the_listener_it_arrived_on() {
    // No script handler: siphon answers the OPTIONS itself (auto_options).
    let TwoListeners { state, tls } = two_tls_listeners("");
    let options = |from: &str, call_id: &str| {
        format!(
            concat!(
                "OPTIONS sip:192.0.2.10 SIP/2.0\r\n",
                "Via: SIP/2.0/TLS {from};branch=z9hG4bK-{call_id}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:probe@example.test>;tag=probe\r\n",
                "To: <sip:192.0.2.10>\r\n",
                "Call-ID: {call_id}@example.test\r\n",
                "CSeq: 1 OPTIONS\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            from = from,
            call_id = call_id,
        )
    };

    request(
        &options(PHONE_A, "phone-probe"),
        PHONE_A,
        901,
        PHONES,
        &state,
    );
    let answer = sent_to(&tls, PHONE_A);
    let contact = answer.headers.get("Contact").cloned().expect("a Contact");
    assert!(
        contact.contains("192.0.2.10:5061") && !contact.contains(TRUNK_NAME),
        "a phone is told the phone listener: {contact}"
    );

    request(
        &options(TRUNK_PEER, "trunk-probe"),
        TRUNK_PEER,
        903,
        TRUNK,
        &state,
    );
    let answer = sent_to(&tls, TRUNK_PEER);
    let contact = answer.headers.get("Contact").cloned().expect("a Contact");
    assert!(
        contact.contains("sbc.example.test:5068"),
        "the trunk is told the trunk listener: {contact}"
    );
}

/// A B2BUA that dials `target`.
fn b2bua_dialling(target: &str) -> String {
    format!(
        "from siphon import b2bua\n\n@b2bua.on_invite\ndef on_invite(call):\n    call.dial(\"{target}\")\n"
    )
}

/// An INVITE handed to the B2BUA INVITE handler, as the dispatcher does in
/// B2BUA mode.
fn b2bua_request(
    raw: &str,
    from: &str,
    connection_id: u64,
    listener: &str,
    state: &Arc<DispatcherState>,
) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_b2bua_invite(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId(connection_id),
            transport: Transport::Tls,
            local_addr: addr(listener),
            remote_addr: addr(from),
            data: Bytes::from(raw.to_string()),
        },
        message,
        state,
    );
}

fn contact_of(message: &SipMessage) -> String {
    message.headers.get("Contact").cloned().expect("a Contact")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_to_a_phone_advertises_the_phone_listener() {
    let TwoListeners { state, tls } =
        two_tls_listeners(&b2bua_dialling("sip:bob@198.51.100.21:40001;transport=tls"));

    b2bua_request(
        &invite(
            "sip:bob@198.51.100.21:40001;transport=tls",
            TRUNK_PEER,
            "b2bua-mt",
        ),
        TRUNK_PEER,
        903,
        TRUNK,
        &state,
    );

    let b_leg = sent_to(&tls, PHONE_B);
    assert!(
        top_via(&b_leg).starts_with("SIP/2.0/TLS 192.0.2.10:5061;"),
        "{}",
        top_via(&b_leg)
    );
    let contact = contact_of(&b_leg);
    assert!(
        contact.contains("192.0.2.10:5061") && !contact.contains(TRUNK_NAME),
        "the phone must reconnect to the phone listener: {contact}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_to_the_trunk_advertises_the_trunk_listener() {
    let TwoListeners { state, tls } = two_tls_listeners(&b2bua_dialling(
        "sip:+15550100@203.0.113.30:5061;transport=tls",
    ));

    b2bua_request(
        &invite(
            "sip:+15550100@203.0.113.30:5061;transport=tls",
            PHONE_A,
            "b2bua-mo",
        ),
        PHONE_A,
        901,
        PHONES,
        &state,
    );

    let b_leg = sent_to(&tls, TRUNK_PEER);
    assert!(
        top_via(&b_leg).starts_with("SIP/2.0/TLS sbc.example.test:5068;"),
        "{}",
        top_via(&b_leg)
    );
    let contact = contact_of(&b_leg);
    assert!(
        contact.contains("sbc.example.test:5068"),
        "the trunk refuses any Contact but its FQDN: {contact}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_pinned_to_the_trunk_listener_advertises_it_in_via_and_contact() {
    // UDP, so the pinned send is read back off the egress rather than opening
    // a real connection: the second UDP listener advertises the trunk name and
    // is not the default egress socket.
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.dial(\"sip:+15550100@203.0.113.30:5060\", send_socket=\"udp:192.0.2.10:15070\")\n",
    );
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(script);
    let default_socket = addr("192.0.2.10:5060");
    let trunk_socket = addr("192.0.2.10:15070");
    state.listen_addrs = std::collections::HashMap::from([(Transport::Udp, default_socket)]);
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (Transport::Udp, default_socket, None),
        (
            Transport::Udp,
            trunk_socket,
            Some(AdvertisedAddress::parse("sbc.example.test:5070").expect("valid")),
        ),
    ]);
    let raw = concat!(
        "INVITE sip:+15550100@203.0.113.30:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 198.51.100.60:5060;branch=z9hG4bK-pinned\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@example.test>;tag=caller\r\n",
        "To: <sip:bob@example.test>\r\n",
        "Call-ID: b2bua-pin@example.test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:alice@198.51.100.60:5060>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: default_socket,
        remote_addr: addr("198.51.100.60:5060"),
        data: Bytes::from_static(raw.as_bytes()),
    };
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("parses");
    handle_b2bua_invite(inbound, message, &state);

    let destination = addr("203.0.113.30:5060");
    let mut b_leg = None;
    while let Ok(sent) = udp.try_recv() {
        if sent.destination == destination {
            assert_eq!(
                sent.source_local_addr,
                Some(trunk_socket),
                "leaves the pinned socket"
            );
            b_leg = Some(parse_sip_message_bytes(&sent.data).expect("parses"));
            break;
        }
    }
    let b_leg = b_leg.expect("a B-leg INVITE to the trunk");
    assert!(
        top_via(&b_leg).starts_with("SIP/2.0/UDP sbc.example.test:5070;"),
        "{}",
        top_via(&b_leg)
    );
    let contact = contact_of(&b_leg);
    assert!(
        contact.contains("sbc.example.test:5070"),
        "a send_socket= pin moves the Contact to the pinned listener: {contact}"
    );
}

/// A listener on a wildcard bind with no `advertise` takes its own identity,
/// never `0.0.0.0` (the 482 trap) and never the sibling's FQDN.
#[test]
fn a_wildcard_listener_flow_never_names_the_unspecified_address_or_a_sibling() {
    let TestDispatcher { mut state, .. } = test_dispatcher_with_script("");
    state.advertised_addrs =
        std::collections::HashMap::from([(Transport::Udp, TRUNK_NAME.to_string())]);
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (Transport::Udp, addr("0.0.0.0:5060"), None),
        (
            Transport::Udp,
            addr("0.0.0.0:5070"),
            Some(AdvertisedAddress::host_only(TRUNK_NAME)),
        ),
    ]);
    let (host, port) = state.wildcard_pinned_sent_by(&Transport::Udp, addr("0.0.0.0:5060"));
    assert_ne!(host, "0.0.0.0");
    assert_ne!(host, TRUNK_NAME);
    assert_eq!(port, 5060);
    assert_eq!(
        state.wildcard_pinned_sent_by(&Transport::Udp, addr("0.0.0.0:5070")),
        (TRUNK_NAME.to_string(), 5070)
    );
}

/// UDP: two listeners on one port and two interfaces. A request that arrives
/// on the second and leaves from the default (the first) crosses two sockets,
/// so it carries two Record-Route entries, each naming its own listener.
#[tokio::test(flavor = "multi_thread")]
async fn a_udp_relay_across_two_interfaces_record_routes_both() {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(PROXY);
    let first = addr("192.0.2.10:5060");
    let second = addr("198.51.100.5:5060");
    state.listen_addrs = std::collections::HashMap::from([(Transport::Udp, first)]);
    state.advertised_addrs =
        std::collections::HashMap::from([(Transport::Udp, "core.example.test".to_string())]);
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (
            Transport::Udp,
            first,
            Some(AdvertisedAddress::host_only("core.example.test")),
        ),
        (
            Transport::Udp,
            second,
            Some(AdvertisedAddress::host_only("access.example.test")),
        ),
    ]);
    let state = Arc::new(state);
    let raw = concat!(
        "INVITE sip:bob@203.0.113.40:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 198.51.100.60:5060;branch=z9hG4bK-udp-two\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@example.test>;tag=caller\r\n",
        "To: <sip:bob@example.test>\r\n",
        "Call-ID: udp-two@example.test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:alice@198.51.100.60:5060>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: second,
            remote_addr: addr("198.51.100.60:5060"),
            data: Bytes::from(raw),
        },
        message,
        "INVITE".to_string(),
        &state,
    );
    let relayed = sent_to(&udp, "203.0.113.40:5060");
    assert!(top_via(&relayed).starts_with("SIP/2.0/UDP core.example.test:5060;"));
    assert_eq!(
        record_routes(&relayed),
        vec![
            "<sip:core.example.test:5060;transport=udp;lr>".to_string(),
            "<sip:access.example.test:5060;transport=udp;lr>".to_string(),
        ]
    );
}
