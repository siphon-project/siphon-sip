//! One listener per transport: the bytes on the wire are what they were before
//! advertised identities became per listener.
//!
//! Each snapshot below was captured from the release before that change, with
//! the same test, and is compared byte for byte (the random Via branches,
//! B-leg Call-ID and tags masked). A deployment with one listener per
//! transport must not see a single header move.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::transport::AdvertisedAddress;

const UDP_LISTENER: &str = "192.0.2.1:5060";
const TLS_LISTENER: &str = "192.0.2.1:5061";
const CALLER: &str = "198.51.100.10:5060";
const PHONE: &str = "198.51.100.21:40001";

fn addr(value: &str) -> SocketAddr {
    value.parse().expect("a literal address")
}

/// Mask what is random per run: Via branches, tags, and a generated Call-ID.
fn masked(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes).to_string();
    text.split("\r\n")
        .map(|line| {
            let mut line = line.to_string();
            for marker in ["branch=", "tag="] {
                if let Some(start) = line.find(marker) {
                    let value_start = start + marker.len();
                    let end = line[value_start..]
                        .find([';', '>', ',', ' '])
                        .map_or(line.len(), |offset| value_start + offset);
                    line.replace_range(value_start..end, "X");
                }
            }
            if line.starts_with("Call-ID:") && !line.contains("@example.test") {
                line = "Call-ID: X".to_string();
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

struct OneListenerEach {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    tls: flume::Receiver<OutboundMessage>,
}

fn one_listener_each(script: &str, advertise: bool) -> OneListenerEach {
    let TestDispatcher { mut state, .. } = test_dispatcher_with_script(script);
    let (udp_sender, udp) = flume::unbounded();
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
    state.listen_addrs = std::collections::HashMap::from([
        (Transport::Udp, addr(UDP_LISTENER)),
        (Transport::Tls, addr(TLS_LISTENER)),
    ]);
    let tls_advertise = advertise.then(|| AdvertisedAddress::host_only("sip.example.test"));
    if advertise {
        state.advertised_addrs =
            std::collections::HashMap::from([(Transport::Tls, "sip.example.test".to_string())]);
    }
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (Transport::Udp, addr(UDP_LISTENER), None),
        (Transport::Tls, addr(TLS_LISTENER), tls_advertise),
    ]);
    state
        .stream_connections
        .register(addr(PHONE), Transport::Tls, ConnectionId(902));
    OneListenerEach {
        state: Arc::new(state),
        udp,
        tls,
    }
}

fn invite(ruri: &str, call_id: &str) -> String {
    format!(
        concat!(
            "INVITE {ruri} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@example.test>;tag=caller\r\n",
            "To: <sip:bob@example.test>\r\n",
            "Call-ID: {call_id}@example.test\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ruri = ruri,
        caller = CALLER,
        call_id = call_id,
    )
}

fn arrive(raw: String, state: &Arc<DispatcherState>) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: addr(UDP_LISTENER),
            remote_addr: addr(CALLER),
            data: Bytes::from(raw),
        },
        message,
        "INVITE".to_string(),
        state,
    );
}

fn arrive_b2bua(raw: String, state: &Arc<DispatcherState>) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_b2bua_invite(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: addr(UDP_LISTENER),
            remote_addr: addr(CALLER),
            data: Bytes::from(raw),
        },
        message,
        state,
    );
}

fn sent_to(egress: &flume::Receiver<OutboundMessage>, destination: &str) -> String {
    let destination = addr(destination);
    let mut others = Vec::new();
    while let Ok(sent) = egress.try_recv() {
        if sent.destination == destination {
            return masked(&sent.data);
        }
        others.push(sent.destination);
    }
    panic!("nothing was sent to {destination}, only to {others:?}");
}

const PROXY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"INVITE\")\n",
    "def route(request):\n",
    "    request.record_route()\n",
    "    request.relay()\n",
);

const B2BUA: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:bob@198.51.100.21:40001;transport=tls\")\n",
);

fn check(name: &str, actual: &str, expected: &str) {
    if std::env::var_os("SIPHON_PRINT_SNAPSHOT").is_some() {
        println!("=== {name}\n{actual:?}");
    }
    assert_eq!(actual, expected, "{name} moved");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_udp_to_tls_relay_is_byte_identical() {
    for advertise in [false, true] {
        let OneListenerEach { state, tls, .. } = one_listener_each(PROXY, advertise);
        arrive(
            invite(
                "sip:bob@198.51.100.21:40001;transport=tls",
                "snapshot-proxy",
            ),
            &state,
        );
        let expected = if advertise {
            PROXY_TLS_ADVERTISED
        } else {
            PROXY_TLS_PLAIN
        };
        check("proxy udp->tls", &sent_to(&tls, PHONE), expected);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_udp_relay_is_byte_identical() {
    let OneListenerEach { state, udp, .. } = one_listener_each(PROXY, true);
    arrive(invite("sip:bob@203.0.113.40:5060", "snapshot-udp"), &state);
    check(
        "proxy udp->udp",
        &sent_to(&udp, "203.0.113.40:5060"),
        PROXY_UDP,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_over_a_reused_tls_connection_is_byte_identical() {
    let OneListenerEach { state, tls, .. } = one_listener_each(B2BUA, true);
    arrive_b2bua(
        invite(
            "sip:bob@198.51.100.21:40001;transport=tls",
            "snapshot-b2bua",
        ),
        &state,
    );
    check("b2bua b-leg tls", &sent_to(&tls, PHONE), B2BUA_TLS);
}

const PROXY_TLS_PLAIN: &str = "INVITE sip:bob@198.51.100.21:40001;transport=tls SIP/2.0\r\nVia: SIP/2.0/TLS 192.0.2.1:5061;branch=X\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=X\r\nMax-Forwards: 69\r\nRecord-Route: <sip:192.0.2.1:5061;transport=tls;lr>\r\nRecord-Route: <sip:192.0.2.1:5060;transport=udp;lr>\r\nFrom: <sip:alice@example.test>;tag=X\r\nTo: <sip:bob@example.test>\r\nCall-ID: snapshot-proxy@example.test\r\nCSeq: 1 INVITE\r\nContact: <sip:alice@198.51.100.10:5060>\r\nContent-Length: 0\r\n\r\n";
const PROXY_TLS_ADVERTISED: &str = "INVITE sip:bob@198.51.100.21:40001;transport=tls SIP/2.0\r\nVia: SIP/2.0/TLS sip.example.test:5061;branch=X\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=X\r\nMax-Forwards: 69\r\nRecord-Route: <sip:sip.example.test:5061;transport=tls;lr>\r\nRecord-Route: <sip:192.0.2.1:5060;transport=udp;lr>\r\nFrom: <sip:alice@example.test>;tag=X\r\nTo: <sip:bob@example.test>\r\nCall-ID: snapshot-proxy@example.test\r\nCSeq: 1 INVITE\r\nContact: <sip:alice@198.51.100.10:5060>\r\nContent-Length: 0\r\n\r\n";
const PROXY_UDP: &str = "INVITE sip:bob@203.0.113.40:5060 SIP/2.0\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=X\r\nVia: SIP/2.0/UDP 198.51.100.10:5060;branch=X\r\nMax-Forwards: 69\r\nRecord-Route: <sip:192.0.2.1:5060;transport=udp;lr>\r\nFrom: <sip:alice@example.test>;tag=X\r\nTo: <sip:bob@example.test>\r\nCall-ID: snapshot-udp@example.test\r\nCSeq: 1 INVITE\r\nContact: <sip:alice@198.51.100.10:5060>\r\nContent-Length: 0\r\n\r\n";
const B2BUA_TLS: &str = "INVITE sip:bob@198.51.100.21:40001;transport=tls SIP/2.0\r\nVia: SIP/2.0/TLS sip.example.test:5061;branch=X\r\nMax-Forwards: 69\r\nFrom: <sip:alice@sip.example.test>;tag=X\r\nTo: <sip:bob@198.51.100.21:40001>\r\nCall-ID: X\r\nCSeq: 1 INVITE\r\nContact: <sip:sip.example.test:5061;transport=tls>\r\nAllow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK, SUBSCRIBE, NOTIFY, REFER, MESSAGE, PUBLISH\r\nP-Asserted-Identity: <sip:alice@sip.example.test>\r\nSupported: replaces\r\nContent-Length: 0\r\n\r\n";
