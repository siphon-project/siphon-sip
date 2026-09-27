//! A listener whose `advertise` names a port other than the one it binds.
//!
//! The shape is a front that translates the port: it owns the public port and
//! forwards to a different inner one. Every header that tells a peer where to
//! reach siphon (Via sent-by, Record-Route, Contact) has to carry the public
//! port, or the peer's next request goes to a port nothing serves.
//!
//! Driven through `handle_request` on a test dispatcher with a real script, and
//! read back off the UDP egress, so the assertion is on the bytes a peer gets.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::transport::AdvertisedAddress;

/// The inner socket siphon binds.
const BOUND: &str = "192.0.2.1:15060";
/// A second inner socket, on a different advertised identity.
const SECOND_BOUND: &str = "192.0.2.1:15062";
const CALLER: &str = "198.51.100.10:5060";
const NEXT_HOP: &str = "198.51.100.20:5060";

const RECORD_ROUTE_AND_RELAY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.record_route()\n",
    "    request.relay(\"sip:198.51.100.20:5060\")\n",
);

/// Point the dispatcher's listener view at the port-translating shape: UDP
/// bound on `BOUND`, advertised as `sip.example.com:5060`, plus a second UDP
/// listener on `SECOND_BOUND` advertised as `edge.example.com:5062`.
fn behind_a_port_translating_front(state: &mut DispatcherState) {
    let bound: SocketAddr = BOUND.parse().expect("a literal address");
    let second: SocketAddr = SECOND_BOUND.parse().expect("a literal address");
    state.listen_addrs = std::collections::HashMap::from([(Transport::Udp, bound)]);
    state.advertised_addrs =
        std::collections::HashMap::from([(Transport::Udp, "sip.example.com".to_string())]);
    state.advertised_ports = std::collections::HashMap::from([(Transport::Udp, 5060)]);
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![
        (
            Transport::Udp,
            bound,
            Some(AdvertisedAddress::parse("sip.example.com:5060").expect("valid")),
        ),
        (
            Transport::Udp,
            second,
            Some(AdvertisedAddress::parse("edge.example.com:5062").expect("valid")),
        ),
    ]);
}

fn invite(local: &str) -> String {
    format!(
        concat!(
            "INVITE sip:bob@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-advertised-port\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@example.com>;tag=caller\r\n",
            "To: <sip:bob@example.com>\r\n",
            "Call-ID: advertised-port-{local}@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
        local = local,
    )
}

fn arriving_on(state: &Arc<DispatcherState>, local: &str, raw: String) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str().to_string(),
        StartLine::Response(_) => panic!("a request"),
    };
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: local.parse().expect("a literal address"),
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        method,
        state,
    );
}

/// The first message sent to `destination`, skipping anything else (a 100
/// Trying back to the caller).
fn sent_to(udp: &flume::Receiver<OutboundMessage>, destination: &str) -> SipMessage {
    let destination: SocketAddr = destination.parse().expect("a literal address");
    while let Ok(sent) = udp.try_recv() {
        if sent.destination == destination {
            return parse_sip_message_bytes(&sent.data).expect("what siphon sent parses");
        }
    }
    panic!("nothing was sent to {destination}");
}

// Multi-thread: next-hop resolution runs the resolver under block_in_place.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_request_carries_the_advertised_port_in_via_and_record_route() {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(RECORD_ROUTE_AND_RELAY);
    behind_a_port_translating_front(&mut state);
    let state = Arc::new(state);

    arriving_on(&state, BOUND, invite(BOUND));

    let relayed = sent_to(&udp, NEXT_HOP);
    let via = relayed
        .headers
        .get_all("Via")
        .and_then(|vias| vias.first().cloned())
        .expect("siphon added a Via");
    assert!(
        via.starts_with("SIP/2.0/UDP sip.example.com:5060;"),
        "the Via must name the advertised port, not the bound 15060: {via}"
    );
    let record_routes = relayed
        .headers
        .get_all("Record-Route")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        record_routes,
        vec!["<sip:sip.example.com:5060;transport=udp;lr>".to_string()],
        "one socket crossed, one Record-Route, on the advertised port"
    );
}

// Multi-thread: next-hop resolution runs the resolver under block_in_place.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_bridging_two_listeners_advertises_each_ones_own_port() {
    // Arrives on the second listener, leaves on the default one: two
    // Record-Route entries, each carrying the port its own front serves.
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(RECORD_ROUTE_AND_RELAY);
    behind_a_port_translating_front(&mut state);
    let state = Arc::new(state);

    arriving_on(&state, SECOND_BOUND, invite(SECOND_BOUND));

    let relayed = sent_to(&udp, NEXT_HOP);
    let record_routes = relayed
        .headers
        .get_all("Record-Route")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        record_routes,
        vec![
            "<sip:sip.example.com:5060;transport=udp;lr>".to_string(),
            "<sip:edge.example.com:5062;transport=udp;lr>".to_string(),
        ],
    );
}

#[test]
fn an_auto_answered_options_contact_carries_the_advertised_port() {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script("");
    behind_a_port_translating_front(&mut state);
    let state = Arc::new(state);

    let raw = format!(
        concat!(
            "OPTIONS sip:siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-advertised-options\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:probe@example.com>;tag=probe\r\n",
            "To: <sip:siphon.example.com>\r\n",
            "Call-ID: advertised-options@example.com\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
    );
    arriving_on(&state, BOUND, raw);

    let answer = sent_to(&udp, CALLER);
    let contact = answer.headers.get("Contact").expect("a Contact");
    assert!(
        contact.contains("sip.example.com:5060"),
        "the Contact must name the advertised port, not the bound 15060: {contact}"
    );
}
