//! Where an in-dialog request goes when the dialog has no route set.
//!
//! RFC 3261 §12.2.1.1: with an empty route set the request goes to the remote
//! target, the peer's Contact. A leg whose INVITE went to a proxy first (a
//! preloaded `route` entry or a pinned `next_hop`) and whose 2xx carries no
//! Record-Route has the Contact for remote target, not the proxy's address. A
//! leg dialled straight at its peer, a flow-bound leg, an A-leg, and a leg whose
//! peer has since sent a request from its own source keep going to the address
//! siphon has cached, which is how a peer behind NAT is reached.
//!
//! Read off the UDP egress: the 2xx ACK, a re-INVITE and the BYE of a dial,
//! route/LCR and transfer leg.

use super::lcr_ring_timeout_tests::{carrier_response, top_via_branch, Sent, Sequence, CALLER};
use super::*;
use crate::script::api::call::CallAction;

/// Where the proxy the INVITE goes to first sits, and where the callee is.
const PROXY: &str = "198.51.100.200:5080";
const PROXY_ROUTE: &str = "<sip:198.51.100.200:5080;lr>";
const CONTACT_ADDRESS: &str = "203.0.113.77:5090";
const CONTACT: &str = "<sip:callee@203.0.113.77:5090>";
const DIRECT_PEER: &str = "198.51.100.50:5060";

fn reply_to() -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::new(),
    }
}

fn dial(
    sequence: &Sequence,
    target: &str,
    next_hop: Option<&str>,
    route: &[&str],
    flow: Option<crate::script::api::registrar::PyFlow>,
) {
    let action = CallAction::Dial {
        target: target.to_string(),
        next_hop: next_hop.map(str::to_string),
        flow,
        route: route.iter().map(|entry| entry.to_string()).collect(),
        send_socket: None,
        timeout: 30,
    };
    run(sequence, action);
}

fn run(sequence: &Sequence, action: CallAction) {
    tokio::task::block_in_place(|| {
        apply_routing_action(
            &sequence.call_id,
            action,
            &sequence.invite,
            &reply_to(),
            &sequence.dispatcher.state,
        )
    });
}

fn the_invite(sequence: &Sequence, address: &str) -> SipMessage {
    let sent = sequence.wire();
    let listed: Vec<String> = sent
        .iter()
        .map(|sent| format!("{} {:?}", sent.destination, sent.message.method()))
        .collect();
    sent.into_iter()
        .find(|sent| {
            sent.destination.to_string() == address
                && sent.message.method() == Some(&Method::Invite)
        })
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("no INVITE to {address}: {listed:?}"))
}

/// The callee answers from `source` with `contact` and `record_route`.
fn answer(
    sequence: &Sequence,
    invite: &SipMessage,
    source: &str,
    contact: &str,
    record_route: Option<&str>,
) -> Vec<Sent> {
    let mut response = carrier_response(invite, 200, "OK");
    response.headers.set("Contact", contact.to_string());
    if let Some(record_route) = record_route {
        response
            .headers
            .set("Record-Route", record_route.to_string());
    }
    let handled = handle_b2bua_response(
        &sequence.call_id,
        &top_via_branch(invite),
        &mut response,
        200,
        source.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    );
    assert!(handled, "the call was gone");
    sequence.wire()
}

fn request_to(sent: &[Sent], method: Method) -> &Sent {
    sent.iter()
        .find(|sent| {
            sent.message.method() == Some(&method) && sent.destination.to_string() != CALLER
        })
        .unwrap_or_else(|| panic!("no {method:?} to the callee"))
}

fn routes(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

fn request_uri(message: &SipMessage) -> String {
    match &message.start_line {
        StartLine::Request(request) => request.request_uri.to_string(),
        StartLine::Response(_) => panic!("a request"),
    }
}

/// The callee's BYE after the call is torn down, and the A-leg's.
fn hang_up(sequence: &Sequence) -> Vec<Sent> {
    let _ = sequence.wire();
    assert!(b2bua_terminate_call_inner(
        &sequence.call_id,
        None,
        "b2bua",
        &sequence.dispatcher.state
    ));
    sequence.wire()
}

/// A re-INVITE siphon sends the callee leg.
fn reinvite_callee(sequence: &Sequence) -> Vec<Sent> {
    let _ = sequence.wire();
    let sent = tokio::task::block_in_place(|| {
        b2bua_send_reinvite_on_leg(
            &sequence.call_id,
            false,
            b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n".to_vec(),
            "reinvite:a2b",
            &sequence.dispatcher.state,
        )
    });
    assert!(sent, "the re-INVITE reached the transport");
    sequence.wire()
}

/// The ACK, the re-INVITE and the BYE of a proxy-first leg whose 2xx named no
/// route set go to the Contact, with the Contact as Request-URI and no Route.
fn assert_goes_to_the_contact(sequence: &Sequence, invite: &SipMessage, source: &str) {
    let sent = answer(sequence, invite, source, CONTACT, None);
    let ack = request_to(&sent, Method::Ack);
    assert_eq!(ack.destination.to_string(), CONTACT_ADDRESS, "ACK");
    assert_eq!(request_uri(&ack.message), "sip:callee@203.0.113.77:5090");
    assert!(routes(&ack.message).is_empty());

    let sent = reinvite_callee(sequence);
    let reinvite = request_to(&sent, Method::Invite);
    assert_eq!(
        reinvite.destination.to_string(),
        CONTACT_ADDRESS,
        "re-INVITE"
    );
    assert!(routes(&reinvite.message).is_empty());

    let sent = hang_up(sequence);
    let bye = request_to(&sent, Method::Bye);
    assert_eq!(bye.destination.to_string(), CONTACT_ADDRESS, "BYE");
    assert_eq!(request_uri(&bye.message), "sip:callee@203.0.113.77:5090");
    assert!(routes(&bye.message).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dial_through_a_preloaded_route_with_no_record_route_goes_to_the_contact() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    assert_goes_to_the_contact(&sequence, &invite, PROXY);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dial_through_a_pinned_next_hop_with_no_record_route_goes_to_the_contact() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        Some("sip:198.51.100.201:5060"),
        &[],
        None,
    );
    let invite = the_invite(&sequence, "198.51.100.201:5060");
    assert_goes_to_the_contact(&sequence, &invite, "198.51.100.201:5060");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_route_sequence_leg_through_a_proxy_goes_to_the_contact() {
    let sequence = Sequence::new_call("");
    run(
        &sequence,
        CallAction::RouteSequence {
            routes: vec![crate::lcr::Route {
                ruri: Some("sip:callee@203.0.113.50".to_string()),
                next_hop: Some(format!("sip:{PROXY}")),
                route: vec![PROXY_ROUTE.to_string()],
                // A route set a controller named, as the `route` verb builds it.
                named_route: true,
                ..Default::default()
            }],
            send_socket: None,
            default_timeout: 30,
        },
    );
    let invite = the_invite(&sequence, PROXY);
    assert_goes_to_the_contact(&sequence, &invite, PROXY);
}

/// A 2xx that carries a Record-Route has a route set: its first hop.
#[tokio::test(flavor = "multi_thread")]
async fn a_record_route_in_the_2xx_still_decides() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let record_route = "<sip:198.51.100.210:5061;lr>";
    let sent = answer(&sequence, &invite, PROXY, CONTACT, Some(record_route));
    let ack = request_to(&sent, Method::Ack);
    assert_eq!(ack.destination.to_string(), "198.51.100.210:5061");
    assert_eq!(routes(&ack.message), [record_route]);
    let sent = hang_up(&sequence);
    let bye = request_to(&sent, Method::Bye);
    assert_eq!(bye.destination.to_string(), "198.51.100.210:5061");
    assert_eq!(routes(&bye.message), [record_route]);
}

/// Straight at the peer, no route and no next hop: a private Contact is the
/// peer's own idea of its address, and the cached source is how it is reached.
#[tokio::test(flavor = "multi_thread")]
async fn a_direct_dial_keeps_the_cached_address_whatever_the_contact_says() {
    let sequence = Sequence::new_call("");
    dial(&sequence, "sip:callee@198.51.100.50:5060", None, &[], None);
    let invite = the_invite(&sequence, DIRECT_PEER);
    let sent = answer(
        &sequence,
        &invite,
        DIRECT_PEER,
        "<sip:callee@10.1.2.3:5060>",
        None,
    );
    let ack = request_to(&sent, Method::Ack);
    assert_eq!(ack.destination.to_string(), DIRECT_PEER, "ACK");
    let sent = reinvite_callee(&sequence);
    assert_eq!(
        request_to(&sent, Method::Invite).destination.to_string(),
        DIRECT_PEER
    );
    let sent = hang_up(&sequence);
    let bye = request_to(&sent, Method::Bye);
    assert_eq!(bye.destination.to_string(), DIRECT_PEER, "BYE");
    assert_eq!(request_uri(&bye.message), "sip:callee@10.1.2.3:5060");
}

/// Once the peer has sent a request of its own, its source is where it is
/// reached, whatever route the INVITE took.
#[tokio::test(flavor = "multi_thread")]
async fn a_peer_request_from_its_own_source_ends_the_contact_rule() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let _ = sequence.wire();

    let own_source = "203.0.113.99:5099";
    let from = format!("{};tag=carrier-tag", invite.headers.get("To").expect("To"));
    let to = invite.headers.get("From").expect("From").to_string();
    let call_id = invite.headers.get("Call-ID").expect("Call-ID").to_string();
    let (raw, message) = super::dialog_state_transfer_tests::in_dialog(
        "INVITE", own_source, &from, &to, &call_id, 9, "",
    );
    tokio::task::block_in_place(|| {
        handle_b2bua_reinvite(
            super::dialog_state_events_tests::inbound(own_source, &raw),
            message,
            &sequence.dispatcher.state,
        )
    });
    let _ = sequence.wire();
    let sent = hang_up(&sequence);
    let bye = request_to(&sent, Method::Bye);
    assert_eq!(bye.destination.to_string(), own_source);
}

/// A flow always wins.
#[tokio::test(flavor = "multi_thread")]
async fn a_flow_bound_leg_keeps_its_flow() {
    let sequence = Sequence::new_call("");
    let flow = crate::script::api::registrar::PyFlow {
        transport: "udp".to_string(),
        source_addr: "198.51.100.60:5070".parse().expect("a literal address"),
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        connection_id: 0,
        kind: crate::script::api::registrar::FlowKind::Inbound,
    };
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        Some("sip:198.51.100.201:5060"),
        &[],
        Some(flow),
    );
    let invite = the_invite(&sequence, "198.51.100.60:5070");
    let sent = answer(&sequence, &invite, "198.51.100.60:5070", CONTACT, None);
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        "198.51.100.60:5070"
    );
    let sent = hang_up(&sequence);
    assert_eq!(
        request_to(&sent, Method::Bye).destination.to_string(),
        "198.51.100.60:5070"
    );
}

/// A Contact that names nothing siphon can resolve leaves the cached address.
#[tokio::test(flavor = "multi_thread")]
async fn an_unresolvable_contact_falls_back_to_the_cached_address() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let sent = answer(&sequence, &invite, PROXY, "<tel:+15550100>", None);
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        PROXY
    );
    let sent = hang_up(&sequence);
    assert_eq!(
        request_to(&sent, Method::Bye).destination.to_string(),
        PROXY
    );
}

/// The caller's leg is never retargeted: it is reached where it called from.
#[tokio::test(flavor = "multi_thread")]
async fn the_a_leg_keeps_its_cached_address() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let call = sequence
        .dispatcher
        .state
        .call_actors
        .get_call(&sequence.call_id)
        .expect("the call");
    assert!(call.a_leg.proxy_first_hop.is_none());
    assert_eq!(call.a_leg.transport.remote_addr.to_string(), CALLER);
}

/// An INFO siphon sends the callee leg on a proxy-first leg goes to the Contact
/// as well: every sender follows the leg's one cached address.
#[tokio::test(flavor = "multi_thread")]
async fn an_info_on_a_proxy_first_leg_goes_to_the_contact() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let _ = sequence.wire();
    send_info_on_leg(
        &sequence.dispatcher.state,
        &sequence.call_id,
        false,
        Some("application/dtmf-relay"),
        b"Signal=1\r\nDuration=100\r\n".to_vec(),
        &[],
    )
    .expect("the INFO is sent");
    let sent = sequence.wire();
    let info = request_to(&sent, Method::Info);
    assert_eq!(info.destination.to_string(), CONTACT_ADDRESS);
    assert!(routes(&info.message).is_empty());
}

/// A registered AoR's contact is reached over the Path its binding carries, a
/// route set that is not a controller's to name: the leg keeps the address
/// siphon has for it, whatever a private Contact says. Parallel (a fork) and
/// sequential (a failover queue) dials of an `{aor}` branch alike.
async fn an_aor_branch_through_a_path_keeps_its_cached_address(parallel: bool) {
    use super::control_dial_identity_tests::{dial_targets, park, wire as egress};
    let dispatcher = super::test_dispatcher::test_dispatcher();
    let call_id = park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![DialTarget {
            uri: "sip:callee@10.9.8.7:5060".to_string(),
            aor: Some("sip:callee@example.com".to_string()),
            route: vec![PROXY_ROUTE.to_string()],
            ..Default::default()
        }],
        parallel,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let invite = egress(&dispatcher)
        .into_iter()
        .find(|sent| {
            sent.destination.to_string() == PROXY && sent.message.method() == Some(&Method::Invite)
        })
        .map(|sent| sent.message)
        .expect("the INVITE goes to the Path's first hop");
    let mut response = carrier_response(&invite, 200, "OK");
    response
        .headers
        .set("Contact", "<sip:callee@10.9.8.7:5060>".to_string());
    assert!(handle_b2bua_response(
        &call_id,
        &top_via_branch(&invite),
        &mut response,
        200,
        PROXY.parse().expect("a literal address"),
        &dispatcher.state,
    ));
    let sent = egress(&dispatcher);
    let ack = sent
        .iter()
        .find(|sent| sent.message.method() == Some(&Method::Ack))
        .expect("an ACK");
    assert_eq!(
        ack.destination.to_string(),
        PROXY,
        "parallel={parallel} ACK"
    );
    assert!(b2bua_terminate_call_inner(
        &call_id,
        None,
        "b2bua",
        &dispatcher.state
    ));
    let sent = egress(&dispatcher);
    let bye = sent
        .iter()
        .find(|sent| {
            sent.message.method() == Some(&Method::Bye) && sent.destination.to_string() != CALLER
        })
        .expect("a BYE to the callee");
    assert_eq!(
        bye.destination.to_string(),
        PROXY,
        "parallel={parallel} BYE"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forked_aor_branch_through_a_path_keeps_its_cached_address() {
    an_aor_branch_through_a_path_keeps_its_cached_address(true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_aor_branch_through_a_path_keeps_its_cached_address() {
    an_aor_branch_through_a_path_keeps_its_cached_address(false).await;
}

/// The remote target the leg's INVITE went to, as the call holds it.
fn b_leg_target(sequence: &Sequence) -> (String, Transport) {
    let call = sequence
        .dispatcher
        .state
        .call_actors
        .get_call(&sequence.call_id)
        .expect("the call");
    let leg = &call.b_legs[0];
    (
        leg.transport.remote_addr.to_string(),
        leg.transport.transport,
    )
}

/// A second 2xx from the dialog of another fork of the proxy, with its own
/// To-tag and Contact.
fn answer_as_another_dialog(sequence: &Sequence, invite: &SipMessage, contact: &str) -> Vec<Sent> {
    let mut response = carrier_response(invite, 200, "OK");
    response.headers.set(
        "To",
        format!("{};tag=y-tag", invite.headers.get("To").expect("To")),
    );
    response.headers.set("Contact", contact.to_string());
    assert!(handle_b2bua_response(
        &sequence.call_id,
        &top_via_branch(invite),
        &mut response,
        200,
        PROXY.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    ));
    sequence.wire()
}

/// A proxy that forks the INVITE and Record-Routes neither answer: each dialog
/// is reached at its own Contact. The one the leg adopts (the first 2xx) fixes
/// the leg's address for later requests; the other's ACK goes to its own
/// Contact, never to the adopted dialog's.
#[tokio::test(flavor = "multi_thread")]
async fn each_dialog_of_a_forking_proxy_is_acked_at_its_own_contact() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let sent = answer(&sequence, &invite, PROXY, CONTACT, None);
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        CONTACT_ADDRESS
    );
    let sent = answer_as_another_dialog(&sequence, &invite, "<sip:callee@203.0.113.78:5091>");
    let other = request_to(&sent, Method::Ack);
    assert_eq!(other.destination.to_string(), "203.0.113.78:5091");
    assert_eq!(request_uri(&other.message), "sip:callee@203.0.113.78:5091");
    assert_eq!(
        b_leg_target(&sequence).0,
        CONTACT_ADDRESS,
        "the adopted one"
    );
    let sent = hang_up(&sequence);
    assert_eq!(
        request_to(&sent, Method::Bye).destination.to_string(),
        CONTACT_ADDRESS
    );
}

/// A dialog whose Contact needs resolving is ACKed at the leg's first hop,
/// whichever dialog the leg's cache has been moved to by then.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostname_contact_of_another_dialog_is_acked_at_the_first_hop() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let sent = answer_as_another_dialog(&sequence, &invite, "<sip:callee@other.example.test:5091>");
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        PROXY
    );
}

/// The decision is from the 2xx's own Record-Route: a route set a reliable
/// provisional of some other early dialog left on the leg does not defer it.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_dialogs_route_set_does_not_defer_the_decision() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    sequence
        .dispatcher
        .state
        .call_actors
        .get_call_mut(&sequence.call_id)
        .expect("the call")
        .b_legs[0]
        .dialog
        .route_set = vec!["<sip:198.51.100.222:5099;lr>".to_string()];
    let sent = answer(&sequence, &invite, PROXY, CONTACT, None);
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        CONTACT_ADDRESS
    );
    assert_eq!(b_leg_target(&sequence).0, CONTACT_ADDRESS);
}

/// The first answer decides once: a copy of that 2xx carrying another Contact
/// changes nothing about where the leg is reached.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_2xx_never_changes_the_routing() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let _ = answer(
        &sequence,
        &invite,
        PROXY,
        "<sip:callee@203.0.113.99:5999>",
        None,
    );
    assert_eq!(b_leg_target(&sequence).0, CONTACT_ADDRESS);
    let sent = hang_up(&sequence);
    assert_eq!(
        request_to(&sent, Method::Bye).destination.to_string(),
        CONTACT_ADDRESS
    );
}

/// A Contact whose connection would have to verify a name (`sips:` to a
/// hostname) is not taken: the leg keeps its cached address, ACK and BYE alike.
#[tokio::test(flavor = "multi_thread")]
async fn a_sips_hostname_contact_keeps_the_cached_address() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let sent = answer(
        &sequence,
        &invite,
        PROXY,
        "<sips:callee@secure.example.test:5091>",
        None,
    );
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        PROXY
    );
    let sent = hang_up(&sequence);
    assert_eq!(
        request_to(&sent, Method::Bye).destination.to_string(),
        PROXY
    );
}

/// RFC 3263 §4.1: a `transport=tcp` Contact is reached over TCP, and a numeric
/// `sip:` Contact with no transport over UDP.
#[tokio::test(flavor = "multi_thread")]
async fn the_contacts_transport_decides_the_legs_transport() {
    for (contact, transport) in [
        (
            "<sip:callee@203.0.113.77:5090;transport=tcp>",
            Transport::Tcp,
        ),
        ("<sip:callee@203.0.113.77:5090>", Transport::Udp),
    ] {
        let sequence = Sequence::new_call("");
        dial(
            &sequence,
            "sip:callee@203.0.113.50",
            None,
            &[PROXY_ROUTE],
            None,
        );
        let invite = the_invite(&sequence, PROXY);
        let _ = answer(&sequence, &invite, PROXY, contact, None);
        assert_eq!(
            b_leg_target(&sequence),
            (CONTACT_ADDRESS.to_string(), transport),
            "{contact}"
        );
    }
}

/// A nameserver on its own thread that answers every A query with
/// `203.0.113.88` after `delay`.
fn slow_nameserver(delay: std::time::Duration) -> SocketAddr {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("a loopback socket");
    let address = socket.local_addr().expect("a bound address");
    std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        while let Ok((length, from)) = socket.recv_from(&mut buffer) {
            std::thread::sleep(delay);
            let query = &buffer[..length];
            if query.len() < 12 {
                continue;
            }
            let mut end = 12;
            while end < query.len() && query[end] != 0 {
                end += usize::from(query[end]) + 1;
            }
            let question_end = end + 5;
            if question_end > query.len() {
                continue;
            }
            let query_type = u16::from_be_bytes([query[question_end - 4], query[question_end - 3]]);
            let mut answer = Vec::new();
            answer.extend_from_slice(&query[0..2]);
            answer.extend_from_slice(&[0x81, 0x80, 0, 1]);
            answer.extend_from_slice(&[0, u8::from(query_type == 1), 0, 0, 0, 0]);
            answer.extend_from_slice(&query[12..question_end]);
            if query_type == 1 {
                answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
                answer.extend_from_slice(&[203, 0, 113, 88]);
            }
            let _ = socket.send_to(&answer, from);
        }
    });
    address
}

/// A hostname Contact is resolved off the response path: the 2xx is relayed and
/// ACKed at the first hop without waiting for the resolver, and the leg moves
/// to the resolved address when it answers, for the requests that follow.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostname_contact_resolves_off_the_response_path() {
    let mut sequence = Sequence::new_call("");
    sequence.dispatcher.state.dns_resolver =
        Arc::new(crate::dns::SipResolver::with_test_nameserver(
            slow_nameserver(std::time::Duration::from_millis(700)),
        ));
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let started = std::time::Instant::now();
    let sent = answer(
        &sequence,
        &invite,
        PROXY,
        "<sip:callee@contact.example.test:5090>",
        None,
    );
    assert!(
        started.elapsed() < std::time::Duration::from_millis(400),
        "the 2xx waited for DNS: {:?}",
        started.elapsed()
    );
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        PROXY
    );
    assert_eq!(b_leg_target(&sequence).0, PROXY, "not resolved yet");
    // The resolution lands, and the leg follows it.
    let mut moved = false;
    for _ in 0..100 {
        if b_leg_target(&sequence).0 == "203.0.113.88:5090" {
            moved = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(moved, "the leg never reached the resolved Contact");
}

/// The BYE of a leg whose proxy fork answered twice carries the adopted
/// dialog's To-tag, Contact and address, all three: a second dialog's 2xx
/// installs none of its identity on the leg. (Main overwrote the leg's remote tag
/// and Contact with the second 2xx's as well; with the destination fixed at the
/// first dialog the BYE then mixed two dialogs.)
#[tokio::test(flavor = "multi_thread")]
async fn a_second_dialogs_2xx_never_changes_the_adopted_dialogs_identity() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(&sequence, &invite, PROXY, CONTACT, None);
    let _ = answer_as_another_dialog(&sequence, &invite, "<sip:callee@203.0.113.78:5091>");
    let sent = hang_up(&sequence);
    let bye = request_to(&sent, Method::Bye);
    assert_eq!(bye.destination.to_string(), CONTACT_ADDRESS);
    assert_eq!(request_uri(&bye.message), "sip:callee@203.0.113.77:5090");
    let to = bye.message.headers.get("To").expect("To").to_string();
    assert!(
        to.contains("tag=carrier-tag"),
        "the adopted dialog's tag: {to}"
    );
}

/// A retry that supersedes the leg (RFC 4028 §6, a 422) is the same leg
/// continuing: its first hop is still a proxy.
#[tokio::test(flavor = "multi_thread")]
async fn a_retried_proxy_first_leg_keeps_its_classification() {
    let mut sequence = Sequence::new_call("");
    super::sdp_strip_tests::with_session_timer(&mut sequence.dispatcher);
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let mut too_small = carrier_response(&invite, 422, "Session Interval Too Small");
    too_small.headers.set("Min-SE", "1800".to_string());
    let branch = top_via_branch(&invite);
    let snapshot = b_leg_response_snapshot(&sequence.call_id, &branch, &sequence.dispatcher.state)
        .expect("the leg");
    assert!(retry_after_422(
        &sequence.call_id,
        &mut too_small,
        422,
        &sequence.dispatcher.state,
        &snapshot,
    ));
    let retry = the_invite(&sequence, PROXY);
    let sent = answer(&sequence, &retry, PROXY, CONTACT, None);
    assert_eq!(
        request_to(&sent, Method::Ack).destination.to_string(),
        CONTACT_ADDRESS,
        "the retried leg lost its proxy-first classification"
    );
}

/// `transport=tls` on a `sip:` Contact defaults to port 5061 as the resolver
/// does, and a `sips:` hostname stays at the cached address whatever its
/// `transport=` says.
#[tokio::test(flavor = "multi_thread")]
async fn a_tls_contact_defaults_to_5061_and_a_sips_hostname_stays_cached() {
    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(
        &sequence,
        &invite,
        PROXY,
        "<sip:callee@203.0.113.77;transport=tls>",
        None,
    );
    assert_eq!(
        b_leg_target(&sequence),
        ("203.0.113.77:5061".to_string(), Transport::Tls)
    );

    let sequence = Sequence::new_call("");
    dial(
        &sequence,
        "sip:callee@203.0.113.50",
        None,
        &[PROXY_ROUTE],
        None,
    );
    let invite = the_invite(&sequence, PROXY);
    let _ = answer(
        &sequence,
        &invite,
        PROXY,
        "<sips:callee@secure.example.test;transport=tcp>",
        None,
    );
    assert_eq!(b_leg_target(&sequence), (PROXY.to_string(), Transport::Udp));
}

/// A transfer target whose Contact resolves after the target was promoted into
/// the caller's place is still the leg the resolution lands on: the lookup is by
/// the leg's own identity, not by the Via branch it had as a callee leg.
#[tokio::test(flavor = "multi_thread")]
async fn a_resolution_that_lands_after_a_promotion_moves_the_promoted_leg() {
    use super::dialog_state_transfer_tests::{answer as transfer_answer, establish, respond};
    let mut call = establish(10200, "terminate");
    call.dispatcher.state.dns_resolver = Arc::new(crate::dns::SipResolver::with_test_nameserver(
        slow_nameserver(std::time::Duration::from_millis(900)),
    ));
    // The call's internal id outlives the promotion that changes the caller's Call-ID.
    let internal = call.call_id();
    let _ = super::dialog_state_events_tests::wire(&call.dispatcher);
    let dial = ReplacementDial {
        route: vec![PROXY_ROUTE.to_string()],
        ..Default::default()
    };
    tokio::task::block_in_place(|| {
        b2bua_replace_peer_with_state(
            &call.dispatcher.state,
            &call.a_call_id,
            &call.c_uri(),
            None,
            true,
            None,
            None,
            30,
            &dial,
        )
    })
    .expect("the replacement is dialled");
    let sent = super::dialog_state_events_tests::wire(&call.dispatcher);
    let to_c = sent
        .iter()
        .find(|sent| sent.destination == PROXY && sent.message.method() == Some(&Method::Invite))
        .map(|sent| sent.message.clone())
        .expect("the INVITE goes through the proxy");
    let mut answered = transfer_answer(&to_c, PROXY, "c-tag");
    answered.headers.set(
        "Contact",
        "<sip:phone@contact.example.test:5090>".to_string(),
    );
    respond(&call.dispatcher, &internal, PROXY, &to_c, answered);
    let promoted = {
        let held = call
            .dispatcher
            .state
            .call_actors
            .get_call(&internal)
            .expect("the call");
        held.a_leg.dialog.call_id == to_c.headers.get("Call-ID").cloned().unwrap_or_default()
    };
    assert!(promoted, "the target was promoted into the caller's place");
    let mut moved = false;
    for _ in 0..150 {
        let address = call
            .dispatcher
            .state
            .call_actors
            .get_call(&internal)
            .map(|held| held.a_leg.transport.remote_addr.to_string());
        if address.as_deref() == Some("203.0.113.88:5090") {
            moved = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(moved, "the promoted leg never reached the resolved Contact");
}
