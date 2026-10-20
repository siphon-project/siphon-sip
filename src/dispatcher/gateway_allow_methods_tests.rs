//! `gateway.groups[].allow_methods`: the `Allow` siphon advertises to the peers
//! of one gateway group, everywhere it advertises one to them.
//!
//! Some trunk peers pick their transfer method from the `Allow` they are shown,
//! and do the transfer themselves when `REFER` is absent. The group's set
//! reaches that peer on the responses relayed to it, siphon's own answers to
//! it, its OPTIONS answers and the INVITEs sent to it, while every other peer
//! keeps the full set. A script's or controller's `Allow` still wins.
//!
//! Driven through the dispatcher's own paths, read back off the UDP egress.

use super::a_leg_reliable_provisional_tests::{default_dial, Call, CALLEE, PLAIN};
use super::lcr_ring_timeout_tests::{invite_to, summaries, Sent, Sequence, FIRST_CARRIER};
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};

/// What the trunk group shows its peers: no `REFER`.
const NO_REFER: &str = "INVITE, ACK, CANCEL, BYE, OPTIONS, PRACK, UPDATE";
/// The caller every harness here places its call from.
const CALLER: &str = "192.0.2.10:5060";
/// A peer in no group.
const STRANGER: &str = "203.0.113.99:5060";

/// One group, `trunk`, admitting `members` (CIDRs) and advertising `allow`.
/// Its destination is an address no test sends to, so membership comes from
/// `source_networks` and the test reads exactly which peer is in it.
fn gateway(members: &[&str], allow: Option<&str>) -> Arc<DispatcherManager> {
    let manager = DispatcherManager::new();
    let destination = Destination::new(
        "sip:203.0.113.200:5060".to_string(),
        "203.0.113.200:5060".parse().expect("a literal address"),
        Transport::Udp,
        1,
        1,
    );
    manager.add_group(
        DispatcherGroup::new("trunk".to_string(), Algorithm::Weighted, vec![destination])
            .with_source_networks(
                members
                    .iter()
                    .map(|member| member.parse().expect("a CIDR"))
                    .collect(),
            )
            .with_allow_methods(allow.map(str::to_string)),
    );
    Arc::new(manager)
}

fn allow(message: &SipMessage) -> Option<Vec<String>> {
    message.headers.get_all("Allow").cloned()
}

fn one(value: &str) -> Option<Vec<String>> {
    Some(vec![value.to_string()])
}

fn full() -> Option<Vec<String>> {
    one(crate::sip::SUPPORTED_METHODS)
}

// ----- Responses relayed to the caller -----

/// The callee answers the caller's call with `status_code`, advertising its
/// own `Allow`; returns the response siphon relayed to the caller.
fn relayed_to_caller(
    script: &str,
    gateway: Option<Arc<DispatcherManager>>,
    status_code: u16,
    reason: &str,
) -> SipMessage {
    let mut sequence = Sequence::start_fork_with_script(&[FIRST_CARRIER], script);
    sequence.dispatcher.state.gateway = gateway;
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers_with(
        FIRST_CARRIER,
        &invite,
        status_code,
        reason,
        &[("Allow", "INVITE, ACK, BYE")],
    );
    let caller: SocketAddr = CALLER.parse().expect("a literal address");
    let sent: Vec<Sent> = sequence.wire();
    let listed = summaries(&sent);
    sent.into_iter()
        .find(|sent| sent.destination == caller && sent.message.status_code() == Some(status_code))
        .map(|sent| sent.message)
        .unwrap_or_else(|| panic!("no {status_code} to the caller, sent: {listed:?}"))
}

/// The reported case: a caller from the trunk group is shown the group's set,
/// no `REFER`, on the 18x and 2xx relayed to it (and a failure).
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_from_the_group_is_shown_its_set_on_relayed_responses() {
    for (status_code, reason) in [(183, "Session Progress"), (200, "OK"), (486, "Busy Here")] {
        let response = relayed_to_caller(
            "",
            Some(gateway(&["192.0.2.10/32"], Some(NO_REFER))),
            status_code,
            reason,
        );
        assert_eq!(allow(&response), one(NO_REFER), "{status_code}");
    }
}

/// A caller the group does not admit keeps the full set, and so does any
/// caller when no group narrows `Allow` or there is no gateway at all.
#[tokio::test(flavor = "multi_thread")]
async fn other_callers_keep_the_full_set() {
    for gateway in [
        Some(gateway(&["198.51.100.0/24"], Some(NO_REFER))),
        Some(gateway(&["192.0.2.10/32"], None)),
        None,
    ] {
        let response = relayed_to_caller("", gateway, 200, "OK");
        assert_eq!(allow(&response), full());
    }
}

/// A script's `Allow` on the relayed response is precedence 1 over the
/// group's set.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_shaped_allow_wins_over_the_groups_set() {
    let response = relayed_to_caller(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_answer\n",
            "def on_answer(call, reply):\n",
            "    reply.set_header(\"Allow\", \"INVITE, ACK, CANCEL, BYE, REFER\")\n",
        ),
        Some(gateway(&["192.0.2.10/32"], Some(NO_REFER))),
        200,
        "OK",
    );
    assert_eq!(allow(&response), one("INVITE, ACK, CANCEL, BYE, REFER"));
}

// ----- B-leg INVITE -----

/// Dial a call from [`CALLER`] to `callee` and return the B-leg INVITE.
fn b_leg_invite(dispatcher: &TestDispatcher, callee: &str) -> SipMessage {
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        "gateway-allow@192.0.2.10".to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-allow".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    let caller_invite = parse_sip_message_bytes(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-allow\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: gateway-allow@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .expect("the caller INVITE parses");
    assert!(b2bua_send_b_leg_invite(
        &call_id,
        &format!("sip:15550100042@{callee}"),
        None,
        None,
        &[],
        None,
        None,
        &caller_invite,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &[],
        &dispatcher.state,
    ));
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data).expect("siphon's message parses"),
        });
    }
    invite_to(sent, callee)
}

/// An INVITE to a destination in the group carries its set; one to anywhere
/// else carries the full set.
#[tokio::test(flavor = "multi_thread")]
async fn a_b_leg_invite_to_the_group_carries_its_set() {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.gateway = Some(gateway(&["198.51.100.7/32"], Some(NO_REFER)));
    assert_eq!(
        allow(&b_leg_invite(&dispatcher, "198.51.100.7:5060")),
        one(NO_REFER)
    );
    assert_eq!(allow(&b_leg_invite(&dispatcher, STRANGER)), full());
}

/// A script's `call.set_header("Allow", …)` still wins on a B-leg to the group.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_allow_wins_on_a_b_leg_to_the_group() {
    let mut dispatcher = test_dispatcher_with_script(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_header(\"Allow\", \"INVITE, ACK, CANCEL, BYE, REFER\")\n",
        "    call.dial(\"sip:15550100042@198.51.100.7:5060\")\n",
    ));
    dispatcher.state.gateway = Some(gateway(&["198.51.100.7/32"], Some(NO_REFER)));
    let raw = concat!(
        "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-allow-script\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>\r\n",
        "Call-ID: gateway-allow-script@192.0.2.10\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:caller@192.0.2.10:5060>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(raw.as_bytes()),
    };
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    handle_b2bua_invite(inbound, invite, &dispatcher.state);
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            message: parse_sip_message_bytes(&outbound.data).expect("siphon's message parses"),
        });
    }
    assert_eq!(
        allow(&invite_to(sent, "198.51.100.7:5060")),
        one("INVITE, ACK, CANCEL, BYE, REFER")
    );
}

// ----- siphon's own answers to the caller -----

fn placed(gateway: Option<Arc<DispatcherManager>>) -> Call {
    let mut dispatcher = test_dispatcher_with_script(&default_dial());
    dispatcher.state.gateway = gateway;
    Call::place_on(dispatcher, PLAIN, true).0
}

fn send(call: &Call, code: u16, reason: &str, headers: &[(String, String)]) -> SipMessage {
    assert!(send_uas_response(
        &call.state,
        &call.call_id,
        &call.invite,
        code,
        reason,
        None,
        None,
        code >= 200,
        headers,
    ));
    let sent = call.to_caller();
    let statuses: Vec<_> = sent.iter().map(SipMessage::status_code).collect();
    sent.into_iter()
        .find(|message| message.status_code() == Some(code))
        .unwrap_or_else(|| panic!("no {code} to the caller, sent {statuses:?}"))
}

/// siphon's own 180 and 200 to a caller from the group carry the group's set;
/// they used to carry no `Allow` at all.
#[tokio::test(flavor = "multi_thread")]
async fn siphons_own_answer_to_a_caller_from_the_group_carries_its_set() {
    let call = placed(Some(gateway(&["192.0.2.10/32"], Some(NO_REFER))));
    assert_eq!(allow(&send(&call, 180, "Ringing", &[])), one(NO_REFER));
    assert_eq!(allow(&send(&call, 200, "OK", &[])), one(NO_REFER));
    // The B-leg went to a callee in no group: the full set.
    assert_eq!(allow(&call.callee_invite), full());
}

/// Without a narrowing group siphon's own 18x and 2xx carry the full set
/// (RFC 3261 §13.3.1.4: a 2xx to INVITE SHOULD carry `Allow`).
#[tokio::test(flavor = "multi_thread")]
async fn siphons_own_answer_carries_the_full_set_by_default() {
    let call = placed(None);
    assert_eq!(allow(&send(&call, 183, "Session Progress", &[])), full());
    assert_eq!(allow(&send(&call, 200, "OK", &[])), full());
}

/// A controller's or script's `headers` `Allow` replaces the group's set.
#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_allow_in_headers_wins_over_the_groups_set() {
    let call = placed(Some(gateway(&["192.0.2.10/32"], Some(NO_REFER))));
    let explicit = vec![("Allow".to_string(), "INVITE, ACK, CANCEL, BYE".to_string())];
    assert_eq!(
        allow(&send(&call, 200, "OK", &explicit)),
        one("INVITE, ACK, CANCEL, BYE")
    );
}

// ----- OPTIONS and 405 answered with no handler -----

fn answer_to(gateway: Option<Arc<DispatcherManager>>, source: &str, method: &str) -> SipMessage {
    let TestDispatcher { mut state, udp } = test_dispatcher();
    state.gateway = gateway;
    let state = Arc::new(state);
    let raw = format!(
        concat!(
            "{method} sip:siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bK-allow-{method}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:probe@peer.example.com>;tag=probe-tag\r\n",
            "To: <sip:siphon.example.com>\r\n",
            "Call-ID: allow-{method}@peer.example.com\r\n",
            "CSeq: 1 {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        source = source,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: source.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        method.to_string(),
        &state,
    );
    udp.try_iter()
        .filter_map(|sent| parse_sip_message_bytes(&sent.data).ok())
        .find(|sent| sent.status_code().is_some_and(|code| code >= 200))
        .expect("the request got a final response")
}

/// The OPTIONS siphon answers itself, and the 405 for a method nobody
/// handles, carry the sender's group set; another sender gets the full set.
#[tokio::test(flavor = "multi_thread")]
async fn options_and_405_answers_carry_the_senders_group_set() {
    let trunk = gateway(&["198.51.100.0/24"], Some(NO_REFER));
    for (method, code) in [("OPTIONS", 200), ("FOO", 405)] {
        let response = answer_to(Some(Arc::clone(&trunk)), "198.51.100.7:5060", method);
        assert_eq!(response.status_code(), Some(code));
        assert_eq!(allow(&response), one(NO_REFER), "{method} from the group");

        let response = answer_to(Some(Arc::clone(&trunk)), STRANGER, method);
        assert_eq!(allow(&response), full(), "{method} from elsewhere");

        let response = answer_to(None, "198.51.100.7:5060", method);
        assert_eq!(allow(&response), full(), "{method} with no gateway");
    }
}

/// A peer narrowed to a set without `REFER` that sends one anyway in a dialog
/// siphon does not have is still answered 481, not 405: whether siphon
/// implements a method does not depend on what it advertises to the peer.
#[tokio::test(flavor = "multi_thread")]
async fn an_unadvertised_method_is_still_judged_as_implemented() {
    let trunk = gateway(&["198.51.100.0/24"], Some(NO_REFER));
    let TestDispatcher { mut state, udp } = test_dispatcher();
    state.gateway = Some(trunk);
    let state = Arc::new(state);
    let raw = concat!(
        "REFER sip:siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 198.51.100.7:5060;branch=z9hG4bK-allow-refer\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:probe@peer.example.com>;tag=probe-tag\r\n",
        "To: <sip:siphon.example.com>;tag=gone\r\n",
        "Call-ID: allow-refer@peer.example.com\r\n",
        "CSeq: 2 REFER\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: "198.51.100.7:5060".parse().expect("a literal address"),
            data: Bytes::from_static(raw.as_bytes()),
        },
        message,
        "REFER".to_string(),
        &state,
    );
    let response = udp
        .try_iter()
        .filter_map(|sent| parse_sip_message_bytes(&sent.data).ok())
        .find(|sent| sent.status_code().is_some_and(|code| code >= 200))
        .expect("the request got a final response");
    assert_eq!(response.status_code(), Some(481));
}

/// [`CALLEE`] of the shared harness is in no group in these tests.
#[test]
fn the_harness_callee_is_not_a_member() {
    let trunk = gateway(&["192.0.2.10/32"], Some(NO_REFER));
    let callee: SocketAddr = CALLEE.parse().expect("a literal address");
    assert_eq!(trunk.allow_methods_for_peer(callee.ip()), None);
}
