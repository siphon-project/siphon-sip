//! The MT path of an IMS UE whose protected REGISTERs bind its protected
//! server port (TS 24.229 5.1.1.4.2 b): the network's request comes over the
//! set from the P-CSCF's protected client port to that port (TS 33.203 7.1,
//! UDP case), lands on the per-UE socket there, and is answered from it,
//! naming it in the 200's Contact. Driven through the B2BUA INVITE handler
//! with a real script and a real per-UE socket.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::registrant::address::LocalAddrQuery;
use crate::registrant::test_support::{self, impu, ue};
use crate::registrant::EgressDefaults;
use crate::transport::acl::TransportAcl;
use crate::transport::ue_sockets::UeSockets;
use std::collections::{HashMap, HashSet};

/// Loopback, so the per-UE socket binds on any host; one no other test uses.
const UE_IP: &str = "127.0.0.199";
const PCSCF_CLIENT: &str = "198.51.100.10:5064";

/// Keeps the call (a B-leg toward a callee that never answers), for the test
/// to answer the caller as `call.answer()` does through `send_uas_response`.
const HOLDING: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:tester@198.51.100.20:5060\")\n",
);

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 198.51.100.10\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

fn mt_invite(ue_server: SocketAddr) -> String {
    format!(
        concat!(
            "INVITE sip:0010100000000001@{ue} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {pcscf};branch=z9hG4bK-mt-1\r\n",
            "Max-Forwards: 69\r\n",
            "From: <sip:caller@ims.mnc01.mcc001.3gppnetwork.org>;tag=mt-caller\r\n",
            "To: <sip:0010100000000001@ims.mnc01.mcc001.3gppnetwork.org>\r\n",
            "Call-ID: mt-over-the-set@example.test\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@{pcscf}>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        ue = ue_server,
        pcscf = PCSCF_CLIENT,
        length = OFFER.len(),
        sdp = OFFER,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn an_mt_request_to_the_protected_server_port_is_answered_from_it() {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(HOLDING);
    let registrant = Arc::new(test_support::manager());
    test_support::install_egress(&registrant);
    registrant
        .try_add(ue(1, Some(UE_IP.parse().expect("an IP literal"))))
        .expect("added");

    // The binding the authenticated REGISTER makes: the protected server port.
    let listen = HashMap::from([(Transport::Udp, addr("192.0.2.1:5060"))]);
    let defaults = EgressDefaults::new(addr("192.0.2.1:5060"), &listen);
    registrant
        .build_register(&impu(1), defaults, 600000)
        .expect("the initial REGISTER");
    let challenge =
        crate::auth::parse_challenge(&test_support::aka_challenge_value("000000000001"))
            .expect("a challenge");
    let server = crate::ipsec::parse_security_client(test_support::SECURITY_SERVER)
        .expect("a Security-Server");
    registrant.store_security_server(&impu(1), &server, test_support::SECURITY_SERVER);
    let authenticated = registrant
        .build_register_aka(
            &impu(1),
            defaults,
            &challenge,
            600000,
            Some(test_support::SECURITY_SERVER),
        )
        .expect("the authenticated REGISTER");
    let ue_server = addr(&format!("{UE_IP}:6101"));
    assert!(authenticated
        .message
        .headers
        .get("Contact")
        .is_some_and(|contact| contact.contains(&ue_server.to_string())));

    // The per-UE socket on that port, as the registration loop opens it.
    let (inbound_tx, _inbound) = flume::unbounded();
    let sockets = Arc::new(UeSockets::new(
        inbound_tx,
        Arc::new(TransportAcl::new(Vec::new(), Vec::new())),
        None,
        0,
        Vec::new(),
    ));
    let outcome = sockets.reconcile(&HashSet::from([ue_server]));
    assert!(outcome.failed.is_empty(), "{outcome:?}");
    state.listener_registry = crate::transport::ListenerRegistry::from_entries(vec![(
        Transport::Udp,
        addr("192.0.2.1:5060"),
        None,
    )])
    .with_dynamic_udp(Some(Arc::clone(&sockets)));
    state.registrant_manager = Some(Arc::clone(&registrant));
    let state = Arc::new(state);

    // The UE the request is for, from the socket it arrived on.
    assert_eq!(
        registrant.find_by_local(LocalAddrQuery::Socket(ue_server)),
        Some(impu(1))
    );

    let raw = mt_invite(ue_server);
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    tokio::task::block_in_place(|| {
        handle_b2bua_invite(
            InboundMessage {
                client_transport: None,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: ue_server,
                remote_addr: addr(PCSCF_CLIENT),
                data: Bytes::from(raw.clone()),
            },
            message,
            &state,
        )
    });

    let call_id = state
        .call_actors
        .find_by_sip_call_id("mt-over-the-set@example.test")
        .expect("the call was placed");
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    assert!(send_uas_response(
        &state,
        &call_id,
        &invite,
        200,
        "OK",
        Some(OFFER.as_bytes().to_vec()),
        Some("application/sdp"),
        true,
        &[],
    ));
    let answer = loop {
        let sent = tokio::time::timeout(std::time::Duration::from_secs(5), udp.recv_async())
            .await
            .expect("an answer in time")
            .expect("egress open");
        let parsed = parse_sip_message_bytes(&sent.data).expect("parses");
        if parsed.status_code() == Some(200) && sent.destination == addr(PCSCF_CLIENT) {
            break (sent, parsed);
        }
    };
    let (sent, parsed) = answer;
    assert_eq!(
        sent.source_local_addr,
        Some(ue_server),
        "from the protected server port (SA #4: port_us -> port_pc)"
    );
    assert_eq!(
        sent.destination,
        addr(PCSCF_CLIENT),
        "to the P-CSCF's port_pc"
    );
    let contact = parsed.headers.get("Contact").cloned().expect("a Contact");
    assert!(
        contact.contains(&ue_server.to_string()),
        "the 200 names the per-UE socket's identity: {contact}"
    );
}
