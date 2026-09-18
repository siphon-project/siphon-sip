//! The dispatcher hop a PROXY-fronted deployment depends on: the client address
//! the transport substituted has to reach the script, not stop at the listener.
//!
//! `tests/integration/transport_tests.rs` proves the transport half (the
//! `InboundMessage` carries the header's client) and the script half (a
//! `PyRequest` built with a client address answers `source_ip_in` correctly).
//! Neither covers the join: `handle_request` building the `PyRequest` from
//! `inbound.remote_addr`. Point that construction at anything else and both
//! existing suites stay green while every script sees the front again — which is
//! the whole defect `proxy_protocol` exists to fix.

use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

/// The address a front's PROXY header claimed for the phone.
const PROXIED_CLIENT: &str = "192.0.2.30:51234";
/// The front's own address — what `remote_addr` would hold without the feature.
const FRONT: &str = "198.51.100.7";

/// Answers every OPTIONS with the source address the script was handed, so the
/// value has to survive the whole dispatch path to appear on the wire.
const ECHO_SOURCE: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request(\"OPTIONS\")\n",
    "def options(request):\n",
    "    request.reply(200, request.source_ip)\n",
);

fn options_from(source: &str) -> String {
    format!(
        concat!(
            "OPTIONS sip:siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {source};branch=z9hG4bKproxied\r\n",
            "From: <sip:probe@example.com>;tag=proxied\r\n",
            "To: <sip:siphon.example.com>\r\n",
            "Call-ID: proxied-source@example.com\r\n",
            "CSeq: 1 OPTIONS\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        source = source,
    )
}

#[test]
fn the_script_is_handed_the_proxied_client_address_not_the_fronts() {
    let TestDispatcher { state, udp } = test_dispatcher_with_script(ECHO_SOURCE);
    let state = Arc::new(state);
    let raw = options_from(PROXIED_CLIENT);
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the OPTIONS parses");

    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            // What the accept site substituted after reading the header. Without
            // `proxy_protocol` this would be FRONT.
            remote_addr: PROXIED_CLIENT.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        "OPTIONS".to_string(),
        &state,
    );

    let sent = udp.try_recv().expect("the script answered");
    // Assert on the REASON PHRASE, which is the only part of the answer the
    // script wrote. A substring search over the whole message passes whatever
    // the script saw, because the response echoes the request's Via — and that
    // Via names the client. A test can be green against wiring that hands the
    // script the front's address entirely.
    let answer = parse_sip_message_bytes(&sent.data).expect("the answer parses");
    let reason = match &answer.start_line {
        StartLine::Response(status_line) => status_line.reason_phrase.clone(),
        StartLine::Request(_) => panic!("the script replied, so this is a response"),
    };
    assert_eq!(
        reason, "192.0.2.30",
        "the script must be handed the client the header named"
    );
    assert_ne!(
        reason, FRONT,
        "handing the script the front's address is the defect this feature exists to fix"
    );
}

// The CDR's own join — `handle_request` feeding `cdr_track_proxy_start` from
// `inbound.remote_addr` — is deliberately NOT unit-tested here. `CdrSession`
// keeps `source_ip` private, and the only test reachable without widening that
// would assert `cdr_session_from_invite` stores the argument it was handed,
// which proves nothing about the caller. The behaviour that matters is covered
// end-to-end instead: the SIPp acceptance case (`scripts/proxy_protocol_test.sh`)
// runs a real HAProxy in `send-proxy-v2` and asserts the emitted CDR row carries
// the client and never the front, with a negative control that fails when the
// feature is switched off.
