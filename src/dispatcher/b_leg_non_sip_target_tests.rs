//! A B-leg dialled to a URI that is not a SIP URI: `tel:` (RFC 3966), or any
//! other scheme sent on by way of a next hop or a route set.
//!
//! The B-leg `To` is the caller's `To` with its host replaced by the dial
//! target's `host[:port]`, so the caller-facing address does not cross. A `tel:`
//! URI has no host (RFC 3966 §3), and neither has an opaque URI such as
//! `urn:service:sos` (RFC 5031), so there is no authority to put there: the
//! caller's `To` crosses as the caller wrote it (RFC 3261 §8.1.1.2: the `To`
//! names the logical recipient, and need not track the Request-URI). The
//! Request-URI is the dialled URI as written.
//!
//! Driven through the INVITE handler, the B-leg response handler and the
//! request handler, with the datagrams read back off the UDP egress as they
//! left.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const NEXT_HOP: &str = "198.51.100.7:5060";
const SIP_CALL_ID: &str = "non-sip-target@192.0.2.10";

/// An INVITE to a number in the 3GPP test range, addressed with a SIP URI.
const SIP_TO_INVITE: &str = concat!(
    "INVITE sip:001010000000002@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-non-sip-target\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:001010000000001@caller.example.com>;tag=caller-tag\r\n",
    "To: \"Callee\" <sip:001010000000002@siphon.example.com;user=phone>\r\n",
    "Call-ID: non-sip-target@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// The same call addressed with a `tel:` URI in both the Request-URI and `To`.
const TEL_TO_INVITE: &str = concat!(
    "INVITE tel:+15550100 SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-non-sip-target\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:001010000000001@caller.example.com>;tag=caller-tag\r\n",
    "To: <tel:+15550100>\r\n",
    "Call-ID: non-sip-target@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

fn dial(arguments: &str) -> String {
    format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    call.dial({arguments})\n",
        ),
        arguments = arguments,
    )
}

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

/// One datagram siphon sent, as text.
struct Datagram {
    destination: SocketAddr,
    text: String,
}

impl Datagram {
    fn start_line(&self) -> &str {
        self.text.lines().next().unwrap_or_default()
    }

    /// Every line of header `name`, as it is on the wire.
    fn header_lines(&self, name: &str) -> Vec<String> {
        let prefix = format!("{name}: ");
        self.text
            .lines()
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.strip_prefix(prefix.as_str()).map(str::to_string))
            .collect()
    }

    fn header(&self, name: &str) -> String {
        let lines = self.header_lines(name);
        assert_eq!(lines.len(), 1, "one {name} in:\n{}", self.text);
        lines[0].clone()
    }

    fn message(&self) -> SipMessage {
        parse_sip_message_bytes(self.text.as_bytes()).expect("siphon sent a message that parses")
    }
}

/// A caller's call dialled by a script.
struct Dialled {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    invite: Datagram,
}

impl Dialled {
    fn place(caller_invite: &'static str, script: &str) -> Dialled {
        let dispatcher = test_dispatcher_with_script(script);
        let state = Arc::new(dispatcher.state);
        let udp = dispatcher.udp;
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: address(CALLER),
            data: Bytes::from_static(caller_invite.as_bytes()),
        };
        let request = parse_sip_message_bytes(caller_invite.as_bytes()).expect("the INVITE parses");
        tokio::task::block_in_place(|| handle_b2bua_invite(inbound, request, &state));
        let call_id = state
            .call_actors
            .find_by_sip_call_id(SIP_CALL_ID)
            .expect("the call was placed");
        let sent = drain(&udp);
        let listed: Vec<String> = sent
            .iter()
            .map(|datagram| format!("{} to {}", datagram.start_line(), datagram.destination))
            .collect();
        let invite = sent
            .into_iter()
            .find(|datagram| {
                datagram.destination == address(NEXT_HOP)
                    && datagram.start_line().starts_with("INVITE ")
            })
            .unwrap_or_else(|| panic!("no INVITE to {NEXT_HOP}, sent: {listed:?}"));
        Dialled {
            state,
            udp,
            call_id,
            invite,
        }
    }

    /// The callee answers 200 with `Contact: <contact>` and the `Record-Route`
    /// lines given, top first.
    fn callee_answers(&self, contact: &str, record_routes: &[&str]) {
        let invite = self.invite.message();
        let header = |name: &str| {
            invite
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("the B-leg INVITE has no {name}"))
        };
        let mut raw = String::from("SIP/2.0 200 OK\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        for record_route in record_routes {
            raw.push_str(&format!("Record-Route: {record_route}\r\n"));
        }
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        raw.push_str(&format!("Contact: <{contact}>\r\n"));
        raw.push_str("Content-Length: 0\r\n\r\n");
        let mut response = parse_sip_message_bytes(raw.as_bytes()).expect("the 200 parses");
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.call_id,
                &top_via_branch(&invite),
                &mut response,
                200,
                address(NEXT_HOP),
                &self.state,
            )
        });
        assert!(handled, "the call was gone when the callee answered");
    }

    /// The caller's in-dialog `method` on the dialog siphon's `answer` confirmed.
    fn caller_sends(&self, method: &str, cseq: u32, answer: &Datagram) {
        let raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-{method}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:001010000000001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {method}\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            method = method,
            cseq = cseq,
            to = answer.header("To"),
            call_id = SIP_CALL_ID,
        );
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(CALLER),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        let request = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        tokio::task::block_in_place(|| {
            super::request::handle_request(inbound, request, method.to_string(), &self.state)
        });
    }

    fn wire(&self) -> Vec<Datagram> {
        drain(&self.udp)
    }
}

fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Datagram> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Datagram {
                destination: outbound.destination,
                text: String::from_utf8_lossy(frame).into_owned(),
            });
        }
    }
    sent
}

/// Known answer: a `tel:` target goes out as the Request-URI as written, and
/// the `To` is the caller's own, display name and URI parameters included,
/// without its tag. Nothing of the target's is spliced into it: a `tel:` URI
/// has no host to give.
#[tokio::test(flavor = "multi_thread")]
async fn a_tel_target_leaves_the_callers_to_as_the_caller_wrote_it() {
    let dialled = Dialled::place(
        SIP_TO_INVITE,
        &dial("\"tel:+15550199\", next_hop=\"sip:198.51.100.7:5060\""),
    );
    assert_eq!(dialled.invite.start_line(), "INVITE tel:+15550199 SIP/2.0");
    assert_eq!(
        dialled.invite.header("To"),
        "\"Callee\" <sip:001010000000002@siphon.example.com;user=phone>"
    );
    let to = crate::sip::headers::nameaddr::NameAddr::parse(&dialled.invite.header("To"))
        .expect("the To parses as a name-addr");
    assert_eq!(to.uri.host, "siphon.example.com");
    assert_eq!(to.tag, None);
}

/// A `tel:` target with parameters, sent over a route set instead of a next
/// hop: the Request-URI keeps them, and the `To` is still the caller's.
#[tokio::test(flavor = "multi_thread")]
async fn a_tel_target_over_a_route_set_keeps_its_parameters() {
    let dialled = Dialled::place(
        SIP_TO_INVITE,
        &dial(concat!(
            "\"tel:0100;phone-context=+1555\", ",
            "route=[\"<sip:198.51.100.7:5060;lr>\"]"
        )),
    );
    assert_eq!(
        dialled.invite.start_line(),
        "INVITE tel:0100;phone-context=+1555 SIP/2.0"
    );
    assert_eq!(
        dialled.invite.header("To"),
        "\"Callee\" <sip:001010000000002@siphon.example.com;user=phone>"
    );
}

/// A caller that addressed the call with a `tel:` URI keeps that `To` whatever
/// the target is: there is no host in it to replace.
#[tokio::test(flavor = "multi_thread")]
async fn a_tel_to_crosses_to_a_tel_target_and_to_a_sip_target() {
    let dialled = Dialled::place(
        TEL_TO_INVITE,
        &dial("\"tel:+15550100\", next_hop=\"sip:198.51.100.7:5060\""),
    );
    assert_eq!(dialled.invite.start_line(), "INVITE tel:+15550100 SIP/2.0");
    assert_eq!(dialled.invite.header("To"), "<tel:+15550100>");

    let dialled = Dialled::place(TEL_TO_INVITE, &dial("\"sip:198.51.100.7:5060\""));
    assert_eq!(dialled.invite.header("To"), "<tel:+15550100>");
}

/// `call.set_to_host()` still pins the host of a SIP `To` when the target has
/// none to offer.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_to_host_applies_to_a_tel_target() {
    let script = concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_invite\n",
        "def on_invite(call):\n",
        "    call.set_to_host(\"carrier.example.com\")\n",
        "    call.dial(\"tel:+15550199\", next_hop=\"sip:198.51.100.7:5060\")\n",
    );
    let dialled = Dialled::place(SIP_TO_INVITE, script);
    assert_eq!(
        dialled.invite.header("To"),
        "\"Callee\" <sip:001010000000002@carrier.example.com;user=phone>"
    );
}

/// An opaque URI in another scheme goes out as written too: neither the
/// caller's user nor a host is spliced into it, and the `To` stays the caller's.
#[tokio::test(flavor = "multi_thread")]
async fn an_opaque_target_is_the_request_uri_as_written() {
    let dialled = Dialled::place(
        SIP_TO_INVITE,
        &dial("\"urn:service:sos\", next_hop=\"sip:198.51.100.7:5060\""),
    );
    assert_eq!(
        dialled.invite.start_line(),
        "INVITE urn:service:sos SIP/2.0"
    );
    assert_eq!(
        dialled.invite.header("To"),
        "\"Callee\" <sip:001010000000002@siphon.example.com;user=phone>"
    );
}

/// A SIP target still gives the `To` its authority, port included, as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_sip_target_still_gives_the_to_its_authority() {
    let dialled = Dialled::place(SIP_TO_INVITE, &dial("\"sip:198.51.100.7:5060\""));
    assert_eq!(
        dialled.invite.header("To"),
        "\"Callee\" <sip:001010000000002@198.51.100.7:5060;user=phone>"
    );
}

/// The BYE siphon sends the callee of a `tel:` dial is on the dialog the 2xx
/// confirmed (RFC 3261 §12.2.1.1): the Request-URI is the callee's Contact, the
/// Route set is the 2xx's Record-Route reversed, the `To` is the INVITE's with
/// the callee's tag, and the `From` and Call-ID are the INVITE's.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_after_a_tel_dial_follows_the_dialog_the_answer_confirmed() {
    let dialled = Dialled::place(
        SIP_TO_INVITE,
        &dial("\"tel:+15550199\", next_hop=\"sip:198.51.100.7:5060\""),
    );
    dialled.callee_answers(
        "sip:callee@198.51.100.99:5070",
        &["<sip:198.51.100.7:5060;lr>", "<sip:edge.example.com;lr>"],
    );
    let sent = dialled.wire();
    let answer = sent
        .iter()
        .find(|datagram| {
            datagram.destination == address(CALLER) && datagram.start_line() == "SIP/2.0 200 OK"
        })
        .expect("the caller gets the 200");
    dialled.caller_sends("ACK", 1, answer);
    dialled.wire();

    dialled.caller_sends("BYE", 2, answer);
    let sent = dialled.wire();
    let bye = sent
        .iter()
        .find(|datagram| datagram.start_line().starts_with("BYE "))
        .expect("siphon sends the callee a BYE");
    assert_eq!(
        bye.start_line(),
        "BYE sip:callee@198.51.100.99:5070 SIP/2.0"
    );
    assert_eq!(
        bye.destination,
        address(NEXT_HOP),
        "to the first hop of the route set"
    );
    assert_eq!(
        bye.header_lines("Route"),
        vec![
            "<sip:edge.example.com;lr>".to_string(),
            "<sip:198.51.100.7:5060;lr>".to_string(),
        ]
    );
    assert_eq!(
        bye.header("To"),
        format!("{};tag=callee-tag", dialled.invite.header("To"))
    );
    assert_eq!(
        bye.header("To"),
        "\"Callee\" <sip:001010000000002@siphon.example.com;user=phone>;tag=callee-tag"
    );
    assert_eq!(bye.header("From"), dialled.invite.header("From"));
    assert_eq!(bye.header("Call-ID"), dialled.invite.header("Call-ID"));
}
