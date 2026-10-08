//! The Request-URI of a B2BUA's B-leg INVITE is the URI the script dialled.
//!
//! `call.dial(uri)` puts `uri` on the wire as written: user, user parameters
//! (the RFC 4694 number-portability `npdi` and `rn`, which sit before the
//! `@`), host, port and URI parameters. That makes `dial` the way a script
//! writes the whole Request-URI of the outgoing leg, and adds or removes a
//! parameter `call.set_ruri_user()` cannot reach.
//!
//! Driven through the INVITE handler, with the B-leg INVITE read back off the
//! UDP egress, so what is asserted is what a carrier would receive.

use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const CALLEE: &str = "198.51.100.7:5060";
const CALLER: &str = "192.0.2.10:5060";

/// An INVITE to a number that has not been dipped: no `npdi`, no `rn`.
const UNDIPPED_INVITE: &str = concat!(
    "INVITE sip:+15550100@siphon.example.com;user=phone SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ruri\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:+15550123@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:+15550100@siphon.example.com>\r\n",
    "Call-ID: b-leg-ruri@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// The same call arriving already dipped (RFC 4694 §5): `npdi` and `rn` are
/// user parameters, before the `@`.
const DIPPED_INVITE: &str = concat!(
    "INVITE sip:+15550100;npdi;rn=+15550199@siphon.example.com;user=phone SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ruri\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:+15550123@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:+15550100@siphon.example.com>\r\n",
    "Call-ID: b-leg-ruri@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// Run `script`'s `@b2bua.on_invite` on `caller_invite` through the INVITE
/// handler and return the Request-URI of the B-leg INVITE it dialled.
///
/// Read from the datagram as it left, not from a parsed message printed back:
/// a parameter the serializer dropped or reordered would otherwise go unseen.
fn dialled_request_uri(caller_invite: &'static str, script: &str) -> String {
    let dispatcher = test_dispatcher_with_script(script);
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(caller_invite.as_bytes()),
    };
    let request = parse_sip_message_bytes(caller_invite.as_bytes()).expect("the INVITE parses");
    handle_b2bua_invite(inbound, request, &dispatcher.state);

    let callee: SocketAddr = CALLEE.parse().expect("a literal address");
    let mut request_lines = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        let text = String::from_utf8_lossy(&outbound.data).into_owned();
        let request_line = text.lines().next().unwrap_or_default().to_string();
        if outbound.destination == callee {
            if let Some(request_uri) = request_line
                .strip_prefix("INVITE ")
                .and_then(|rest| rest.strip_suffix(" SIP/2.0"))
            {
                return request_uri.to_string();
            }
        }
        request_lines.push(format!("{request_line} to {}", outbound.destination));
    }
    panic!("no INVITE to {CALLEE}, sent: {request_lines:?}");
}

/// Known answer: a dial that adds the number-portability parameters puts
/// exactly that Request-URI on the dialled INVITE.
#[tokio::test(flavor = "multi_thread")]
async fn a_dialled_uri_with_user_parameters_is_the_request_uri_verbatim() {
    let request_uri = dialled_request_uri(
        UNDIPPED_INVITE,
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    assert call.ruri.user_params == {}\n",
            "    call.dial(\n",
            "        \"sip:+15550100;npdi;rn=+15550199@example.com;user=phone\",\n",
            "        next_hop=\"sip:198.51.100.7:5060\",\n",
            "    )\n",
        ),
    );
    assert_eq!(
        request_uri,
        "sip:+15550100;npdi;rn=+15550199@example.com;user=phone"
    );
}

/// And the other direction: a call that arrived dipped leaves without the
/// parameters when the script dials a URI that does not carry them.
#[tokio::test(flavor = "multi_thread")]
async fn a_dialled_uri_without_user_parameters_removes_the_callers() {
    let request_uri = dialled_request_uri(
        DIPPED_INVITE,
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    assert call.ruri.user_params == {\"npdi\": \"\", \"rn\": \"+15550199\"}\n",
            "    call.dial(\n",
            "        \"sip:+15550100@example.com;user=phone\",\n",
            "        next_hop=\"sip:198.51.100.7:5060\",\n",
            "    )\n",
        ),
    );
    assert_eq!(request_uri, "sip:+15550100@example.com;user=phone");
}

/// A script that reads the Request-URI and dials it back as read: the round
/// trip through `call.ruri` loses nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_dipped_request_uri_dialled_back_as_read_is_unchanged() {
    let request_uri = dialled_request_uri(
        DIPPED_INVITE,
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    call.dial(str(call.ruri), next_hop=\"sip:198.51.100.7:5060\")\n",
        ),
    );
    assert_eq!(
        request_uri,
        "sip:+15550100;npdi;rn=+15550199@siphon.example.com;user=phone"
    );
}
