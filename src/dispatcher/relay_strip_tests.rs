//! `strip=` on `request.relay()` / `request.fork()`: header fields removed from
//! what goes on the wire, and only from that.
//!
//! An edge proxy can be the node that must not forward a header field and the
//! node that reports on it at once. TS 24.229 §5.2.1 has the P-CSCF remove
//! P-Charging-Vector and P-Charging-Function-Addresses from anything it sends
//! to the UE, and the same P-CSCF opens the terminating leg's Rf record from
//! the session's request, whose ICID and IOIs are in that vector. Removing the
//! header from the request in the script takes it out of both; `strip=` takes
//! it out of the forwarded copy only.

use super::proxy_dialog_state_tests::{
    find, header, headers, invites_by_destination, knows_itself, response_to, Proxy,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const VECTOR: &str = "icid-value=strip-icid-1;orig-ioi=home.example.net";
const ADDRESSES: &str = "ccf=192.0.2.200";

fn proxy(routing: &str) -> Proxy {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    {routing}\n",
        ),
        routing = routing,
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    knows_itself(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// An INVITE from the core carrying both charging header fields.
fn charged_invite(call_id: &str, to: &str) -> String {
    format!(
        concat!(
            "INVITE {to} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@example.com>;tag=core-tag\r\n",
            "To: <{to}>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 5 INVITE\r\n",
            "Contact: <sip:core@203.0.113.5:5060>\r\n",
            "P-Charging-Vector: {vector}\r\n",
            "P-Charging-Function-Addresses: {addresses}\r\n",
            "Subject: kept\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        to = to,
        call_id = call_id,
        vector = VECTOR,
        addresses = ADDRESSES,
    )
}

/// The request the proxy session holds for `raw`, the one the charging and
/// CDR paths read.
fn session_request(proxy: &Proxy, raw: &str) -> SipMessage {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let server_key = TransactionManager::key_from_message(&message).expect("a server key");
    let session = proxy
        .state
        .session_store
        .get_by_server_key(&server_key)
        .expect("a proxy session for the relayed INVITE");
    let guard = session.read().expect("the session lock");
    guard.original_request.clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_strip_leaves_the_header_fields_off_the_wire_only() {
    let callee = "198.51.100.41:5060";
    let proxy = proxy(&format!(
        "request.relay(\"sip:callee@{callee}\", \
         strip=[\"P-Charging-Vector\", \"p-charging-function-addresses\"])"
    ));
    let raw = charged_invite("strip-relay@203.0.113.5", "sip:callee@example.com");
    proxy.request("203.0.113.5:5060", &raw);

    let sent = invites_by_destination(&proxy.wire());
    let relayed = find(&sent, callee);
    assert!(
        headers(relayed, "P-Charging-Vector").is_empty(),
        "{relayed:?}"
    );
    assert!(headers(relayed, "P-Charging-Function-Addresses").is_empty());
    assert_eq!(
        header(relayed, "Subject"),
        "kept",
        "nothing else is touched"
    );

    let held = session_request(&proxy, &raw);
    assert_eq!(header(&held, "P-Charging-Vector"), VECTOR);
    assert_eq!(header(&held, "P-Charging-Function-Addresses"), ADDRESSES);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_without_strip_forwards_the_header_fields() {
    let callee = "198.51.100.42:5060";
    let proxy = proxy(&format!("request.relay(\"sip:callee@{callee}\")"));
    let raw = charged_invite("strip-none@203.0.113.5", "sip:callee@example.com");
    proxy.request("203.0.113.5:5060", &raw);

    let sent = invites_by_destination(&proxy.wire());
    let relayed = find(&sent, callee);
    assert_eq!(header(relayed, "P-Charging-Vector"), VECTOR);
    assert_eq!(header(relayed, "P-Charging-Function-Addresses"), ADDRESSES);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_branch_of_a_sequential_fork_is_stripped() {
    let (first, second) = ("198.51.100.43:5060", "198.51.100.44:5060");
    let proxy = proxy(&format!(
        "request.fork([\"sip:a@{first}\", \"sip:b@{second}\"], strategy=\"sequential\", \
         strip=[\"P-Charging-Vector\"])"
    ));
    let raw = charged_invite("strip-fork@203.0.113.5", "sip:group@example.com");
    proxy.request("203.0.113.5:5060", &raw);

    let sent = invites_by_destination(&proxy.wire());
    let to_first = find(&sent, first).clone();
    assert!(headers(&to_first, "P-Charging-Vector").is_empty());
    assert_eq!(
        header(&to_first, "P-Charging-Function-Addresses"),
        ADDRESSES
    );

    // The first branch declines; the second starts from the session's request.
    proxy.response(
        first,
        response_to(
            &to_first,
            486,
            "Busy Here",
            "busy-tag",
            &format!("sip:a@{first}"),
            "",
        ),
    );
    let sent = invites_by_destination(&proxy.wire());
    let to_second = find(&sent, second);
    assert!(headers(to_second, "P-Charging-Vector").is_empty());
    assert_eq!(
        header(to_second, "P-Charging-Function-Addresses"),
        ADDRESSES
    );

    let held = session_request(&proxy, &raw);
    assert_eq!(header(&held, "P-Charging-Vector"), VECTOR);
}
