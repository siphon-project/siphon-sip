//! The `Route` of a B-leg INVITE dialled with `call.dial(route=[...])`.
//!
//! RFC 3261 §20.34 has `Route` carry `name-addr` values, and §20 says why the
//! angle brackets matter: "If the URI is not enclosed in angle brackets, any
//! semicolon-delimited parameters are header-parameters, not URI parameters."
//! A route entry written to the wire bare, `Route: sip:host;lr`, therefore has
//! no `lr` on its URI as the next hop reads it, and that hop treats the request
//! as strictly routed (§16.4). Whatever form the script hands over, a bare URI,
//! a bracketed one or a full `name-addr`, each entry goes out as a `name-addr`
//! with every parameter where the script put it.
//!
//! Driven through the INVITE handler, with the B-leg INVITE read back off the
//! UDP egress as the datagram that left.

use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const FIRST_HOP: &str = "198.51.100.7:5060";

const CALLER_INVITE: &str = concat!(
    "INVITE sip:001010000000002@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-route-entry\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:001010000000001@caller.example.com>;tag=caller-tag\r\n",
    "To: <sip:001010000000002@siphon.example.com>\r\n",
    "Call-ID: route-entry@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:caller@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// Where the callee itself is, which is not where a routed INVITE goes.
const CALLEE: &str = "198.51.100.99:5060";

/// Run a script that dials the callee with `route=[<entries>]` and return the
/// `Route` lines of the B-leg INVITE as they are on the wire, or what siphon
/// sent instead when no INVITE went to the first hop of the route set (RFC 3261
/// §8.1.2).
fn dialled_route_lines(entries: &str) -> Result<Vec<String>, Vec<String>> {
    let script = format!(
        concat!(
            "from siphon import b2bua\n",
            "\n",
            "@b2bua.on_invite\n",
            "def on_invite(call):\n",
            "    call.dial(\"sip:001010000000002@{callee}\", route=[{entries}])\n",
        ),
        callee = CALLEE,
        entries = entries,
    );
    let dispatcher = test_dispatcher_with_script(&script);
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(CALLER_INVITE.as_bytes()),
    };
    let request = parse_sip_message_bytes(CALLER_INVITE.as_bytes()).expect("the INVITE parses");
    handle_b2bua_invite(inbound, request, &dispatcher.state);

    let first_hop: SocketAddr = FIRST_HOP.parse().expect("a literal address");
    let mut sent = Vec::new();
    while let Ok(outbound) = dispatcher.udp.try_recv() {
        let text = String::from_utf8_lossy(&outbound.data).into_owned();
        let start_line = text.lines().next().unwrap_or_default().to_string();
        if outbound.destination == first_hop && start_line.starts_with("INVITE ") {
            return Ok(text
                .lines()
                .take_while(|line| !line.is_empty())
                .filter_map(|line| line.strip_prefix("Route: ").map(str::to_string))
                .collect());
        }
        let routes: Vec<&str> = text
            .lines()
            .take_while(|line| !line.is_empty())
            .filter(|line| line.starts_with("Route: "))
            .collect();
        sent.push(format!(
            "{start_line} to {} {routes:?}",
            outbound.destination
        ));
    }
    Err(sent)
}

/// Known answer: a bare URI with parameters goes out in angle brackets, so its
/// parameters are the URI's and the next hop sees `lr`.
#[tokio::test(flavor = "multi_thread")]
async fn a_bare_uri_goes_out_as_a_name_addr_with_its_parameters_inside() {
    assert_eq!(
        dialled_route_lines("\"sip:198.51.100.7:5060;lr;x=y\""),
        Ok(vec!["<sip:198.51.100.7:5060;lr;x=y>".to_string()])
    );
}

/// A bracketed URI is already a name-addr and goes out as written.
#[tokio::test(flavor = "multi_thread")]
async fn a_bracketed_uri_goes_out_as_written() {
    assert_eq!(
        dialled_route_lines("\"<sip:198.51.100.7:5060;lr;x=y>\""),
        Ok(vec!["<sip:198.51.100.7:5060;lr;x=y>".to_string()])
    );
}

/// A name-addr with a display name keeps it, and the parameters after the
/// closing bracket stay header parameters.
#[tokio::test(flavor = "multi_thread")]
async fn a_name_addr_keeps_its_display_name_and_header_parameters() {
    assert_eq!(
        dialled_route_lines("'\"First hop\" <sip:198.51.100.7:5060;lr>;hop=1'"),
        Ok(vec![
            "\"First hop\" <sip:198.51.100.7:5060;lr>;hop=1".to_string()
        ])
    );
}

/// Each entry is one `Route` line, in the order given, whatever mix of forms
/// the list is in; a received `Route` value handed over whole, several entries
/// on one line, is taken apart at its commas.
#[tokio::test(flavor = "multi_thread")]
async fn every_entry_is_its_own_route_in_the_order_given() {
    assert_eq!(
        dialled_route_lines(concat!(
            "\"sip:orig@198.51.100.7:5060;lr\", ",
            "\"<sip:edge.example.com;lr>, Core <sip:core.example.com;lr;odi=abc>\""
        )),
        Ok(vec![
            "<sip:orig@198.51.100.7:5060;lr>".to_string(),
            "<sip:edge.example.com;lr>".to_string(),
            "Core <sip:core.example.com;lr;odi=abc>".to_string(),
        ])
    );
}

/// An entry that is not a URI stops the dial where the script made it: nothing
/// is sent toward a callee, and the caller's INVITE is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_entry_that_is_no_uri_dials_nothing() {
    let sent = dialled_route_lines("\"198.51.100.7:5060;lr\"")
        .expect_err("no INVITE goes to the first hop");
    assert!(
        sent.iter()
            .all(|line| line.contains(&format!(" to {CALLER} "))),
        "{sent:?}"
    );
    assert!(
        sent.iter().any(|line| line.starts_with("SIP/2.0 500 ")),
        "{sent:?}"
    );
}
