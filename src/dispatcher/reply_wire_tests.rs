//! `reply.wire` in `@proxy.on_reply`: the response as siphon received it, in
//! the compact forms and order the peer sent, not as the parsed message
//! serialises; and the request the handler is handed, rebuilt from the parsed
//! message, has no wire.

use pyo3::types::PyAnyMethods;

use super::response::run_reply_handlers;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const RESPONSE: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Content-Length: 0\r\n",
    "i: reply-wire-1\r\n",
    "CSeq: 1 REGISTER\r\n",
    "t: <sip:alice@siphon.example.com>;tag=to-1\r\n",
    "f: <sip:alice@siphon.example.com>;tag=from-1\r\n",
    "v: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-reply-wire\r\n",
    "\r\n",
);

const REQUEST: &str = concat!(
    "REGISTER sip:siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-reply-wire\r\n",
    "From: <sip:alice@siphon.example.com>;tag=from-1\r\n",
    "To: <sip:alice@siphon.example.com>\r\n",
    "Call-ID: reply-wire-1\r\n",
    "CSeq: 1 REGISTER\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

type Row = (Option<Vec<u8>>, Option<Vec<u8>>);

fn run(wire: Option<Bytes>) -> Vec<Row> {
    let dispatcher = test_dispatcher_with_script(concat!(
        "from siphon import proxy\n",
        "SEEN = []\n",
        "@proxy.on_reply\n",
        "def on_reply(request, reply):\n",
        "    SEEN.append((request.wire, reply.wire))\n",
        "    reply.relay()\n",
    ));
    let (_message, forwarded, _) = run_reply_handlers(
        parse_sip_message_bytes(RESPONSE.as_bytes()).expect("the response parses"),
        200,
        "z9hG4bK-reply-wire",
        &dispatcher.state,
        parse_sip_message_bytes(REQUEST.as_bytes()).expect("the request parses"),
        "192.0.2.10:5060".parse().expect("a literal address"),
        Transport::Udp,
        "198.51.100.20:5060".parse().expect("a literal address"),
        dispatcher.state.local_addr,
        ConnectionId(0),
        wire,
    );
    assert!(forwarded);

    let engine_state = dispatcher.state.engine.state();
    let handlers = engine_state.handlers_for(&crate::script::engine::HandlerKind::ProxyReply(None));
    let handler = handlers.first().expect("the reply handler");
    pyo3::Python::attach(|python| {
        handler
            .callable
            .bind(python)
            .getattr("__globals__")
            .and_then(|globals| globals.get_item("SEEN"))
            .and_then(|seen| seen.extract())
            .expect("SEEN")
    })
}

#[test]
fn an_on_reply_handler_sees_the_response_as_received_and_no_request_wire() {
    assert_eq!(
        run(Some(Bytes::from(RESPONSE))),
        vec![(None, Some(RESPONSE.as_bytes().to_vec()))]
    );
}

#[test]
fn a_reply_without_received_bytes_has_no_wire() {
    assert_eq!(run(None), vec![(None, None)]);
}
