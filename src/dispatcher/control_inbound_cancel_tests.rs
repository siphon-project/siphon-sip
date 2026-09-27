//! CANCEL for a call nothing but the control plane knows about.
//!
//! The B2BUA route in [`super::cancel_ack::handle_cancel`] used to be reached
//! only when the *script* had registered a B2BUA handler. That asks the wrong
//! question: a call created over `control.inbound` and driven by a control
//! application has a call actor and no script handlers, so its CANCEL fell
//! through to the `ProxySession` lookup — which cannot match a B2BUA call — and
//! was answered `481 Call/Transaction Does Not Exist`. The callee went on
//! ringing and the flow answered a call the caller had already abandoned.
//!
//! Every other CANCEL test drives [`super::b2bua::cancel::handle_b2bua_cancel`]
//! directly, which is why none of them saw this: they start past the routing
//! decision that was wrong. These go in through `handle_cancel`.

use super::test_dispatcher::test_dispatcher;
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const SIP_CALL_ID: &str = "control-inbound@192.0.2.10";
const BRANCH: &str = "z9hG4bK-control-inbound";

fn cancel_bytes() -> &'static str {
    concat!(
        "CANCEL sip:15550100042@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-control-inbound\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>\r\n",
        "Call-ID: control-inbound@192.0.2.10\r\n",
        "CSeq: 1 CANCEL\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
}

/// A control-plane call actor exists and the script registers nothing. The
/// CANCEL must reach the B2BUA teardown, not the proxy path's 481.
#[test]
fn a_cancel_tears_down_a_call_no_script_handler_claims() {
    // The empty script is the point: `has_b2bua_handlers()` is false here,
    // exactly as in a deployment whose calls arrive over `control.inbound`.
    let dispatcher = test_dispatcher();
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        SIP_CALL_ID.to_string(),
        "caller-tag".to_string(),
        BRANCH.to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));

    let raw = cancel_bytes();
    let cancel = parse_sip_message_bytes(raw.as_bytes()).expect("the CANCEL parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: dispatcher.state.local_addr,
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from_static(raw.as_bytes()),
    };

    handle_cancel(inbound, cancel, Some(BRANCH), CALLER, &dispatcher.state);

    let wire: Vec<String> = dispatcher
        .udp
        .try_iter()
        .map(|sent| String::from_utf8_lossy(&sent.data).into_owned())
        .collect();
    assert!(
        !wire.iter().any(|message| message.contains("481")),
        "the CANCEL was answered 481 — it did not reach the B2BUA teardown: {wire:?}"
    );
    assert!(
        dispatcher.state.call_actors.get_call(&call_id).is_none(),
        "the call actor survived its own CANCEL"
    );
}
