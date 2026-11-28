//! A script hunt over a registered AoR's bindings behind an edge proxy.
//!
//! `call.fork(registrar.lookup(aor), strategy="sequential")` reaches each
//! binding through the route set its Path gives (RFC 3327 §5.3): the INVITE
//! carries exactly that Route, and goes to its topmost entry, which is the
//! edge proxy, whose Path token says which binding the call is for.
//!
//! The decision is the script API's own (`PyCall::fork`, run here from Python
//! against the real registrar) and the INVITE is what the dispatcher puts on the
//! UDP egress for it (`apply_routing_action`), so the route set is followed from
//! the binding to the wire.

use super::lcr_ring_timeout_tests::{summaries, Sequence, CALLER};
use super::*;
use crate::script::api::call::PyCall;
use crate::script::api::registrar::PyRegistrar;
use pyo3::types::{PyDict, PyList};

const EDGE_ADDRESS: &str = "198.51.100.230:5080";
const PATH: &str = "<sip:TOKEN-A@198.51.100.230:5080;lr>";
const CONTACT: &str = "sip:hunt-path@203.0.113.40:5060";

#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_hunt_reaches_a_binding_through_its_path() {
    let aor = "sip:hunt-path@example.com";
    crate::script::api::test_registrar()
        .save_full(
            aor,
            parse_uri_standalone(CONTACT).expect("a contact URI"),
            3600,
            1.0,
            "register-hunt-path".to_string(),
            1,
            None,
            None,
            None,
            None,
            vec![PATH.to_string()],
            Default::default(),
            Vec::new(),
        )
        .expect("the binding saves");
    let sequence = Sequence::new_call("");

    // The script's decision: fork the AoR's bindings, one after the other.
    let registrar = PyRegistrar::new(Arc::clone(crate::script::api::test_registrar()));
    let action = Python::attach(|py| {
        let call = Bound::new(
            py,
            PyCall::new(
                sequence.call_id.clone(),
                Arc::clone(&sequence.invite),
                "192.0.2.10".to_string(),
                "udp".to_string(),
            ),
        )
        .expect("a call object");
        let contacts = PyList::empty(py);
        for contact in registrar.lookup_str(aor) {
            contacts
                .append(Bound::new(py, contact).expect("a contact object"))
                .expect("a list entry");
        }
        let globals = PyDict::new(py);
        globals.set_item("call", &call).expect("a global");
        globals.set_item("contacts", contacts).expect("a global");
        py.run(
            c"call.fork(contacts, strategy='sequential')",
            Some(&globals),
            None,
        )
        .expect("the hunt is accepted");
        let action = call.borrow().action().clone();
        action
    });

    let reply_to = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::new(),
    };
    tokio::task::block_in_place(|| {
        apply_routing_action(
            &sequence.call_id,
            action,
            &sequence.invite,
            &reply_to,
            &sequence.dispatcher.state,
        )
    });

    let sent = sequence.wire();
    let to_binding = sent
        .iter()
        .find(|sent| {
            sent.destination.to_string() == EDGE_ADDRESS
                && sent.message.method() == Some(&Method::Invite)
        })
        .unwrap_or_else(|| panic!("nothing went to the edge proxy: {:?}", summaries(&sent)));
    assert_eq!(
        to_binding
            .message
            .headers
            .get_all("Route")
            .cloned()
            .unwrap_or_default(),
        [PATH],
        "the binding's Path, and nothing else, is the route set"
    );
    match &to_binding.message.start_line {
        StartLine::Request(request) => assert_eq!(
            request.request_uri.to_string(),
            CONTACT,
            "the Request-URI stays the contact"
        ),
        StartLine::Response(_) => panic!("an INVITE is a request"),
    }
}

/// The hunt reaches a registered binding through its Path, which is not a route a
/// script named: the binding's dialog stays at the address siphon has for it. The
/// 2xx's private Contact and missing Record-Route do not move the ACK or the BYE.
#[tokio::test(flavor = "multi_thread")]
async fn a_hunted_binding_keeps_its_cached_address_after_it_answers() {
    let aor = "sip:hunt-path-answer@example.com";
    crate::script::api::test_registrar()
        .save_full(
            aor,
            parse_uri_standalone("sip:hunt-path-answer@203.0.113.41:5060").expect("a contact URI"),
            3600,
            1.0,
            "register-hunt-path-answer".to_string(),
            1,
            None,
            None,
            None,
            None,
            vec![PATH.to_string()],
            Default::default(),
            Vec::new(),
        )
        .expect("the binding saves");
    let sequence = Sequence::new_call("");
    let registrar = PyRegistrar::new(Arc::clone(crate::script::api::test_registrar()));
    let action = Python::attach(|py| {
        let call = Bound::new(
            py,
            PyCall::new(
                sequence.call_id.clone(),
                Arc::clone(&sequence.invite),
                "192.0.2.10".to_string(),
                "udp".to_string(),
            ),
        )
        .expect("a call object");
        let contacts = PyList::empty(py);
        for contact in registrar.lookup_str(aor) {
            contacts
                .append(Bound::new(py, contact).expect("a contact object"))
                .expect("a list entry");
        }
        let globals = PyDict::new(py);
        globals.set_item("call", &call).expect("a global");
        globals.set_item("contacts", contacts).expect("a global");
        py.run(
            c"call.fork(contacts, strategy='sequential')",
            Some(&globals),
            None,
        )
        .expect("the hunt is accepted");
        let action = call.borrow().action().clone();
        action
    });
    let reply_to = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::new(),
    };
    tokio::task::block_in_place(|| {
        apply_routing_action(
            &sequence.call_id,
            action,
            &sequence.invite,
            &reply_to,
            &sequence.dispatcher.state,
        )
    });
    let invite = sequence
        .wire()
        .into_iter()
        .find(|sent| {
            sent.destination.to_string() == EDGE_ADDRESS
                && sent.message.method() == Some(&Method::Invite)
        })
        .map(|sent| sent.message)
        .expect("the INVITE goes to the edge proxy");
    let mut response = super::lcr_ring_timeout_tests::carrier_response(&invite, 200, "OK");
    response.headers.set(
        "Contact",
        "<sip:hunt-path-answer@10.9.8.7:5060>".to_string(),
    );
    assert!(handle_b2bua_response(
        &sequence.call_id,
        &super::lcr_ring_timeout_tests::top_via_branch(&invite),
        &mut response,
        200,
        EDGE_ADDRESS.parse().expect("a literal address"),
        &sequence.dispatcher.state,
    ));
    let ack = sequence
        .wire()
        .into_iter()
        .find(|sent| sent.message.method() == Some(&Method::Ack))
        .expect("an ACK");
    assert_eq!(ack.destination.to_string(), EDGE_ADDRESS, "ACK");
    assert!(b2bua_terminate_call_inner(
        &sequence.call_id,
        None,
        "b2bua",
        &sequence.dispatcher.state
    ));
    let bye = sequence
        .wire()
        .into_iter()
        .find(|sent| {
            sent.message.method() == Some(&Method::Bye) && sent.destination.to_string() != CALLER
        })
        .expect("a BYE to the binding");
    assert_eq!(bye.destination.to_string(), EDGE_ADDRESS, "BYE");
}
