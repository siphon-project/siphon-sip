//! The route set a controller-issued `dial` or `route` target names for its
//! B-leg.
//!
//! A routing B2BUA continues a request through the proxy that sent it by
//! copying the Route that proxy gave it (TS 24.229 §5.7.5.2.1 step 4): an IMS
//! application server sends the session back through the S-CSCF with the
//! S-CSCF's own Route, whose original dialog identifier tells the S-CSCF which
//! session the request continues (§5.4.3.4). `Route` is framework-managed on a
//! B-leg, so the target names it, and these tests read back off the UDP egress
//! that the INVITE carries exactly that route set and went to its topmost
//! entry — on a fork, on every attempt of a sequential hunt, and on a `route`
//! verb's carriers.

use super::control_dial_identity_tests::{
    advance_from_the_stored_invite, dial_targets, park, wire, SIP_CALL_ID,
};
use super::lcr_ring_timeout_tests::summaries;
use super::test_dispatcher::test_dispatcher;
use super::*;

/// Where the route set says the request goes: the S-CSCF stand-in.
const ROUTE_HOP: &str = "198.51.100.50:5070";
/// The Route entry it gave the application server, identifier and all.
const ROUTE_ENTRY: &str = "<sip:term@198.51.100.50:5070;lr;odi=4f1c2b>";
/// The served user the request is addressed to. Its host is not where the
/// INVITE may go while a route set names a hop.
const SERVED_USER_HOST: &str = "198.51.100.7:5060";

fn served_user_target(route: Vec<String>) -> DialTarget {
    DialTarget {
        uri: format!("sip:15550100077@{SERVED_USER_HOST}"),
        route,
        ..Default::default()
    }
}

fn route_header(message: &SipMessage) -> Option<Vec<String>> {
    message.headers.get_all("Route").cloned()
}

/// The INVITE goes to the topmost Route and carries it, with the Request-URI
/// still naming the served user. The positive control is the same dial with no
/// route set, which goes to the Request-URI's own host and carries no Route.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_target_with_a_route_set_is_sent_through_it() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    assert!(dial_targets(
        &dispatcher,
        vec![served_user_target(vec![ROUTE_ENTRY.to_string()])],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));

    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {ROUTE_HOP}")]);
    assert_eq!(
        route_header(&sent[0].message),
        Some(vec![ROUTE_ENTRY.to_string()]),
        "the route set is not on the wire as named"
    );
    let StartLine::Request(request_line) = &sent[0].message.start_line else {
        panic!("an INVITE is a request");
    };
    assert_eq!(
        request_line.request_uri.to_string(),
        format!("sip:15550100077@{SERVED_USER_HOST}"),
        "the Request-URI must keep naming the served user"
    );

    let control = test_dispatcher();
    park(&control);
    assert!(dial_targets(
        &control,
        vec![served_user_target(Vec::new())],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&control);
    assert_eq!(summaries(&sent), [format!("INVITE to {SERVED_USER_HOST}")]);
    assert_eq!(route_header(&sent[0].message), None);
}

/// A route set of several entries goes out whole and in order, to the first.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_set_of_several_entries_keeps_its_order() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let route = vec![
        ROUTE_ENTRY.to_string(),
        "<sip:198.51.100.51:5080;lr>".to_string(),
    ];
    assert!(dial_targets(
        &dispatcher,
        vec![served_user_target(route.clone())],
        true,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {ROUTE_HOP}")]);
    let on_the_wire: Vec<String> = route_header(&sent[0].message)
        .expect("a Route header")
        .iter()
        .flat_map(|value| value.split(", ").map(str::to_string).collect::<Vec<_>>())
        .collect();
    assert_eq!(on_the_wire, route);
}

/// Every attempt of a sequential hunt is rebuilt by the failover engine, so a
/// route set that reached only the first would send the second straight to its
/// Request-URI, outside the session it belongs to.
#[tokio::test(flavor = "multi_thread")]
async fn every_attempt_of_a_sequential_dial_carries_its_targets_route_set() {
    let dispatcher = test_dispatcher();
    let call_id = park(&dispatcher);
    let second_entry = "<sip:orig@198.51.100.52:5090;lr;odi=77aa>";
    assert!(dial_targets(
        &dispatcher,
        vec![
            served_user_target(vec![ROUTE_ENTRY.to_string()]),
            served_user_target(vec![second_entry.to_string()]),
        ],
        false,
        &DialShaping::default(),
    )
    .expect("the dial runs"));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {ROUTE_HOP}")]);
    assert_eq!(
        route_header(&sent[0].message),
        Some(vec![ROUTE_ENTRY.to_string()])
    );

    advance_from_the_stored_invite(&dispatcher, &call_id);
    let sent = wire(&dispatcher);
    assert_eq!(
        summaries(&sent),
        ["INVITE to 198.51.100.52:5090".to_string()]
    );
    assert_eq!(
        route_header(&sent[0].message),
        Some(vec![second_entry.to_string()]),
        "the second attempt lost its own route set"
    );
}

/// The `route` verb hands its carriers to the same engine, so its target's
/// route set reaches the wire the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_route_verb_target_with_a_route_set_is_sent_through_it() {
    let dispatcher = test_dispatcher();
    park(&dispatcher);
    let routed = b2bua_route_call_with_state(
        SIP_CALL_ID,
        vec![RouteTarget {
            uri: format!("sip:15550100077@{SERVED_USER_HOST}"),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs: None,
            reroute_after_progress: false,
            route: vec![ROUTE_ENTRY.to_string()],
        }],
        &[],
        &dispatcher.state,
    );
    assert_eq!(routed, Ok(true));
    let sent = wire(&dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE to {ROUTE_HOP}")]);
    assert_eq!(
        route_header(&sent[0].message),
        Some(vec![ROUTE_ENTRY.to_string()])
    );
}

/// A bridging dial rings each phone as a call siphon places itself, from the
/// control plane's own parse of the target, so this drives the verb end to end:
/// the `route` the controller wrote reaches the INVITE, and the INVITE goes to
/// its topmost entry. The positive control is the same dial without one, which
/// goes to the Request-URI's host.
#[tokio::test(flavor = "multi_thread")]
async fn a_bridging_dial_carries_the_route_set_the_controller_named() {
    use super::dial_bridge_test_harness::{
        answered_caller, bridging_dispatcher, controller_owning, dial,
    };
    use super::originate_test_harness::{drain, requests_to, socket};
    use crate::rtpengine::test_native_engine::NativeTestEngine;

    const PHONE: &str = "198.51.100.225:5060";
    for (call_id, route, destination) in [
        ("route-bridge@192.0.2.10", Some(ROUTE_ENTRY), ROUTE_HOP),
        ("route-bridge-control@192.0.2.10", None, PHONE),
    ] {
        let engine = NativeTestEngine::start().await;
        let dispatcher = bridging_dispatcher(&engine);
        let caller = answered_caller(&dispatcher, call_id);
        let controller = controller_owning(call_id, dispatcher, &caller, call_id, "hangup");
        let mut target = serde_json::json!({ "uri": format!("sip:2101@{PHONE}") });
        if let Some(route) = route {
            target["route"] = serde_json::json!([route]);
        }
        let (reply, _) = dial(
            &controller,
            call_id,
            serde_json::json!({ "on_answer": "bridge", "targets": [target] }),
        )
        .await;
        assert_eq!(reply["status"], "ok", "{reply}");
        let invite = requests_to(
            &drain(&controller.dispatcher.udp),
            socket(destination),
            Method::Invite,
        )
        .pop()
        .unwrap_or_else(|| panic!("no INVITE reached {destination}"))
        .message;
        assert_eq!(
            route_header(&invite),
            route.map(|route| vec![route.to_string()]),
            "{call_id}"
        );
    }
}
