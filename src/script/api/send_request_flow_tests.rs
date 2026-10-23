//! `proxy.send_request(flow=, route=)`: a request over a flow, and the route
//! set it carries, read off the wire.

use std::net::SocketAddr;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use super::tests::{run_send_request, SendFixture};
use crate::script::api::flow_kind::{FlowKind, RegistrantFlow};
use crate::script::api::registrar::PyFlow;
use crate::sip::parser::parse_sip_message_bytes;
use crate::transport::OutboundMessage;

/// The UE's protected client port, the P-CSCF's protected server port and the
/// UE's protected server port, as `registration.flow()` sets them.
const UE_CLIENT: &str = "192.0.2.10:6100";
const PCSCF_SERVER: &str = "192.0.2.50:5066";
const UE_SERVER: &str = "192.0.2.10:6101";

/// A UE's route set: the P-CSCF's protected URI, then the Service-Route. No
/// host resolves, so a request that went anywhere but the flow would fail.
fn ue_route_set() -> Vec<String> {
    vec![
        "<sip:pcscf.invalid:5066;lr>".to_string(),
        "<sip:orig@scscf.invalid;lr>".to_string(),
    ]
}

fn registrant_flow() -> PyFlow {
    PyFlow {
        transport: "udp".to_string(),
        source_addr: PCSCF_SERVER.parse().unwrap(),
        local_addr: UE_CLIENT.parse().unwrap(),
        connection_id: 0,
        kind: FlowKind::Outbound(RegistrantFlow {
            aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org".to_string(),
            sent_by: UE_SERVER.parse().unwrap(),
        }),
    }
}

/// A callee's flow: the one its REGISTER arrived on.
fn inbound_flow() -> PyFlow {
    PyFlow {
        transport: "udp".to_string(),
        source_addr: "198.51.100.40:50000".parse().unwrap(),
        local_addr: "192.0.2.1:5062".parse().unwrap(),
        connection_id: 0,
        kind: FlowKind::Inbound,
    }
}

/// Send a MESSAGE from Python with `flow` and `route`, and return what went
/// out, or the error the call raised.
fn send_message(
    fixture: &SendFixture,
    flow: Option<PyFlow>,
    route: &[String],
    extra: impl FnOnce(&Bound<'_, PyDict>),
) -> PyResult<OutboundMessage> {
    Python::attach(|python| {
        let proxy = Py::new(
            python,
            super::PyProxyUtils::new(std::sync::Arc::clone(&fixture.resolver)),
        )?;
        let kwargs = PyDict::new(python);
        let headers = PyDict::new(python);
        headers.set_item("To", "<sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org>")?;
        headers.set_item("Content-Type", "application/vnd.3gpp.sms")?;
        kwargs.set_item("headers", &headers)?;
        kwargs.set_item("body", pyo3::types::PyBytes::new(python, &[0x01, 0x02]))?;
        if let Some(flow) = flow {
            kwargs.set_item("flow", Py::new(python, flow)?)?;
        }
        kwargs.set_item("route", PyList::new(python, route)?)?;
        extra(&kwargs);
        run_send_request(
            python,
            proxy.bind(python).as_any(),
            "MESSAGE",
            "sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org",
            &kwargs,
        )
    })?;
    Ok(fixture
        .udp
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the MESSAGE went out"))
}

fn routes(sent: &OutboundMessage) -> Vec<String> {
    let message = parse_sip_message_bytes(&sent.data).unwrap();
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

fn via(sent: &OutboundMessage) -> String {
    let message = parse_sip_message_bytes(&sent.data).unwrap();
    message.headers.get("Via").cloned().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_message_over_a_registrant_flow_rides_the_sa_with_its_route_set() {
    let (_turn, fixture) = SendFixture::turn();
    let sent = send_message(fixture, Some(registrant_flow()), &ue_route_set(), |_| {})
        .expect("sent over the flow");
    assert_eq!(
        sent.destination,
        PCSCF_SERVER.parse::<SocketAddr>().unwrap()
    );
    assert_eq!(sent.source_local_addr, Some(UE_CLIENT.parse().unwrap()));
    assert_eq!(
        routes(&sent),
        ue_route_set(),
        "the whole route set, in order"
    );
    assert!(
        via(&sent).contains(&format!(" {UE_SERVER};")),
        "the Via names the UE's protected server port: {}",
        via(&sent)
    );
    let message = parse_sip_message_bytes(&sent.data).unwrap();
    assert_eq!(
        message.request_uri().map(|uri| uri.to_string()).as_deref(),
        Some("sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org")
    );
    assert_eq!(message.body, vec![0x01, 0x02]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_flow_with_no_route_set_is_the_destination() {
    let (_turn, fixture) = SendFixture::turn();
    let flow = inbound_flow();
    let sent = send_message(fixture, Some(flow.clone()), &[], |_| {}).expect("sent");
    assert_eq!(sent.destination, flow.source_addr);
    assert_eq!(sent.source_local_addr, Some(flow.local_addr));
    assert!(
        via(&sent).contains(":5062;"),
        "the flow's listener: {}",
        via(&sent)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_flow_yields_to_a_route_set() {
    let (_turn, fixture) = SendFixture::turn();
    let route = vec!["<sip:token@198.51.100.50:5070;lr>".to_string()];
    let sent = send_message(fixture, Some(inbound_flow()), &route, |_| {}).expect("sent");
    assert_eq!(sent.destination, "198.51.100.50:5070".parse().unwrap());
    assert_eq!(sent.source_local_addr, None);
    assert_eq!(routes(&sent), route);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_set_alone_goes_to_its_topmost_entry() {
    let (_turn, fixture) = SendFixture::turn();
    let route = vec![
        "<sip:198.51.100.50:5070;lr>".to_string(),
        "<sip:orig@198.51.100.60;lr>".to_string(),
    ];
    let sent = send_message(fixture, None, &route, |_| {}).expect("sent");
    assert_eq!(sent.destination, "198.51.100.50:5070".parse().unwrap());
    assert_eq!(routes(&sent), route);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flow_with_a_next_hop_or_two_route_sets_is_refused() {
    let (_turn, fixture) = SendFixture::turn();
    let error = send_message(fixture, Some(registrant_flow()), &[], |kwargs| {
        kwargs.set_item("next_hop", "sip:198.51.100.60").unwrap();
    })
    .expect_err("flow and next_hop together");
    assert!(error.to_string().contains("not both"), "{error}");

    let error = send_message(
        fixture,
        Some(registrant_flow()),
        &ue_route_set(),
        |kwargs| {
            let headers = kwargs
                .get_item("headers")
                .unwrap()
                .unwrap()
                .cast_into::<PyDict>()
                .unwrap();
            headers.set_item("Route", "<sip:198.51.100.60;lr>").unwrap();
        },
    )
    .expect_err("route= and a Route header together");
    assert!(error.to_string().contains("not both"), "{error}");
    assert!(fixture.udp.try_recv().is_err(), "nothing went out");
}
