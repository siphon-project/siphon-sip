//! `subscribe_state.send(flow=, route=)`: a subscription made as a UE over its
//! security association, and its refresh and unsubscribe, read off the wire.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use super::{send_in_dialog, PySubscribeState, SubscribeSend};
use crate::dns::SipResolver;
use crate::registrant::RegistrantManager;
use crate::registrant::{established_ue, rotate_sa_set};
use crate::script::api::flow_kind::registrant_flow;
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_sip_message_bytes;
use crate::subscribe_state::{SubscribeDialog, SubscribeStore};
use crate::transport::OutboundMessage;

const UE_IP: &str = "192.0.2.77";
/// The P-CSCF's protected server port of the registrant fixtures.
const PCSCF_SERVER: &str = "198.51.100.10:5066";
/// The UE's protected server port of the registrant fixtures.
const UE_SERVER: &str = "192.0.2.77:6101";

/// A UE's route set: the P-CSCF's protected URI, then the Service-Route. No
/// host resolves, so a SUBSCRIBE that went anywhere but the SA would fail.
fn ue_route_set() -> Vec<String> {
    vec![
        "<sip:pcscf.invalid:5066;lr>".to_string(),
        "<sip:orig@scscf.invalid;lr>".to_string(),
    ]
}

struct Watcher {
    uac: &'static crate::gateway::tests::TestUac,
    resolver: &'static SipResolver,
    registrants: Arc<RegistrantManager>,
    store: Arc<SubscribeStore>,
}

impl Watcher {
    fn new() -> Self {
        Watcher {
            uac: Box::leak(Box::new(crate::gateway::tests::test_uac())),
            resolver: Box::leak(Box::new(SipResolver::from_system().unwrap())),
            registrants: Arc::new(crate::registrant::test_support::manager()),
            store: Arc::new(SubscribeStore::new()),
        }
    }

    fn send(
        &self,
        flow: Option<crate::script::api::registrar::PyFlow>,
        route: Vec<String>,
    ) -> SubscribeSend {
        SubscribeSend {
            store: Arc::clone(&self.store),
            uac: &self.uac.sender,
            resolver: self.resolver,
            flow,
            route,
        }
    }

    async fn sent(&self) -> OutboundMessage {
        tokio::time::timeout(Duration::from_secs(5), self.uac.udp.recv_async())
            .await
            .expect("something was sent")
            .expect("the channel is open")
    }

    /// The notifier's 2xx to `subscribe`, record-routed by the S-CSCF and the
    /// P-CSCF, the P-CSCF nearest the UE.
    fn accept(&self, subscribe: &SipMessage) {
        let header = |name: &str| subscribe.headers.get(name).cloned().unwrap();
        let response = format!(
            "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=notifier-1\r\nCall-ID: {}\r\n\
             CSeq: {}\r\nContact: <sip:scscf.invalid:6060>\r\n\
             Record-Route: <sip:orig@scscf.invalid;lr>, <sip:pcscf.invalid:5066;lr>\r\n\
             Expires: 600000\r\nContent-Length: 0\r\n\r\n",
            header("Via"),
            header("From"),
            header("To"),
            header("Call-ID"),
            header("CSeq"),
        );
        let response = parse_sip_message_bytes(response.as_bytes()).unwrap();
        assert!(self.uac.sender.match_response(&response), "the 2xx is ours");
    }
}

fn routes(message: &SipMessage) -> Vec<String> {
    message
        .headers
        .get_all("Route")
        .cloned()
        .unwrap_or_default()
}

fn assert_rides_the_sa(sent: &OutboundMessage, client: SocketAddr) -> SipMessage {
    assert_eq!(
        sent.destination,
        PCSCF_SERVER.parse::<SocketAddr>().unwrap()
    );
    assert_eq!(
        sent.source_local_addr,
        Some(client),
        "from the current client port"
    );
    let message = parse_sip_message_bytes(&sent.data).unwrap();
    let via = message.headers.get("Via").cloned().unwrap();
    assert!(
        via.contains(&format!(" {UE_SERVER};")),
        "Via names the protected server port: {via}"
    );
    message
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_over_a_registrant_flow_keeps_to_its_sa() {
    let watcher = Arc::new(Watcher::new());
    let ue_ip: IpAddr = UE_IP.parse().unwrap();
    let aor = established_ue(&watcher.registrants, 1, ue_ip);
    let flow = registrant_flow(&watcher.registrants, &aor, ue_ip).expect("a flow");
    let client = flow.local_addr;

    let send = watcher.send(Some(flow), ue_route_set());
    let subscriber = aor.clone();
    let handle = tokio::spawn(async move {
        PySubscribeState::send_inner(
            send,
            &subscriber,
            "reg",
            600000,
            Some("application/reginfo+xml"),
            None,
            vec![("From".to_string(), format!("<{subscriber}>"))],
            5000,
        )
        .await
    });

    // The SUBSCRIBE: over the SA, with the whole route set in order.
    let subscribe = assert_rides_the_sa(&watcher.sent().await, client);
    assert_eq!(routes(&subscribe), ue_route_set());
    let contact = subscribe.headers.get("Contact").cloned().unwrap();
    assert!(
        contact.contains(UE_SERVER),
        "Contact names the protected server port: {contact}"
    );
    watcher.accept(&subscribe);
    let id = handle.await.unwrap().expect("subscribed").id;
    let dialog: SubscribeDialog = watcher.store.get_local(&id).expect("the dialog");
    assert_eq!(
        dialog.route_set,
        vec![
            "<sip:pcscf.invalid:5066;lr>".to_string(),
            "<sip:orig@scscf.invalid;lr>".to_string()
        ],
        "the reversed Record-Route"
    );

    // A re-registration replaces the SA set; the refresh rides the new one.
    rotate_sa_set(&watcher.registrants, &aor);
    let rotated = registrant_flow(&watcher.registrants, &aor, ue_ip)
        .unwrap()
        .local_addr;
    assert_ne!(rotated, client);
    let refresh = {
        let (watcher, dialog) = (Arc::clone(&watcher), dialog.clone());
        tokio::spawn(async move {
            send_in_dialog(
                &watcher.uac.sender,
                watcher.resolver,
                Some(&watcher.registrants),
                &dialog,
                600000,
                Some(Duration::from_secs(5)),
            )
            .await
        })
    };
    let refreshed = assert_rides_the_sa(&watcher.sent().await, rotated);
    assert_eq!(
        routes(&refreshed),
        dialog.route_set,
        "the dialog's route set"
    );
    assert_eq!(
        refreshed.headers.get("Expires").map(String::as_str),
        Some("600000")
    );
    watcher.accept(&refreshed);
    refresh.await.unwrap().expect("the 2xx");

    // The unsubscribe, the same way.
    send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        Some(&watcher.registrants),
        &dialog,
        0,
        None,
    )
    .await
    .expect("sent");
    let unsubscribe = assert_rides_the_sa(&watcher.sent().await, rotated);
    assert_eq!(routes(&unsubscribe), dialog.route_set);
    assert_eq!(
        unsubscribe.headers.get("Expires").map(String::as_str),
        Some("0")
    );

    // A registration that is gone has no SA: nothing leaves outside it.
    watcher.registrants.remove(&aor);
    let error = send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        Some(&watcher.registrants),
        &dialog,
        0,
        None,
    )
    .await
    .expect_err("no security association");
    assert!(
        error.to_string().contains("no security association"),
        "{error}"
    );
    assert!(watcher.uac.udp.try_recv().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_set_without_a_flow_goes_to_its_topmost_entry() {
    let watcher = Watcher::new();
    let route = vec![
        "<sip:198.51.100.50:5070;lr>".to_string(),
        "<sip:orig@198.51.100.60;lr>".to_string(),
    ];
    let send = watcher.send(None, route.clone());
    let attempt = tokio::spawn(async move {
        PySubscribeState::send_inner(
            send,
            "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "reg",
            600,
            None,
            None,
            Vec::new(),
            50,
        )
        .await
    });
    let sent = watcher.sent().await;
    assert_eq!(sent.destination, "198.51.100.50:5070".parse().unwrap());
    assert_eq!(sent.source_local_addr, None);
    assert_eq!(routes(&parse_sip_message_bytes(&sent.data).unwrap()), route);
    assert!(attempt.await.unwrap().is_err(), "unanswered");
}

/// An in-dialog SUBSCRIBE that is resolved names siphon in its Via, not the
/// next hop, so the 2xx comes back (RFC 3261 §18.2.2).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resolved_refresh_names_siphon_in_its_via() {
    let watcher = Watcher::new();
    let dialog = SubscribeDialog {
        id: "flowless".to_string(),
        call_id: "py-sub-flowless".to_string(),
        local_tag: "local".to_string(),
        remote_tag: "remote".to_string(),
        local_uri: "sip:watcher@192.0.2.1".to_string(),
        remote_uri: "sip:resource@198.51.100.70".to_string(),
        remote_target: "sip:resource@198.51.100.70:5060".to_string(),
        received_address: None,
        received_transport: None,
        received_connection_id: None,
        route_set: vec!["<sip:198.51.100.71:5060;lr>".to_string()],
        event: "reg".to_string(),
        expires_secs: 600,
        created_at_unix: 0,
        cseq: 2,
        event_version: 0,
        terminated: false,
        is_outbound: true,
        registrant_flow: None,
    };
    send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        None,
        &dialog,
        0,
        None,
    )
    .await
    .expect("sent");
    let sent = watcher.sent().await;
    assert_eq!(sent.destination, "198.51.100.71:5060".parse().unwrap());
    let message = parse_sip_message_bytes(&sent.data).unwrap();
    let via = message.headers.get("Via").cloned().unwrap();
    assert!(
        via.contains(" 127.0.0.1:5060;"),
        "siphon's own sent-by: {via}"
    );
}

#[test]
fn a_callee_flow_cannot_carry_a_subscription() {
    pyo3::Python::initialize();
    let flow = crate::script::api::registrar::PyFlow {
        transport: "udp".to_string(),
        source_addr: "198.51.100.40:50000".parse().unwrap(),
        local_addr: "192.0.2.1:5060".parse().unwrap(),
        connection_id: 0,
        kind: crate::script::api::flow_kind::FlowKind::Inbound,
    };
    let namespace = PySubscribeState::new(Arc::new(SubscribeStore::new()));
    let error = pyo3::Python::attach(|python| {
        namespace
            .send(
                python,
                "sip:resource@198.51.100.70",
                "reg",
                600,
                None,
                None,
                None,
                2000,
                Some(flow),
                Vec::new(),
            )
            .map(|_| ())
            .expect_err("an inbound flow is refused")
    });
    assert!(error.to_string().contains("registration.flow()"), "{error}");
}
