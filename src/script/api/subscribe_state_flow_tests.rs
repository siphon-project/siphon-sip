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
            None,
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
            None,
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
        body: None,
        local_contact: None,
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
                None,
                None,
            )
            .map(|_| ())
            .expect_err("an inbound flow is refused")
    });
    assert!(error.to_string().contains("registration.flow()"), "{error}");
}

const MCPTT_INFO: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<mcpttinfo xmlns=\"urn:3gpp:ns:mcpttInfo:1.0\"><mcpttURI>sip:mcptt-id@example.com</mcpttURI></mcpttinfo>";
const MCPTT_TYPE: &str = "application/vnd.3gpp.mcptt-info+xml";

fn mcptt_body() -> crate::subscribe_state::DialogBody {
    crate::subscribe_state::DialogBody {
        content_type: MCPTT_TYPE.to_string(),
        bytes: MCPTT_INFO.to_vec(),
    }
}

/// The body on the wire: its Content-Type, a Content-Length of exactly its
/// bytes, and those bytes as the tail of what was sent.
fn assert_carries_body(sent: &OutboundMessage, message: &SipMessage, body: &[u8]) {
    assert_eq!(
        message.headers.get("Content-Type").map(String::as_str),
        Some(MCPTT_TYPE)
    );
    assert_eq!(
        message.headers.get("Content-Length").cloned(),
        Some(body.len().to_string())
    );
    assert_eq!(message.body, body);
    assert!(sent.data.ends_with(body), "the body ends the datagram");
}

fn assert_bodyless(message: &SipMessage) {
    assert_eq!(
        message.headers.get("Content-Length").map(String::as_str),
        Some("0")
    );
    assert!(message.headers.get("Content-Type").is_none());
    assert!(message.body.is_empty());
}

/// The body goes on the SUBSCRIBE over the SA, on every refresh of it, and not
/// on the unsubscribe; a NOTIFY with a body of its own is then matched to the
/// subscription and found by its tags.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_body_rides_the_initial_subscribe_and_every_refresh() {
    let watcher = Arc::new(Watcher::new());
    let ue_ip: IpAddr = UE_IP.parse().unwrap();
    let aor = established_ue(&watcher.registrants, 1, ue_ip);
    let flow = registrant_flow(&watcher.registrants, &aor, ue_ip).expect("a flow");
    let client = flow.local_addr;

    let send = watcher.send(Some(flow), ue_route_set());
    let subscriber = aor.clone();
    let attempt = tokio::spawn(async move {
        PySubscribeState::send_inner(
            send,
            &subscriber,
            "reg",
            600,
            None,
            None,
            vec![("From".to_string(), format!("<{subscriber}>"))],
            5000,
            Some(mcptt_body()),
        )
        .await
    });
    let initial = watcher.sent().await;
    let subscribe = assert_rides_the_sa(&initial, client);
    assert_carries_body(&initial, &subscribe, MCPTT_INFO);
    watcher.accept(&subscribe);
    let id = attempt.await.unwrap().expect("subscribed").id;
    let dialog: SubscribeDialog = watcher.store.get_local(&id).expect("the dialog");
    assert_eq!(dialog.body, Some(mcptt_body()), "kept for the refreshes");

    // It survives the L2 cache's serialisation, and a payload cached before
    // the field existed reads as bodyless.
    let cached: SubscribeDialog =
        serde_json::from_str(&serde_json::to_string(&dialog).unwrap()).unwrap();
    assert_eq!(cached.body, dialog.body);
    let mut legacy = serde_json::to_value(&dialog).unwrap();
    legacy.as_object_mut().unwrap().remove("body");
    let legacy: SubscribeDialog = serde_json::from_value(legacy).unwrap();
    assert_eq!(legacy.body, None);

    // The notifier's NOTIFY, with a body of its own, is this subscription's.
    let notify = parse_sip_message_bytes(
        format!(
            "NOTIFY sip:watcher@192.0.2.77:6101 SIP/2.0\r\nVia: SIP/2.0/UDP 198.51.100.10:5066;branch=z9hG4bKn1\r\n\
             From: <{aor}>;tag=notifier-1\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: 1 NOTIFY\r\nEvent: reg\r\n\
             Subscription-State: active;expires=600\r\nContact: <sip:scscf.invalid:6060>\r\n\
             Content-Type: application/reginfo+xml\r\nContent-Length: 6\r\n\r\n<x/>\r\n",
            subscribe.headers.get("From").unwrap(),
            dialog.call_id,
        )
        .as_bytes(),
    )
    .unwrap();
    assert!(matches!(
        watcher.store.notify_received(&notify),
        crate::subscribe_state::NotifyDisposition::Deliver
    ));
    let namespace = PySubscribeState::new(Arc::clone(&watcher.store));
    let found = namespace
        .find(&dialog.call_id, &dialog.local_tag, "notifier-1")
        .expect("the NOTIFY's dialog is the subscription");
    assert_eq!(found.id, id);

    // A refresh carries the body again, over the SA as it stands.
    let dialog = watcher.store.get_local(&id).unwrap();
    let refresh = {
        let (watcher, dialog) = (Arc::clone(&watcher), dialog.clone());
        tokio::spawn(async move {
            send_in_dialog(
                &watcher.uac.sender,
                watcher.resolver,
                Some(&watcher.registrants),
                &dialog,
                600,
                Some(Duration::from_secs(5)),
            )
            .await
        })
    };
    let sent = watcher.sent().await;
    let refreshed = assert_rides_the_sa(&sent, client);
    assert_carries_body(&sent, &refreshed, MCPTT_INFO);
    // Exactly one Contact (RFC 6665 §4.1.2.1), the one the SUBSCRIBE carried.
    assert_eq!(
        refreshed.headers.get_all("Contact").map(Vec::len),
        Some(1),
        "one Contact on the refresh"
    );
    assert_eq!(
        refreshed.headers.get("Contact"),
        subscribe.headers.get("Contact")
    );
    assert_eq!(
        dialog.local_contact,
        subscribe.headers.get("Contact").cloned()
    );
    assert_eq!(
        refreshed.headers.get("Expires").map(String::as_str),
        Some("600")
    );
    watcher.accept(&refreshed);
    refresh.await.unwrap().expect("the 2xx");

    // The unsubscribe is not a refresh: no body.
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
    let unsubscribe = assert_rides_the_sa(&watcher.sent().await, client);
    assert_bodyless(&unsubscribe);
    assert_eq!(
        unsubscribe.headers.get("Contact"),
        subscribe.headers.get("Contact")
    );
}

/// A dialog cached before the Contact was kept still refreshes with one: the
/// default `send()` derives, from siphon's own sent-by.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_of_a_dialog_without_a_kept_contact_derives_the_default() {
    let watcher = Watcher::new();
    let dialog = SubscribeDialog {
        id: "legacy".to_string(),
        call_id: "py-sub-legacy".to_string(),
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
        body: None,
        local_contact: None,
    };
    send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        None,
        &dialog,
        600,
        None,
    )
    .await
    .expect("sent");
    let message = parse_sip_message_bytes(&watcher.sent().await.data).unwrap();
    assert_eq!(
        message.headers.get_all("Contact").cloned(),
        Some(vec!["<sip:127.0.0.1:5060>".to_string()])
    );
}

/// Without a flow the body goes the same way, and a subscription made without
/// one sends no Content-Type.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_body_goes_on_a_resolved_subscribe_too() {
    let watcher = Watcher::new();
    for (body, expected) in [
        (Some(mcptt_body()), Some(MCPTT_INFO)),
        (None, None::<&[u8]>),
    ] {
        let send = watcher.send(None, vec!["<sip:198.51.100.50:5070;lr>".to_string()]);
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
                body,
            )
            .await
        });
        let sent = watcher.sent().await;
        let message = parse_sip_message_bytes(&sent.data).unwrap();
        match expected {
            Some(bytes) => assert_carries_body(&sent, &message, bytes),
            None => assert_bodyless(&message),
        }
        assert!(attempt.await.unwrap().is_err(), "unanswered");
    }
}

use crate::script::api::uac_flow_lab::{filler, UeLab};
use crate::transport::pool::ConnectionPool;
use crate::transport::Transport;

impl Watcher {
    /// A watcher whose UAC moves a request over a UE's SA flow that is over
    /// 1280 bytes to TCP on `pool`.
    fn over_mtu(pool: Arc<ConnectionPool>) -> Self {
        Watcher {
            uac: Box::leak(Box::new(crate::gateway::tests::test_uac_over_mtu(Some((
                pool, 1280,
            ))))),
            resolver: Box::leak(Box::new(SipResolver::from_system().unwrap())),
            registrants: Arc::new(crate::registrant::test_support::manager()),
            store: Arc::new(SubscribeStore::new()),
        }
    }

    /// What went out next, and whether over TCP.
    async fn sent_either(&self) -> (bool, OutboundMessage) {
        tokio::select! {
            sent = self.uac.tcp.recv_async() => (true, sent.expect("open")),
            sent = self.uac.udp.recv_async() => (false, sent.expect("open")),
            _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("nothing was sent"),
        }
    }
}

fn pool() -> Arc<ConnectionPool> {
    let (inbound_tx, inbound) = flume::unbounded();
    std::mem::forget(inbound);
    Arc::new(ConnectionPool::for_tests(
        Arc::new(dashmap::DashMap::new()),
        inbound_tx,
    ))
}

fn route_set_of(entries: usize) -> Vec<String> {
    (0..entries)
        .map(|index| {
            format!(
                "<sip:hop{index}.{}.ims.mnc001.mcc001.3gppnetwork.org:5066;lr>",
                "x".repeat(60)
            )
        })
        .collect()
}

/// A subscription over the SA with a request over the MTU goes over TCP from
/// the set's client port, its refresh and its unsubscribe each by their own
/// size (RFC 3261 clause 18.1.1), the response matched as for UDP.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_and_its_refreshes_pick_tcp_or_udp_by_their_own_size() {
    let pool = pool();
    let watcher = Arc::new(Watcher::over_mtu(Arc::clone(&pool)));
    let lab = UeLab::new(144, true).await;
    let aor = lab.established(&watcher.registrants, 1);
    let flow = registrant_flow(&watcher.registrants, &aor, lab.ue_ip).expect("a flow");
    assert_eq!(flow.local_addr, lab.source);
    lab.pin(&pool);

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
            vec![
                ("From".to_string(), format!("<{subscriber}>")),
                (
                    "X-Filler".to_string(),
                    String::from_utf8(filler(1500)).unwrap(),
                ),
            ],
            5000,
            None,
        )
        .await
    });
    let (over_tcp, sent) = watcher.sent_either().await;
    assert!(over_tcp, "the SUBSCRIBE over the MTU goes over TCP");
    assert_eq!(sent.transport, Transport::Tcp);
    assert_eq!(sent.destination, lab.pcscf);
    assert_eq!(sent.source_local_addr, Some(lab.source));
    let subscribe = parse_sip_message_bytes(&sent.data).unwrap();
    let via = subscribe.headers.get("Via").cloned().unwrap();
    assert!(
        via.starts_with(&format!("SIP/2.0/TCP {};branch=", lab.server)),
        "{via}"
    );
    let (_connection, peer) = lab.accept().await;
    assert_eq!(peer, lab.source);
    watcher.accept(&subscribe);
    let id = handle.await.unwrap().expect("subscribed").id;
    let dialog: SubscribeDialog = watcher.store.get_local(&id).expect("the dialog");

    send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        Some(&watcher.registrants),
        &dialog,
        600000,
        None,
    )
    .await
    .expect("sent");
    let (over_tcp, sent) = watcher.sent_either().await;
    assert!(!over_tcp, "a small refresh stays UDP");
    assert_eq!(sent.source_local_addr, Some(lab.source));

    let mut grown = dialog.clone();
    grown.route_set = route_set_of(12);
    let refresh = {
        let (watcher, grown) = (Arc::clone(&watcher), grown.clone());
        tokio::spawn(async move {
            send_in_dialog(
                &watcher.uac.sender,
                watcher.resolver,
                Some(&watcher.registrants),
                &grown,
                600000,
                Some(Duration::from_secs(5)),
            )
            .await
        })
    };
    let (over_tcp, sent) = watcher.sent_either().await;
    assert!(over_tcp, "a refresh over the MTU goes over TCP");
    assert_eq!(sent.source_local_addr, Some(lab.source));
    let refreshed = parse_sip_message_bytes(&sent.data).unwrap();
    assert!(refreshed
        .headers
        .get("Via")
        .is_some_and(|via| via.starts_with("SIP/2.0/TCP ")));
    watcher.accept(&refreshed);
    refresh.await.unwrap().expect("the 2xx over the connection");

    send_in_dialog(
        &watcher.uac.sender,
        watcher.resolver,
        Some(&watcher.registrants),
        &grown,
        0,
        None,
    )
    .await
    .expect("sent");
    let (over_tcp, _) = watcher.sent_either().await;
    assert!(over_tcp, "the unsubscribe over the MTU goes over TCP");
    assert_eq!(pool.connections_bound_on(lab.ue_ip), 1, "one connection");
    pool.reconcile_pinned_sources(Default::default(), &Default::default());
}
