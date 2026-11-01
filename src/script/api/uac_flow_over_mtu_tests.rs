//! A request a script sends over a registrant UE's SA flow that is over
//! `listen.mtu` leaves over TCP on the SA (RFC 3261 clause 18.1.1), from the
//! UE's protected client port to the P-CSCF's protected server port, read off
//! the wire on loopback.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::io::AsyncWriteExt;

use super::uac_flow::FlowEgress;
use super::uac_flow_lab::{filler, UeLab};
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_sip_message_bytes;
use crate::transport::pool::ConnectionPool;
use crate::transport::send_queue::SendQueue;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, OutboundRouter, Transport};
use crate::uac::{UacResult, UacSender};

const MTU: u16 = 1280;

struct Wire {
    uac: UacSender,
    udp: flume::Receiver<OutboundMessage>,
    tcp: flume::Receiver<OutboundMessage>,
    pool: Arc<ConnectionPool>,
    connection_map: Arc<DashMap<ConnectionId, SendQueue>>,
    inbound: flume::Receiver<InboundMessage>,
}

fn wire(mtu: Option<u16>) -> Wire {
    let (udp_tx, udp) = flume::unbounded();
    let (tcp_tx, tcp) = flume::unbounded();
    let (tls_tx, _tls) = flume::unbounded();
    let (ws_tx, _ws) = flume::unbounded();
    let (wss_tx, _wss) = flume::unbounded();
    let router = Arc::new(OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: tcp_tx,
        tls: tls_tx,
        ws: ws_tx,
        wss: wss_tx,
        sctp: None,
    });
    let (inbound_tx, inbound) = flume::unbounded();
    let connection_map: Arc<DashMap<ConnectionId, SendQueue>> = Arc::new(DashMap::new());
    let pool = Arc::new(ConnectionPool::for_tests(
        Arc::clone(&connection_map),
        inbound_tx,
    ));
    let uac = UacSender::new(
        router,
        "127.0.0.1:5060".parse().expect("an address"),
        std::collections::HashMap::new(),
        std::collections::HashMap::new(),
        None,
        None,
        crate::config::IdentityHeaders::default().shared(),
    )
    .with_over_mtu(Arc::clone(&pool), mtu);
    // The router's other channels stay open for the test's length.
    std::mem::forget((_tls, _ws, _wss));
    Wire {
        uac,
        udp,
        tcp,
        pool,
        connection_map,
        inbound,
    }
}

/// A MESSAGE as the script API builds one over the flow: UDP Via naming the
/// UE's protected server port.
fn message(lab: &UeLab, branch: &str, body: usize) -> SipMessage {
    let head = format!(
        "MESSAGE sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n\
         Via: SIP/2.0/UDP {};branch=z9hG4bK-uac-{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=a1\r\n\
         To: <sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org>\r\n\
         Call-ID: over-mtu-{branch}\r\n\
         CSeq: 1 MESSAGE\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {body}\r\n\r\n",
        lab.server
    );
    let mut bytes = head.into_bytes();
    bytes.extend(filler(body));
    parse_sip_message_bytes(&bytes).expect("a message")
}

fn egress(wire: &Wire, flow: &super::registrar::PyFlow) -> FlowEgress {
    FlowEgress::of(flow, &wire.uac).expect("an egress")
}

fn via_of(sent: &OutboundMessage) -> String {
    parse_sip_message_bytes(&sent.data)
        .expect("a message")
        .headers
        .get("Via")
        .cloned()
        .expect("a Via")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_over_threshold_request_over_a_ue_flow_goes_tcp_from_the_client_port() {
    let lab = UeLab::new(131, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);
    let flow = lab.flow();

    let _receiver = egress(&wire, &flow)
        .send(&wire.uac, message(&lab, "big", 1500))
        .await;

    let sent = wire.tcp.try_recv().expect("it left over TCP");
    assert_eq!(sent.transport, Transport::Tcp);
    assert_eq!(sent.destination, lab.pcscf, "to the P-CSCF's port_ps");
    assert_eq!(sent.source_local_addr, Some(lab.source), "from port_uc");
    assert_eq!(sent.connection_id, ConnectionId::default());
    assert!(
        via_of(&sent).starts_with(&format!(
            "SIP/2.0/TCP {};branch=z9hG4bK-uac-big",
            lab.server
        )),
        "the top Via follows the transport, sent-by stays the protected server port: {}",
        via_of(&sent)
    );
    assert!(wire.udp.try_recv().is_err(), "and not over UDP as well");
    let (_connection, peer) = lab.accept().await;
    assert_eq!(peer, lab.source, "the P-CSCF sees port_uc");
    assert!(wire.pool.has_live_from(lab.source, lab.pcscf));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_under_threshold_request_stays_udp_and_opens_nothing() {
    let lab = UeLab::new(132, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);

    egress(&wire, &lab.flow())
        .send(&wire.uac, message(&lab, "small", 100))
        .await;

    let sent = wire.udp.try_recv().expect("UDP");
    assert_eq!(sent.transport, Transport::Udp);
    assert_eq!(sent.source_local_addr, Some(lab.source));
    assert!(
        via_of(&sent).starts_with("SIP/2.0/UDP "),
        "{}",
        via_of(&sent)
    );
    assert!(!lab.sees_connection().await);
    assert!(!wire.pool.has_live_from(lab.source, lab.pcscf));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_threshold_is_the_relays_and_without_an_mtu_nothing_switches() {
    let lab = UeLab::new(133, true).await;
    let probe = message(&lab, "edge", 1500);
    let length = probe.to_bytes().len();
    // Exactly `mtu - 200` is not over, one byte more is (RFC 3261 18.1.1).
    let at = |len: usize| Some(u16::try_from(len + 200).expect("an MTU"));
    for (mtu, expect_tcp) in [(at(length), false), (at(length - 1), true), (None, false)] {
        let wire = wire(mtu);
        lab.pin(&wire.pool);
        egress(&wire, &lab.flow())
            .send(&wire.uac, message(&lab, "edge", 1500))
            .await;
        assert_eq!(
            wire.tcp.try_recv().is_ok(),
            expect_tcp,
            "mtu {mtu:?}, length {length}"
        );
        assert_eq!(wire.udp.try_recv().is_ok(), !expect_tcp);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_connection_sends_the_request_over_udp() {
    let lab = UeLab::new(134, false).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);

    egress(&wire, &lab.flow())
        .send(&wire.uac, message(&lab, "refused", 1500))
        .await;

    let sent = wire.udp.try_recv().expect("the UDP retry");
    assert_eq!(sent.transport, Transport::Udp);
    assert_eq!(sent.source_local_addr, Some(lab.source));
    assert!(
        via_of(&sent).starts_with("SIP/2.0/UDP "),
        "{}",
        via_of(&sent)
    );
    assert!(sent.data.len() > 1500, "the whole request");
    assert!(wire.tcp.try_recv().is_err());
    assert!(!wire.pool.has_live_from(lab.source, lab.pcscf));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callee_flow_over_the_mtu_is_unchanged() {
    let lab = UeLab::new(135, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);

    egress(&wire, &lab.inbound_flow())
        .send(&wire.uac, message(&lab, "callee", 1500))
        .await;

    let sent = wire.udp.try_recv().expect("still UDP");
    assert!(via_of(&sent).starts_with("SIP/2.0/UDP "));
    assert!(wire.tcp.try_recv().is_err());
    assert!(!lab.sees_connection().await, "nothing was opened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_ue_flow_already_on_tcp_keeps_its_connection_and_via() {
    let lab = UeLab::new(136, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);
    let flow = super::registrar::PyFlow {
        transport: "tcp".to_string(),
        connection_id: 77,
        ..lab.flow()
    };
    let mut big = message(&lab, "stream", 1500);
    big.headers.set(
        "Via",
        format!("SIP/2.0/TCP {};branch=z9hG4bK-uac-stream", lab.server),
    );

    egress(&wire, &flow).send(&wire.uac, big).await;

    let sent = wire.tcp.try_recv().expect("TCP");
    assert_eq!(sent.connection_id, ConnectionId(77), "the flow's own");
    assert!(!lab.sees_connection().await, "no second connection");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_request_picks_by_its_own_size_and_they_share_one_connection() {
    let lab = UeLab::new(137, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);
    let flow = lab.flow();
    for (index, (body, over)) in [(1500, true), (50, false), (1500, true), (50, false)]
        .into_iter()
        .enumerate()
    {
        egress(&wire, &flow)
            .send(&wire.uac, message(&lab, &format!("seq{index}"), body))
            .await;
        let (tcp, udp) = (wire.tcp.try_recv().is_ok(), wire.udp.try_recv().is_ok());
        assert_eq!((tcp, udp), (over, !over), "request {index}");
    }
    assert_eq!(wire.pool.connections_bound_on(lab.ue_ip), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_response_comes_back_on_the_connection() {
    let lab = UeLab::new(138, true).await;
    let wire = wire(Some(MTU));
    lab.pin(&wire.pool);

    let mut receiver = egress(&wire, &lab.flow())
        .send(&wire.uac, message(&lab, "answered", 1500))
        .await;
    let sent = wire.tcp.try_recv().expect("over TCP");
    let (mut pcscf, _) = lab.accept().await;

    // The P-CSCF answers over the connection the request came in on (RFC 3261
    // clause 18.2.2), echoing the Via.
    let response = format!(
        "SIP/2.0 202 Accepted\r\nVia: {}\r\nFrom: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=a1\r\n\
         To: <sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org>;tag=p1\r\nCall-ID: over-mtu-answered\r\n\
         CSeq: 1 MESSAGE\r\nContent-Length: 0\r\n\r\n",
        via_of(&sent)
    );
    pcscf.write_all(response.as_bytes()).await.expect("written");
    let inbound = tokio::time::timeout(Duration::from_secs(5), wire.inbound.recv_async())
        .await
        .expect("it reaches the UE's stream machinery")
        .expect("open");
    assert_eq!(inbound.transport, Transport::Tcp);
    assert_eq!(inbound.local_addr, lab.source);
    let parsed = parse_sip_message_bytes(&inbound.data).expect("a response");
    assert!(wire.uac.match_response(&parsed), "the UAC's pending entry");
    match tokio::time::timeout(Duration::from_secs(2), &mut receiver).await {
        Ok(Ok(UacResult::Response(response))) => {
            assert_eq!(response.status_code(), Some(202));
        }
        other => panic!("no response delivered: {other:?}"),
    }
}

/// Leak gate: switch over TCP and let the SA set go, over and over. The pooled
/// connection, its map entry and the pending entry are all back to baseline.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn over_mtu_cycles_leave_no_connection_behind() {
    let lab = UeLab::new(139, true).await;
    let wire = wire(Some(MTU));
    let flow = lab.flow();
    let mut held = Vec::new();
    for cycle in 0..10 {
        lab.pin(&wire.pool);
        let receiver = egress(&wire, &flow)
            .send(&wire.uac, message(&lab, &format!("cycle{cycle}"), 1500))
            .await;
        drop(receiver);
        held.push(lab.accept().await.0);
        assert_eq!(
            wire.pool.connections_bound_on(lab.ue_ip),
            1,
            "cycle {cycle}"
        );
        // The SA set is gone: the registration loop reconciles it away.
        wire.pool
            .reconcile_pinned_sources(Default::default(), &Default::default());
        for _ in 0..300 {
            if wire.pool.connections_bound_on(lab.ue_ip) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            wire.pool.connections_bound_on(lab.ue_ip),
            0,
            "cycle {cycle}"
        );
    }
    for _ in 0..300 {
        if wire.connection_map.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(wire.connection_map.is_empty());
    while wire.tcp.try_recv().is_ok() {}
}
