//! A request siphon sends as a UE over its own SA flow that is over
//! `listen.mtu` leaves over TCP on the SA (RFC 3261 clause 18.1.1), from the
//! UE's protected client port to the P-CSCF's protected server port: a B-leg
//! dialled with `call.dial(flow=registration.flow())` and a request relayed
//! over that flow. Read off the wire on loopback.

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use super::b_leg_2xx_ack_tests::{caller_invite, caller_leg};
use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::script::api::uac_flow_lab::{filler, UeLab};
use crate::transport::pool::ConnectionPool;

const MTU: u16 = 1280;

struct Lab {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    tcp: flume::Receiver<OutboundMessage>,
    pool: Arc<ConnectionPool>,
    call_id: String,
}

/// A dispatcher with `mtu`, a pool a connection can really be opened with, and
/// the TCP egress on a channel of its own, holding the caller's call.
fn lab(mtu: Option<u16>) -> Lab {
    let mut dispatcher = test_dispatcher();
    let (udp_tx, udp) = flume::unbounded();
    let (tcp_tx, tcp) = flume::unbounded();
    let (other_tx, other_rx) = flume::unbounded();
    std::mem::forget(other_rx);
    dispatcher.state.outbound = Arc::new(OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: tcp_tx,
        tls: other_tx.clone(),
        ws: other_tx.clone(),
        wss: other_tx.clone(),
        sctp: Some(other_tx),
    });
    let (inbound_tx, inbound) = flume::unbounded();
    std::mem::forget(inbound);
    let pool = Arc::new(ConnectionPool::for_tests(
        Arc::new(DashMap::new()),
        inbound_tx,
    ));
    dispatcher.state.connection_pool = Arc::clone(&pool);
    dispatcher.state.mtu = mtu;
    let state = Arc::new(dispatcher.state);
    let call_id = state.call_actors.create_call(caller_leg());
    Lab {
        state,
        udp,
        tcp,
        pool,
        call_id,
    }
}

/// The caller's INVITE with `extra` more bytes of SDP.
fn invite_of(extra: usize) -> SipMessage {
    let mut invite = caller_invite();
    if extra > 0 {
        let mut body = invite.body.clone();
        body.extend_from_slice(b"a=note:");
        body.extend(filler(extra));
        body.extend_from_slice(b"\r\n");
        invite.headers.set("Content-Length", body.len().to_string());
        invite.body = body;
    }
    invite
}

fn dial(lab: &Lab, flow: &crate::script::api::registrar::PyFlow, invite: &SipMessage) -> bool {
    tokio::task::block_in_place(|| {
        b2bua_send_b_leg_invite(
            &lab.call_id,
            "sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org",
            None,
            Some(flow),
            &[],
            None,
            None,
            invite,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
            &lab.state,
        )
    })
}

fn via_of(sent: &OutboundMessage) -> String {
    parse_sip_message_bytes(&sent.data)
        .expect("an INVITE")
        .headers
        .get("Via")
        .cloned()
        .expect("a Via")
}

fn leg_transport(lab: &Lab) -> (Transport, Option<SocketAddr>) {
    let call = lab
        .state
        .call_actors
        .get_call(&lab.call_id)
        .expect("a call");
    let transport = &call.b_legs[0].transport;
    (transport.transport, transport.local_addr)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_over_threshold_dial_over_the_ue_flow_goes_tcp_from_the_client_port() {
    let ue = UeLab::new(151, true).await;
    let lab = lab(Some(MTU));
    ue.pin(&lab.pool);
    let flow = ue.flow();

    assert!(dial(&lab, &flow, &invite_of(1500)), "the B-leg is dialled");

    let sent = lab.tcp.try_recv().expect("the INVITE left over TCP");
    assert_eq!(sent.transport, Transport::Tcp);
    assert_eq!(sent.destination, ue.pcscf, "to the P-CSCF's port_ps");
    assert_eq!(sent.source_local_addr, Some(ue.source), "from port_uc");
    assert_eq!(sent.connection_id, ConnectionId::default());
    // The Via names the flow's own socket, as the UDP INVITE does, with the
    // transport token of the hop.
    assert!(
        via_of(&sent).starts_with(&format!("SIP/2.0/TCP {};branch=", ue.source)),
        "{}",
        via_of(&sent)
    );
    assert!(lab.udp.try_recv().is_err(), "nothing over UDP as well");
    let (_connection, peer) = ue.accept().await;
    assert_eq!(peer, ue.source);
    // The leg is a TCP leg: its CANCEL, the ACK of a non-2xx and its in-dialog
    // requests follow the INVITE (RFC 3261 clause 9.1, 17.1.1.3), from the same
    // protected client port.
    assert_eq!(leg_transport(&lab), (Transport::Tcp, Some(ue.source)));
    // Its Contact still names the flow's socket, as for UDP.
    let invite = parse_sip_message_bytes(&sent.data).expect("an INVITE");
    assert!(
        invite
            .headers
            .get("Contact")
            .is_some_and(|contact| contact.contains(&ue.source.to_string())),
        "{:?}",
        invite.headers.get("Contact")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_under_threshold_dial_or_no_mtu_stays_udp() {
    for (octet, mtu, extra) in [(152u8, Some(MTU), 0usize), (153, None, 1500)] {
        let ue = UeLab::new(octet, true).await;
        let lab = lab(mtu);
        ue.pin(&lab.pool);

        assert!(dial(&lab, &ue.flow(), &invite_of(extra)));

        let sent = lab.udp.try_recv().expect("UDP");
        assert!(
            via_of(&sent).starts_with("SIP/2.0/UDP "),
            "{}",
            via_of(&sent)
        );
        assert_eq!(sent.source_local_addr, Some(ue.source));
        assert!(lab.tcp.try_recv().is_err());
        assert!(!ue.sees_connection().await, "mtu {mtu:?}: no connection");
        assert_eq!(leg_transport(&lab), (Transport::Udp, Some(ue.source)));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connection_dials_over_udp() {
    let ue = UeLab::new(154, false).await;
    let lab = lab(Some(MTU));
    ue.pin(&lab.pool);

    assert!(dial(&lab, &ue.flow(), &invite_of(1500)));

    let sent = lab.udp.try_recv().expect("the UDP retry");
    assert!(
        via_of(&sent).starts_with("SIP/2.0/UDP "),
        "{}",
        via_of(&sent)
    );
    assert!(sent.data.len() > 1500, "the whole INVITE");
    assert!(lab.tcp.try_recv().is_err());
    assert_eq!(leg_transport(&lab), (Transport::Udp, Some(ue.source)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callee_flow_over_the_mtu_is_unchanged() {
    let ue = UeLab::new(155, true).await;
    let lab = lab(Some(MTU));
    ue.pin(&lab.pool);

    assert!(dial(&lab, &ue.inbound_flow(), &invite_of(1500)));

    let sent = lab.udp.try_recv().expect("still UDP");
    assert!(
        via_of(&sent).starts_with("SIP/2.0/UDP "),
        "{}",
        via_of(&sent)
    );
    assert!(lab.tcp.try_recv().is_err());
    assert!(!ue.sees_connection().await, "nothing was opened");
}

/// Leak gate: dial over TCP and let the SA set go, over and over: no pooled
/// connection is left.
#[tokio::test(flavor = "multi_thread")]
async fn over_mtu_dial_cycles_leave_no_connection_behind() {
    let ue = UeLab::new(156, true).await;
    let lab = lab(Some(MTU));
    let mut held = Vec::new();
    for cycle in 0..5 {
        ue.pin(&lab.pool);
        assert!(dial(&lab, &ue.flow(), &invite_of(1500)), "cycle {cycle}");
        assert!(lab.tcp.try_recv().is_ok());
        held.push(ue.accept().await.0);
        assert_eq!(lab.pool.connections_bound_on(ue.ue_ip), 1);
        lab.pool
            .reconcile_pinned_sources(Default::default(), &Default::default());
        for _ in 0..300 {
            if lab.pool.connections_bound_on(ue.ue_ip) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(lab.pool.connections_bound_on(ue.ue_ip), 0, "cycle {cycle}");
    }
}

/// A request relayed over the UE's flow takes the same rule, the Via naming the
/// flow's socket with the hop's transport token.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_over_the_ue_flow_over_the_mtu_goes_tcp() {
    let ue = UeLab::new(157, true).await;
    let lab = lab(Some(MTU));
    ue.pin(&lab.pool);
    let raw = format!(
        concat!(
            "MESSAGE sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.12:5060;branch=z9hG4bK-relay-157\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:caller@ims.mnc01.mcc001.3gppnetwork.org>;tag=core\r\n",
            "To: <sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org>\r\n",
            "Call-ID: relay-157\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
        ),
        length = 1500
    );
    let mut bytes = raw.into_bytes();
    bytes.extend(filler(1500));
    let message = parse_sip_message_bytes(&bytes).expect("a MESSAGE");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("an address"),
        remote_addr: "198.51.100.12:5060".parse().expect("an address"),
        data: Bytes::from(message.to_bytes()),
    };
    let server_key = TransactionKey::new(
        "z9hG4bK-relay-157".to_string(),
        message.method().expect("a request").clone(),
        "198.51.100.12:5060".to_string(),
    );
    tokio::task::block_in_place(|| {
        relay_request(
            &message,
            None,
            false,
            &inbound,
            Some(&server_key),
            &lab.state,
            None,
            None,
            None,
            None,
            Some(&ue.flow()),
            None,
            &[],
            None,
        )
    });

    let sent = lab.tcp.try_recv().expect("relayed over TCP");
    assert_eq!(sent.destination, ue.pcscf);
    assert_eq!(sent.source_local_addr, Some(ue.source));
    assert!(
        via_of(&sent).starts_with(&format!("SIP/2.0/TCP {};branch=", ue.source)),
        "{}",
        via_of(&sent)
    );
    assert!(lab.udp.try_recv().is_err());
    let (_connection, peer) = ue.accept().await;
    assert_eq!(peer, ue.source);
}
