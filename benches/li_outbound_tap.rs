//! Criterion perf gate for the lawful-intercept tap on what siphon sends.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench li_outbound_tap`.
//!
//! Every frame siphon sends passes `OutboundRouter::deliver`, which asks the
//! tap whether the frame goes to a target. Three costs matter:
//!
//! - `deliver_gate_off`: a node with no lawful intercept, which is the cost
//!   the tap must not add to. The router's `send` is `deliver` plus the IPsec
//!   checks that were already there.
//! - `gate_on_miss`: a node with a warranted session, and a frame of some other
//!   call. What it costs is the gate, the Call-ID scan and one lookup; the
//!   frame is not parsed.
//! - `gate_on_hit`: a frame of the warranted call, up to the warrants it goes
//!   to the target of (the parse is the cost of an intercepted call alone).
#![allow(clippy::disallowed_methods)] // test, bench and example code may block

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, Criterion};
use siphon::config::LawfulInterceptConfig;
use siphon::li::x1::message::{DestinationDetails, TaskDetails};
use siphon::li::x1::store::ContentCapability;
use siphon::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, IpAddressPort, Port, TargetIdentifier, XId,
};
use siphon::li::{Identities, LiManager, MessageFacts};
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};
use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

const INTERCEPTED_CALL_ID: &str = "intercepted-call@192.0.2.10";

const ANSWER: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
    "From: <sip:alice@example.com>;tag=caller-tag\r\n",
    "To: <sip:bob@example.com>;tag=siphon-tag\r\n",
    "Call-ID: intercepted-call@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const OTHER_CALL: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 192.0.2.11:5060;branch=z9hG4bK-other-invite\r\n",
    "From: <sip:carol@example.com>;tag=other-tag\r\n",
    "To: <sip:dave@example.com>;tag=siphon-tag\r\n",
    "Call-ID: other-call@192.0.2.11\r\n",
    "CSeq: 1 INVITE\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

fn warranted_manager() -> LiManager {
    let (manager, _iri, _audit) = LiManager::new(
        LawfulInterceptConfig {
            enabled: true,
            audit_log: None,
            x1: None,
            x2: None,
            x3: None,
            siprec: None,
        },
        100,
        ContentCapability::Available,
    );
    let d_id = DId::generate();
    manager
        .destinations()
        .create(DestinationDetails {
            d_id,
            friendly_name: None,
            delivery_type: DeliveryType::X2Only,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                port: Port::Tcp(42069),
            }),
        })
        .expect("destination must provision");
    manager
        .tasks()
        .activate(TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri(
                "sip:alice@example.com".to_string(),
            )],
            delivery_type: DeliveryType::X2Only,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        })
        .expect("task must provision");
    // The call's INVITE arrives, and a session is decided for it.
    let invite = Identities {
        request_uri: Some("sip:bob@example.com"),
        from_uri: Some("<sip:alice@example.com>;tag=caller-tag"),
        to_uri: Some("<sip:bob@example.com>"),
        source_ip: None,
    };
    let facts = MessageFacts {
        request: true,
        method: "INVITE",
        status_code: None,
        to_tagged: false,
        branch: Some("z9hG4bK-caller-invite"),
    };
    let view = manager.resolve_session(INTERCEPTED_CALL_ID, &facts, &invite, || None);
    assert_eq!(view.matches.len(), 1);
    assert!(manager.any_warranted_session());
    manager
}

fn router() -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp_sender, receiver) = flume::unbounded();
    let (stream_sender, _) = flume::unbounded();
    let router = OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: HashMap::new(),
        udp_dynamic: None,
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender.clone(),
        sctp: Some(stream_sender),
    };
    (router, receiver)
}

fn bench(criterion: &mut Criterion) {
    let (router, receiver) = router();
    let data = Bytes::from_static(ANSWER.as_bytes());
    criterion.bench_function("li_outbound_tap/deliver_gate_off", |bencher| {
        bencher.iter(|| {
            let sent = router.send(OutboundMessage {
                relayed: false,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                destination: "192.0.2.10:5060".parse().expect("a literal address"),
                data: black_box(data.clone()),
                source_local_addr: None,
                server_name: None,
                verify_server: None,
                followups: None,
            });
            black_box(sent.is_ok());
            // Keep the channel from growing without bound.
            while receiver.try_recv().is_ok() {}
        });
    });

    let manager = warranted_manager();
    let miss = Bytes::from_static(OTHER_CALL.as_bytes());
    criterion.bench_function("li_outbound_tap/gate_on_miss", |bencher| {
        bencher.iter(|| {
            if manager.any_warranted_session() {
                if let Some(call_id) = siphon::capture::call_id_from_bytes(black_box(&miss)) {
                    black_box(manager.outbound_leg(&call_id, || None));
                }
            }
        });
    });

    // An initial INVITE siphon sends on a Call-ID nothing has resolved, which no
    // warrant names: the match is the whole cost, and nothing is remembered.
    let originated = Identities {
        request_uri: Some("sip:dave@example.com"),
        from_uri: Some("<sip:15550100001@192.0.2.1>;tag=s"),
        to_uri: Some("<sip:dave@example.com>"),
        source_ip: None,
    };
    let initial_invite = MessageFacts {
        request: true,
        method: "INVITE",
        status_code: None,
        to_tagged: false,
        branch: Some("z9hG4bK-originated"),
    };
    criterion.bench_function("li_outbound_tap/originated_invite_unnamed", |bencher| {
        bencher.iter(|| {
            black_box(manager.decide_outbound_invite(
                black_box("originated-call@192.0.2.1"),
                &initial_invite,
                &originated,
                || None,
            ));
        });
    });

    let hit = Bytes::from_static(ANSWER.as_bytes());
    criterion.bench_function("li_outbound_tap/gate_on_hit", |bencher| {
        bencher.iter(|| {
            if manager.any_warranted_session() {
                if let Some(call_id) = siphon::capture::call_id_from_bytes(black_box(&hit)) {
                    if let Some(session_id) = manager.outbound_leg(&call_id, || None) {
                        if let Ok(message) = parse_sip_message_bytes(&hit) {
                            let from = message.headers.get("From").map(String::as_str);
                            let to = message.headers.get("To").map(String::as_str);
                            let facts = MessageFacts {
                                request: false,
                                method: "INVITE",
                                status_code: Some(200),
                                to_tagged: true,
                                branch: None,
                            };
                            let identities = Identities {
                                request_uri: None,
                                from_uri: from,
                                to_uri: to,
                                source_ip: None,
                            };
                            black_box(manager.outbound_matches(
                                session_id,
                                &call_id,
                                &facts,
                                &identities,
                            ));
                        }
                    }
                }
            }
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
