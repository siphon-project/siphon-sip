#![allow(clippy::disallowed_methods)] // test, bench and example code may block

//! RFC 3261 §18.1.1 over a UE's SA flow: the decision every request a script
//! sends over a flow makes (`PyFlow::over_mtu_tcp`). Only a registrant UE's
//! UDP flow with an MTU set reads the request's size; every other flow, and a
//! deployment without `listen.mtu`, pays the comparisons alone.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::script::api::flow_kind::{FlowKind, RegistrantFlow};
use siphon::script::api::registrar::PyFlow;
use siphon::sip::parser::parse_sip_message_bytes;

fn flow(kind: FlowKind) -> PyFlow {
    PyFlow {
        transport: "udp".to_string(),
        source_addr: "198.51.100.50:5066".parse().expect("an address"),
        local_addr: "192.0.2.10:6100".parse().expect("an address"),
        connection_id: 0,
        kind,
    }
}

fn ue_flow() -> PyFlow {
    flow(FlowKind::Outbound(RegistrantFlow {
        aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org".to_string(),
        sent_by: "192.0.2.10:6101".parse().expect("an address"),
    }))
}

fn bench_decision(criterion: &mut Criterion) {
    let message = parse_sip_message_bytes(
        concat!(
            "MESSAGE sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:6101;branch=z9hG4bK-uac-1;rport\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org>;tag=a1\r\n",
            "To: <sip:+15550100@ims.mnc01.mcc001.3gppnetwork.org>\r\n",
            "Call-ID: bench-1\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .expect("a message");
    let callee = flow(FlowKind::Inbound);
    let ue = ue_flow();

    // A callee's flow: the registrant check alone, whatever the MTU.
    criterion.bench_function("flow_over_mtu/callee_flow", |bencher| {
        bencher.iter(|| {
            black_box(callee.over_mtu_tcp(black_box(Some(1280)), || message.to_bytes().len()))
        });
    });
    // A UE flow with no MTU configured: no size read.
    criterion.bench_function("flow_over_mtu/ue_flow_no_mtu", |bencher| {
        bencher.iter(|| black_box(ue.over_mtu_tcp(black_box(None), || message.to_bytes().len())));
    });
    // A UE flow under the threshold: the size is read (one serialisation).
    criterion.bench_function("flow_over_mtu/ue_flow_under_threshold", |bencher| {
        bencher.iter(|| {
            black_box(ue.over_mtu_tcp(black_box(Some(1280)), || message.to_bytes().len()))
        });
    });
    // A UE flow over the threshold, the size known: the switch decision.
    criterion.bench_function("flow_over_mtu/ue_flow_over_threshold", |bencher| {
        bencher.iter(|| black_box(ue.over_mtu_tcp(black_box(Some(1280)), || 4000)));
    });
}

criterion_group!(benches, bench_decision);
criterion_main!(benches);
