//! Criterion bench for a registrar lookup by **Contact**.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench registrar_contact`.
//!
//! `registrar.lookup_contact` and the dialog-state publisher's
//! `binding_for_contact` find a binding by its Contact rather than its AoR,
//! once per terminating call. They scanned every binding; the contact index
//! reads only the AoRs it names, so the cost is flat in the registration
//! count. Measured at 100k and 500k AoRs, for a Contact that is registered
//! and for one that is not (a miss scanned the whole table).
//!
//! `binding_for_source` is the same match by the address a binding's REGISTER
//! came from, which the dialog-state publisher runs for a branch relayed over
//! a captured flow.
//!
//! Fixtures use RFC 5737 addresses and example.com AoRs.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::sip::uri::SipUri;
use siphon::transport::Transport;
use std::net::SocketAddr;

/// Where binding `index`'s REGISTER came from: one host per 250, a port each.
fn source_of(index: u32) -> SocketAddr {
    SocketAddr::from((
        [203, 0, 113, (index % 250 + 1) as u8],
        10_000 + (index / 250) as u16,
    ))
}

fn registrar_with(bindings: u32) -> Registrar {
    let registrar = Registrar::new(RegistrarConfig {
        default_expires: 3600,
        max_expires: 7200,
        ..Default::default()
    });
    for index in 0..bindings {
        let host = format!("198.51.100.{}", index % 250 + 1);
        registrar
            .save_with_source(
                &format!("sip:u{index}@example.com"),
                SipUri::new(host)
                    .with_user(format!("u{index}"))
                    .with_port(5060),
                3600,
                1.0,
                format!("reg-{index}"),
                1,
                Some(source_of(index)),
                Some(Transport::Udp),
            )
            .expect("the binding saves");
    }
    registrar
}

fn bench_lookup(criterion: &mut Criterion) {
    for (label, bindings) in [("100k", 100_000u32), ("500k", 500_000u32)] {
        let registrar = registrar_with(bindings);
        let hit = format!(
            "sip:u{}@198.51.100.{}",
            bindings / 2,
            (bindings / 2) % 250 + 1
        );
        criterion.bench_function(
            &format!("registrar/lookup_contact_hit_{label}"),
            |bencher| {
                bencher.iter(|| black_box(registrar.lookup_contact(black_box(&hit))));
            },
        );
        criterion.bench_function(
            &format!("registrar/lookup_contact_miss_{label}"),
            |bencher| {
                bencher.iter(|| {
                    black_box(registrar.lookup_contact(black_box("sip:nobody@198.51.100.1:5060")))
                });
            },
        );
    }
}

fn bench_source(criterion: &mut Criterion) {
    for (label, bindings) in [("100k", 100_000u32), ("500k", 500_000u32)] {
        let registrar = registrar_with(bindings);
        let hit = source_of(bindings / 2);
        let miss = SocketAddr::from(([203, 0, 113, 1], 9_999));
        criterion.bench_function(
            &format!("registrar/binding_for_source_hit_{label}"),
            |bencher| {
                bencher.iter(|| black_box(registrar.binding_for_source(black_box(hit))));
            },
        );
        criterion.bench_function(
            &format!("registrar/binding_for_source_miss_{label}"),
            |bencher| {
                bencher.iter(|| black_box(registrar.binding_for_source(black_box(miss))));
            },
        );
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_lookup, bench_source
}
criterion_main!(benches);
