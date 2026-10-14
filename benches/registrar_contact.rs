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
//! Fixtures use RFC 5737 addresses and example.com AoRs.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::registrar::{Registrar, RegistrarConfig};
use siphon::sip::uri::SipUri;

fn registrar_with(bindings: u32) -> Registrar {
    let registrar = Registrar::new(RegistrarConfig {
        default_expires: 3600,
        max_expires: 7200,
        ..Default::default()
    });
    for index in 0..bindings {
        let host = format!("198.51.100.{}", index % 250 + 1);
        registrar
            .save(
                &format!("sip:u{index}@example.com"),
                SipUri::new(host)
                    .with_user(format!("u{index}"))
                    .with_port(5060),
                3600,
                1.0,
                format!("reg-{index}"),
                1,
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

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench_lookup
}
criterion_main!(benches);
