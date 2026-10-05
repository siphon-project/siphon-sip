//! Criterion perf gate for inbound call admission.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench admission`.
//!
//! Every inbound B2BUA INVITE passes the admission check before a call or a
//! script exists, so its cost is paid once per call whether or not a limit is
//! configured. The ids below are the paths that check takes: the default
//! (nothing configured), each ceiling on its own, both together, a refusal,
//! and the lookup that answers a retransmitted refusal.

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::admission::refused::{RefusedAnswer, RefusedInvites};
use siphon::admission::{is_emergency_service_urn, AdmissionController, InboundLimits};
use std::hint::black_box;
use std::time::Instant;

const CALL_ID: &str = "a84b4c76e66710@192.0.2.1";
const BRANCH: &str = "z9hG4bK776asdhds";

fn limits(max_concurrent_calls: u32, max_calls_per_second: u32) -> InboundLimits {
    InboundLimits {
        max_concurrent_calls,
        max_calls_per_second,
        ..InboundLimits::UNLIMITED
    }
}

fn bench_admission(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("admission");

    // Admit and release: the whole cost a completed call pays.
    let unlimited = AdmissionController::unlimited();
    group.bench_function("admit_unlimited", |bencher| {
        bencher.iter(|| black_box(unlimited.admit()));
    });

    let concurrent = AdmissionController::new(limits(1_000_000, 0));
    group.bench_function("admit_concurrent_ceiling", |bencher| {
        bencher.iter(|| black_box(concurrent.admit()));
    });

    // A rate no bench loop reaches, so every iteration is an admitted call.
    let rate = AdmissionController::new(limits(0, 1_000_000_000));
    group.bench_function("admit_rate_ceiling", |bencher| {
        bencher.iter(|| black_box(rate.admit()));
    });

    let both = AdmissionController::new(limits(1_000_000, 1_000_000_000));
    group.bench_function("admit_both_ceilings", |bencher| {
        bencher.iter(|| black_box(both.admit()));
    });

    let full = AdmissionController::new(limits(1, 0));
    let _held = full.admit().expect("the one slot");
    group.bench_function("refuse_at_concurrent_ceiling", |bencher| {
        bencher.iter(|| black_box(full.admit()));
    });

    group.bench_function("admit_unrefused", |bencher| {
        bencher.iter(|| black_box(unlimited.admit_unrefused()));
    });

    group.bench_function("emergency_urn_check", |bencher| {
        bencher.iter(|| {
            black_box(is_emergency_service_urn(
                black_box("sip"),
                black_box("siphon.example.com"),
            ))
        });
    });

    // The lookup every INVITE makes. Empty is the case with nothing refused,
    // which is one atomic load; populated hashes the Call-ID and branch.
    let now = Instant::now();
    let empty = RefusedInvites::default();
    group.bench_function("refused_lookup_empty", |bencher| {
        bencher.iter(|| black_box(empty.lookup(black_box(CALL_ID), black_box(BRANCH))));
    });

    let populated = RefusedInvites::default();
    let answer = RefusedAnswer {
        reject_code: 503,
        retry_after_secs: 1,
    };
    for index in 0..10_000 {
        populated.remember(&format!("call-{index}@192.0.2.1"), BRANCH, answer, now);
    }
    group.bench_function("refused_lookup_miss_among_10k", |bencher| {
        bencher.iter(|| black_box(populated.lookup(black_box(CALL_ID), black_box(BRANCH))));
    });

    group.finish();
}

criterion_group!(benches, bench_admission);
criterion_main!(benches);
