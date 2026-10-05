//! Criterion perf gate for inbound call admission.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench admission`.
//!
//! Every inbound B2BUA INVITE passes the admission check before a call or a
//! script exists, so its cost is paid once per call whether or not a limit is
//! configured. The ids below are the paths that check takes: the default
//! (nothing configured), each ceiling on its own, both together, a refusal,
//! and the lookup that answers a retransmitted refusal.
//!
//! The `gateway_*` ids are the per-group half: finding which limited gateway
//! groups admit the caller's address, which also runs for every INVITE, and
//! admitting a call against one.

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::admission::refused::{RefusedAnswer, RefusedInvites};
use siphon::admission::{is_emergency_service_urn, AdmissionController, InboundLimits};
use siphon::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
use siphon::transport::Transport;
use std::hint::black_box;
use std::net::IpAddr;
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

/// A manager with `limited` groups that have an inbound limit, each admitting
/// one address of its own and a /24, and as many again without one.
fn gateway(limited: usize) -> DispatcherManager {
    let manager = DispatcherManager::new();
    for index in 0..limited * 2 {
        let address = format!("198.51.100.{}:5060", index + 1);
        let group = DispatcherGroup::new(
            format!("carrier-{index:02}"),
            Algorithm::Weighted,
            vec![Destination::new(
                format!("sip:{address}"),
                address.parse().expect("a literal address"),
                Transport::Udp,
                1,
                1,
            )],
        )
        .with_source_networks(vec![format!("10.{index}.0.0/24")
            .parse()
            .expect("a literal network")]);
        let limit = (index % 2 == 0).then_some(limits(1_000_000, 0));
        manager.add_group(group.with_inbound_limits(limit));
    }
    manager
}

fn bench_gateway(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("admission");
    let stranger: IpAddr = "192.0.2.99".parse().expect("a literal address");
    // The last limited group's own address: every group before it is a miss.
    let member = |limited: usize| -> IpAddr {
        format!("198.51.100.{}", (limited - 1) * 2 + 1)
            .parse()
            .expect("a literal address")
    };

    // No group has a limit: the cost every deployment without the feature pays.
    let unlimited = gateway(0);
    group.bench_function("gateway_lookup_no_limited_group", |bencher| {
        bencher.iter(|| black_box(unlimited.inbound_limits_admitting(black_box(stranger))));
    });

    for limited in [1usize, 16] {
        let manager = gateway(limited);
        group.bench_function(
            format!("gateway_lookup_miss_{limited}_limited"),
            |bencher| {
                bencher.iter(|| black_box(manager.inbound_limits_admitting(black_box(stranger))));
            },
        );
        let source = member(limited);
        group.bench_function(format!("gateway_lookup_hit_{limited}_limited"), |bencher| {
            bencher.iter(|| black_box(manager.inbound_limits_admitting(black_box(source))));
        });
    }

    // Admit and release against one group's limit and the instance's.
    let manager = gateway(1);
    let controller = AdmissionController::unlimited();
    let groups = manager.inbound_limits_admitting(member(1));
    group.bench_function("admit_from_one_group", |bencher| {
        bencher.iter(|| black_box(controller.admit_from(black_box(&groups))));
    });

    group.finish();
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

criterion_group!(benches, bench_admission, bench_gateway);
criterion_main!(benches);
