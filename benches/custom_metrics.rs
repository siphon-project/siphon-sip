//! Criterion perf gate for script custom metric updates.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench custom_metrics`.
//!
//! A script calls `counter.inc()` / `histogram.observe()` on its hot path, so
//! every update of an already-seen label combination must stay one lookup plus
//! an atomic add. The ids are the repeat-update shapes: no labels, one label,
//! two labels, a histogram, and a gauge.
#![allow(clippy::disallowed_methods)] // test, bench and example code may block

use criterion::{criterion_group, criterion_main, Criterion};
use prometheus::Registry;
use siphon::metrics::custom::CustomMetrics;
use std::hint::black_box;

fn bench_custom_metrics(criterion: &mut Criterion) {
    let registry = Registry::new();
    let custom = CustomMetrics::new(&registry);
    custom
        .register_counter("bench_plain_total", "plain", &[])
        .expect("register");
    custom
        .register_counter("bench_one_label_total", "one", &["method"])
        .expect("register");
    custom
        .register_counter("bench_two_labels_total", "two", &["method", "result"])
        .expect("register");
    custom
        .register_histogram(
            "bench_duration_seconds",
            "histogram",
            &["method"],
            vec![0.01, 0.1, 1.0],
        )
        .expect("register");
    custom
        .register_gauge("bench_active", "gauge", &["method"])
        .expect("register");

    let mut group = criterion.benchmark_group("custom_metrics");

    group.bench_function("counter_inc_no_labels", |bencher| {
        bencher.iter(|| black_box(custom.counter_inc("bench_plain_total", &[], 1.0)));
    });
    group.bench_function("counter_inc_one_label_repeat", |bencher| {
        bencher.iter(|| {
            black_box(custom.counter_inc(
                "bench_one_label_total",
                &[("method", black_box("INVITE"))],
                1.0,
            ))
        });
    });
    group.bench_function("counter_inc_two_labels_repeat", |bencher| {
        bencher.iter(|| {
            black_box(custom.counter_inc(
                "bench_two_labels_total",
                &[("result", black_box("ok")), ("method", black_box("INVITE"))],
                1.0,
            ))
        });
    });
    group.bench_function("histogram_observe_one_label_repeat", |bencher| {
        bencher.iter(|| {
            black_box(custom.histogram_observe(
                "bench_duration_seconds",
                &[("method", black_box("INVITE"))],
                black_box(0.05),
            ))
        });
    });
    group.bench_function("gauge_set_one_label_repeat", |bencher| {
        bencher.iter(|| {
            black_box(custom.gauge_set("bench_active", &[("method", black_box("INVITE"))], 1.0))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_custom_metrics);
criterion_main!(benches);
