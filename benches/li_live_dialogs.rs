//! Criterion perf gate for the lawful-intercept live-dialog index.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench li_live_dialogs`.
//!
//! The dispatcher remembers every initial INVITE while lawful intercept is
//! enabled, with or without a warrant, so a warrant activated while the call
//! is up can find it. That is one insert per call on the INVITE path, and a
//! release when the call ends. The ids are what it costs: a new dialog's
//! insert and release, the lookup that finds a retransmitted INVITE already
//! held, and the same call on a node with lawful intercept off, which must
//! cost next to nothing.
#![allow(clippy::disallowed_methods)] // test, bench and example code may block

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::config::LawfulInterceptConfig;
use siphon::li::x1::store::ContentCapability;
use siphon::li::LiManager;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};

const CALL_ID: &str = "a84b4c76e66710@192.0.2.10";
const REQUEST_URI: &str = "sip:bob@biloxi.example.com";
const FROM: &str = "\"Alice\" <sip:alice@atlanta.example.com>;tag=1928301774";
const TO: &str = "<sip:bob@biloxi.example.com>";

fn manager(enabled: bool) -> LiManager {
    let (manager, _iri, _audit) = LiManager::new(
        LawfulInterceptConfig {
            enabled,
            audit_log: None,
            x1: None,
            x2: None,
            x3: None,
            siprec: None,
        },
        100,
        ContentCapability::Available,
    );
    manager
}

fn bench(criterion: &mut Criterion) {
    let source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));

    let enabled = manager(true);
    criterion.bench_function("li_live_dialogs/open_and_release_dialog", |bencher| {
        bencher.iter(|| {
            enabled.live_dialog_opened(
                black_box(CALL_ID),
                black_box(&REQUEST_URI),
                black_box(FROM),
                black_box(TO),
                black_box(source),
            );
            enabled.live_dialog_ended(black_box(CALL_ID));
        });
    });

    // A retransmitted INVITE: the dialog is held, so nothing is built.
    let held = manager(true);
    held.live_dialog_opened(CALL_ID, &REQUEST_URI, FROM, TO, source);
    criterion.bench_function("li_live_dialogs/retransmitted_invite", |bencher| {
        bencher.iter(|| {
            held.live_dialog_opened(
                black_box(CALL_ID),
                black_box(&REQUEST_URI),
                black_box(FROM),
                black_box(TO),
                black_box(source),
            );
        });
    });

    // The response path on a node that holds a dialog: one load to decide.
    criterion.bench_function("li_live_dialogs/holds_any", |bencher| {
        bencher.iter(|| black_box(held.holds_live_dialogs()));
    });

    let disabled = manager(false);
    criterion.bench_function("li_live_dialogs/open_disabled", |bencher| {
        bencher.iter(|| {
            disabled.live_dialog_opened(
                black_box(CALL_ID),
                black_box(&REQUEST_URI),
                black_box(FROM),
                black_box(TO),
                black_box(source),
            );
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
