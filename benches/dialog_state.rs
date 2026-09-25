//! Criterion bench for what `DialogStateChanged` adds to the proxy path.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench dialog_state`.
//!
//! - `gate_unsubscribed` is the whole per-message cost when no control app
//!   subscribes to `dialog`: every hook on the relay, response, CANCEL and
//!   in-dialog paths stops at this check (the subscription gate plus the
//!   tracking store's emptiness, one atomic load each). It has to stay at a
//!   few nanoseconds.
//! - With a subscriber, each INVITE branch pays the registrar match for its
//!   target (`match_callee_1k_bindings`, an O(bindings) scan like
//!   `registrar.lookup_contact`), and each tracked call the store's bookkeeping
//!   from INVITE to BYE (`track_proxied_call`).
//!
//! Fixtures use RFC 5737 addresses and example.com AoRs.

use std::net::SocketAddr;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::b2bua::actor::{DialogDirection, DialogState, DialogWatch};
use siphon::config::DialogStateConfig;
use siphon::proxy::dialog_state::{Answer, Hop, NewBranch, NewDialog, ProxyDialogStore};
use siphon::registrar::Registrar;
use siphon::sip::uri::SipUri;
use siphon::transport::{ConnectionId, Transport};
use std::hint::black_box;

fn hop(address: &str) -> Hop {
    Hop {
        destination: address.parse().expect("a literal address"),
        transport: Transport::Udp,
        connection_id: ConnectionId::default(),
        local_addr: None,
    }
}

fn watch(aor: &str, direction: DialogDirection) -> DialogWatch {
    DialogWatch {
        leg_id: format!("{aor}-leg"),
        aor: aor.to_string(),
        direction,
        call_id: "bench@192.0.2.10".to_string(),
        local_tag: None,
        remote_tag: None,
        remote_uri: "sip:peer@example.com".to_string(),
        remote_display_name: None,
        state: DialogState::Trying,
        contact: Some(format!("{aor}-contact")),
    }
}

fn bench_gate(criterion: &mut Criterion) {
    let store = ProxyDialogStore::new();
    criterion.bench_function("dialog_state/gate_unsubscribed", |bencher| {
        bencher.iter(|| {
            black_box(siphon::control::app_event_wanted(black_box("dialog")))
                || black_box(!store.is_empty())
        });
    });
}

fn bench_match(criterion: &mut Criterion) {
    let registrar = Registrar::default();
    for index in 0..1000u32 {
        let host = format!("198.51.{}.{}", 100 + index / 250, index % 250 + 1);
        let source: SocketAddr = format!("{host}:5060").parse().expect("an address");
        registrar
            .save_with_source(
                &format!("sip:{index}@example.com"),
                SipUri::new(host).with_user(index.to_string()),
                3600,
                1.0,
                format!("reg-{index}"),
                1,
                Some(source),
                Some(Transport::Udp),
            )
            .expect("the binding saves");
    }
    criterion.bench_function("dialog_state/match_callee_1k_bindings", |bencher| {
        bencher
            .iter(|| black_box(registrar.binding_for_contact(black_box("sip:500@198.51.102.1"))));
    });
}

fn bench_track(criterion: &mut Criterion) {
    let store = ProxyDialogStore::new();
    let config = DialogStateConfig::default();
    criterion.bench_function("dialog_state/track_proxied_call", |bencher| {
        bencher.iter(|| {
            let now = Instant::now();
            let key = ("bench@192.0.2.10".to_string(), "caller-tag".to_string());
            store.begin(
                NewDialog {
                    call_id: key.0.clone(),
                    caller_tag: key.1.clone(),
                    caller: Some(watch("sip:201@example.com", DialogDirection::Initiator)),
                    caller_hop: hop("192.0.2.10:5060"),
                    caller_contact: Some("sip:201@192.0.2.10:5060".to_string()),
                    from: "<sip:201@example.com>;tag=caller-tag".to_string(),
                    to: "<sip:202@example.com>".to_string(),
                    invite_cseq: 1,
                    route_to_caller: Vec::new(),
                },
                now,
            );
            store.add_branch(
                &key,
                NewBranch {
                    via_branch: "z9hG4bK-bench".to_string(),
                    watch: Some(watch("sip:202@example.com", DialogDirection::Recipient)),
                    hop: hop("198.51.100.20:5060"),
                    own_record_routes: 1,
                },
            );
            store.branch_response("z9hG4bK-bench", 180, Some("callee-tag"), None, now, &config);
            store.upstream_response(&key, 180, Some("callee-tag"));
            store.branch_response(
                "z9hG4bK-bench",
                200,
                Some("callee-tag"),
                Some(Answer::default()),
                now,
                &config,
            );
            store.upstream_response(&key, 200, Some("callee-tag"));
            store.settle(&key);
            black_box(store.in_dialog_request(
                &key.0,
                "caller-tag",
                "callee-tag",
                "BYE",
                Some(2),
                None,
            ))
        });
    });
}

criterion_group!(benches, bench_gate, bench_match, bench_track);
criterion_main!(benches);
