//! Criterion bench for what recording a provisional response costs the
//! response path.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench b2bua_provisional`.
//!
//! RFC 3261 §9.1 has a CANCEL wait for a provisional on the INVITE it cancels,
//! so every provisional to an INVITE is recorded on its branch, and checked
//! against the branches whose CANCEL is waiting
//! (`CallActorStore::provisional_received`). That runs per message, for a
//! `100 Trying` as much as for a `180`, so it has to stay at two map reads and
//! allocate nothing:
//!
//! - `branch_not_ours` is the proxy datapath: the branch belongs to no B2BUA
//!   leg, both branch indexes miss, and no CANCEL is waiting anywhere.
//! - `live_branch` is the common B2BUA case: the branch is a ringing leg's,
//!   its provisional is recorded, and no CANCEL is waiting anywhere.
//! - `live_branch_while_a_cancel_waits` is the same with another branch's
//!   CANCEL waiting, which adds one more map read that misses.
//!
//! Fixtures use RFC 5737 addresses and example.com AoRs.

use std::hint::black_box;
use std::sync::{Arc, Mutex};

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::b2bua::actor::{CallActorStore, Leg, TransportInfo};
use siphon::sip::parser::parse_sip_message_bytes;
use siphon::transport::{ConnectionId, Transport};

fn transport() -> TransportInfo {
    TransportInfo {
        remote_addr: "192.0.2.20:5060".parse().expect("a literal address"),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    }
}

/// A B-leg on `branch` whose INVITE is on the wire.
fn ringing_leg(branch: &str) -> Leg {
    let mut leg = Leg::new_b_leg(
        format!("{branch}@example.com"),
        "siphon-tag".to_string(),
        "sip:callee@192.0.2.20".to_string(),
        branch.to_string(),
        transport(),
    );
    let invite = parse_sip_message_bytes(
        format!(
            concat!(
                "INVITE sip:callee@192.0.2.20 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
                "From: <sip:caller@example.com>;tag=siphon-tag\r\n",
                "To: <sip:callee@example.com>\r\n",
                "Call-ID: {branch}@example.com\r\n",
                "CSeq: 1 INVITE\r\n",
                "Content-Length: 0\r\n\r\n",
            ),
            branch = branch
        )
        .as_bytes(),
    )
    .expect("the INVITE parses");
    leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
    leg
}

/// A store with 1000 calls, each ringing one B-leg on `z9hG4bK-leg-<n>`.
fn store_with_ringing_calls() -> CallActorStore {
    let store = CallActorStore::new();
    for index in 0..1000u32 {
        let call_id = store.create_call(Leg::new_a_leg(
            format!("caller-{index}@example.com"),
            "caller-tag".to_string(),
            format!("z9hG4bK-caller-{index}"),
            transport(),
        ));
        assert!(store.add_b_leg(&call_id, ringing_leg(&format!("z9hG4bK-leg-{index}"))));
    }
    store
}

fn bench_provisional(criterion: &mut Criterion) {
    let store = store_with_ringing_calls();
    criterion.bench_function("b2bua_provisional/branch_not_ours", |bencher| {
        bencher.iter(|| black_box(store.provisional_received(black_box("z9hG4bK-proxied"))));
    });
    criterion.bench_function("b2bua_provisional/live_branch", |bencher| {
        bencher.iter(|| black_box(store.provisional_received(black_box("z9hG4bK-leg-500"))));
    });

    // One branch given up on with no response yet: its CANCEL waits, and every
    // other provisional now also looks among the kept branches.
    let waiting = ringing_leg("z9hG4bK-waiting");
    assert!(store.keep_answerable(std::iter::once(&waiting)));
    assert!(!store.claim_cancel("z9hG4bK-waiting"));
    criterion.bench_function(
        "b2bua_provisional/live_branch_while_a_cancel_waits",
        |bencher| {
            bencher.iter(|| black_box(store.provisional_received(black_box("z9hG4bK-leg-500"))));
        },
    );
}

criterion_group!(benches, bench_provisional);
criterion_main!(benches);
