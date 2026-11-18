//! Criterion perf gate for the dispatch loop's INVITE registration.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench inflight_invite`.
//!
//! The dispatch loop runs `initial_invite_key` on every inbound message, and
//! registers every initial INVITE it finds, so that a CANCEL taken by another
//! worker right behind it finds it (RFC 3261 §9.2). The ids are what that step
//! costs: the classification of a message that is not an INVITE (which must cost
//! next to nothing), the key read off an INVITE's raw bytes, and the INVITE's
//! whole registration, from the bytes to the registration released.
#![allow(clippy::disallowed_methods)] // test, bench and example code may block

use criterion::{criterion_group, criterion_main, Criterion};
use siphon::b2bua::inflight::{initial_invite_key, InflightInvites};
use std::hint::black_box;

const INVITE: &[u8] = concat!(
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;rport;branch=z9hG4bK776asdhds\r\n",
    "Max-Forwards: 70\r\n",
    "From: \"Alice\" <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
    "To: <sip:bob@biloxi.example.com>\r\n",
    "Call-ID: a84b4c76e66710@192.0.2.10\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:alice@192.0.2.10:5060>\r\n",
    "Content-Type: application/sdp\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
)
.as_bytes();

const INVITE_IPV6: &[u8] = concat!(
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/TCP [2001:db8::10]:5060;branch=z9hG4bK776asdhds\r\n",
    "Max-Forwards: 70\r\n",
    "Call-ID: a84b4c76e66710@192.0.2.10\r\n",
    "\r\n",
)
.as_bytes();

const REGISTER: &[u8] = concat!(
    "REGISTER sip:registrar.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKnashds7\r\n",
    "\r\n",
)
.as_bytes();

const RESPONSE: &[u8] = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKnashds7\r\n",
    "\r\n",
)
.as_bytes();

fn bench(criterion: &mut Criterion) {
    criterion.bench_function("inflight_invite/classify_register", |bencher| {
        bencher.iter(|| black_box(initial_invite_key(black_box(REGISTER))));
    });
    criterion.bench_function("inflight_invite/classify_response", |bencher| {
        bencher.iter(|| black_box(initial_invite_key(black_box(RESPONSE))));
    });
    criterion.bench_function("inflight_invite/key_of_invite", |bencher| {
        bencher.iter(|| black_box(initial_invite_key(black_box(INVITE))));
    });
    criterion.bench_function("inflight_invite/key_of_invite_ipv6", |bencher| {
        bencher.iter(|| black_box(initial_invite_key(black_box(INVITE_IPV6))));
    });

    let store: InflightInvites<()> = InflightInvites::default();
    criterion.bench_function("inflight_invite/register_and_release_invite", |bencher| {
        bencher.iter(|| {
            if let Some(key) = initial_invite_key(black_box(INVITE)) {
                store.register(key.clone());
                black_box(store.release(&key));
            }
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
