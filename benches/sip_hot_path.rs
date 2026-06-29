//! Criterion perf gates for the per-message SIP hot paths.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench sip_hot_path`.
//!
//! These lock the cost of the work the proxy/B2BUA does on *every* SIP message —
//! parse, header touch, transaction keying, serialize — so a regression on the
//! datapath fails the release-cut gate (`scripts/bench_regression.sh`, wired into
//! `scripts/cut-release.sh`).  The end-to-end SIPp baseline in README.md measures
//! aggregate CPS; these microbenches isolate the individual per-message costs —
//! string sharing, header clone, branch keying — so an improvement or regression
//! in one is visible directly, not averaged into a CPS number.
//!
//! Fixtures use only RFC 5737 documentation addresses (192.0.2.0/24) and generic
//! example.com hosts — never real IPs or subscriber identities.

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput,
};
use siphon::sip::parse_sip_message;
use siphon::transaction::TransactionManager;

/// A realistic offer SDP — the common INVITE body the parser walks on every call.
const SDP_BODY: &str = concat!(
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 atlanta.example.com\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.101\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 96\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:96 telephone-event/8000\r\n",
    "a=fmtp:96 0-15\r\n",
    "a=sendrecv\r\n",
);

/// INVITE carrying the SDP offer above. Built with `format!` so Content-Length
/// always matches the body byte count exactly (the parser slices on it).
fn invite_with_sdp() -> String {
    format!(
        concat!(
            "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n",
            "Max-Forwards: 70\r\n",
            "To: Bob <sip:bob@biloxi.example.com>\r\n",
            "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
            "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:alice@pc33.atlanta.example.com>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        SDP_BODY.len(),
        SDP_BODY,
    )
}

/// Bodyless INVITE — the lower bound for request parse cost.
const INVITE_NO_SDP: &str = concat!(
    "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n",
    "Max-Forwards: 70\r\n",
    "To: Bob <sip:bob@biloxi.example.com>\r\n",
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:alice@pc33.atlanta.example.com>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const REGISTER: &str = concat!(
    "REGISTER sip:registrar.biloxi.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP bobspc.biloxi.example.com:5060;branch=z9hG4bKnashds7\r\n",
    "Max-Forwards: 70\r\n",
    "To: Bob <sip:bob@biloxi.example.com>\r\n",
    "From: Bob <sip:bob@biloxi.example.com>;tag=456248\r\n",
    "Call-ID: 843817637684230@998sdasdh09\r\n",
    "CSeq: 1826 REGISTER\r\n",
    "Contact: <sip:bob@192.0.2.4>\r\n",
    "Expires: 7200\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const RESPONSE_200: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n",
    "To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf\r\n",
    "From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n",
    "Call-ID: a84b4c76e66710@pc33.atlanta.example.com\r\n",
    "CSeq: 314159 INVITE\r\n",
    "Contact: <sip:bob@192.0.2.4>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// Parse cost — the first thing every inbound byte stream pays.
fn bench_parse(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("parse");

    group.throughput(Throughput::Bytes(invite_sdp.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) =
                parse_sip_message(black_box(invite_sdp.as_str())).expect("parse invite+sdp");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(INVITE_NO_SDP.len() as u64));
    group.bench_function("invite_no_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) =
                parse_sip_message(black_box(INVITE_NO_SDP)).expect("parse invite");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(REGISTER.len() as u64));
    group.bench_function("register", |bencher| {
        bencher.iter(|| {
            let (_, message) = parse_sip_message(black_box(REGISTER)).expect("parse register");
            black_box(message)
        });
    });

    group.throughput(Throughput::Bytes(RESPONSE_200.len() as u64));
    group.bench_function("response_200", |bencher| {
        bencher.iter(|| {
            let (_, message) = parse_sip_message(black_box(RESPONSE_200)).expect("parse 200");
            black_box(message)
        });
    });

    group.finish();
}

/// Serialize cost — what every relayed/forwarded message pays on the way out.
fn bench_serialize(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, message) = parse_sip_message(&invite_sdp).expect("setup parse invite+sdp");
    let wire_len = message.to_bytes().len() as u64;

    let mut group = criterion.benchmark_group("serialize");
    group.throughput(Throughput::Bytes(wire_len));
    group.bench_function("invite_sdp_to_bytes", |bencher| {
        bencher.iter(|| black_box(black_box(&message).to_bytes()));
    });
    group.finish();
}

/// Full proxy touch: parse an inbound INVITE then serialize it back out.
fn bench_roundtrip(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let mut group = criterion.benchmark_group("roundtrip");
    group.throughput(Throughput::Bytes(invite_sdp.len() as u64));
    group.bench_function("invite_sdp", |bencher| {
        bencher.iter(|| {
            let (_, message) =
                parse_sip_message(black_box(invite_sdp.as_str())).expect("roundtrip parse");
            black_box(message.to_bytes())
        });
    });
    group.finish();
}

/// Header access + mutation. `set`/`add` go through the copy-on-write
/// `Arc<HeadersInner>`, so the batched setup clones a fresh (cheap, Arc-bump)
/// message and the timed routine pays the make_mut deep-clone — exactly the
/// cost a fork/relay incurs when it rewrites a header.
fn bench_headers(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, message) = parse_sip_message(&invite_sdp).expect("setup parse invite+sdp");
    let mut group = criterion.benchmark_group("headers");

    group.bench_function("get_via", |bencher| {
        bencher.iter(|| black_box(black_box(&message).headers.get("Via")));
    });

    group.bench_function("has_route", |bencher| {
        bencher.iter(|| black_box(black_box(&message).headers.has("Route")));
    });

    group.bench_function("set_max_forwards", |bencher| {
        bencher.iter_batched(
            || message.clone(),
            |mut owned| {
                owned
                    .headers
                    .set("Max-Forwards", black_box("69".to_string()));
                black_box(owned)
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("add_via", |bencher| {
        bencher.iter_batched(
            || message.clone(),
            |mut owned| {
                owned.headers.add(
                    "Via",
                    black_box(
                        "SIP/2.0/UDP proxy.example.com;branch=z9hG4bK-proxy-1".to_string(),
                    ),
                );
                black_box(owned)
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

/// Transaction-key extraction (RFC 3261 §17) — done for every message that
/// reaches the transaction layer, to match it to an existing transaction.
fn bench_txn_key(criterion: &mut Criterion) {
    let invite_sdp = invite_with_sdp();
    let (_, invite) = parse_sip_message(&invite_sdp).expect("setup parse invite");
    let (_, response) = parse_sip_message(RESPONSE_200).expect("setup parse 200");

    let mut group = criterion.benchmark_group("txn_key");
    group.bench_function("invite", |bencher| {
        bencher.iter(|| {
            black_box(
                TransactionManager::key_from_message(black_box(&invite)).expect("invite key"),
            )
        });
    });
    group.bench_function("response", |bencher| {
        bencher.iter(|| {
            black_box(
                TransactionManager::key_from_message(black_box(&response))
                    .expect("response key"),
            )
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_parse,
    bench_serialize,
    bench_roundtrip,
    bench_headers,
    bench_txn_key
);
criterion_main!(benches);
