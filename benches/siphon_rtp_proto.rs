//! Criterion perf gate for the siphon-rtp native control codec.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench siphon_rtp_proto`.
//!
//! When the `siphon-rtp` backend anchors media, every call's offer / answer /
//! delete is a length-prefixed JSON control frame. This is the JSON twin of the
//! `rtpengine_bencode` gate — same per-call media-control cost, different
//! encoding — so the two can be compared head-to-head. The benched message is a
//! representative `offer` carrying an SDP body (the realistic large value).

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use siphon_rtp_proto::{frame, CmdResult, Command, ProfileFlags, Request, Response};
use std::hint::black_box;

const OFFER_SDP: &str = concat!(
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// A representative native `offer` request.
fn offer_request() -> Request {
    Request {
        id: 1,
        command: Command::Offer {
            call_id: "a84b4c76e66710@192.0.2.1".to_string(),
            from_tag: "1928301774".to_string(),
            sdp: OFFER_SDP.to_string(),
            profile: ProfileFlags {
                ice: Some("remove".to_string()),
                flags: vec!["trust-address".to_string(), "replace-origin".to_string()],
                replace: vec!["origin".to_string()],
                ..Default::default()
            },
        },
    }
}

/// A representative `ok` response carrying rewritten SDP.
fn offer_response() -> Response {
    Response {
        id: 1,
        result: CmdResult::Ok {
            sdp: Some(OFFER_SDP.to_string()),
            duration_ms: None,
            to_tag: None,
            stats: None,
        },
    }
}

fn bench_proto(criterion: &mut Criterion) {
    let request = offer_request();
    let request_wire = frame::encode(&request).expect("encode offer request");
    let response_wire = frame::encode(&offer_response()).expect("encode offer response");

    let mut group = criterion.benchmark_group("siphon_rtp_proto");
    group.throughput(Throughput::Bytes(request_wire.len() as u64));

    group.bench_function("encode_offer_request", |bencher| {
        bencher.iter(|| black_box(frame::encode(black_box(&request)).expect("encode")));
    });

    group.bench_function("decode_offer_response", |bencher| {
        bencher.iter(|| {
            let decoded: Option<(Response, usize)> =
                frame::decode(black_box(&response_wire)).expect("decode");
            black_box(decoded)
        });
    });

    group.finish();
}

criterion_group!(benches, bench_proto);
criterion_main!(benches);
