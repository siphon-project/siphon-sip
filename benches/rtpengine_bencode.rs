//! Criterion perf gate for the rtpengine NG bencode codec.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench rtpengine_bencode`.
//!
//! When the B2BUA anchors media, every call's offer / answer / delete is a
//! bencode-encoded rtpengine NG control message. That codec runs per call on
//! the media-anchoring path. The benched dict is a representative `offer`
//! carrying an SDP body (the realistic large value in these messages).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use siphon::rtpengine::bencode::{decode_full_dict, encode, BencodeValue};

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

/// A representative rtpengine NG `offer` request.
fn offer_dict() -> BencodeValue {
    BencodeValue::Dict(vec![
        (b"command".to_vec(), BencodeValue::String(b"offer".to_vec())),
        (
            b"call-id".to_vec(),
            BencodeValue::String(b"a84b4c76e66710@192.0.2.1".to_vec()),
        ),
        (b"from-tag".to_vec(), BencodeValue::String(b"1928301774".to_vec())),
        (
            b"ICE".to_vec(),
            BencodeValue::String(b"remove".to_vec()),
        ),
        (
            b"flags".to_vec(),
            BencodeValue::List(vec![
                BencodeValue::String(b"trust-address".to_vec()),
                BencodeValue::String(b"replace-origin".to_vec()),
            ]),
        ),
        (b"sdp".to_vec(), BencodeValue::String(OFFER_SDP.as_bytes().to_vec())),
    ])
}

fn bench_bencode(criterion: &mut Criterion) {
    let dict = offer_dict();
    let wire = encode(&dict);

    let mut group = criterion.benchmark_group("bencode");
    group.throughput(Throughput::Bytes(wire.len() as u64));

    group.bench_function("encode_offer", |bencher| {
        bencher.iter(|| black_box(encode(black_box(&dict))));
    });

    group.bench_function("decode_offer", |bencher| {
        bencher.iter(|| black_box(decode_full_dict(black_box(&wire)).expect("decode offer")));
    });

    group.finish();
}

criterion_group!(benches, bench_bencode);
criterion_main!(benches);
