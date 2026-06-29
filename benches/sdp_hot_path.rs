//! Criterion perf gate for the SDP hot path.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench sdp_hot_path`.
//!
//! Every call that carries media touches SDP: the offer/answer is parsed,
//! codec-filtered, and re-serialized on the INVITE/200 path. This is on the
//! same per-call datapath as SIP parsing itself — string-heavy, siphon-owned,
//! and run once (often twice) per call. Gated by `scripts/bench_regression.sh`.

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use siphon::media::sdp::SdpBody;

/// A representative offer: G.711 + Opus + telephone-event, the common VoIP shape.
const SAMPLE_SDP: &str = concat!(
    "v=0\r\n",
    "o=alice 2890844526 2890844526 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 49170 RTP/AVP 0 8 97 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:97 opus/48000/2\r\n",
    "a=fmtp:97 minptime=10;useinbandfec=1\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=fmtp:101 0-16\r\n",
    "a=sendrecv\r\n",
);

fn bench_sdp(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("sdp");
    group.throughput(Throughput::Bytes(SAMPLE_SDP.len() as u64));

    group.bench_function("parse", |bencher| {
        bencher.iter(|| black_box(SdpBody::parse(black_box(SAMPLE_SDP))));
    });

    // filter_codecs mutates in place; the batched setup parses a fresh body
    // (untimed) so the routine measures only the codec filter.
    group.bench_function("filter_codecs", |bencher| {
        bencher.iter_batched(
            || SdpBody::parse(SAMPLE_SDP),
            |mut sdp| {
                sdp.filter_codecs(black_box(&["PCMU", "PCMA"]));
                black_box(sdp)
            },
            BatchSize::SmallInput,
        );
    });

    let parsed = SdpBody::parse(SAMPLE_SDP);
    group.bench_function("serialize", |bencher| {
        bencher.iter(|| black_box(black_box(&parsed).to_string()));
    });

    // The full per-call SDP rewrite: parse the offer, keep G.711 only,
    // serialize back out.
    group.bench_function("roundtrip_filter", |bencher| {
        bencher.iter(|| {
            let mut sdp = SdpBody::parse(black_box(SAMPLE_SDP));
            sdp.filter_codecs(&["PCMU", "PCMA"]);
            black_box(sdp.to_string())
        });
    });

    group.finish();
}

criterion_group!(benches, bench_sdp);
criterion_main!(benches);
