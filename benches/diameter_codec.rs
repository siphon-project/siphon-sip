//! Criterion perf gate for the Diameter message codec.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench diameter_codec`.
//!
//! In an IMS deployment Diameter is on the per-call / per-registration path:
//! Cx (MAR/SAR/LIR) per registration, Rf/Rx (charging/policy) per call. The
//! AVP encode + message decode is a binary TLV codec siphon owns — exactly the
//! kind of per-message work criterion measures well. The benched message is a
//! representative Cx Multimedia-Auth-Request (MAR). Fixtures use only the 3GPP
//! test realm (`ims.example.com`), never real identities.

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;
use siphon::diameter::codec::{
    decode_diameter, encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32,
    encode_avp_u32_3gpp, encode_avp_utf8, encode_avp_utf8_3gpp, encode_diameter_message,
    encode_vendor_specific_app_id, FLAG_PROXIABLE, FLAG_REQUEST,
};
use siphon::diameter::dictionary::{avp, CMD_MULTIMEDIA_AUTH, CX_APP_ID, VENDOR_3GPP};

/// Build the AVP block of a Cx MAR (with a SIP-Auth-Data-Item carrying a
/// resync token) — the per-request encode work an S-CSCF does on registration.
fn build_mar_avps() -> Vec<u8> {
    let resync_data: Vec<u8> = {
        let rand = [0xABu8; 16];
        let auts = [0xCDu8; 14];
        let mut data = Vec::with_capacity(30);
        data.extend_from_slice(&rand);
        data.extend_from_slice(&auts);
        data
    };

    let mut auth_children = Vec::new();
    auth_children
        .extend_from_slice(&encode_avp_utf8_3gpp(avp::SIP_AUTHENTICATION_SCHEME, "Digest-AKAv1-MD5"));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHORIZATION, &resync_data));
    let sip_auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

    let mut avp_bytes = Vec::new();
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "scscf.ims.example.com;1;1"));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.example.com"));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, "ims.example.com"));
    avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(VENDOR_3GPP, CX_APP_ID));
    avp_bytes
        .extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:alice@ims.example.com"));
    avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    avp_bytes.extend_from_slice(&sip_auth_data_item);
    avp_bytes
}

fn encode_mar() -> Vec<u8> {
    let avp_bytes = build_mar_avps();
    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        CMD_MULTIMEDIA_AUTH,
        CX_APP_ID,
        100,
        200,
        &avp_bytes,
    )
}

fn bench_diameter(criterion: &mut Criterion) {
    let wire = encode_mar();
    let mut group = criterion.benchmark_group("diameter");
    group.throughput(Throughput::Bytes(wire.len() as u64));

    // Full per-request encode: build every AVP + frame the message.
    group.bench_function("encode_mar", |bencher| {
        bencher.iter(|| black_box(encode_mar()));
    });

    // Inbound decode of a MAR/MAA-shaped message.
    group.bench_function("decode_mar", |bencher| {
        bencher.iter(|| black_box(decode_diameter(black_box(&wire)).expect("decode mar")));
    });

    group.finish();
}

criterion_group!(benches, bench_diameter);
criterion_main!(benches);
