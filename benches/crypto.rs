//! Criterion perf gate for the per-auth crypto siphon *owns*.
//!
//! Run with `PYO3_PYTHON=python3 cargo bench --bench crypto`.
//!
//! Scope note: these bench the constructions siphon implements itself, NOT the
//! vendored hash/cipher primitives under them.
//!
//! - Milenage f1–f5 / OPc derivation (3GPP TS 35.206) — siphon's own algorithm;
//!   only the AES block op is vendored. Per IMS registration.
//! - Digest response assembly (RFC 2617 / 7616: HA1 / HA2 / KD over MD5 or
//!   SHA-256) — siphon's own string assembly + hashing. Per REGISTER /
//!   proxy-auth challenge.
//!
//! Raw MD5/SHA-1 are deliberately NOT benched — that would measure the `md5` /
//! `sha2` crates, not siphon code.
//!
//! Fixtures use the 3GPP TS 35.208 Test Set 1 reference vector and the 3GPP
//! test realm — never real subscriber secrets.

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use siphon::auth::{
    compute_aka_response, compute_digest_response, DigestAlgorithm, DigestChallenge,
    DigestCredentials,
};
use siphon::ipsec::milenage::{compute_opc, generate_vector_with_rand};

// 3GPP TS 35.208 Test Set 1.
const KEY: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
const OP: [u8; 16] = [
    0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18,
];
const RAND: [u8; 16] = [
    0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
];
const SQN: [u8; 6] = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
const AMF: [u8; 2] = [0xb9, 0xb9];

fn bench_milenage(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("milenage");

    // OPc derivation — done once per subscriber, but it is one AES block + XOR
    // and a common precompute, so track it.
    group.bench_function("compute_opc", |bencher| {
        bencher.iter(|| black_box(compute_opc(black_box(&KEY), black_box(&OP))));
    });

    // Full AKA vector (f1 + f2345): RES, CK, IK, AK, AUTN. The per-challenge
    // cost on the IMS registration path.
    group.bench_function("generate_vector", |bencher| {
        bencher.iter(|| {
            black_box(generate_vector_with_rand(
                black_box(&KEY),
                black_box(&OP),
                black_box(&SQN),
                black_box(&AMF),
                black_box(&RAND),
            ))
        });
    });

    group.finish();
}

fn bench_digest(criterion: &mut Criterion) {
    let credentials = DigestCredentials {
        username: "alice".to_string(),
        password: "secret-passphrase".to_string(),
    };
    let challenge = |algorithm| DigestChallenge {
        realm: "sip.example.com".to_string(),
        nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
        opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".to_string()),
        qop: Some("auth".to_string()),
        algorithm,
        stale: false,
    };

    let mut group = criterion.benchmark_group("digest");

    let md5_challenge = challenge(DigestAlgorithm::Md5);
    group.bench_function("response_md5", |bencher| {
        bencher.iter(|| {
            black_box(compute_digest_response(
                black_box(&md5_challenge),
                black_box(&credentials),
                "REGISTER",
                "sip:sip.example.com",
                Some(1),
                Some("0a4f113b"),
            ))
        });
    });

    let sha256_challenge = challenge(DigestAlgorithm::Sha256);
    group.bench_function("response_sha256", |bencher| {
        bencher.iter(|| {
            black_box(compute_digest_response(
                black_box(&sha256_challenge),
                black_box(&credentials),
                "REGISTER",
                "sip:sip.example.com",
                Some(1),
                Some("0a4f113b"),
            ))
        });
    });

    // IMS AKAv1-MD5: digest over the binary RES (from Milenage), not a secret.
    let aka_challenge = challenge(DigestAlgorithm::AkaV1Md5);
    let res: [u8; 8] = [0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf];
    group.bench_function("response_aka_md5", |bencher| {
        bencher.iter(|| {
            black_box(compute_aka_response(
                black_box(&aka_challenge),
                "001010000000001@ims.example.com",
                black_box(&res),
                "REGISTER",
                "sip:ims.example.com",
                Some(1),
                Some("0a4f113b"),
            ))
        });
    });

    group.finish();
}

criterion_group!(benches, bench_milenage, bench_digest);
criterion_main!(benches);
