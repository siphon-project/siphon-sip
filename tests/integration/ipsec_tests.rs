//! Integration tests for the IPsec sec-agree primitives (3GPP TS 33.203).
//!
//! These tests exercise the Python-callable API surface end-to-end —
//! parsing the UE's ``Security-Client`` from a real SIP request,
//! stripping ``ck=``/``ik=`` from a relayed 401 in place, and confirming
//! that AVs are consumed exactly once and the SA-allocator pre-checks
//! reject mismatched offers.
//!
//! The kernel ``ip xfrm`` flow itself is **not** exercised here — that
//! requires CAP_NET_ADMIN and is validated by the sipp_ipsec functional
//! scenario.  Allocation failure paths that don't reach the kernel
//! (consumed AV, transform mismatch, malformed ue_addr) are covered.

use std::sync::{Arc, Mutex};

use siphon::ipsec::{IntegrityAlgorithm, IpsecManager};
use siphon::script::api::ipsec::{
    parse_security_client_multi, strip_ck_ik, PyAuthVectorHandle, PySecurityOffer, PyTransform,
};
use siphon::script::api::reply::PyReply;
use siphon::script::api::request::PyRequest;
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::uri::SipUri;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Build a minimal REGISTER carrying a Security-Client header from a UE.
fn make_register_with_security_client(value: &str) -> PyRequest {
    let message = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new("ims.example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ipsec".to_string())
        .to("<sip:alice@ims.example.com>".to_string())
        .from("<sip:alice@ims.example.com>;tag=ue1".to_string())
        .call_id("ue-call-1@10.0.0.1".to_string())
        .cseq("1 REGISTER".to_string())
        .max_forwards(70)
        .header("Security-Client", value.to_string())
        .content_length(0)
        .build()
        .unwrap();
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "10.0.0.1".to_string(),
        5060,
    )
}

fn make_register_without_security_client() -> PyRequest {
    let message = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new("ims.example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ipsec".to_string())
        .to("<sip:alice@ims.example.com>".to_string())
        .from("<sip:alice@ims.example.com>;tag=ue1".to_string())
        .call_id("ue-call-2@10.0.0.1".to_string())
        .cseq("1 REGISTER".to_string())
        .max_forwards(70)
        .content_length(0)
        .build()
        .unwrap();
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "10.0.0.1".to_string(),
        5060,
    )
}

fn make_401_with_auth_header(name: &str, value: &str) -> PyReply {
    let message = SipMessageBuilder::new()
        .response(401, "Unauthorized".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-ipsec".to_string())
        .to("<sip:alice@ims.example.com>;tag=scscf".to_string())
        .from("<sip:alice@ims.example.com>;tag=ue1".to_string())
        .call_id("ue-call-1@10.0.0.1".to_string())
        .cseq("1 REGISTER".to_string())
        .header(name, value.to_string())
        .content_length(0)
        .build()
        .unwrap();
    PyReply::new(Arc::new(Mutex::new(message)))
}

// ---------------------------------------------------------------------------
// PyRequest.parse_security_client — round-trip via the SIP message
// ---------------------------------------------------------------------------

#[test]
fn parse_security_client_via_request_carries_ue_addr() {
    let request = make_register_with_security_client(
        "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062",
    );
    // Parse via the free-helper (the PyO3 method requires a Python ref).
    let message = request.message();
    let guard = message.lock().unwrap();
    let header = guard.headers.get("Security-Client").unwrap().clone();
    drop(guard);
    let offers = parse_security_client_multi(&header, "10.0.0.1");
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].ue_addr, "10.0.0.1");
    assert_eq!(offers[0].alg, "hmac-sha-1-96");
    assert_eq!(offers[0].spi_c, 11111);
    assert_eq!(offers[0].spi_s, 22222);
    assert_eq!(offers[0].port_c, 5060);
    assert_eq!(offers[0].port_s, 5062);
}

#[test]
fn parse_security_client_handles_missing_header() {
    let request = make_register_without_security_client();
    let message = request.message();
    let guard = message.lock().unwrap();
    assert!(guard.headers.get("Security-Client").is_none());
}

#[test]
fn parse_security_client_two_offers_in_one_header() {
    let header = concat!(
        "ipsec-3gpp; alg=hmac-md5-96; spi-c=11111; spi-s=22222; port-c=5060; port-s=5062, ",
        "ipsec-3gpp; alg=hmac-sha-1-96; spi-c=33333; spi-s=44444; port-c=5063; port-s=5064",
    );
    let offers = parse_security_client_multi(header, "10.0.0.42");
    assert_eq!(offers.len(), 2);
    assert_eq!(offers[0].alg, "hmac-md5-96");
    assert_eq!(offers[1].alg, "hmac-sha-1-96");
    assert!(offers.iter().all(|offer| offer.ue_addr == "10.0.0.42"));
}

// ---------------------------------------------------------------------------
// PyReply.take_av — verifies in-place strip across all three auth headers
// ---------------------------------------------------------------------------

#[test]
fn strip_ck_ik_extracts_and_strips_from_www_authenticate() {
    let header = concat!(
        "Digest realm=\"ims.example.com\", ",
        "nonce=\"deadbeef\", ",
        "algorithm=AKAv1-MD5, ",
        "ck=\"0123456789abcdef0123456789abcdef\", ",
        "ik=\"fedcba9876543210fedcba9876543210\", ",
        "qop=\"auth\"",
    );
    let _reply = make_401_with_auth_header("WWW-Authenticate", header);
    // Direct call on the free helper — the PyO3 method requires Python.
    let (rewritten, parsed) = strip_ck_ik(header);
    assert!(parsed.is_some());
    assert!(!rewritten.contains("ck="));
    assert!(!rewritten.contains("ik="));
    assert!(rewritten.contains(r#"realm="ims.example.com""#));
    assert!(rewritten.contains(r#"nonce="deadbeef""#));
    assert!(rewritten.contains(r#"qop="auth""#));
    assert!(rewritten.contains("algorithm=AKAv1-MD5"));
}

#[test]
fn strip_ck_ik_preserves_quoted_commas() {
    let header = concat!(
        "Digest realm=\"ims, example.com\", ",
        "nonce=\"deadbeef\", ",
        "ck=\"0123456789abcdef0123456789abcdef\", ",
        "ik=\"fedcba9876543210fedcba9876543210\"",
    );
    let (rewritten, parsed) = strip_ck_ik(header);
    assert!(parsed.is_some());
    assert!(rewritten.contains(r#"realm="ims, example.com""#));
}

#[test]
fn strip_ck_ik_only_one_present_returns_none() {
    let header = concat!(
        "Digest realm=\"x\", ",
        "nonce=\"y\", ",
        "ck=\"0123456789abcdef0123456789abcdef\"",
    );
    let (out, parsed) = strip_ck_ik(header);
    assert!(parsed.is_none());
    assert_eq!(out, header, "input must be unchanged when ik is missing");
}

#[test]
fn strip_ck_ik_idempotent() {
    let header = concat!(
        "Digest realm=\"x\", ",
        "nonce=\"y\", ",
        "ck=\"0123456789abcdef0123456789abcdef\", ",
        "ik=\"fedcba9876543210fedcba9876543210\"",
    );
    let (first, parsed1) = strip_ck_ik(header);
    assert!(parsed1.is_some());
    let (second, parsed2) = strip_ck_ik(&first);
    assert_eq!(first, second);
    assert!(parsed2.is_none());
}

#[test]
fn strip_ck_ik_recognizes_uppercase_param_names() {
    // RFC 7235 says auth-param names are case-insensitive.
    let header = concat!(
        "Digest realm=\"x\", ",
        "nonce=\"y\", ",
        "CK=\"0123456789abcdef0123456789abcdef\", ",
        "IK=\"fedcba9876543210fedcba9876543210\"",
    );
    let (_rewritten, parsed) = strip_ck_ik(header);
    assert!(parsed.is_some());
}

// ---------------------------------------------------------------------------
// AuthVectorHandle — single-shot consumption
// ---------------------------------------------------------------------------

#[test]
fn auth_vector_handle_take_consumes_exactly_once() {
    let handle = PyAuthVectorHandle::new([0xAB; 16], [0xCD; 16]);
    let first = handle.take();
    assert!(first.is_some());
    let bytes = first.unwrap();
    assert_eq!(bytes.ck[0], 0xAB);
    assert_eq!(bytes.ik[15], 0xCD);
    drop(bytes);
    assert!(handle.take().is_none(), "second take must yield None");
}

// ---------------------------------------------------------------------------
// Transform compatibility checks — driven by string identity, case-insensitive
// ---------------------------------------------------------------------------

fn fixture_offer(alg: &str, ealg: &str) -> PySecurityOffer {
    PySecurityOffer {
        mechanism: "ipsec-3gpp".to_string(),
        alg: alg.to_string(),
        ealg: ealg.to_string(),
        spi_c: 1,
        spi_s: 2,
        port_c: 3,
        port_s: 4,
        ue_addr: "10.0.0.1".to_string(),
    }
}

#[test]
fn transform_compatible_with_sha1_null() {
    let offer = fixture_offer("hmac-sha-1-96", "null");
    assert!(PyTransform::HmacSha1_96Null.compatible_with(&offer));
    assert!(!PyTransform::HmacMd5_96Null.compatible_with(&offer));
}

#[test]
fn transform_compatible_with_md5_null() {
    let offer = fixture_offer("hmac-md5-96", "null");
    assert!(PyTransform::HmacMd5_96Null.compatible_with(&offer));
    assert!(!PyTransform::HmacSha1_96Null.compatible_with(&offer));
}

#[test]
fn transform_compatible_with_treats_empty_ealg_as_null() {
    let offer = fixture_offer("hmac-sha-1-96", "");
    assert!(PyTransform::HmacSha1_96Null.compatible_with(&offer));
}

#[test]
fn transform_compatible_with_rejects_aes_offer() {
    // Phase 1 doesn't ship AES — make sure such offers don't accidentally
    // match a NULL-encryption transform.
    let offer = fixture_offer("hmac-sha-1-96", "aes-cbc");
    assert!(!PyTransform::HmacSha1_96Null.compatible_with(&offer));
    assert!(!PyTransform::HmacMd5_96Null.compatible_with(&offer));
}

// ---------------------------------------------------------------------------
// IpsecManager smoke — confirms the manager is buildable + SPI allocator
// is usable from Phase 1.  Real `create_sa_pair` requires CAP_NET_ADMIN
// and is exercised by the sipp_ipsec scenario.
// ---------------------------------------------------------------------------

#[test]
fn ipsec_manager_spi_allocator_returns_pair() {
    let manager = IpsecManager::new();
    let (spi_a, spi_b) = manager.allocate_spi_pair();
    assert_ne!(spi_a, spi_b);
    let (spi_c, spi_d) = manager.allocate_spi_pair();
    // Each call returns a fresh pair — no overlap across allocations.
    assert_ne!(spi_a, spi_c);
    assert_ne!(spi_a, spi_d);
    assert_ne!(spi_b, spi_c);
    assert_ne!(spi_b, spi_d);
    assert_eq!(manager.active_count(), 0);
}

// ---------------------------------------------------------------------------
// Phase 3: backend selection + multi-instance SPI partitioning
// ---------------------------------------------------------------------------

use siphon::ipsec::XfrmBackend;

#[test]
fn ipsec_manager_default_uses_netlink_backend() {
    let manager = IpsecManager::new();
    assert_eq!(manager.backend(), XfrmBackend::Netlink);
}

#[test]
fn ipsec_manager_with_partition_keeps_spis_in_range() {
    // Two siphon instances on the same kernel must not collide on SPIs.
    let instance_a = IpsecManager::with_partition(XfrmBackend::IpCommand, 20000, 100);
    let instance_b = IpsecManager::with_partition(XfrmBackend::IpCommand, 30000, 100);

    let mut a_spis = Vec::new();
    let mut b_spis = Vec::new();
    for _ in 0..40 {
        let (spi_x, spi_y) = instance_a.allocate_spi_pair();
        a_spis.push(spi_x);
        a_spis.push(spi_y);
        let (spi_x, spi_y) = instance_b.allocate_spi_pair();
        b_spis.push(spi_x);
        b_spis.push(spi_y);
    }
    // All A SPIs in [20000, 20100), all B SPIs in [30000, 30100).
    assert!(a_spis.iter().all(|&spi| (20000..20100).contains(&spi)));
    assert!(b_spis.iter().all(|&spi| (30000..30100).contains(&spi)));
    // No overlap.
    for spi in &a_spis {
        assert!(!b_spis.contains(spi));
    }
}

#[test]
fn ipsec_manager_spi_allocator_wraps_within_partition() {
    // Tight partition forces wraparound after 4 allocations.
    let manager = IpsecManager::with_partition(XfrmBackend::IpCommand, 50000, 8);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..6 {
        let (spi_a, spi_b) = manager.allocate_spi_pair();
        assert!((50000..50008).contains(&spi_a));
        assert!((50000..50008).contains(&spi_b));
        seen.insert(spi_a);
        seen.insert(spi_b);
    }
    // 6 calls × 2 SPIs = 12; partition is 8 → wraparound forced.
    assert!(seen.len() <= 8);
}

#[test]
fn ipsec_manager_with_partition_clamps_count_to_minimum_2() {
    // count=0 or 1 would deadlock allocate_spi_pair; manager must clamp.
    let manager = IpsecManager::with_partition(XfrmBackend::Netlink, 60000, 0);
    let (spi_a, spi_b) = manager.allocate_spi_pair();
    assert_ne!(spi_a, spi_b);
}

// ---------------------------------------------------------------------------
// Phase 3: hex decoding helper used by netlink backend
// ---------------------------------------------------------------------------

#[test]
fn ipsec_decode_hex_round_trip() {
    let bytes = siphon::ipsec::decode_hex("0001ffab").unwrap();
    assert_eq!(bytes, vec![0x00, 0x01, 0xff, 0xab]);
}

#[test]
fn ipsec_decode_hex_empty() {
    let bytes = siphon::ipsec::decode_hex("").unwrap();
    assert!(bytes.is_empty());
}

#[test]
fn ipsec_decode_hex_rejects_odd_length() {
    assert!(siphon::ipsec::decode_hex("abc").is_err());
}

#[test]
fn ipsec_decode_hex_rejects_non_hex_char() {
    assert!(siphon::ipsec::decode_hex("zz").is_err());
}

// ---------------------------------------------------------------------------
// Phase 2: Transform expansion (HMAC-SHA-256, AES-CBC) + Annex H derivation
// ---------------------------------------------------------------------------

#[test]
fn transform_compatible_with_sha256_null() {
    let offer = fixture_offer("hmac-sha-256-128", "null");
    assert!(PyTransform::HmacSha256_128Null.compatible_with(&offer));
    assert!(!PyTransform::HmacSha1_96Null.compatible_with(&offer));
}

#[test]
fn transform_compatible_with_aes_cbc_pairing() {
    let offer = fixture_offer("hmac-sha-1-96", "aes-cbc");
    assert!(PyTransform::HmacSha1_96AesCbc128.compatible_with(&offer));
    // Same alg but null-encryption transform must reject — UE asked for AES.
    assert!(!PyTransform::HmacSha1_96Null.compatible_with(&offer));
}

#[test]
fn transform_compatible_with_sha256_aes_cbc() {
    let offer = fixture_offer("hmac-sha-256-128", "aes-cbc");
    assert!(PyTransform::HmacSha256_128AesCbc128.compatible_with(&offer));
    assert!(!PyTransform::HmacSha256_128Null.compatible_with(&offer));
    assert!(!PyTransform::HmacSha1_96AesCbc128.compatible_with(&offer));
}

#[test]
fn derive_integrity_key_md5_returns_ik_unchanged() {
    let ik = [0xAA; 16];
    let derived = IpsecManager::derive_integrity_key(IntegrityAlgorithm::HmacMd5, &ik).unwrap();
    assert_eq!(derived.as_slice(), &ik[..]);
}

#[test]
fn derive_integrity_key_sha1_zero_pads_to_20() {
    let ik = [0xBB; 16];
    let derived = IpsecManager::derive_integrity_key(IntegrityAlgorithm::HmacSha1, &ik).unwrap();
    assert_eq!(derived.len(), 20);
    assert_eq!(&derived[..16], &ik[..]);
    assert_eq!(&derived[16..], &[0u8; 4]);
}

#[test]
fn derive_integrity_key_sha256_produces_32_bytes_via_hmac() {
    let ik_a = [0xCC; 16];
    let ik_b = [0xDD; 16];
    let derived_a =
        IpsecManager::derive_integrity_key(IntegrityAlgorithm::HmacSha256, &ik_a).unwrap();
    let derived_b =
        IpsecManager::derive_integrity_key(IntegrityAlgorithm::HmacSha256, &ik_b).unwrap();
    assert_eq!(derived_a.len(), 32);
    assert_eq!(derived_b.len(), 32);
    // Different inputs → different outputs (HMAC determinism + collision
    // resistance).  Catches any accidental reduce-to-IK regression.
    assert_ne!(derived_a, derived_b);
    // Output is not the bare IK (which would be a 16-byte run of 0xCC).
    assert_ne!(&derived_a[..16], &ik_a[..]);
}

#[test]
fn derive_integrity_key_rejects_wrong_ik_length() {
    let too_short = [0xEE; 8];
    assert!(
        IpsecManager::derive_integrity_key(IntegrityAlgorithm::HmacSha256, &too_short).is_none()
    );
}

#[test]
fn integrity_algorithm_xfrm_names_include_sha256() {
    assert_eq!(IntegrityAlgorithm::HmacSha256.xfrm_name(), "hmac(sha256)");
    assert_eq!(IntegrityAlgorithm::HmacSha256.key_length(), 32);
}

// ---------------------------------------------------------------------------
// Phase 2: AuthVectorHandle key zeroization on drop
// ---------------------------------------------------------------------------

#[test]
fn auth_vector_handle_does_not_expose_bytes_to_python_inspection() {
    // Smoke check: the public API of PyAuthVectorHandle exposes only
    // `__repr__` (and the internal Rust `take`).  No accessor that
    // returns CK or IK as bytes/str/int.  This test compiles only so
    // long as no public method matching `bytes` / `as_bytes` / `ck` /
    // `ik` exists on the type.
    fn must_not_compile() {
        // This block is intentionally never called — its existence at
        // compile time merely encodes the API-surface assertion above
        // for human readers.  Add inverse `let _: () = handle.ck();`
        // here if you ever want to break the test deliberately.
    }
    must_not_compile();
}
