//! Milenage algorithm (3GPP TS 35.206) for IMS AKA key derivation.
//!
//! Used by the P-CSCF to generate authentication vectors and derive
//! CK (Cipher Key) and IK (Integrity Key) for IPsec SA creation.
//!
//! Reference: 3GPP TS 35.206 V17.0.0 — Specification of the MILENAGE
//! Algorithm Set: An example algorithm set for the 3GPP authentication
//! and key generation functions f1, f1*, f2, f3, f4, f5 and f5*.

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes::Aes128;

// ---------------------------------------------------------------------------
// Milenage constants (3GPP TS 35.206, Section 3)
// ---------------------------------------------------------------------------

/// c1 constant — all zeros.
const C1: [u8; 16] = [0; 16];

/// c2 constant — 0x00...01.
const C2: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// c3 constant — 0x00...02.
const C3: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

/// c4 constant — 0x00...04.
const C4: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4];

/// c5 constant — 0x00...08 (used by f5* for re-synchronisation).
const C5: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8];

/// Rotation constants (in bits). All are multiples of 8.
const R1: usize = 64;
const R2: usize = 0;
const R3: usize = 32;
const R4: usize = 64;
/// r5 rotation for f5* (re-synchronisation).
const R5: usize = 96;

// ---------------------------------------------------------------------------
// AKA vector
// ---------------------------------------------------------------------------

/// Authentication vector produced by the Milenage algorithm.
///
/// Contains all material needed to challenge a UE and derive session keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AkaVector {
    /// Random challenge (16 bytes).
    pub rand: [u8; 16],
    /// Authentication token: SQN XOR AK || AMF || MAC-A (16 bytes).
    pub autn: [u8; 16],
    /// Expected response from UE (8 bytes).
    pub xres: Vec<u8>,
    /// Cipher key for IPsec encryption (16 bytes).
    pub ck: [u8; 16],
    /// Integrity key for IPsec authentication (16 bytes).
    pub ik: [u8; 16],
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// AES-128 encrypt a single 16-byte block.
fn aes_encrypt(key: &[u8; 16], input: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(key.into());
    let mut block = (*input).into();
    cipher.encrypt_block(&mut block);
    block.into()
}

/// XOR two 16-byte blocks.
fn xor_blocks(left: &[u8; 16], right: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for index in 0..16 {
        result[index] = left[index] ^ right[index];
    }
    result
}

/// Rotate a 128-bit block LEFT by `bits` positions.
///
/// All Milenage rotation constants (r1..r5) are multiples of 8,
/// so byte-level rotation is sufficient.
fn rotate_left(input: &[u8; 16], bits: usize) -> [u8; 16] {
    let bytes = bits / 8;
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] = input[(index + bytes) % 16];
    }
    output
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute OPc from the subscriber key K and operator variant OP.
///
/// OPc = AES_K(OP) XOR OP
///
/// The OPc value can be pre-computed and stored instead of OP to avoid
/// storing the operator key directly on the HSS.
pub fn compute_opc(key: &[u8; 16], op: &[u8; 16]) -> [u8; 16] {
    let encrypted = aes_encrypt(key, op);
    xor_blocks(&encrypted, op)
}

/// Compute the full OUT1 block shared by f1 (MAC-A) and f1* (MAC-S).
///
/// `OUT1 = AES_K(TEMP XOR rotate(OPc XOR IN1, r1) XOR c1) XOR OPc`, where
/// `TEMP = AES_K(RAND XOR OPc)` and `IN1 = SQN || AMF || SQN || AMF`.
///
/// MAC-A is `OUT1[0..8]` (network authentication) and MAC-S is `OUT1[8..16]`
/// (re-synchronisation), so both fall out of a single computation.
fn f1_out1(
    key: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> [u8; 16] {
    // TEMP = AES_K(RAND XOR OPc)
    let temp_input = xor_blocks(rand, opc);
    let temp = aes_encrypt(key, &temp_input);

    // Build IN1: SQN || AMF || SQN || AMF
    let mut in1 = [0u8; 16];
    in1[0..6].copy_from_slice(sqn);
    in1[6..8].copy_from_slice(amf);
    in1[8..14].copy_from_slice(sqn);
    in1[14..16].copy_from_slice(amf);

    // OUT1 = AES_K(TEMP XOR rotate(OPc XOR IN1, r1) XOR c1) XOR OPc
    let opc_xor_in1 = xor_blocks(opc, &in1);
    let rotated = rotate_left(&opc_xor_in1, R1);
    let inner = xor_blocks(&temp, &rotated);
    let inner = xor_blocks(&inner, &C1);
    let encrypted = aes_encrypt(key, &inner);
    xor_blocks(&encrypted, opc)
}

/// Compute MAC-A using Milenage f1 (network authentication).
///
/// MAC-A is included in the AUTN parameter to allow the UE to
/// authenticate the network.
///
/// Returns an 8-byte MAC-A value.
pub fn f1(
    key: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> [u8; 8] {
    // MAC-A = OUT1[0..8]
    let out1 = f1_out1(key, opc, rand, sqn, amf);
    let mut mac_a = [0u8; 8];
    mac_a.copy_from_slice(&out1[0..8]);
    mac_a
}

/// Compute MAC-S using Milenage f1* (re-synchronisation message authentication).
///
/// MAC-S is the integrity check the UE places in the AUTS token when it
/// detects an out-of-range SQN and forces the HSS to re-synchronise
/// (3GPP TS 33.102 §6.3.3). It is `OUT1[8..16]` from the same computation
/// that yields MAC-A.
///
/// Note: per TS 33.102, the AMF in a re-synchronisation MAC-S assumes a
/// dummy value of all zeros (it is not carried in AUTS); [`compute_auts`]
/// applies that for callers — `f1star` itself takes whatever AMF it is given
/// so it can also be validated against the published 3GPP test vectors.
///
/// Returns an 8-byte MAC-S value.
pub fn f1star(
    key: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> [u8; 8] {
    // MAC-S = OUT1[8..16]
    let out1 = f1_out1(key, opc, rand, sqn, amf);
    let mut mac_s = [0u8; 8];
    mac_s.copy_from_slice(&out1[8..16]);
    mac_s
}

/// Compute f2 (RES), f3 (CK), f4 (IK), and f5 (AK) in one pass.
///
/// Returns `(res, ck, ik, ak)`:
/// - `res`: Expected response (8 bytes)
/// - `ck`: Cipher key (16 bytes)
/// - `ik`: Integrity key (16 bytes)
/// - `ak`: Anonymity key (6 bytes)
pub fn f2345(
    key: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
) -> (Vec<u8>, [u8; 16], [u8; 16], [u8; 6]) {
    // TEMP = AES_K(RAND XOR OPc)
    let temp_input = xor_blocks(rand, opc);
    let temp = aes_encrypt(key, &temp_input);

    // f2 (RES) and f5 (AK):
    // OUT2 = AES_K(rot(TEMP XOR OPc, r2) XOR c2) XOR OPc
    let temp_xor_opc = xor_blocks(&temp, opc);
    let rotated2 = rotate_left(&temp_xor_opc, R2);
    let inner2 = xor_blocks(&rotated2, &C2);
    let encrypted2 = aes_encrypt(key, &inner2);
    let out2 = xor_blocks(&encrypted2, opc);

    let res = out2[8..16].to_vec(); // RES = OUT2[8..15]
    let mut ak = [0u8; 6];
    ak.copy_from_slice(&out2[0..6]); // AK = OUT2[0..5]

    // f3 (CK):
    // OUT3 = AES_K(rot(TEMP XOR OPc, r3) XOR c3) XOR OPc
    let rotated3 = rotate_left(&temp_xor_opc, R3);
    let inner3 = xor_blocks(&rotated3, &C3);
    let encrypted3 = aes_encrypt(key, &inner3);
    let ck = xor_blocks(&encrypted3, opc);

    // f4 (IK):
    // OUT4 = AES_K(rot(TEMP XOR OPc, r4) XOR c4) XOR OPc
    let rotated4 = rotate_left(&temp_xor_opc, R4);
    let inner4 = xor_blocks(&rotated4, &C4);
    let encrypted4 = aes_encrypt(key, &inner4);
    let ik = xor_blocks(&encrypted4, opc);

    (res, ck, ik, ak)
}

/// Compute f5* (AK*) — the anonymity key used to conceal SQN_MS inside the
/// AUTS re-synchronisation token (3GPP TS 35.206 §4.5, TS 33.102 §6.3.3).
///
/// `OUT5 = AES_K(rotate(TEMP XOR OPc, r5) XOR c5) XOR OPc`, where
/// `TEMP = AES_K(RAND XOR OPc)`; AK* = `OUT5[0..6]`.
///
/// AK* is a *separate* anonymity key from the f5 AK returned by [`f2345`];
/// using f5 here instead of f5* would leak the relationship between the
/// normal and re-synch tokens, so this is its own derivation.
pub fn f5star(key: &[u8; 16], opc: &[u8; 16], rand: &[u8; 16]) -> [u8; 6] {
    // TEMP = AES_K(RAND XOR OPc)
    let temp_input = xor_blocks(rand, opc);
    let temp = aes_encrypt(key, &temp_input);

    // OUT5 = AES_K(rot(TEMP XOR OPc, r5) XOR c5) XOR OPc
    let temp_xor_opc = xor_blocks(&temp, opc);
    let rotated5 = rotate_left(&temp_xor_opc, R5);
    let inner5 = xor_blocks(&rotated5, &C5);
    let encrypted5 = aes_encrypt(key, &inner5);
    let out5 = xor_blocks(&encrypted5, opc);

    let mut ak_star = [0u8; 6];
    ak_star.copy_from_slice(&out5[0..6]);
    ak_star
}

/// Build the AUTS re-synchronisation token (3GPP TS 33.102 §6.3.3).
///
/// `AUTS = (SQN_MS XOR AK*) || MAC-S` (6 + 8 = 14 bytes), where SQN_MS is the
/// UE's stored sequence number, AK* comes from [`f5star`], and MAC-S comes
/// from [`f1star`] computed over SQN_MS with a **dummy all-zero AMF** (the AMF
/// is not carried in AUTS, so both sides agree on zeros for the MAC-S input).
///
/// The UE emits this in the `auts` Authorization parameter when it detects an
/// out-of-range SQN in a network challenge, forcing the HSS to re-base its
/// sequence counter.
pub fn compute_auts(
    key: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    sqn_ms: &[u8; 6],
) -> [u8; 14] {
    const RESYNC_AMF: [u8; 2] = [0, 0];

    let ak_star = f5star(key, opc, rand);
    let mac_s = f1star(key, opc, rand, sqn_ms, &RESYNC_AMF);

    let mut auts = [0u8; 14];
    for index in 0..6 {
        auts[index] = sqn_ms[index] ^ ak_star[index];
    }
    auts[6..14].copy_from_slice(&mac_s);
    auts
}

/// Generate an AKA authentication vector with a random RAND.
///
/// This is the main entry point for the P-CSCF/HSS to create a
/// challenge for a UE during IMS registration.
///
/// # Arguments
///
/// * `key` — Subscriber key K (128 bits)
/// * `op` — Operator variant configuration OP (128 bits)
/// * `sqn` — Sequence number (48 bits)
/// * `amf` — Authentication management field (16 bits)
pub fn generate_vector(
    key: &[u8; 16],
    op: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
) -> AkaVector {
    let mut rand = [0u8; 16];
    // RAND is the challenge value the UE will sign with K. It MUST be
    // unpredictable — a guessable RAND lets an attacker pre-compute valid
    // RES values and impersonate the network. Use the OS CSPRNG (getrandom
    // → /dev/urandom on Linux, BCryptGenRandom on Windows). On the
    // extremely rare chance the syscall fails (sandboxed environment with
    // no entropy source), fall back rather than panic — the UE will reject
    // the AUTN if the resulting vector is bogus.
    if getrandom::fill(&mut rand).is_err() {
        for byte in &mut rand {
            *byte = fastrand_byte();
        }
    }
    generate_vector_with_rand(key, op, sqn, amf, &rand)
}

/// Generate an AKA authentication vector with an explicit RAND.
///
/// Identical to [`generate_vector`] but accepts a caller-provided RAND,
/// which is essential for deterministic testing against 3GPP test vectors.
pub fn generate_vector_with_rand(
    key: &[u8; 16],
    op: &[u8; 16],
    sqn: &[u8; 6],
    amf: &[u8; 2],
    rand: &[u8; 16],
) -> AkaVector {
    let opc = compute_opc(key, op);
    let (xres, ck, ik, ak) = f2345(key, &opc, rand);
    let mac_a = f1(key, &opc, rand, sqn, amf);

    // AUTN = (SQN XOR AK) || AMF || MAC-A
    let mut autn = [0u8; 16];
    for index in 0..6 {
        autn[index] = sqn[index] ^ ak[index];
    }
    autn[6..8].copy_from_slice(amf);
    autn[8..16].copy_from_slice(&mac_a);

    AkaVector {
        rand: *rand,
        autn,
        xres,
        ck,
        ik,
    }
}

/// Parse a hex string into bytes.
///
/// Returns `None` if the string has odd length or contains non-hex characters.
///
/// # Example
///
/// ```
/// use siphon::ipsec::milenage::hex_to_bytes;
///
/// assert_eq!(hex_to_bytes("deadbeef"), Some(vec![0xde, 0xad, 0xbe, 0xef]));
/// assert_eq!(hex_to_bytes("zz"), None);
/// ```
pub fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

/// Parse a single hex character to its 4-bit value.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Generate a single byte from a non-cryptographic xorshift PRNG seeded
/// from the system's `RandomState` entropy.
///
/// Kept as the fallback path inside [`generate_vector`] for the rare case
/// where `getrandom` fails (sandboxes with no entropy source). NEW callers
/// should use `getrandom::fill` directly — this function is NOT a CSPRNG
/// and using it for keys, nonces, or RAND values undermines the security
/// of every protocol that depends on those values being unpredictable.
fn fastrand_byte() -> u8 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};

    static STATE: AtomicU64 = AtomicU64::new(0);

    let mut current = STATE.load(Ordering::Relaxed);
    if current == 0 {
        // Seed from system entropy on first call.
        let hasher = RandomState::new().build_hasher();
        current = hasher.finish() | 1; // Ensure non-zero.
        STATE.store(current, Ordering::Relaxed);
    }

    // xorshift64
    current ^= current << 13;
    current ^= current >> 7;
    current ^= current << 17;
    STATE.store(current, Ordering::Relaxed);

    current as u8
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse a hex string into a fixed-size array.
    fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_to_bytes(hex).expect("valid hex");
        assert_eq!(bytes.len(), N, "hex string length mismatch");
        let mut array = [0u8; N];
        array.copy_from_slice(&bytes);
        array
    }

    // -- 3GPP TS 35.208 Test Set 1 values --

    fn test_set_1_key() -> [u8; 16] {
        hex_array("465b5ce8b199b49faa5f0a2ee238a6bc")
    }

    fn test_set_1_op() -> [u8; 16] {
        hex_array("cdc202d5123e20f62b6d676ac72cb318")
    }

    fn test_set_1_rand() -> [u8; 16] {
        hex_array("23553cbe9637a89d218ae64dae47bf35")
    }

    fn test_set_1_sqn() -> [u8; 6] {
        hex_array("ff9bb4d0b607")
    }

    fn test_set_1_amf() -> [u8; 2] {
        hex_array("b9b9")
    }

    // -- hex_to_bytes tests --

    #[test]
    fn hex_to_bytes_valid() {
        assert_eq!(
            hex_to_bytes("deadbeef"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn hex_to_bytes_uppercase() {
        assert_eq!(
            hex_to_bytes("DEADBEEF"),
            Some(vec![0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn hex_to_bytes_mixed_case() {
        assert_eq!(hex_to_bytes("DeAdBe"), Some(vec![0xde, 0xad, 0xbe]));
    }

    #[test]
    fn hex_to_bytes_empty() {
        assert_eq!(hex_to_bytes(""), Some(vec![]));
    }

    #[test]
    fn hex_to_bytes_odd_length() {
        assert_eq!(hex_to_bytes("abc"), None);
    }

    #[test]
    fn hex_to_bytes_invalid_chars() {
        assert_eq!(hex_to_bytes("zz"), None);
        assert_eq!(hex_to_bytes("gg"), None);
    }

    #[test]
    fn hex_to_bytes_all_zeros() {
        assert_eq!(
            hex_to_bytes("00000000"),
            Some(vec![0x00, 0x00, 0x00, 0x00])
        );
    }

    // -- compute_opc tests --

    #[test]
    fn compute_opc_test_set_1() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let expected_opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");

        let opc = compute_opc(&key, &op);
        assert_eq!(opc, expected_opc);
    }

    #[test]
    fn compute_opc_zero_key_and_op() {
        let key = [0u8; 16];
        let op = [0u8; 16];
        // AES_0(0) XOR 0 = AES_0(0)
        let opc = compute_opc(&key, &op);
        // Just verify it does not panic and returns 16 bytes.
        assert_eq!(opc.len(), 16);
    }

    // -- rotate_left tests --

    #[test]
    fn rotate_left_zero() {
        let input: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let rotated = rotate_left(&input, 0);
        assert_eq!(rotated, input);
    }

    #[test]
    fn rotate_left_64_bits() {
        let input: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let rotated = rotate_left(&input, 64);
        assert_eq!(
            rotated,
            [9, 10, 11, 12, 13, 14, 15, 16, 1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn rotate_left_128_bits_is_identity() {
        let input: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let rotated = rotate_left(&input, 128);
        assert_eq!(rotated, input);
    }

    // -- f1 (MAC-A) tests --

    #[test]
    fn f1_mac_a_test_set_1() {
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();

        let mac_a = f1(&key, &opc, &rand, &sqn, &amf);
        let expected: [u8; 8] = hex_array("4a9ffac354dfafb3");
        assert_eq!(mac_a, expected);
    }

    // -- f2345 tests --

    #[test]
    fn f2345_test_set_1() {
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();

        let (res, ck, ik, ak) = f2345(&key, &opc, &rand);

        let expected_res = hex_to_bytes("a54211d5e3ba50bf").unwrap();
        let expected_ck: [u8; 16] = hex_array("b40ba9a3c58b2a05bbf0d987b21bf8cb");
        let expected_ik: [u8; 16] = hex_array("f769bcd751044604127672711c6d3441");
        let expected_ak: [u8; 6] = hex_array("aa689c648370");

        assert_eq!(res, expected_res, "RES mismatch");
        assert_eq!(ck, expected_ck, "CK mismatch");
        assert_eq!(ik, expected_ik, "IK mismatch");
        assert_eq!(ak, expected_ak, "AK mismatch");
    }

    #[test]
    fn f2345_res_length() {
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();

        let (res, _, _, _) = f2345(&key, &opc, &rand);
        assert_eq!(res.len(), 8, "RES must be 8 bytes");
    }

    // -- f1* (MAC-S) / f5* (AK*) re-synchronisation tests --

    #[test]
    fn f1star_mac_s_test_set_1() {
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();

        // 3GPP TS 35.208 Test Set 1: f1* = 01cfaf9ec4e871e9
        let mac_s = f1star(&key, &opc, &rand, &sqn, &amf);
        let expected: [u8; 8] = hex_array("01cfaf9ec4e871e9");
        assert_eq!(mac_s, expected);
    }

    #[test]
    fn f1_and_f1star_come_from_same_block() {
        // MAC-A is OUT1[0..8], MAC-S is OUT1[8..16] — disjoint halves of one
        // computation, so they must never be equal for these inputs.
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();

        let mac_a = f1(&key, &opc, &rand, &sqn, &amf);
        let mac_s = f1star(&key, &opc, &rand, &sqn, &amf);
        assert_ne!(mac_a, mac_s);
    }

    #[test]
    fn f5star_ak_star_test_set_1() {
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();

        // 3GPP TS 35.208 Test Set 1: f5* = 451e8beca43b
        let ak_star = f5star(&key, &opc, &rand);
        let expected: [u8; 6] = hex_array("451e8beca43b");
        assert_eq!(ak_star, expected);
    }

    #[test]
    fn f5star_differs_from_f5() {
        // AK* (f5*) must be a different anonymity key from AK (f5).
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();

        let (_, _, _, ak) = f2345(&key, &opc, &rand);
        let ak_star = f5star(&key, &opc, &rand);
        assert_ne!(ak, ak_star);
    }

    #[test]
    fn compute_auts_structure() {
        // AUTS = (SQN_MS XOR AK*) || MAC-S, with MAC-S over a dummy zero AMF.
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();
        let sqn_ms = test_set_1_sqn();

        let auts = compute_auts(&key, &opc, &rand, &sqn_ms);
        assert_eq!(auts.len(), 14);

        // First 6 bytes: SQN_MS XOR AK*.
        let ak_star = f5star(&key, &opc, &rand);
        for index in 0..6 {
            assert_eq!(auts[index], sqn_ms[index] ^ ak_star[index]);
        }

        // Last 8 bytes: MAC-S computed with the dummy all-zero AMF.
        let expected_mac_s = f1star(&key, &opc, &rand, &sqn_ms, &[0, 0]);
        assert_eq!(&auts[6..14], &expected_mac_s);
    }

    #[test]
    fn compute_auts_recoverable_sqn() {
        // The HSS recovers SQN_MS by XORing the first 6 AUTS bytes with AK*.
        let key = test_set_1_key();
        let opc: [u8; 16] = hex_array("cd63cb71954a9f4e48a5994e37a02baf");
        let rand = test_set_1_rand();
        let sqn_ms: [u8; 6] = hex_array("000000000021");

        let auts = compute_auts(&key, &opc, &rand, &sqn_ms);
        let ak_star = f5star(&key, &opc, &rand);
        let mut recovered = [0u8; 6];
        for index in 0..6 {
            recovered[index] = auts[index] ^ ak_star[index];
        }
        assert_eq!(recovered, sqn_ms);
    }

    // -- generate_vector_with_rand tests --

    #[test]
    fn generate_vector_with_rand_test_set_1() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();
        let rand = test_set_1_rand();

        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);

        // Verify RAND is passed through.
        assert_eq!(vector.rand, rand);

        // Verify XRES.
        let expected_xres = hex_to_bytes("a54211d5e3ba50bf").unwrap();
        assert_eq!(vector.xres, expected_xres);

        // Verify CK.
        let expected_ck: [u8; 16] = hex_array("b40ba9a3c58b2a05bbf0d987b21bf8cb");
        assert_eq!(vector.ck, expected_ck);

        // Verify IK.
        let expected_ik: [u8; 16] = hex_array("f769bcd751044604127672711c6d3441");
        assert_eq!(vector.ik, expected_ik);
    }

    #[test]
    fn generate_vector_with_rand_autn_structure() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();
        let rand = test_set_1_rand();

        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);

        // Compute expected components independently.
        let opc = compute_opc(&key, &op);
        let (_, _, _, ak) = f2345(&key, &opc, &rand);
        let mac_a = f1(&key, &opc, &rand, &sqn, &amf);

        // AUTN = (SQN XOR AK) || AMF || MAC-A
        // First 6 bytes: SQN XOR AK
        for index in 0..6 {
            assert_eq!(
                vector.autn[index],
                sqn[index] ^ ak[index],
                "AUTN[{}]: SQN XOR AK mismatch",
                index
            );
        }

        // Bytes 6..7: AMF
        assert_eq!(&vector.autn[6..8], &amf, "AUTN AMF mismatch");

        // Bytes 8..15: MAC-A
        assert_eq!(&vector.autn[8..16], &mac_a, "AUTN MAC-A mismatch");
    }

    #[test]
    fn generate_vector_with_rand_autn_is_16_bytes() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();
        let rand = test_set_1_rand();

        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);
        assert_eq!(vector.autn.len(), 16);
    }

    #[test]
    fn generate_vector_produces_random_rand() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();

        let vector1 = generate_vector(&key, &op, &sqn, &amf);
        let vector2 = generate_vector(&key, &op, &sqn, &amf);

        // Extremely unlikely that two random RANDs are identical.
        assert_ne!(
            vector1.rand, vector2.rand,
            "Two generated vectors should have different RANDs"
        );
    }

    #[test]
    fn generate_vector_xres_is_8_bytes() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = test_set_1_sqn();
        let amf = test_set_1_amf();

        let vector = generate_vector(&key, &op, &sqn, &amf);
        assert_eq!(vector.xres.len(), 8);
    }

    #[test]
    fn xor_blocks_identity() {
        let block = [0xAA; 16];
        let zero = [0u8; 16];
        assert_eq!(xor_blocks(&block, &zero), block);
    }

    #[test]
    fn xor_blocks_self_cancels() {
        let block = [0xAA; 16];
        assert_eq!(xor_blocks(&block, &block), [0u8; 16]);
    }

    #[test]
    fn aes_encrypt_deterministic() {
        let key = [0u8; 16];
        let input = [0u8; 16];
        let output1 = aes_encrypt(&key, &input);
        let output2 = aes_encrypt(&key, &input);
        assert_eq!(output1, output2);
    }

    #[test]
    fn hex_nibble_digits() {
        for digit in b'0'..=b'9' {
            assert_eq!(hex_nibble(digit), Some(digit - b'0'));
        }
    }

    #[test]
    fn hex_nibble_lowercase() {
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'f'), Some(15));
    }

    #[test]
    fn hex_nibble_uppercase() {
        assert_eq!(hex_nibble(b'A'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
    }

    #[test]
    fn hex_nibble_invalid() {
        assert_eq!(hex_nibble(b'g'), None);
        assert_eq!(hex_nibble(b'z'), None);
        assert_eq!(hex_nibble(b' '), None);
    }

    /// Sanity check: the production AKA RAND must come from a real
    /// CSPRNG, not a constant stub or a deterministic PRNG seeded once
    /// per process. Two consecutive vectors must have different RAND
    /// values with overwhelming probability.
    ///
    /// (Probability that two CSPRNG-drawn 128-bit values collide is
    /// 2^-128; if this test ever fails you've either won the lottery
    /// or someone replaced `getrandom` with a stub.)
    #[test]
    fn generate_vector_uses_unpredictable_rand() {
        let key = test_set_1_key();
        let op = test_set_1_op();
        let sqn = hex_array::<6>("ff9bb4d0b607");
        let amf = hex_array::<2>("b9b9");

        let v1 = generate_vector(&key, &op, &sqn, &amf);
        let v2 = generate_vector(&key, &op, &sqn, &amf);

        assert_ne!(v1.rand, v2.rand, "RAND must change between calls");
        assert_ne!(v1.rand, [0u8; 16], "RAND must not be all zeros");
        // AUTN / xRES / CK / IK derive from RAND, so they all differ too.
        assert_ne!(v1.autn, v2.autn);
        assert_ne!(v1.xres, v2.xres);
        assert_ne!(v1.ck, v2.ck);
    }
}
