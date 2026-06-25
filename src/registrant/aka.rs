//! UE-side IMS AKA glue for the outbound registrant (RFC 3310 / 3GPP TS 33.203).
//!
//! When the registrant authenticates *into* an IMS core as a handset, the
//! 401 challenge carries `algorithm=AKAv1-MD5` with `nonce = base64(RAND ‖
//! AUTN ‖ …)`. The UE:
//!
//! 1. splits the nonce into RAND and AUTN ([`decode_aka_nonce`]);
//! 2. runs Milenage to authenticate the network (verify MAC), recover the
//!    sequence number, and derive RES/CK/IK ([`aka_challenge`]);
//! 3. on a fresh, in-range SQN, returns RES (the digest "password", see
//!    [`crate::auth::compute_aka_response`]) plus CK/IK for the IPsec SAs;
//! 4. on an out-of-range SQN, returns an AUTS re-synchronisation token so the
//!    registrar of record re-bases its sequence counter (TS 33.102 §6.3.3).
//!
//! This module is pure (no I/O, no shared state): the caller owns the stored
//! sequence number `SQN_MS` and passes it in / stores the new value out.

use base64::Engine as _;
use thiserror::Error;

use crate::ipsec::milenage::{compute_auts, compute_opc, f1, f2345, hex_to_bytes};

/// Standard base64 alphabet with padding — RFC 3310 §3.2 encodes the AKA
/// nonce (and the UE's AUTS) with the standard alphabet, not base64url.
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Errors building [`AkaCredentials`] from configured hex strings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AkaConfigError {
    #[error("{field} is not valid hex")]
    InvalidHex { field: &'static str },
    #[error("{field} must be {expected} bytes ({} hex chars), got {got}", expected * 2)]
    WrongLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
    #[error("AKA credentials need exactly one of `op` or `opc`")]
    MissingOperatorKey,
}

/// Parsed per-subscriber IMS AKA credentials (the USIM secrets).
#[derive(Debug, Clone)]
pub struct AkaCredentials {
    /// Subscriber key K (128-bit).
    pub k: [u8; 16],
    /// Operator variant OPc (128-bit), either configured directly or derived
    /// from OP via `OPc = E_K(OP) XOR OP`.
    pub opc: [u8; 16],
    /// Authentication Management Field (16-bit). Used only as an input to the
    /// XMAC the UE computes to authenticate the network.
    pub amf: [u8; 2],
}

impl AkaCredentials {
    /// Build from configured hex strings.
    ///
    /// Exactly one of `op_hex` / `opc_hex` must be `Some` — `opc_hex` is taken
    /// verbatim, `op_hex` is run through [`compute_opc`] with K. `amf_hex`
    /// defaults to `"8000"` when empty (the common VoLTE AMF).
    pub fn from_hex(
        k_hex: &str,
        op_hex: Option<&str>,
        opc_hex: Option<&str>,
        amf_hex: &str,
    ) -> Result<Self, AkaConfigError> {
        let k = parse_fixed::<16>(k_hex, "k")?;
        let amf_source = if amf_hex.is_empty() { "8000" } else { amf_hex };
        let amf = parse_fixed::<2>(amf_source, "amf")?;

        let opc = match (opc_hex, op_hex) {
            (Some(opc_hex), _) => parse_fixed::<16>(opc_hex, "opc")?,
            (None, Some(op_hex)) => {
                let op = parse_fixed::<16>(op_hex, "op")?;
                compute_opc(&k, &op)
            }
            (None, None) => return Err(AkaConfigError::MissingOperatorKey),
        };

        Ok(Self { k, opc, amf })
    }
}

/// Outcome of authenticating a network AKA challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkaOutcome {
    /// Network authenticated and SQN was in range. `res` is the digest
    /// password (RFC 3310), `ck`/`ik` seed the IPsec SAs, and `sqn` is the
    /// freshly accepted sequence number the caller should store as the new
    /// `SQN_MS`.
    Success {
        res: Vec<u8>,
        ck: [u8; 16],
        ik: [u8; 16],
        sqn: [u8; 6],
    },
    /// MAC verified but SQN was out of range — emit `auts` (base64) in the
    /// next REGISTER's Authorization to force HSS re-synchronisation.
    SyncFailure { auts: [u8; 14] },
    /// AUTN MAC did not verify — the challenge is not from a trusted network
    /// (wrong K/OPc, or a forged/altered AUTN). Abort, do not resync.
    MacFailure,
}

/// Split an AKAv1-MD5 `nonce` into its RAND and AUTN components.
///
/// The nonce is `base64(RAND[16] ‖ AUTN[16] ‖ server-specific-data)`
/// (RFC 3310 §3.2); any trailing server data after the first 32 octets is
/// ignored. Returns `None` if the value isn't valid base64 or is too short.
pub fn decode_aka_nonce(nonce: &str) -> Option<([u8; 16], [u8; 16])> {
    let bytes = B64.decode(nonce.as_bytes()).ok()?;
    if bytes.len() < 32 {
        return None;
    }
    let mut rand = [0u8; 16];
    let mut autn = [0u8; 16];
    rand.copy_from_slice(&bytes[0..16]);
    autn.copy_from_slice(&bytes[16..32]);
    Some((rand, autn))
}

/// Authenticate a network AKA challenge and derive the UE's response.
///
/// `sqn_ms` is the UE's stored sequence number; a challenge is considered
/// fresh when its recovered SQN is strictly greater (a single soft-UE sees a
/// monotonically increasing HSS sequence, so the full-48-bit comparison is
/// sufficient — this does not implement the per-index window of TS 33.102
/// Annex C, which only matters for USIMs shared across many auth contexts).
pub fn aka_challenge(
    credentials: &AkaCredentials,
    rand: &[u8; 16],
    autn: &[u8; 16],
    sqn_ms: &[u8; 6],
) -> AkaOutcome {
    let (res, ck, ik, ak) = f2345(&credentials.k, &credentials.opc, rand);

    // Recover SQN = (SQN XOR AK) XOR AK from AUTN, and read the AMF the network
    // used — both feed the XMAC, so a mismatch in either fails authentication.
    let mut sqn = [0u8; 6];
    for index in 0..6 {
        sqn[index] = autn[index] ^ ak[index];
    }
    let mut amf = [0u8; 2];
    amf.copy_from_slice(&autn[6..8]);

    let expected_mac = f1(&credentials.k, &credentials.opc, rand, &sqn, &amf);
    if expected_mac != autn[8..16] {
        return AkaOutcome::MacFailure;
    }

    if sqn_to_u64(&sqn) > sqn_to_u64(sqn_ms) {
        AkaOutcome::Success { res, ck, ik, sqn }
    } else {
        let auts = compute_auts(&credentials.k, &credentials.opc, rand, sqn_ms);
        AkaOutcome::SyncFailure { auts }
    }
}

/// Base64-encode an AUTS token for the `auts=` Authorization parameter.
pub fn encode_auts(auts: &[u8; 14]) -> String {
    B64.encode(auts)
}

/// Interpret a 48-bit big-endian SQN as a `u64` for ordering comparisons.
fn sqn_to_u64(sqn: &[u8; 6]) -> u64 {
    let mut value = 0u64;
    for byte in sqn {
        value = (value << 8) | (*byte as u64);
    }
    value
}

/// Parse a hex string into a fixed-size byte array with field-aware errors.
fn parse_fixed<const N: usize>(hex: &str, field: &'static str) -> Result<[u8; N], AkaConfigError> {
    let bytes = hex_to_bytes(hex).ok_or(AkaConfigError::InvalidHex { field })?;
    if bytes.len() != N {
        return Err(AkaConfigError::WrongLength {
            field,
            expected: N,
            got: bytes.len(),
        });
    }
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipsec::milenage::{f5star, generate_vector_with_rand};

    // 3GPP TS 35.208 Test Set 1.
    const K_HEX: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const OP_HEX: &str = "cdc202d5123e20f62b6d676ac72cb318";
    const OPC_HEX: &str = "cd63cb71954a9f4e48a5994e37a02baf";
    const RAND_HEX: &str = "23553cbe9637a89d218ae64dae47bf35";
    const AMF_HEX: &str = "b9b9";

    fn array<const N: usize>(hex: &str) -> [u8; N] {
        let bytes = hex_to_bytes(hex).expect("valid hex");
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        out
    }

    fn test_credentials() -> AkaCredentials {
        AkaCredentials::from_hex(K_HEX, None, Some(OPC_HEX), AMF_HEX).unwrap()
    }

    #[test]
    fn credentials_from_op_computes_opc() {
        let from_op = AkaCredentials::from_hex(K_HEX, Some(OP_HEX), None, AMF_HEX).unwrap();
        assert_eq!(from_op.opc, array::<16>(OPC_HEX));
    }

    #[test]
    fn credentials_from_opc_used_directly() {
        let creds = AkaCredentials::from_hex(K_HEX, None, Some(OPC_HEX), AMF_HEX).unwrap();
        assert_eq!(creds.opc, array::<16>(OPC_HEX));
        assert_eq!(creds.amf, array::<2>(AMF_HEX));
    }

    #[test]
    fn credentials_amf_defaults_to_8000() {
        let creds = AkaCredentials::from_hex(K_HEX, None, Some(OPC_HEX), "").unwrap();
        assert_eq!(creds.amf, [0x80, 0x00]);
    }

    #[test]
    fn credentials_require_operator_key() {
        let result = AkaCredentials::from_hex(K_HEX, None, None, AMF_HEX);
        assert_eq!(result.unwrap_err(), AkaConfigError::MissingOperatorKey);
    }

    #[test]
    fn credentials_reject_wrong_length_k() {
        let result = AkaCredentials::from_hex("465b5ce8", None, Some(OPC_HEX), AMF_HEX);
        assert!(matches!(
            result,
            Err(AkaConfigError::WrongLength { field: "k", .. })
        ));
    }

    #[test]
    fn credentials_reject_invalid_hex() {
        let result = AkaCredentials::from_hex("zz", None, Some(OPC_HEX), AMF_HEX);
        assert_eq!(result.unwrap_err(), AkaConfigError::InvalidHex { field: "k" });
    }

    #[test]
    fn decode_nonce_splits_rand_and_autn() {
        let rand = array::<16>(RAND_HEX);
        let autn = array::<16>("ff9bb4d0b6079b9b4a9ffac354dfafb3");
        let mut joined = Vec::new();
        joined.extend_from_slice(&rand);
        joined.extend_from_slice(&autn);
        let nonce = B64.encode(&joined);

        let (got_rand, got_autn) = decode_aka_nonce(&nonce).unwrap();
        assert_eq!(got_rand, rand);
        assert_eq!(got_autn, autn);
    }

    #[test]
    fn decode_nonce_ignores_trailing_server_data() {
        let rand = array::<16>(RAND_HEX);
        let autn = array::<16>("ff9bb4d0b6079b9b4a9ffac354dfafb3");
        let mut joined = Vec::new();
        joined.extend_from_slice(&rand);
        joined.extend_from_slice(&autn);
        joined.extend_from_slice(b"server-specific-extra"); // RFC 3310 §3.2 allows this
        let nonce = B64.encode(&joined);

        let (got_rand, got_autn) = decode_aka_nonce(&nonce).unwrap();
        assert_eq!(got_rand, rand);
        assert_eq!(got_autn, autn);
    }

    #[test]
    fn decode_nonce_rejects_short_input() {
        let nonce = B64.encode([0u8; 20]);
        assert!(decode_aka_nonce(&nonce).is_none());
    }

    #[test]
    fn decode_nonce_rejects_non_base64() {
        assert!(decode_aka_nonce("not valid base64 @@@@").is_none());
    }

    /// A correctly-formed network challenge with a fresh SQN authenticates and
    /// yields the same RES/CK/IK the network expects (XRES from the AV).
    #[test]
    fn challenge_success_returns_res_and_keys() {
        let key = array::<16>(K_HEX);
        let op = array::<16>(OP_HEX);
        let sqn = array::<6>("ff9bb4d0b607");
        let amf = array::<2>(AMF_HEX);
        let rand = array::<16>(RAND_HEX);
        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);

        let creds = test_credentials();
        // Stored SQN_MS well below the challenge SQN → fresh.
        let outcome = aka_challenge(&creds, &vector.rand, &vector.autn, &[0u8; 6]);
        match outcome {
            AkaOutcome::Success { res, ck, ik, sqn: accepted } => {
                assert_eq!(res, vector.xres);
                assert_eq!(ck, vector.ck);
                assert_eq!(ik, vector.ik);
                assert_eq!(accepted, sqn);
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    /// A tampered MAC (or wrong K/OPc) must fail authentication outright — not
    /// be mistaken for a sequence-number problem.
    #[test]
    fn challenge_mac_failure_on_tampered_autn() {
        let key = array::<16>(K_HEX);
        let op = array::<16>(OP_HEX);
        let sqn = array::<6>("ff9bb4d0b607");
        let amf = array::<2>(AMF_HEX);
        let rand = array::<16>(RAND_HEX);
        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);

        let mut autn = vector.autn;
        autn[8] ^= 0xff; // corrupt the MAC region

        let creds = test_credentials();
        assert_eq!(
            aka_challenge(&creds, &vector.rand, &autn, &[0u8; 6]),
            AkaOutcome::MacFailure
        );
    }

    /// MAC verifies but the stored SQN is ahead of the challenge → emit AUTS,
    /// and the SQN_MS recoverable from AUTS matches what the UE has stored.
    #[test]
    fn challenge_sync_failure_emits_recoverable_auts() {
        let key = array::<16>(K_HEX);
        let op = array::<16>(OP_HEX);
        let challenge_sqn = array::<6>("000000000005");
        let amf = array::<2>(AMF_HEX);
        let rand = array::<16>(RAND_HEX);
        let vector = generate_vector_with_rand(&key, &op, &challenge_sqn, &amf, &rand);

        let creds = test_credentials();
        let sqn_ms = array::<6>("000000000010"); // ahead of the challenge

        match aka_challenge(&creds, &vector.rand, &vector.autn, &sqn_ms) {
            AkaOutcome::SyncFailure { auts } => {
                // HSS recovers SQN_MS = AUTS[0..6] XOR AK*.
                let ak_star = f5star(&creds.k, &creds.opc, &vector.rand);
                let mut recovered = [0u8; 6];
                for index in 0..6 {
                    recovered[index] = auts[index] ^ ak_star[index];
                }
                assert_eq!(recovered, sqn_ms);
            }
            other => panic!("expected SyncFailure, got {other:?}"),
        }
    }

    #[test]
    fn equal_sqn_is_not_fresh() {
        // SQN_HE == SQN_MS must be treated as a replay → SyncFailure.
        let key = array::<16>(K_HEX);
        let op = array::<16>(OP_HEX);
        let sqn = array::<6>("000000000007");
        let amf = array::<2>(AMF_HEX);
        let rand = array::<16>(RAND_HEX);
        let vector = generate_vector_with_rand(&key, &op, &sqn, &amf, &rand);

        let creds = test_credentials();
        assert!(matches!(
            aka_challenge(&creds, &vector.rand, &vector.autn, &sqn),
            AkaOutcome::SyncFailure { .. }
        ));
    }

    #[test]
    fn encode_auts_roundtrips_through_base64() {
        let auts: [u8; 14] = array::<14>("0102030405060708090a0b0c0d0e");
        let encoded = encode_auts(&auts);
        let decoded = B64.decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, auts);
    }
}
