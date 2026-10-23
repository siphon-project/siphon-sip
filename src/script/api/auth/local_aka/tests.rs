//! Local AKA against siphon's own UE side (`registrant::aka`), which checks
//! SQN freshness and answers an out-of-range SQN with an AUTS. The Milenage
//! functions themselves are held to the TS 35.208 test sets in
//! `ipsec::milenage`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::*;
use crate::registrant::aka::{
    aka_challenge, decode_aka_nonce, encode_auts, AkaCredentials, AkaOutcome,
};
use crate::script::api::request::RequestAction;
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::uri::SipUri;

const IMPI: &str = "001010000000001";
const REALM: &str = "ims.mnc001.mcc001.3gppnetwork.org";
/// TS 35.208 Test Set 1 K and OP.
const K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
const OP: &str = "cdc202d5123e20f62b6d676ac72cb318";
const AMF: &str = "8000";

fn credential(sqn: Option<&str>) -> AkaCredential {
    AkaCredential {
        k: K.to_string(),
        op: OP.to_string(),
        amf: AMF.to_string(),
        sqn: sqn.map(str::to_string),
    }
}

fn auth_with(identities: &[&str], sqn: Option<&str>) -> PyAuth {
    let mut auth = PyAuth::empty();
    let credentials: HashMap<String, AkaCredential> = identities
        .iter()
        .map(|identity| (identity.to_string(), credential(sqn)))
        .collect();
    auth.set_aka_credentials(credentials);
    auth
}

fn ue() -> AkaCredentials {
    AkaCredentials::from_hex(K, Some(OP), None, AMF).expect("UE credentials")
}

fn register(user: &str, authorization: Option<&str>) -> PyRequest {
    let mut builder = SipMessageBuilder::new()
        .request(Method::Register, SipUri::new(REALM.to_string()))
        .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-local-aka".to_string())
        .to(format!("<sip:{user}@{REALM}>"))
        .from(format!("<sip:{user}@{REALM}>;tag=local-aka"))
        .call_id("local-aka@192.0.2.10".to_string())
        .cseq("1 REGISTER".to_string())
        .content_length(0);
    if let Some(value) = authorization {
        builder = builder.header("Authorization", value.to_string());
    }
    let message = builder.build().expect("a REGISTER");
    PyRequest::new(
        Arc::new(Mutex::new(message)),
        "udp".to_string(),
        "192.0.2.10".to_string(),
        5060,
    )
}

fn reply_code(request: &PyRequest) -> Option<u16> {
    match request.action() {
        RequestAction::Reply { code, .. } => Some(*code),
        _ => None,
    }
}

fn challenge_of(request: &PyRequest) -> String {
    request
        .message()
        .lock()
        .expect("lock")
        .headers
        .get("WWW-Authenticate")
        .cloned()
        .expect("a 401 carries WWW-Authenticate")
}

/// What the UE makes of the challenge in `request`'s 401, holding `sqn_ms`.
fn ue_outcome(request: &PyRequest, sqn_ms: u64) -> (String, AkaOutcome) {
    let header = challenge_of(request);
    let nonce = extract_nonce_field(&header).expect("a nonce");
    let (rand, autn) = decode_aka_nonce(&nonce).expect("RAND || AUTN");
    (
        header,
        aka_challenge(&ue(), &rand, &autn, &sqn_bytes(sqn_ms)),
    )
}

/// The SQN of the challenge in `request`'s 401, which the UE accepts.
fn accepted_sqn(request: &PyRequest, sqn_ms: u64) -> u64 {
    match ue_outcome(request, sqn_ms).1 {
        AkaOutcome::Success { sqn, .. } => sqn_value(&sqn),
        other => panic!("the UE holding {sqn_ms:012x} refused the challenge: {other:?}"),
    }
}

/// The Authorization siphon's UE sends for `header`: the response, or the
/// AUTS with an empty response (RFC 3310 3.4).
fn ue_authorization(header: &str, res: &[u8], auts: Option<&[u8; 14]>) -> String {
    ue_authorization_as(IMPI, header, res, auts)
}

fn ue_authorization_as(
    username: &str,
    header: &str,
    res: &[u8],
    auts: Option<&[u8; 14]>,
) -> String {
    let challenge = crate::auth::parse_challenge(header).expect("a challenge the UE reads");
    let auts = auts.map(encode_auts);
    crate::auth::format_aka_authorization_header(
        &challenge,
        username,
        res,
        &format!("sip:{REALM}"),
        None,
        None,
        auts.as_deref(),
    )
}

fn challenge(auth: &PyAuth) -> PyRequest {
    let mut request = register(IMPI, None);
    assert!(!auth
        .require_aka_digest(&mut request, Some(REALM))
        .expect("challenge runs"));
    assert_eq!(reply_code(&request), Some(401));
    request
}

/// Forget the vector a challenge left behind, as a test that never answers it.
fn discard(request: &PyRequest) {
    if let Some(nonce) = extract_nonce_field(&challenge_of(request)) {
        let _ = take_auth_vector(&nonce);
    }
}

#[test]
fn sqn_advances_seq_with_ind_zero() {
    assert_eq!(sqn_after(1), 32);
    assert_eq!(sqn_after(31), 32);
    assert_eq!(sqn_after(32), 64);
    assert_eq!(sqn_after(0x4e5), 0x500);
    assert_eq!(sqn_value(&sqn_bytes(0x0123_4567_89ab)), 0x0123_4567_89ab);
}

/// The bug: every challenge carried SQN 1, so a UE accepted the first and
/// refused every later one. Each challenge now carries a later SQN, and the
/// UE, holding the SQN it last accepted, takes each and authenticates.
#[test]
fn successive_challenges_carry_increasing_sqns_the_ue_accepts() {
    let auth = auth_with(&[IMPI], None);
    let mut sqn_ms = 0;
    for expected in [1, 32, 64, 96] {
        let request = challenge(&auth);
        let (header, outcome) = ue_outcome(&request, sqn_ms);
        let AkaOutcome::Success { res, sqn, .. } = outcome else {
            panic!("the UE refused SQN {expected:012x}: {outcome:?}");
        };
        assert_eq!(sqn_value(&sqn), expected);
        sqn_ms = expected;

        let mut answer = register(IMPI, Some(&ue_authorization(&header, &res, None)));
        assert!(auth
            .require_aka_digest(&mut answer, Some(REALM))
            .expect("verification runs"));
        assert_eq!(answer.get_auth_user(), Some(IMPI));
    }
}

#[test]
fn the_configured_sqn_is_the_first_challenges() {
    let auth = auth_with(&[IMPI], Some("0000000004e5"));
    let first = challenge(&auth);
    assert_eq!(accepted_sqn(&first, 0), 0x4e5);
    let second = challenge(&auth);
    assert_eq!(accepted_sqn(&second, 0x4e5), 0x500);
    discard(&first);
    discard(&second);
}

/// A UE further along than siphon (a restart, another node) answers with an
/// AUTS. A genuine one re-bases the SQN past the UE's and the fresh 401 is
/// one the UE accepts, ending what used to be a loop.
#[test]
fn a_genuine_auts_resynchronises_and_the_fresh_challenge_is_accepted() {
    let auth = auth_with(&[IMPI], None);
    let sqn_ms = 0x0000_0010_0003;
    let request = challenge(&auth);
    let (header, outcome) = ue_outcome(&request, sqn_ms);
    let AkaOutcome::SyncFailure { auts } = outcome else {
        panic!("the UE should find SQN 1 out of range: {outcome:?}");
    };

    let mut resync = register(IMPI, Some(&ue_authorization(&header, &[], Some(&auts))));
    assert!(!auth
        .require_aka_digest(&mut resync, Some(REALM))
        .expect("resync runs"));
    assert_eq!(reply_code(&resync), Some(401), "a fresh challenge");
    assert_eq!(accepted_sqn(&resync, sqn_ms), 0x0000_0010_0020);
    discard(&resync);
}

/// An AUTS whose MAC-S does not verify is refused with 403 and moves nothing:
/// the next challenge carries the SQN it would have anyway.
#[test]
fn an_auts_with_a_bad_mac_s_is_refused_and_moves_nothing() {
    let auth = auth_with(&[IMPI], None);
    let request = challenge(&auth);
    let (header, outcome) = ue_outcome(&request, 0x0000_0010_0003);
    let AkaOutcome::SyncFailure { mut auts } = outcome else {
        panic!("the UE should find SQN 1 out of range: {outcome:?}");
    };
    auts[13] ^= 0x01;

    let mut forged = register(IMPI, Some(&ue_authorization(&header, &[], Some(&auts))));
    assert!(!auth
        .require_aka_digest(&mut forged, Some(REALM))
        .expect("resync runs"));
    assert_eq!(reply_code(&forged), Some(403));
    assert_eq!(forged.get_auth_user(), None);

    let next = challenge(&auth);
    assert_eq!(accepted_sqn(&next, 1), 32, "the SQN was not re-based");
    discard(&next);
}

/// An AUTS for a challenge that is not live (answered, expired, never
/// issued) has no RAND to check against: challenged afresh, not re-based.
#[test]
fn an_auts_for_no_live_challenge_is_challenged_afresh() {
    let auth = auth_with(&[IMPI], None);
    let request = challenge(&auth);
    let (header, outcome) = ue_outcome(&request, 0x0000_0010_0003);
    let AkaOutcome::SyncFailure { auts } = outcome else {
        panic!("the UE should find SQN 1 out of range: {outcome:?}");
    };
    discard(&request);

    let mut late = register(IMPI, Some(&ue_authorization(&header, &[], Some(&auts))));
    assert!(!auth
        .require_aka_digest(&mut late, Some(REALM))
        .expect("resync runs"));
    assert_eq!(reply_code(&late), Some(401));
    assert_eq!(accepted_sqn(&late, 1), 32, "the SQN was not re-based");
    discard(&late);
}

/// Per-module leak gate: the SQN store holds one entry per configured
/// subscriber however many challenges, answers and resyncs go through it,
/// and a REGISTER for an identity with no credential adds nothing.
#[test]
fn the_sqn_store_holds_one_entry_per_configured_subscriber() {
    let identities = ["001010000000101", "001010000000102", "001010000000103"];
    let auth = auth_with(&identities, None);
    assert_eq!(auth.aka_sequence.len(), 0);

    for round in 0..300 {
        for identity in identities {
            let mut request = register(identity, None);
            assert!(!auth
                .require_aka_digest(&mut request, Some(REALM))
                .expect("challenge runs"));
            discard(&request);
        }
        let mut stranger = register(&format!("999990000{round:06}"), None);
        assert!(!auth
            .require_aka_digest(&mut stranger, Some(REALM))
            .expect("lookup runs"));
        assert_eq!(reply_code(&stranger), Some(403));
    }
    assert_eq!(auth.aka_sequence.len(), identities.len());

    // A resync re-bases an existing entry rather than adding one.
    let mut request = register(identities[0], None);
    assert!(!auth
        .require_aka_digest(&mut request, Some(REALM))
        .expect("challenge runs"));
    let (header, outcome) = ue_outcome(&request, 0x0000_0100_0000);
    let AkaOutcome::SyncFailure { auts } = outcome else {
        panic!("the UE should find the SQN out of range: {outcome:?}");
    };
    let authorization = ue_authorization_as(identities[0], &header, &[], Some(&auts));
    let mut resync = register(identities[0], Some(&authorization));
    assert!(!auth
        .require_aka_digest(&mut resync, Some(REALM))
        .expect("resync runs"));
    assert_eq!(accepted_sqn(&resync, 0x0000_0100_0000), 0x0000_0100_0020);
    discard(&resync);
    assert_eq!(auth.aka_sequence.len(), identities.len());
}
