//! The Cx Multimedia-Auth round trips behind `auth.require_ims_digest`.
//!
//! The challenge this path issues is IMS-AKA and nothing else, so every MAR
//! names that scheme and every answer is checked for it. SIP Digest (TS 33.203
//! Annex N), where the subscriber server hands out H(A1), is a different
//! scheme with different AVPs and is not implemented here.

use pyo3::prelude::*;
use serde_json::Value;
use tracing::{error, warn};

use super::vectors::{auth_vectors, ims_auth_store, take_auth_vector};
use super::{
    base64_decode, extract_digest_param, extract_nonce_field, md5_ha1_aka, DigestFields, PyAuth,
};
use crate::diameter::cx::{DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED, SIP_AUTH_SCHEME_IMS_AKA};
use crate::diameter::{codec, dictionary::avp, DiameterClient};
use crate::script::api::request::PyRequest;

/// What the subscriber server said to a request for an IMS-AKA vector.
enum VectorAnswer {
    /// DIAMETER_SUCCESS: the AVPs of the answer, vector included.
    Granted(Value),
    /// Any other result: the REGISTER is refused.
    Refused,
}

/// Ask the subscriber server for one IMS-AKA vector.
///
/// `resync` is RAND followed by AUTS after a synchronisation failure. TS 29.228
/// table 6.3.2 allows it with IMS-AKA only, and the first request for a vector
/// names the same scheme: "Digest-AKAv1-MD5" is IMS-AKA and "SIP Digest" is
/// not (TS 29.229 clause 6.3.9), and "Unknown" resolves to NASS-Bundled or SIP
/// Digest only (TS 29.228 clause 6.3.1 step 4).
///
/// A successful answer labelled with another scheme is an error, not a
/// refusal: its item does not hold RAND, AUTN and XRES, and a challenge built
/// from it is one no UE can answer.
async fn request_aka_vector(
    client: &DiameterClient,
    public_identity: &str,
    resync: Option<&[u8]>,
) -> PyResult<VectorAnswer> {
    let what = if resync.is_some() {
        "MAR resync"
    } else {
        "MAR"
    };
    let maa = client
        .send_mar(public_identity, 1, SIP_AUTH_SCHEME_IMS_AKA, resync)
        .await
        .map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("{what} failed: {error}"))
        })?;

    if codec::extract_u32_avp(&maa.avps, avp::RESULT_CODE) != Some(2001) {
        if experimental_result_code(&maa.avps) == Some(DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED) {
            warn!(
                %public_identity,
                requested = SIP_AUTH_SCHEME_IMS_AKA,
                "IMS auth: the subscriber server answered the {what} with \
                 DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (5006), it has no \
                 IMS-AKA authentication for this identity; refusing the REGISTER"
            );
        }
        return Ok(VectorAnswer::Refused);
    }

    let answered = codec::extract_grouped_avp(&maa.avps, avp::SIP_AUTH_DATA_ITEM)
        .as_ref()
        .and_then(|item| item.get("SIP-Authentication-Scheme"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    match answered {
        Some(scheme) if !scheme.eq_ignore_ascii_case(SIP_AUTH_SCHEME_IMS_AKA) => {
            error!(
                %public_identity,
                requested = SIP_AUTH_SCHEME_IMS_AKA,
                answered = %scheme,
                "IMS auth: the subscriber server answered the {what} in another \
                 authentication scheme; no IMS-AKA challenge can be built from it"
            );
            Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "{what} failed: asked for SIP-Authentication-Scheme \
                 \"{SIP_AUTH_SCHEME_IMS_AKA}\", the answer carries \"{scheme}\""
            )))
        }
        _ => Ok(VectorAnswer::Granted(maa.avps)),
    }
}

/// The code inside Experimental-Result, which is where a Cx error is carried
/// (TS 29.228 table 6.3.4).
fn experimental_result_code(avps: &Value) -> Option<u32> {
    let code = avps
        .get("Experimental-Result")?
        .get("Experimental-Result-Code")?
        .as_u64()?;
    u32::try_from(code).ok()
}

impl PyAuth {
    /// The MAR round trips and everything they decide.
    ///
    /// Takes an owned `Py<PyRequest>` because the request is written to *after*
    /// each await (a 403, an auth-user stamp, or the 401 challenge) and a
    /// borrow cannot be held across one. Each write re-borrows inside
    /// `Python::attach`, which is safe for the same reason the original borrow
    /// was: nothing else holds the request while its handler runs.
    pub(super) async fn ims_digest_flow(
        auth: PyAuth,
        client: std::sync::Arc<DiameterClient>,
        request: Py<PyRequest>,
        realm: String,
        public_identity: String,
        existing_auth: Option<String>,
    ) -> PyResult<bool> {
        let realm = realm.as_str();
        let mut resync = None;

        // ── Second REGISTER (has Authorization): verify against stored vector ──
        if let Some(ref auth_value) = existing_auth {
            // Check for AUTS resynchronization (TS 29.228 table 6.3.2).
            // UE detected SQN out of sync → sends auts= in Authorization.
            // We MUST send a new MAR with RAND||AUTS so the HSS can resync.
            resync = resync_data(auth_value);
            if resync.is_none() {
                if let Some(verified) = Self::verify_stored_vector(auth_value, realm) {
                    Python::attach(|python| request.borrow_mut(python).set_auth_user(verified));
                    return Ok(true);
                }
            }
        }

        // ── First REGISTER, a re-challenge or a resynchronisation: send MAR ──
        match request_aka_vector(&client, &public_identity, resync.as_deref()).await? {
            VectorAnswer::Granted(avps) => Python::attach(|python| {
                auth.send_ims_challenge_from_maa(&mut request.borrow_mut(python), realm, &avps)
            }),
            VectorAnswer::Refused => {
                Python::attach(|python| {
                    request
                        .borrow_mut(python)
                        .set_reply(403, "Forbidden".to_string())
                });
                Ok(false)
            }
        }
    }

    /// Check `response=` against the XRES stored when the challenge went out,
    /// consuming the vector. Returns the username that verified.
    fn verify_stored_vector(auth_value: &str, realm: &str) -> Option<String> {
        let nonce_str = extract_nonce_field(auth_value);
        let found = nonce_str
            .as_ref()
            .is_some_and(|n| auth_vectors().contains(n));
        tracing::debug!(
            nonce_prefix = nonce_str.as_ref().map(|n| &n[..n.len().min(16)]),
            found,
            store_size = auth_vectors().len(),
            "IMS auth: cache lookup",
        );
        let Some(vector) = nonce_str.as_ref().and_then(|n| take_auth_vector(n)) else {
            // No stored vector (expired or replayed nonce): need fresh MAR
            tracing::debug!("IMS auth: no cached vector, sending fresh MAR");
            return None;
        };

        // Per RFC 3310 §3.3: for AKAv1-MD5, raw XRES bytes are used
        // directly as the "password" in HA1 = MD5(username:realm:XRES).
        // Not hex-encoded, not base64-encoded: raw binary bytes.
        let fields = DigestFields::parse(auth_value)?;
        let ha1 = md5_ha1_aka(&fields.username, realm, &vector.expected_response);
        let matches = fields.verify(&ha1, "REGISTER");
        tracing::debug!(
            response = %fields.response,
            xres_len = vector.expected_response.len(),
            ha1 = %ha1,
            matches,
            "IMS auth: AKAv1-MD5 digest verification",
        );
        // Response mismatch: re-challenge with a fresh vector
        matches.then_some(fields.username)
    }
}

/// RAND followed by AUTS, when the Authorization header reports a
/// synchronisation failure: a 14-octet `auts=` against a nonce that holds a
/// RAND. The vector issued under that nonce is dropped.
fn resync_data(auth_value: &str) -> Option<Vec<u8>> {
    let auts = base64_decode(&extract_digest_param(auth_value, "auts")?)?;
    if auts.len() != 14 {
        return None;
    }
    let nonce = extract_nonce_field(auth_value)?;
    let rand_and_autn = base64_decode(&nonce)?;
    if rand_and_autn.len() < 16 {
        return None;
    }
    // Clean up the stale vector for the old nonce
    ims_auth_store().remove(&nonce);

    let mut data = Vec::with_capacity(30);
    data.extend_from_slice(&rand_and_autn[..16]);
    data.extend_from_slice(&auts);
    Some(data)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use super::super::base64_encode;
    use super::*;
    use crate::diameter::codec::{
        self, encode_avp, encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32,
        encode_avp_u32_3gpp, encode_avp_utf8, encode_avp_utf8_3gpp, encode_diameter_message,
        encode_vendor_specific_app_id, DiameterMessage, AVP_FLAG_MANDATORY, FLAG_PROXIABLE,
    };
    use crate::diameter::dictionary::{self, avp};
    use crate::diameter::peer::{spawn_connection_tasks, IncomingRequest, PeerConfig};
    use crate::diameter::transport::DiameterStream;
    use crate::diameter::DiameterClient;
    use crate::script::api::request::RequestAction;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    const REALM: &str = "ims.mnc001.mcc001.3gppnetwork.org";
    const PUBLIC_IDENTITY: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    const PRIVATE_IDENTITY: &str = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    /// The scheme TS 29.229 clause 6.3.9 defines for IMS-AKA, spelled out here
    /// rather than taken from the code under test.
    const IMS_AKA: &str = "Digest-AKAv1-MD5";
    /// SIP-Item-Number (TS 29.229 clause 6.3.14).
    const SIP_ITEM_NUMBER: u32 = 613;
    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (TS 29.229 clause 6.2.2.6).
    const AUTH_SCHEME_NOT_SUPPORTED: u32 = 5006;
    const AUTN: [u8; 16] = [0x22; 16];
    const AUTS: [u8; 14] = [0x44; 14];

    /// How the subscriber server at the far end answers a MAR. The subscriber
    /// is provisioned for IMS-AKA in every case.
    #[derive(Clone, Copy)]
    enum Hss {
        /// TS 29.228 clause 6.3.1 step 4: a vector for a request that names
        /// IMS-AKA, DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED for one that names
        /// another scheme or "Unknown" (which only resolves to NASS-Bundled or
        /// SIP Digest).
        Conformant,
        /// Success, with the item labelled as this scheme whatever was asked.
        AnswersScheme(&'static str),
        /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED whatever was asked.
        RefusesScheme,
    }

    /// A subscriber server on a loopback connection, with every MAR it
    /// received as sent on the wire.
    struct MockHss {
        client: Arc<DiameterClient>,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        _incoming: mpsc::Receiver<IncomingRequest>,
    }

    impl MockHss {
        /// `rand_fill` fills the RAND of the vectors, so each test owns its
        /// nonces in the process-wide vector store. A vector answering a
        /// resynchronisation gets `rand_fill + 1`.
        async fn start(behaviour: Hss, rand_fill: u8) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&requests);

            tokio::spawn(async move {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = BufReader::new(read_half);
                while let Ok(bytes) = codec::read_diameter_message(&mut reader).await {
                    let Some(request) = codec::decode_diameter(&bytes) else {
                        break;
                    };
                    seen.lock().unwrap().push(bytes);
                    let answer = multimedia_auth_answer(&request, behaviour, rand_fill);
                    if write_half.write_all(&answer).await.is_err() {
                        break;
                    }
                }
            });

            let stream = TcpStream::connect(address).await.unwrap();
            let (incoming_tx, incoming) = mpsc::channel(4);
            let config = PeerConfig {
                host: "127.0.0.1".to_string(),
                port: address.port(),
                origin_host: format!("scscf.{REALM}"),
                origin_realm: REALM.to_string(),
                destination_host: None,
                destination_realm: REALM.to_string(),
                local_ip: "127.0.0.1".parse().unwrap(),
                application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
                // Longer than any test, so no watchdog request is interleaved.
                watchdog_interval: 3600,
                reconnect_delay: 5,
                product_name: "SIPhon".to_string(),
                firmware_revision: 1,
            };
            let peer = spawn_connection_tasks(config, DiameterStream::Tcp(stream), incoming_tx);
            Self {
                client: Arc::new(DiameterClient::new(peer)),
                requests,
                _incoming: incoming,
            }
        }

        /// The MARs received so far, decoded.
        fn requests(&self) -> Vec<DiameterMessage> {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .map(|bytes| codec::decode_diameter(bytes).unwrap())
                .collect()
        }
    }

    fn requested_scheme(request: &DiameterMessage) -> Option<&str> {
        request
            .avps
            .get("SIP-Auth-Data-Item")?
            .get("SIP-Authentication-Scheme")?
            .as_str()
    }

    /// The SIP-Authorization of the request's item, as octets.
    fn requested_authorization(request: &DiameterMessage) -> Option<Vec<u8>> {
        let hex = request
            .avps
            .get("SIP-Auth-Data-Item")?
            .get("SIP-Authorization")?
            .as_str()?;
        codec::hex::decode(hex)
    }

    fn multimedia_auth_answer(request: &DiameterMessage, behaviour: Hss, rand_fill: u8) -> Vec<u8> {
        let session_id = request.avps["Session-Id"].as_str().unwrap();
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        avps.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avps.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &format!("hss.{REALM}")));
        avps.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, REALM));

        let scheme = match behaviour {
            Hss::Conformant if requested_scheme(request) == Some(IMS_AKA) => IMS_AKA,
            Hss::Conformant | Hss::RefusesScheme => {
                let mut result = Vec::new();
                result.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, dictionary::VENDOR_3GPP));
                result.extend_from_slice(&encode_avp_u32(
                    avp::EXPERIMENTAL_RESULT_CODE,
                    AUTH_SCHEME_NOT_SUPPORTED,
                ));
                avps.extend_from_slice(&encode_avp(
                    avp::EXPERIMENTAL_RESULT,
                    AVP_FLAG_MANDATORY,
                    &result,
                ));
                return encode_diameter_message(
                    FLAG_PROXIABLE,
                    dictionary::CMD_MULTIMEDIA_AUTH,
                    dictionary::CX_APP_ID,
                    request.hop_by_hop,
                    request.end_to_end,
                    &avps,
                );
            }
            Hss::AnswersScheme(scheme) => scheme,
        };

        let resynchronised = requested_authorization(request).is_some();
        let mut authenticate = vec![rand_fill + u8::from(resynchronised); 16];
        authenticate.extend_from_slice(&AUTN);

        let mut item = Vec::new();
        item.extend_from_slice(&encode_avp_u32_3gpp(SIP_ITEM_NUMBER, 1));
        item.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SIP_AUTHENTICATION_SCHEME,
            scheme,
        ));
        item.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHENTICATE, &authenticate));
        item.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHORIZATION, &[0x55; 8]));
        item.extend_from_slice(&encode_avp_octet_3gpp(
            avp::CONFIDENTIALITY_KEY,
            &[0x66; 16],
        ));
        item.extend_from_slice(&encode_avp_octet_3gpp(avp::INTEGRITY_KEY, &[0x77; 16]));

        avps.extend_from_slice(&encode_avp_u32(
            avp::RESULT_CODE,
            dictionary::DIAMETER_SUCCESS,
        ));
        avps.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, PRIVATE_IDENTITY));
        avps.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, PUBLIC_IDENTITY));
        avps.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
        avps.extend_from_slice(&encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &item));
        encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            request.hop_by_hop,
            request.end_to_end,
            &avps,
        )
    }

    /// The nonce of the challenge built from a vector whose RAND is `fill`.
    fn nonce(fill: u8) -> String {
        let mut bytes = vec![fill; 16];
        bytes.extend_from_slice(&AUTN);
        base64_encode(&bytes)
    }

    fn authorization(nonce: &str, extra: &str) -> String {
        format!(
            "Digest username=\"{PRIVATE_IDENTITY}\", realm=\"{REALM}\", nonce=\"{nonce}\", \
             uri=\"sip:{REALM}\", algorithm=AKAv1-MD5, response=\"{}\"{extra}",
            "0".repeat(32),
        )
    }

    /// What `require_ims_digest` left on the REGISTER.
    struct Outcome {
        result: PyResult<bool>,
        reply: Option<u16>,
        challenge: Option<String>,
    }

    /// Run the flow for one REGISTER, as `require_ims_digest` does once it has
    /// read the identity and the Authorization header off the request.
    async fn register(hss: &MockHss, authorization: Option<String>) -> Outcome {
        Python::initialize();
        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new(REALM.to_string()))
            .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ims".to_string())
            .to(format!("<{PUBLIC_IDENTITY}>"))
            .from(format!("<{PUBLIC_IDENTITY}>;tag=ims"))
            .call_id("ims-register@192.0.2.10".to_string())
            .cseq("1 REGISTER".to_string())
            .content_length(0);
        if let Some(value) = &authorization {
            builder = builder.header("Authorization", value.clone());
        }
        let request = PyRequest::new(
            Arc::new(Mutex::new(builder.build().unwrap())),
            "udp".to_string(),
            "192.0.2.10".to_string(),
            5060,
        );
        let (handle, kept) = Python::attach(|python| {
            let handle = Py::new(python, request).unwrap();
            (handle.clone_ref(python), handle)
        });

        let result = PyAuth::ims_digest_flow(
            PyAuth::new(HashMap::new(), REALM.to_string()),
            Arc::clone(&hss.client),
            handle,
            REALM.to_string(),
            PUBLIC_IDENTITY.to_string(),
            authorization,
        )
        .await;

        Python::attach(|python| {
            let request = kept.borrow(python);
            let reply = match request.action() {
                RequestAction::Reply { code, .. } => Some(*code),
                _ => None,
            };
            let message = request.message();
            let challenge = message
                .lock()
                .unwrap()
                .headers
                .get("WWW-Authenticate")
                .cloned();
            Outcome {
                result,
                reply,
                challenge,
            }
        })
    }

    fn assert_aka_challenge(outcome: &Outcome, rand_fill: u8) {
        assert!(
            !outcome.result.as_ref().unwrap(),
            "challenged, not verified"
        );
        assert_eq!(outcome.reply, Some(401));
        let challenge = outcome.challenge.as_deref().expect("WWW-Authenticate");
        assert!(challenge.contains("algorithm=AKAv1-MD5"), "{challenge}");
        assert!(
            challenge.contains(&format!("nonce=\"{}\"", nonce(rand_fill))),
            "{challenge}"
        );
    }

    /// TS 29.229 clause 6.3.9: "Digest-AKAv1-MD5" indicates the IMS-AKA
    /// scheme and "SIP Digest" a different one, which a subscriber server
    /// following TS 29.228 clause 6.3.1 refuses for an IMS-AKA subscriber.
    #[tokio::test]
    async fn the_first_register_asks_for_an_ims_aka_vector() {
        let hss = MockHss::start(Hss::Conformant, 0x10).await;

        let outcome = register(&hss, None).await;

        let requests = hss.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].command_code, dictionary::CMD_MULTIMEDIA_AUTH);
        assert_eq!(requested_scheme(&requests[0]), Some(IMS_AKA));
        // Table 6.3.2: present only for a synchronisation failure.
        assert_eq!(requested_authorization(&requests[0]), None);
        assert_aka_challenge(&outcome, 0x10);
    }

    /// A response that does not verify consumes the vector, and the fresh one
    /// is asked for under the same scheme as the first.
    #[tokio::test]
    async fn a_failed_response_is_challenged_again_with_an_ims_aka_vector() {
        let hss = MockHss::start(Hss::Conformant, 0x18).await;
        assert_aka_challenge(&register(&hss, None).await, 0x18);

        let outcome = register(&hss, Some(authorization(&nonce(0x18), ""))).await;

        let requests = hss.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requested_scheme(&requests[1]), Some(IMS_AKA));
        assert_eq!(requested_authorization(&requests[1]), None);
        assert_aka_challenge(&outcome, 0x18);
    }

    /// TS 29.228 table 6.3.2: Authorization Information carries RAND and AUTS
    /// after a synchronisation failure, and "only IMS-AKA authentication
    /// schemes are allowed" with it.
    #[tokio::test]
    async fn a_resynchronisation_asks_for_an_ims_aka_vector_with_rand_and_auts() {
        let hss = MockHss::start(Hss::Conformant, 0x20).await;
        let auts = format!(", auts=\"{}\"", base64_encode(&AUTS));

        let outcome = register(&hss, Some(authorization(&nonce(0x20), &auts))).await;

        let requests = hss.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requested_scheme(&requests[0]), Some(IMS_AKA));
        let mut rand_and_auts = vec![0x20; 16];
        rand_and_auts.extend_from_slice(&AUTS);
        assert_eq!(requested_authorization(&requests[0]), Some(rand_and_auts));
        assert_aka_challenge(&outcome, 0x21);
    }

    /// An answer labelled with another scheme does not hold RAND, AUTN and
    /// XRES, whatever octets sit in the item, so no challenge is built from it.
    #[tokio::test]
    async fn an_answer_in_another_scheme_is_an_error_and_not_a_challenge() {
        for (rand_fill, register_with) in [
            (0x28, None),
            (0x30, Some(format!(", auts=\"{}\"", base64_encode(&AUTS)))),
        ] {
            let hss = MockHss::start(Hss::AnswersScheme("SIP Digest"), rand_fill).await;
            let header = register_with.map(|auts| authorization(&nonce(rand_fill), &auts));

            let outcome = register(&hss, header).await;

            let error = outcome.result.expect_err("a scheme mismatch must raise");
            let text = error.to_string();
            assert!(
                text.contains("SIP Digest") && text.contains(IMS_AKA),
                "{text}"
            );
            assert_eq!(outcome.reply, None);
            assert_eq!(outcome.challenge, None);
            for fill in [rand_fill, rand_fill + 1] {
                assert!(
                    take_auth_vector(&nonce(fill)).is_none(),
                    "no expected response may be stored for a refused answer"
                );
            }
        }
    }

    /// The scheme names are compared as the tokens they are, so a server that
    /// writes the IMS-AKA name in another case is not refused.
    #[tokio::test]
    async fn the_answered_scheme_is_compared_without_regard_to_case() {
        let hss = MockHss::start(Hss::AnswersScheme("digest-akav1-md5"), 0x38).await;
        assert_aka_challenge(&register(&hss, None).await, 0x38);
    }

    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED is the server refusing the
    /// scheme for this subscriber: the REGISTER is refused and nothing is
    /// challenged.
    #[tokio::test]
    async fn auth_scheme_not_supported_refuses_the_register() {
        let hss = MockHss::start(Hss::RefusesScheme, 0x40).await;

        let outcome = register(&hss, None).await;

        assert_eq!(requested_scheme(&hss.requests()[0]), Some(IMS_AKA));
        assert!(!outcome.result.unwrap());
        assert_eq!(outcome.reply, Some(403));
        assert_eq!(outcome.challenge, None);
    }

    /// Emit the MARs of a first REGISTER and of a resynchronisation as hex for
    /// [`scripts/validate_cx_mar.sh`] to feed to tshark, which reads the
    /// scheme back with its own dictionary rather than ours.
    #[tokio::test]
    async fn emit_cx_mar_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_CX_MAR_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let hss = MockHss::start(Hss::Conformant, 0x48).await;
        let auts = format!(", auts=\"{}\"", base64_encode(&AUTS));
        register(&hss, None).await;
        register(&hss, Some(authorization(&nonce(0x48), &auts))).await;

        // `text2pcap`'s hex-dump form: an offset, then the octets. An offset
        // of zero starts the next packet.
        let mut dump = String::new();
        for wire in hss.requests.lock().unwrap().iter() {
            for (offset, chunk) in wire.chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }
}
