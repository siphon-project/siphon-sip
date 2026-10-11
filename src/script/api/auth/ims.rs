//! The Cx Multimedia-Auth round trips behind `auth.require_ims_digest`.
//!
//! The challenge this path issues is IMS-AKA and nothing else, so every MAR
//! names that scheme and every answer is checked for it. SIP Digest (TS 33.203
//! Annex N), where the subscriber server hands out H(A1), is a different
//! scheme with different AVPs and is not implemented here.

use pyo3::prelude::*;
use serde_json::Value;
use tracing::{error, warn};

use super::vectors::{auth_vectors, ims_auth_store, store_auth_vector, take_auth_vector};
use super::{
    base64_decode, base64_encode, extract_digest_param, extract_nonce_field, extract_sip_uri,
    md5_ha1_aka, DigestFields, PyAuth,
};
use crate::diameter::cx::{
    MultimediaAuth, DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED, SCHEME_IMS_AKA,
};
use crate::diameter::{codec, dictionary::avp, DiameterClient};
use crate::script::api::diameter_cx::{ims_private_identity, ImsRegistration};
use crate::script::api::request::PyRequest;
use crate::sip::headers::SipHeaders;

/// What the Multimedia-Auth-Request says about a REGISTER.
///
/// TS 24.229 clause 5.4.1.2.1 step 1: "identify the user by the public user
/// identity as received in the To header field and if the REGISTER request
/// includes an Authorization header field, identify the private user identity
/// as received in the "username" Authorization header field parameter".
/// Without that parameter the private identity is derived from the public one
/// (clause 5.4.1.1 item 3).
pub(super) fn registration_of(headers: &SipHeaders, server_name: Option<&str>) -> ImsRegistration {
    // The Public-Identity AVP is a bare URI: no display name, no angle
    // brackets, no header parameters.
    let public_identity = extract_sip_uri(headers.to().map_or("", String::as_str));
    let authorization = headers.get("Authorization").cloned();
    ImsRegistration {
        user_name: ims_private_identity(authorization.as_deref(), &public_identity),
        public_identity,
        server_name: server_name.map(str::to_string),
        authorization,
    }
}

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
    registration: &ImsRegistration,
    resync: Option<&[u8]>,
) -> PyResult<VectorAnswer> {
    let what = if resync.is_some() {
        "MAR resync"
    } else {
        "MAR"
    };
    let public_identity = registration.public_identity.as_str();
    let maa = client
        .send_mar(&MultimediaAuth {
            public_identity,
            user_name: &registration.user_name,
            server_name: registration.server_name.as_deref(),
            sip_number_auth_items: 1,
            sip_auth_scheme: SCHEME_IMS_AKA,
            sip_authorization: resync,
        })
        .await
        .map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("{what} failed: {error}"))
        })?;

    let result_code = codec::extract_u32_avp(&maa.avps, avp::RESULT_CODE);
    if result_code != Some(2001) {
        let experimental = experimental_result_code(&maa.avps);
        if experimental == Some(DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED) {
            warn!(
                %public_identity,
                requested = SCHEME_IMS_AKA,
                "IMS auth: the subscriber server answered the {what} with \
                 DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (5006), it has no \
                 IMS-AKA authentication for this identity; refusing the REGISTER"
            );
        } else {
            warn!(
                %public_identity,
                result_code,
                experimental_result_code = experimental,
                "IMS auth: the subscriber server refused the {what}; refusing the REGISTER"
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
        Some(scheme) if !scheme.eq_ignore_ascii_case(SCHEME_IMS_AKA) => {
            error!(
                %public_identity,
                requested = SCHEME_IMS_AKA,
                answered = %scheme,
                "IMS auth: the subscriber server answered the {what} in another \
                 authentication scheme; no IMS-AKA challenge can be built from it"
            );
            Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                "{what} failed: asked for SIP-Authentication-Scheme \
                 \"{SCHEME_IMS_AKA}\", the answer carries \"{scheme}\""
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
        registration: ImsRegistration,
    ) -> PyResult<bool> {
        let realm = realm.as_str();
        let mut resync = None;

        // ── Second REGISTER (has Authorization): verify against stored vector ──
        if let Some(ref auth_value) = registration.authorization {
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
        match request_aka_vector(&client, &registration, resync.as_deref()).await? {
            VectorAnswer::Granted(avps) => {
                let vector = AkaVector::from_answer(&avps, &registration.public_identity)?;
                Python::attach(|python| {
                    auth.challenge_with(&mut request.borrow_mut(python), realm, vector)
                })
            }
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

    /// Store XRES under the nonce of the challenge, so the REGISTER that
    /// answers it is verified without another MAR, and set the 401.
    /// Returns `Ok(false)`: challenged, not yet verified.
    fn challenge_with(
        &self,
        request: &mut PyRequest,
        realm: &str,
        vector: AkaVector,
    ) -> PyResult<bool> {
        let nonce = base64_encode(&vector.rand_and_autn);
        tracing::debug!(
            nonce_prefix = &nonce[..nonce.len().min(16)],
            xres_len = vector.expected_response.len(),
            "IMS auth: stored pending challenge",
        );
        store_auth_vector(nonce, vector.expected_response);
        self.send_ims_challenge(
            request,
            realm,
            &vector.rand_and_autn,
            vector.confidentiality_key.as_deref(),
            vector.integrity_key.as_deref(),
        )?;
        Ok(false)
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
        // H(A1) and the response are credential material and stay out of the
        // log: either one is enough to answer this challenge.
        tracing::debug!(
            username = %fields.username,
            xres_len = vector.expected_response.len(),
            matches,
            "IMS auth: AKAv1-MD5 digest verification",
        );
        // Response mismatch: re-challenge with a fresh vector
        matches.then_some(fields.username)
    }
}

/// The IMS-AKA item of a successful Multimedia-Auth-Answer (TS 29.228
/// table 6.3.5).
struct AkaVector {
    /// SIP-Authenticate: RAND followed by AUTN, the nonce of the challenge.
    rand_and_autn: Vec<u8>,
    /// SIP-Authorization: XRES.
    expected_response: Vec<u8>,
    confidentiality_key: Option<Vec<u8>>,
    integrity_key: Option<Vec<u8>>,
}

impl AkaVector {
    /// A success without RAND and AUTN, or without XRES, is an error: a
    /// challenge with a nonce made up here carries no AUTN for the UE to
    /// check, and one with no XRES behind it can never be answered. Either
    /// would loop the UE through 401s, so nothing is sent.
    fn from_answer(avps: &Value, public_identity: &str) -> PyResult<Self> {
        let item = codec::extract_grouped_avp(avps, avp::SIP_AUTH_DATA_ITEM);
        let octets = |code: u32| {
            item.as_ref()
                .and_then(|item| codec::extract_octet_avp(item, code))
                .filter(|octets| !octets.is_empty())
        };
        let missing = match (
            octets(avp::SIP_AUTHENTICATE),
            octets(avp::SIP_AUTHORIZATION),
        ) {
            (Some(rand_and_autn), Some(expected_response)) => {
                return Ok(Self {
                    rand_and_autn,
                    expected_response,
                    confidentiality_key: octets(avp::CONFIDENTIALITY_KEY),
                    integrity_key: octets(avp::INTEGRITY_KEY),
                });
            }
            _ if item.is_none() => "SIP-Auth-Data-Item",
            (None, _) => "SIP-Authenticate",
            (Some(_), None) => "SIP-Authorization",
        };
        error!(
            %public_identity,
            missing,
            "IMS auth: the subscriber server answered the MAR with DIAMETER_SUCCESS \
             and no usable IMS-AKA vector; no challenge is sent"
        );
        Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
            "MAR failed: the answer is DIAMETER_SUCCESS without {missing}, \
             there is no IMS-AKA vector to challenge with"
        )))
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
mod tests;
