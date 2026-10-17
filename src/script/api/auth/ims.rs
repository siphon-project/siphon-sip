//! The Cx Multimedia-Auth round trips behind `auth.require_ims_digest`, and
//! the choice of authentication mechanism they serve.
//!
//! TS 24.229 clause 5.4.1.1 has the S-CSCF pick the mechanism from the
//! REGISTER and from what the subscriber server has assigned. Two are
//! implemented: IMS-AKA, here, and SIP Digest (TS 33.203 Annex N), in
//! [`super::sip_digest`]. The others are refused, never treated as one of
//! these two.

use std::time::Duration;

use pyo3::prelude::*;
use serde_json::Value;
use tracing::{error, warn};

use super::sip_digest::{forbid, SipDigestVector};
use super::vectors::{
    auth_vectors, forget_challenge, pending_scheme, store_auth_vector, take_auth_vector,
    PendingScheme,
};
use super::{
    base64_decode, base64_encode, extract_digest_param, extract_nonce_field, extract_sip_uri,
    md5_ha1_aka, DigestFields, PyAuth,
};
use crate::diameter::cx::{
    MultimediaAuth, DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED, SCHEME_IMS_AKA, SCHEME_SIP_DIGEST,
    SCHEME_UNKNOWN,
};
use crate::diameter::{codec, dictionary::avp, DiameterClient};
use crate::script::api::diameter_cx::{
    auth_items, ims_private_identity, AuthItem, ImsRegistration,
};
use crate::script::api::ipsec::auth_header_param;
use crate::script::api::request::PyRequest;
use crate::sip::message::SipMessage;

/// What `require_ims_digest` reads off a REGISTER before it asks the
/// subscriber server about it.
pub(super) struct Register {
    /// The method, which enters the digest computation.
    pub(super) method: String,
    /// What the Multimedia-Auth-Request says about it: the public and the
    /// private user identity, the S-CSCF name, and the Authorization header.
    pub(super) cx: ImsRegistration,
    /// Its `integrity-protected` parameter, which the P-CSCF sets
    /// (TS 24.229 clause 7.2A.2).
    integrity_protected: Option<String>,
    /// Whether a P-Access-Network-Info the network provided names an access
    /// other than a 3GPP one.
    non_3gpp_access: bool,
    pub(super) call_id: String,
}

/// The mechanism TS 24.229 clause 5.4.1.1 selects for a REGISTER.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Mechanism {
    ImsAka,
    /// SIP Digest, or whatever the subscriber server has assigned when the
    /// scheme to ask for is "Unknown".
    SipDigest {
        scheme: &'static str,
    },
    /// A mechanism this S-CSCF does not implement.
    Refused(&'static str),
}

impl Register {
    /// TS 24.229 clause 5.4.1.2.1 step 1: "identify the user by the public
    /// user identity as received in the To header field and if the REGISTER
    /// request includes an Authorization header field, identify the private
    /// user identity as received in the "username" Authorization header field
    /// parameter". Without that parameter the private identity is derived
    /// from the public one (clause 5.4.1.1 item 3).
    pub(super) fn read(message: &SipMessage, server_name: Option<&str>) -> Self {
        let headers = &message.headers;
        // The Public-Identity AVP is a bare URI: no display name, no angle
        // brackets, no header parameters.
        let public_identity = extract_sip_uri(headers.to().map_or("", String::as_str));
        let authorization = headers.get("Authorization").cloned();
        let integrity_protected = authorization
            .as_deref()
            .and_then(|value| auth_header_param(value, "integrity-protected"));
        let non_3gpp_access = headers
            .get_all("P-Access-Network-Info")
            .is_some_and(|values| network_provided_non_3gpp(values));
        Self {
            method: message.method().map_or_else(
                || "REGISTER".to_string(),
                |method| method.as_str().to_string(),
            ),
            cx: ImsRegistration {
                user_name: ims_private_identity(authorization.as_deref(), &public_identity),
                public_identity,
                server_name: server_name.map(str::to_string),
                authorization,
            },
            integrity_protected,
            non_3gpp_access,
            call_id: headers.call_id().cloned().unwrap_or_default(),
        }
    }

    /// The numbered list of TS 24.229 clause 5.4.1.1, for an S-CSCF that
    /// supports IMS-AKA and SIP Digest and neither NASS-IMS bundled nor
    /// GPRS-IMS-Bundled authentication.
    ///
    /// A REGISTER that answers a challenge this S-CSCF issued is handled
    /// under the mechanism of that challenge whatever the list would say:
    /// the nonce says which one it was.
    pub(super) fn mechanism(&self) -> Mechanism {
        const SIP_DIGEST: Mechanism = Mechanism::SipDigest {
            scheme: SCHEME_SIP_DIGEST,
        };
        const ASSIGNED: Mechanism = Mechanism::SipDigest {
            scheme: SCHEME_UNKNOWN,
        };
        let Some(authorization) = self.cx.authorization.as_deref() else {
            // Items 3 to 8. Item 5: "an IP-CAN different from 3GPP and
            // containing the "network provided" header field parameter and
            // the S-CSCF supports SIP digest but does not support
            // NASS-IMS-bundled authentication" is SIP Digest. Items 4, 7 and
            // 8 need NASS support and item 6 GPRS-IMS-Bundled support. What
            // is left, a 3GPP access or none the network vouches for, is no
            // item of the list for this S-CSCF: the subscriber server
            // decides.
            return if self.non_3gpp_access {
                SIP_DIGEST
            } else {
                ASSIGNED
            };
        };
        if resync_data(authorization, false).is_some() {
            return Mechanism::ImsAka;
        }
        match extract_nonce_field(authorization)
            .as_deref()
            .and_then(pending_scheme)
        {
            Some(PendingScheme::Aka) => return Mechanism::ImsAka,
            Some(PendingScheme::SipDigest) => return SIP_DIGEST,
            None => {}
        }
        match self.integrity_protected.as_deref() {
            // Items 1 and 2.
            Some("no" | "yes") => Mechanism::ImsAka,
            // Item 2A, "if the S-CSCF supports the IMS AKA using HTTP Digest
            // AKAv2 without IPSec security association".
            Some("tls-connected") => {
                Mechanism::Refused("IMS AKA over TLS (integrity-protected=tls-connected)")
            }
            // Item 9.
            None => ASSIGNED,
            // Item 10.
            Some("tls-pending" | "tls-yes" | "ip-assoc-pending" | "ip-assoc-yes") => SIP_DIGEST,
            // Item 11: "shall not perform authentication". Only a trusted
            // node may say so, and none is configured here.
            Some("auth-done") => {
                Mechanism::Refused("trusted node authentication (integrity-protected=auth-done)")
            }
            Some(_) => Mechanism::Refused("an integrity-protected value TS 24.229 does not define"),
        }
    }
}

/// Whether one of the P-Access-Network-Info values carries the
/// "network-provided" parameter and an access type or class other than the
/// 3GPP ones, which all start with "3GPP-" (TS 24.229 clause 7.2A.4).
fn network_provided_non_3gpp(values: &[String]) -> bool {
    let mut provided = values
        .iter()
        .flat_map(|value| value.split(','))
        .filter_map(|value| {
            let mut parts = value.split(';').map(str::trim);
            let access = parts.next()?;
            parts
                .any(|part| part.eq_ignore_ascii_case("network-provided"))
                .then_some(access)
        })
        .peekable();
    provided.peek().is_some()
        && provided.all(|access| {
            !access
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("3GPP-"))
        })
}

/// What the subscriber server said to a Multimedia-Auth-Request.
pub(super) enum HssAnswer {
    /// DIAMETER_SUCCESS with an IMS-AKA item.
    Aka(AkaVector),
    /// DIAMETER_SUCCESS with a SIP Digest item.
    SipDigest(SipDigestVector),
    /// Any other result, or a scheme this S-CSCF does not implement: the
    /// REGISTER is refused.
    Refused,
}

/// Ask the subscriber server for one authentication vector under `scheme`.
///
/// `resync` is RAND followed by AUTS after a synchronisation failure. TS 29.228
/// table 6.3.2 allows it with IMS-AKA only. "Digest-AKAv1-MD5" is IMS-AKA and
/// "SIP Digest" is not (TS 29.229 clause 6.3.9), and "Unknown" has the server
/// answer in the scheme it has stored, which TS 29.228 clause 6.3.1 step 4
/// limits to NASS-Bundled and SIP Digest.
///
/// A successful answer to a request that named a scheme, labelled with
/// another one, is an error and not a refusal: its item does not hold what was
/// asked for, and a challenge built from it is one no UE can answer.
pub(super) async fn request_authentication(
    client: &DiameterClient,
    register: &Register,
    scheme: &'static str,
    resync: Option<&[u8]>,
) -> PyResult<HssAnswer> {
    let what = if resync.is_some() {
        "MAR resync"
    } else {
        "MAR"
    };
    let public_identity = register.cx.public_identity.as_str();
    let maa = client
        .send_mar(&MultimediaAuth {
            public_identity,
            user_name: &register.cx.user_name,
            server_name: register.cx.server_name.as_deref(),
            sip_number_auth_items: 1,
            sip_auth_scheme: scheme,
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
                requested = scheme,
                "IMS auth: the subscriber server answered the {what} with \
                 DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (5006), it has no \
                 authentication in this scheme for the identity; refusing the REGISTER"
            );
        } else {
            warn!(
                %public_identity,
                result_code,
                experimental_result_code = experimental,
                "IMS auth: the subscriber server refused the {what}; refusing the REGISTER"
            );
        }
        return Ok(HssAnswer::Refused);
    }

    // One vector was asked for: the first item is the answer.
    let item = auth_items(&maa).into_iter().next();
    let answered = item.as_ref().and_then(|item| item.scheme.clone());
    let answered = answered.as_deref();
    let is = |name: &str| answered.is_some_and(|scheme| scheme.eq_ignore_ascii_case(name));
    let asked_for_aka = scheme == SCHEME_IMS_AKA;
    let assigned = scheme == SCHEME_UNKNOWN;

    // An item with no scheme is read as the scheme that was asked for, and
    // under "Unknown" as SIP Digest when it holds SIP-Digest-Authenticate.
    let digest_item = item.as_ref().is_some_and(|item| item.has_digest);
    let aka_item = if answered.is_some() {
        is(SCHEME_IMS_AKA) && (asked_for_aka || assigned)
    } else {
        asked_for_aka
    };
    if aka_item {
        return AkaVector::from_item(item, public_identity).map(HssAnswer::Aka);
    }
    let sip_digest_item = if answered.is_some() {
        is(SCHEME_SIP_DIGEST) && !asked_for_aka
    } else {
        !asked_for_aka && (digest_item || !assigned)
    };
    if sip_digest_item {
        let vector = item
            .as_ref()
            .ok_or_else(|| "SIP-Auth-Data-Item".to_string())
            .and_then(SipDigestVector::from_item);
        return match vector {
            Ok(vector) => Ok(HssAnswer::SipDigest(vector)),
            Err(missing) => {
                error!(
                    %public_identity,
                    missing = %missing,
                    "IMS auth: the subscriber server answered the {what} with DIAMETER_SUCCESS \
                     and no usable SIP Digest item; no challenge is sent"
                );
                Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "{what} failed: the answer is DIAMETER_SUCCESS without {missing}, \
                     there is no H(A1) to challenge with"
                )))
            }
        };
    }

    let answered = answered.unwrap_or("none");
    if assigned {
        // The subscriber server did what it was asked: it named the scheme it
        // has stored. It is one this S-CSCF does not implement.
        error!(
            %public_identity,
            assigned = answered,
            "IMS auth: the subscriber server has assigned an authentication scheme \
             this S-CSCF does not implement; refusing the REGISTER"
        );
        return Ok(HssAnswer::Refused);
    }
    error!(
        %public_identity,
        requested = scheme,
        %answered,
        "IMS auth: the subscriber server answered the {what} in another \
         authentication scheme; no challenge can be built from it"
    );
    Err(pyo3::exceptions::PyRuntimeError::new_err(format!(
        "{what} failed: asked for SIP-Authentication-Scheme \
         \"{scheme}\", the answer carries \"{answered}\""
    )))
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
    /// Select the mechanism and run it.
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
        register: Register,
        nonce_lifetime: Duration,
    ) -> PyResult<bool> {
        match register.mechanism() {
            Mechanism::ImsAka => auth.aka_flow(&client, &request, &realm, &register).await,
            Mechanism::SipDigest { scheme } => {
                auth.sip_digest_flow(&client, &request, &realm, &register, scheme, nonce_lifetime)
                    .await
            }
            Mechanism::Refused(mechanism) => {
                warn!(
                    public_identity = %register.cx.public_identity,
                    mechanism,
                    "IMS auth: the REGISTER asks for an authentication mechanism this \
                     S-CSCF does not implement; refusing it"
                );
                Python::attach(|python| Ok(forbid(&mut request.borrow_mut(python))))
            }
        }
    }

    /// IMS-AKA: the MAR round trips and everything they decide.
    async fn aka_flow(
        &self,
        client: &DiameterClient,
        request: &Py<PyRequest>,
        realm: &str,
        register: &Register,
    ) -> PyResult<bool> {
        let mut resync = None;

        // ── Second REGISTER (has Authorization): verify against stored vector ──
        if let Some(ref auth_value) = register.cx.authorization {
            // Check for AUTS resynchronization (TS 29.228 table 6.3.2).
            // UE detected SQN out of sync → sends auts= in Authorization.
            // We MUST send a new MAR with RAND||AUTS so the HSS can resync.
            resync = resync_data(auth_value, true);
            if resync.is_none() {
                if let Some(verified) = Self::verify_stored_vector(auth_value, realm) {
                    Python::attach(|python| request.borrow_mut(python).set_auth_user(verified));
                    return Ok(true);
                }
            }
        }

        // ── First REGISTER, a re-challenge or a resynchronisation: send MAR ──
        let answer =
            request_authentication(client, register, SCHEME_IMS_AKA, resync.as_deref()).await?;
        Python::attach(|python| {
            let mut request = request.borrow_mut(python);
            match answer {
                HssAnswer::Aka(vector) => self.challenge_with(&mut request, realm, vector),
                // Not reachable: a request that names IMS-AKA is answered
                // with an IMS-AKA item or not at all.
                HssAnswer::SipDigest(_) | HssAnswer::Refused => Ok(forbid(&mut request)),
            }
        })
    }

    /// Store XRES under the nonce of the challenge, so the REGISTER that
    /// answers it is verified without another MAR, and set the 401.
    /// Returns `Ok(false)`: challenged, not yet verified.
    pub(super) fn challenge_with(
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

    /// Send a 401 AKA challenge whose nonce is `rand_and_autn`, base64-encoded.
    pub(super) fn send_ims_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        rand_and_autn: &[u8],
        ck: Option<&[u8]>,
        ik: Option<&[u8]>,
    ) -> PyResult<()> {
        request.set_reply(401, "Unauthorized".to_string());

        let nonce = base64_encode(rand_and_autn);
        // Per TS 33.203 §6.3, include CK and IK from the HSS MAA so the
        // P-CSCF can extract them for IPsec SA setup with the UE.
        let mut header_value = format!(
            "Digest realm=\"{realm}\", nonce=\"{nonce}\", algorithm=AKAv1-MD5, qop=\"auth\""
        );
        if let Some(ck_bytes) = ck {
            header_value.push_str(&format!(
                ", ck=\"{}\"",
                crate::diameter::codec::hex::encode(ck_bytes)
            ));
        }
        if let Some(ik_bytes) = ik {
            header_value.push_str(&format!(
                ", ik=\"{}\"",
                crate::diameter::codec::hex::encode(ik_bytes)
            ));
        }

        let message = request.message();
        let mut message_guard = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message_guard.headers.set("WWW-Authenticate", header_value);
        Ok(())
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
pub(super) struct AkaVector {
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
    fn from_item(item: Option<AuthItem>, public_identity: &str) -> PyResult<Self> {
        let filled = |octets: Option<Vec<u8>>| octets.filter(|octets| !octets.is_empty());
        let missing = match item {
            None => "SIP-Auth-Data-Item",
            Some(item) => match (filled(item.authenticate), filled(item.authorization)) {
                (Some(rand_and_autn), Some(expected_response)) => {
                    return Ok(Self {
                        rand_and_autn,
                        expected_response,
                        confidentiality_key: filled(item.confidentiality_key),
                        integrity_key: filled(item.integrity_key),
                    });
                }
                (None, _) => "SIP-Authenticate",
                (Some(_), None) => "SIP-Authorization",
            },
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
/// RAND. With `consume` the vector issued under that nonce is dropped.
fn resync_data(auth_value: &str, consume: bool) -> Option<Vec<u8>> {
    let auts = base64_decode(&extract_digest_param(auth_value, "auts")?)?;
    if auts.len() != 14 {
        return None;
    }
    let nonce = extract_nonce_field(auth_value)?;
    let rand_and_autn = base64_decode(&nonce)?;
    if rand_and_autn.len() < 16 {
        return None;
    }
    if consume {
        // Clean up the stale vector for the old nonce
        forget_challenge(&nonce);
    }

    let mut data = Vec::with_capacity(30);
    data.extend_from_slice(&rand_and_autn[..16]);
    data.extend_from_slice(&auts);
    Some(data)
}

#[cfg(test)]
mod tests;
