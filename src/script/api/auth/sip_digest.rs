//! SIP Digest for IMS registration (TS 33.203 Annex N, TS 24.229 clauses
//! 5.4.1.2.1B and 5.4.1.2.2A).
//!
//! The subscriber server hands out H(A1) and never the password. The S-CSCF
//! generates the nonce, challenges once per algorithm it holds an H(A1) for,
//! and computes the expected response as RFC 7616 describes. Neither H(A1)
//! nor a response is ever logged or formatted.

use std::fmt;
use std::time::Duration;

use pyo3::prelude::*;
use tracing::warn;

use super::ims::{request_authentication, HssAnswer, Register};
use super::vectors::{
    digest_challenge, forget_challenge, record_nonce_count, store_digest_challenge, NonceCount,
};
use super::{constant_time_eq, PyAuth};
use crate::auth::{hash_hex_public, DigestAlgorithm};
use crate::diameter::DiameterClient;
use crate::script::api::diameter_cx::AuthItem;
use crate::script::api::ipsec::auth_header_param;
use crate::script::api::request::PyRequest;

/// The SIP Digest item of a Multimedia-Auth-Answer (TS 29.228 table 6.3.7).
#[derive(Clone)]
pub(super) struct SipDigestVector {
    /// Digest-Realm: the realm H(A1) was computed with, so the realm of the
    /// challenge.
    realm: String,
    /// H(A1) per algorithm, most preferred first: the alternate algorithm when
    /// the server sent one, then MD5.
    hashes: Vec<(DigestAlgorithm, String)>,
}

impl fmt::Debug for SipDigestVector {
    /// H(A1) is credential material and stays out of any formatted output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algorithms: Vec<String> = self
            .hashes
            .iter()
            .map(|(algorithm, _)| algorithm.to_string())
            .collect();
        formatter
            .debug_struct("SipDigestVector")
            .field("realm", &self.realm)
            .field("algorithms", &algorithms)
            .finish_non_exhaustive()
    }
}

/// Lower-case hex of the length `algorithm` produces, or nothing.
fn hash_value(algorithm: DigestAlgorithm, value: &str) -> Option<String> {
    let length = match algorithm {
        DigestAlgorithm::Md5 => 32,
        _ => 64,
    };
    let value = value.trim();
    (value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

impl SipDigestVector {
    /// Read SIP-Digest-Authenticate out of a SIP-Auth-Data-Item. The error
    /// names what is missing or unusable, never a value.
    pub(super) fn from_item(item: &AuthItem) -> Result<Self, String> {
        if !item.has_digest {
            return Err("SIP-Digest-Authenticate".to_string());
        }
        let realm = item
            .digest_realm
            .clone()
            .filter(|realm| !realm.is_empty())
            .ok_or("Digest-Realm")?;
        // "This information element shall be set to a value of "auth" by the
        // HSS" (TS 29.228 table 6.3.7), and a challenge without one gets
        // "auth" (TS 24.229 clause 5.4.1.2.1B). Another value asks for a
        // protection this path does not compute.
        if let Some(qop) = item.digest_qop.as_deref() {
            if !qop.eq_ignore_ascii_case("auth") {
                return Err(format!("a supported Digest-QoP (it is \"{qop}\")"));
            }
        }
        // "If this information element is present, it shall contain "MD5"."
        if let Some(algorithm) = item.digest_algorithm.as_deref() {
            if !algorithm.eq_ignore_ascii_case("MD5") {
                return Err(format!("Digest-Algorithm \"MD5\" (it is \"{algorithm}\")"));
            }
        }
        let md5 = item
            .digest_ha1
            .as_deref()
            .and_then(|value| hash_value(DigestAlgorithm::Md5, value))
            .ok_or("a Digest-HA1 of 32 hexadecimal digits")?;

        let mut hashes = Vec::with_capacity(2);
        if let Some(name) = item.alternate_digest_algorithm.as_deref() {
            let algorithm = DigestAlgorithm::parse(name).filter(|algorithm| {
                matches!(
                    algorithm,
                    DigestAlgorithm::Sha256 | DigestAlgorithm::Sha512_256
                )
            });
            let hash = algorithm.and_then(|algorithm| {
                hash_value(algorithm, item.alternate_digest_ha1.as_deref()?)
                    .map(|hash| (algorithm, hash))
            });
            match hash {
                Some(entry) => hashes.push(entry),
                None => warn!(
                    algorithm = name,
                    "IMS auth: the Alternate-Digest-Algorithm of the subscriber server is \
                     not one this S-CSCF verifies, or its Alternate-Digest-HA1 is missing \
                     or malformed; challenging with MD5 only"
                ),
            }
        }
        hashes.push((DigestAlgorithm::Md5, md5));
        Ok(Self { realm, hashes })
    }

    /// One WWW-Authenticate value per algorithm, most preferred first
    /// (TS 24.229 clause 5.4.1.2.1B).
    fn challenges(&self, nonce: &str, stale: bool) -> Vec<String> {
        let stale = if stale { ", stale=true" } else { "" };
        self.hashes
            .iter()
            .map(|(algorithm, _)| {
                format!(
                    "Digest realm=\"{}\", nonce=\"{nonce}\", algorithm={algorithm}, \
                     qop=\"auth\"{stale}",
                    self.realm
                )
            })
            .collect()
    }

    /// The checks of TS 24.229 clause 5.4.1.2.2A steps 3 and 4 that need
    /// nothing but the vector: realm, algorithm, cnonce, nc, and the response.
    fn check(&self, answer: &DigestAnswer, method: &str) -> Result<Verified, &'static str> {
        if answer.realm != self.realm {
            return Err("the realm is not the one of the challenge");
        }
        let algorithm = answer
            .algorithm
            .as_deref()
            .and_then(DigestAlgorithm::parse)
            .ok_or("no algorithm the challenge offered")?;
        let (_, hash) = self
            .hashes
            .iter()
            .find(|(offered, _)| *offered == algorithm)
            .ok_or("no algorithm the challenge offered")?;
        if !answer
            .qop
            .as_deref()
            .is_some_and(|qop| qop.eq_ignore_ascii_case("auth"))
        {
            return Err("qop is not auth");
        }
        let client_nonce = answer
            .client_nonce
            .as_deref()
            .filter(|client_nonce| !client_nonce.is_empty())
            .ok_or("no cnonce")?;
        let count_text = answer.nonce_count.as_deref().ok_or("no nc")?;
        let nonce_count = u32::from_str_radix(count_text, 16)
            .ok()
            .filter(|count| *count > 0)
            .ok_or("nc is not a positive hexadecimal count")?;

        let exchange = Exchange {
            algorithm,
            hash,
            uri: &answer.uri,
            nonce: &answer.nonce,
            nonce_count: count_text,
            client_nonce,
        };
        let expected = exchange.response(method);
        if !constant_time_eq(
            expected.as_bytes(),
            answer.response.to_ascii_lowercase().as_bytes(),
        ) {
            return Err("the response does not match");
        }
        Ok(Verified {
            nonce_count,
            authentication_info: format!(
                "qop=auth, rspauth=\"{}\", cnonce=\"{client_nonce}\", nc={count_text}",
                exchange.response_auth()
            ),
        })
    }
}

/// A response that matched.
struct Verified {
    nonce_count: u32,
    /// The Authentication-Info value for the 200 (TS 24.229 clause
    /// 5.4.1.2.2A step 11): qop, rspauth, cnonce and nc. No nextnonce, the
    /// nonce stays valid.
    authentication_info: String,
}

/// The inputs of one qop=auth digest computation (RFC 7616 clause 3.4).
struct Exchange<'a> {
    algorithm: DigestAlgorithm,
    /// H(A1), lower-case hex.
    hash: &'a str,
    uri: &'a str,
    nonce: &'a str,
    /// As the client wrote it: the eight digits enter the hash as text.
    nonce_count: &'a str,
    client_nonce: &'a str,
}

impl Exchange<'_> {
    fn keyed(&self, a2: &str) -> String {
        let hash_a2 = hash_hex_public(self.algorithm, a2.as_bytes());
        let data = format!(
            "{}:{}:{}:{}:auth:{hash_a2}",
            self.hash, self.nonce, self.nonce_count, self.client_nonce
        );
        hash_hex_public(self.algorithm, data.as_bytes())
    }

    /// The response the client owes: A2 is `method:uri`.
    fn response(&self, method: &str) -> String {
        self.keyed(&format!("{method}:{}", self.uri))
    }

    /// The rspauth the server owes in Authentication-Info: A2 is `:uri`
    /// (RFC 7616 clause 3.5).
    fn response_auth(&self) -> String {
        self.keyed(&format!(":{}", self.uri))
    }
}

/// A challenge response read off an Authorization header.
pub(super) struct DigestAnswer {
    username: String,
    realm: String,
    pub(super) nonce: String,
    uri: String,
    response: String,
    algorithm: Option<String>,
    qop: Option<String>,
    client_nonce: Option<String>,
    nonce_count: Option<String>,
}

impl DigestAnswer {
    /// `None` when the header carries no challenge response: an IMS UE sends
    /// an Authorization header with an empty `response` and `nonce` in its
    /// first REGISTER.
    pub(super) fn parse(authorization: &str) -> Option<Self> {
        let param = |name: &str| auth_header_param(authorization, name);
        let filled = |name: &str| param(name).filter(|value| !value.is_empty());
        Some(Self {
            response: filled("response")?,
            nonce: filled("nonce")?,
            username: param("username").unwrap_or_default(),
            realm: param("realm").unwrap_or_default(),
            uri: param("uri").unwrap_or_default(),
            algorithm: param("algorithm"),
            qop: param("qop"),
            client_nonce: param("cnonce"),
            nonce_count: param("nc"),
        })
    }
}

/// A SIP Digest challenge as kept under its nonce: the vector and the
/// REGISTER it was issued to.
#[derive(Debug, Clone)]
pub(super) struct SipDigestChallenge {
    vector: SipDigestVector,
    public_identity: String,
    private_identity: String,
    /// The Call-ID of the REGISTER that was challenged, which the answer has
    /// to repeat (TS 24.229 clause 5.4.1.2.2A).
    call_id: String,
}

impl PyAuth {
    /// The SIP Digest side of `require_ims_digest`: verify an answer to a
    /// challenge this S-CSCF issued, or ask the subscriber server and
    /// challenge. `scheme` is what a Multimedia-Auth-Request names when one
    /// is needed.
    pub(super) async fn sip_digest_flow(
        &self,
        client: &DiameterClient,
        request: &Py<PyRequest>,
        aka_realm: &str,
        register: &Register,
        scheme: &'static str,
        nonce_lifetime: Duration,
    ) -> PyResult<bool> {
        let answer = register
            .cx
            .authorization
            .as_deref()
            .and_then(DigestAnswer::parse);

        if let Some(answer) = &answer {
            // A nonce issued for another public identity is no nonce for this
            // one: the subscriber server has not been asked whether the two
            // identities belong together.
            let pending = digest_challenge(&answer.nonce)
                .filter(|(challenge, _)| challenge.public_identity == register.cx.public_identity);
            if let Some((challenge, answered_before)) = pending {
                return Python::attach(|python| {
                    self.answer_to_challenge(
                        &mut request.borrow_mut(python),
                        register,
                        &challenge,
                        answered_before,
                        answer,
                        nonce_lifetime,
                    )
                });
            }
        }

        match request_authentication(client, register, scheme, None).await? {
            HssAnswer::SipDigest(vector) => {
                // TS 24.229 clause 5.4.1.2.3B: "an invalid "nonce" ... with a
                // valid challenge response for that nonce (indicating that
                // the client knows the correct username/password)" is
                // challenged again with stale=true. A response that is not
                // valid for its nonce is a failed authentication.
                let stale = match &answer {
                    None => false,
                    Some(answer)
                        if answer.username == register.cx.user_name
                            && vector.check(answer, &register.method).is_ok() =>
                    {
                        true
                    }
                    Some(_) => {
                        warn!(
                            public_identity = %register.cx.public_identity,
                            "IMS auth: a SIP Digest response under a nonce that is not \
                             valid does not verify either; refusing the REGISTER"
                        );
                        return Python::attach(|python| {
                            Ok(forbid(&mut request.borrow_mut(python)))
                        });
                    }
                };
                Python::attach(|python| {
                    self.challenge_sip_digest(
                        &mut request.borrow_mut(python),
                        register,
                        vector,
                        stale,
                    )
                })
            }
            HssAnswer::Aka(vector) => Python::attach(|python| {
                self.challenge_with(&mut request.borrow_mut(python), aka_realm, vector)
            }),
            HssAnswer::Refused => {
                Python::attach(|python| Ok(forbid(&mut request.borrow_mut(python))))
            }
        }
    }

    /// TS 24.229 clause 5.4.1.2.2A: the REGISTER answers a challenge whose
    /// nonce is still valid.
    fn answer_to_challenge(
        &self,
        request: &mut PyRequest,
        register: &Register,
        challenge: &SipDigestChallenge,
        answered_before: bool,
        answer: &DigestAnswer,
        nonce_lifetime: Duration,
    ) -> PyResult<bool> {
        // "The S-CSCF shall only proceed further if the Call-IDs match", for
        // the REGISTER that answers the 401. A later one under the same nonce
        // is held to the nonce count instead.
        let failure = if !answered_before && challenge.call_id != register.call_id {
            Err("the Call-ID is not the one of the challenged REGISTER")
        } else if answer.username != challenge.private_identity {
            Err("the username is not the private identity that was challenged")
        } else {
            challenge.vector.check(answer, &register.method)
        };
        let verified = match failure {
            Ok(verified) => verified,
            Err(reason) => {
                // TS 33.203 clause N.2.2.1: a failure notification with no
                // security parameters. The nonce is not usable again.
                warn!(
                    public_identity = %register.cx.public_identity,
                    private_identity = %challenge.private_identity,
                    reason,
                    "IMS auth: SIP Digest authentication failed; refusing the REGISTER"
                );
                forget_challenge(&answer.nonce);
                return Ok(forbid(request));
            }
        };

        match record_nonce_count(&answer.nonce, verified.nonce_count, nonce_lifetime) {
            NonceCount::Accepted => {
                request.set_auth_user(answer.username.clone());
                request
                    .push_reply_header_replace("Authentication-Info", verified.authentication_info);
                Ok(true)
            }
            // TS 24.229 clause 5.4.1.2.3B: "when the nonce-count value sent
            // by the UE is not the expected value" a fresh nonce goes out
            // with stale=true. The client has shown it knows the password.
            NonceCount::Replayed | NonceCount::Unknown => {
                self.challenge_sip_digest(request, register, challenge.vector.clone(), true)
            }
        }
    }

    /// Set the 401 with one challenge per algorithm and keep the vector under
    /// the nonce. Returns `Ok(false)`: challenged, not verified.
    fn challenge_sip_digest(
        &self,
        request: &mut PyRequest,
        register: &Register,
        vector: SipDigestVector,
        stale: bool,
    ) -> PyResult<bool> {
        let nonce = self.generate_nonce();
        let values = vector.challenges(&nonce, stale);
        store_digest_challenge(
            nonce,
            SipDigestChallenge {
                vector,
                public_identity: register.cx.public_identity.clone(),
                private_identity: register.cx.user_name.clone(),
                call_id: register.call_id.clone(),
            },
        );

        request.set_reply(401, "Unauthorized".to_string());
        let message = request.message();
        let mut message = message.lock().map_err(|error| {
            pyo3::exceptions::PyRuntimeError::new_err(format!("lock poisoned: {error}"))
        })?;
        message.headers.remove("WWW-Authenticate");
        for value in values {
            message.headers.add("WWW-Authenticate", value);
        }
        Ok(false)
    }
}

/// Refuse the REGISTER. Returns `false`, the value `require_ims_digest` hands
/// back with it.
pub(super) fn forbid(request: &mut PyRequest) -> bool {
    request.set_reply(403, "Forbidden".to_string());
    false
}

#[cfg(test)]
mod tests;
