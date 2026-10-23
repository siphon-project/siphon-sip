//! `auth.require_aka_digest()`: IMS AKA computed locally from
//! `auth.aka_credentials` (Milenage, TS 35.206), with the per-subscriber
//! sequence number an HE/AuC keeps (TS 33.102 6.3.2, annex C) and the
//! re-synchronisation it runs on an AUTS (6.3.5).
//!
//! SQN = SEQ || IND with a 5-bit IND (annex C.3.2). Every challenge takes the
//! next SEQ with IND 0, so successive challenges are strictly increasing
//! whatever freshness scheme the USIM runs: the plain full-SQN comparison and
//! the per-IND array of annex C.2.2 both accept them. An AUTS re-bases SEQ on
//! the SEQ of the SQN_MS it carries (annex C.3.4), so the challenge sent with
//! it is the first the UE accepts.
//!
//! The counters live in memory, one per configured subscriber. After a restart
//! a subscriber's first challenge carries the configured `sqn` again; a UE
//! that is further along answers it with an AUTS and is re-synchronised.

use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, info, warn};

use super::vectors::{store_auth_vector, take_auth_vector};
use super::{
    base64_decode, base64_encode, extract_digest_param, extract_nonce_field, extract_username,
    extract_username_from_uri, md5_ha1_aka, DigestFields, PyAuth, PyRequest,
};
use crate::config::AkaCredential;
use crate::ipsec::milenage;

/// Width of IND in SQN = SEQ || IND (TS 33.102 C.3.2 suggests 5 bits).
const IND_BITS: u32 = 5;

/// SQN is 48 bits (TS 33.102 6.3.2).
const SQN_MASK: u64 = (1 << 48) - 1;

/// SQN of a subscriber's first challenge when its credential sets no `sqn`.
const DEFAULT_STARTING_SQN: u64 = 1;

/// The first SQN after `sqn`: the next SEQ, with IND 0.
fn sqn_after(sqn: u64) -> u64 {
    (((sqn >> IND_BITS) + 1) << IND_BITS) & SQN_MASK
}

fn sqn_bytes(sqn: u64) -> [u8; 6] {
    let wide = sqn.to_be_bytes();
    let mut bytes = [0u8; 6];
    bytes.copy_from_slice(&wide[2..8]);
    bytes
}

fn sqn_value(bytes: &[u8; 6]) -> u64 {
    bytes
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

/// The SQN of each subscriber's next challenge, keyed by the identity its
/// credential is configured under. Only a configured identity gets an entry,
/// so the store is bounded by `auth.aka_credentials`, whatever peers send.
#[derive(Debug, Default)]
pub(crate) struct SqnStore {
    next: DashMap<String, u64>,
}

impl SqnStore {
    /// The SQN for a challenge to `identity` now, advancing the counter.
    /// `starting` is the first one when the subscriber has none yet.
    fn issue(&self, identity: &str, starting: u64) -> u64 {
        let mut next = self
            .next
            .entry(identity.to_string())
            .or_insert(starting & SQN_MASK);
        let sqn = *next;
        *next = sqn_after(sqn);
        sqn
    }

    /// Re-base `identity` on the SQN_MS an AUTS carried: its next challenge is
    /// the first one past it.
    fn resynchronise(&self, identity: &str, sqn_ms: u64) {
        self.next.insert(identity.to_string(), sqn_after(sqn_ms));
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.next.len()
    }
}

/// The Milenage inputs of one subscriber, parsed from its credential.
struct SubscriberKeys {
    k: [u8; 16],
    op: [u8; 16],
    amf: [u8; 2],
    starting_sqn: u64,
}

fn runtime_error(message: &str) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(message.to_string())
}

impl SubscriberKeys {
    fn parse(credential: &AkaCredential) -> PyResult<Self> {
        let k = milenage::hex_to_bytes(&credential.k)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| runtime_error("invalid AKA K (need 32 hex chars)"))?;
        let op = milenage::hex_to_bytes(&credential.op)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| runtime_error("invalid AKA OP (need 32 hex chars)"))?;
        let amf = milenage::hex_to_bytes(&credential.amf)
            .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
            .ok_or_else(|| runtime_error("invalid AKA AMF (need 4 hex chars)"))?;
        let starting_sqn = credential
            .starting_sqn()
            .map_err(|error| runtime_error(&format!("invalid AKA SQN: {error}")))?
            .unwrap_or(DEFAULT_STARTING_SQN);
        Ok(Self {
            k,
            op,
            amf,
            starting_sqn,
        })
    }
}

impl PyAuth {
    /// The body of `require_aka_digest`; see its docstring.
    pub(super) fn local_aka_digest(
        &self,
        request: &mut PyRequest,
        realm: Option<&str>,
    ) -> PyResult<bool> {
        let realm = realm.unwrap_or(&self.default_realm);

        let (existing_auth, from_user, method) = {
            let message = request.message();
            let guard = message
                .lock()
                .map_err(|error| runtime_error(&format!("lock poisoned: {error}")))?;
            let auth = guard.headers.get("Authorization").cloned();
            let from = guard.headers.from().cloned().unwrap_or_default();
            // HA2 is H(method:uri), so the method has to be the one the UE
            // actually sent rather than an assumed REGISTER.
            let method = match &guard.start_line {
                crate::sip::message::StartLine::Request(line) => line.method.as_str().to_string(),
                _ => "REGISTER".to_string(),
            };
            (auth, extract_username_from_uri(&from), method)
        };

        let impi = existing_auth
            .as_deref()
            .and_then(extract_username)
            .or(from_user)
            .unwrap_or_default();
        let Some((identity, credential)) = self.aka_credential(&impi, realm) else {
            request.set_reply(403, "Forbidden".to_string());
            return Ok(false);
        };
        let keys = SubscriberKeys::parse(&credential)?;

        let Some(auth_value) = existing_auth else {
            self.send_aka_challenge(request, realm, &identity, &keys)?;
            return Ok(false);
        };

        // RFC 3310 3.4: an "auts" answers a challenge whose SQN the UE found
        // out of range. It carries no usable response.
        if let Some(auts) = extract_digest_param(&auth_value, "auts") {
            return self.resynchronise(request, realm, &identity, &keys, &auth_value, &auts);
        }

        // Verify `response=` against the XRES cached when the challenge went
        // out. RFC 3310 3.3: for AKAv1-MD5 the digest password is the raw XRES
        // bytes, so HA1 = MD5(username:realm:XRES). The vector is consumed
        // whether or not it verifies, so a replayed Authorization finds nothing.
        let stored = extract_nonce_field(&auth_value).and_then(|nonce| take_auth_vector(&nonce));
        match (stored, DigestFields::parse(&auth_value)) {
            (Some(vector), Some(fields)) => {
                let ha1 = md5_ha1_aka(&fields.username, realm, &vector.expected_response);
                if fields.verify(&ha1, &method) {
                    request.set_auth_user(fields.username);
                    return Ok(true);
                }
                debug!(username = %fields.username, "AKA auth: digest response did not verify");
            }
            (None, _) => debug!(
                "AKA auth: no live vector for this nonce (expired, replayed, or never issued)"
            ),
            (Some(_), None) => debug!("AKA auth: Authorization header could not be parsed"),
        }

        // Wrong, stale or replayed: challenge again with a fresh vector.
        self.send_aka_challenge(request, realm, &identity, &keys)?;
        Ok(false)
    }

    /// The credential for `impi` and the identity it is configured under:
    /// the full IMPI, then its user part, then the IMPI at `realm`.
    fn aka_credential(&self, impi: &str, realm: &str) -> Option<(String, AkaCredential)> {
        let bare = impi.split('@').next().unwrap_or(impi).to_string();
        let with_domain = format!("{impi}@{realm}");
        [impi.to_string(), bare, with_domain]
            .into_iter()
            .find_map(|identity| {
                let credential = self.aka_credentials.get(&identity)?.clone();
                Some((identity, credential))
            })
    }

    /// Check an AUTS (TS 33.102 6.3.5) against the RAND of the challenge it
    /// answers. Genuine: re-base the subscriber's SQN on SQN_MS and send a
    /// fresh challenge. Not genuine: 403.
    fn resynchronise(
        &self,
        request: &mut PyRequest,
        realm: &str,
        identity: &str,
        keys: &SubscriberKeys,
        auth_value: &str,
        auts: &str,
    ) -> PyResult<bool> {
        // Only a challenge siphon issued and nobody has answered yet: its
        // nonce is RAND || AUTN, so it is where the RAND comes from.
        let nonce = extract_nonce_field(auth_value);
        let rand = nonce
            .as_deref()
            .and_then(take_auth_vector)
            .and(nonce.as_deref())
            .and_then(base64_decode)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes.get(..16)?).ok());
        let Some(rand) = rand else {
            debug!(
                identity,
                "AKA auth: AUTS for no live challenge, challenging afresh"
            );
            self.send_aka_challenge(request, realm, identity, keys)?;
            return Ok(false);
        };

        let opc = milenage::compute_opc(&keys.k, &keys.op);
        let sqn_ms = base64_decode(auts)
            .and_then(|bytes| <[u8; 14]>::try_from(bytes).ok())
            .and_then(|token| milenage::verify_auts(&keys.k, &opc, &rand, &token));
        let Some(sqn_ms) = sqn_ms else {
            warn!(
                identity,
                "AKA auth: AUTS did not verify (MAC-S mismatch or malformed), refusing"
            );
            request.set_reply(403, "Forbidden".to_string());
            return Ok(false);
        };

        let sqn_ms = sqn_value(&sqn_ms);
        info!(
            identity,
            sqn_ms = format_args!("{sqn_ms:012x}"),
            "AKA auth: re-synchronised SQN from AUTS"
        );
        self.aka_sequence.resynchronise(identity, sqn_ms);
        self.send_aka_challenge(request, realm, identity, keys)?;
        Ok(false)
    }

    /// A 401 carrying a vector under the subscriber's next SQN.
    ///
    /// The nonce is base64(RAND || AUTN) (TS 33.203), and the 401 carries
    /// `ck=`/`ik=` as the HSS path does, for a P-CSCF in front to take off
    /// and set up the SAs from.
    fn send_aka_challenge(
        &self,
        request: &mut PyRequest,
        realm: &str,
        identity: &str,
        keys: &SubscriberKeys,
    ) -> PyResult<()> {
        let sqn = self.aka_sequence.issue(identity, keys.starting_sqn);
        let vector = milenage::generate_vector(&keys.k, &keys.op, &sqn_bytes(sqn), &keys.amf);

        let mut nonce_bytes = Vec::with_capacity(32);
        nonce_bytes.extend_from_slice(&vector.rand);
        nonce_bytes.extend_from_slice(&vector.autn);
        // The answer has to be checked against this vector: a fresh one would
        // carry a different RAND, so its XRES could never match.
        store_auth_vector(base64_encode(&nonce_bytes), vector.xres.clone());

        self.send_ims_challenge(
            request,
            realm,
            &nonce_bytes,
            Some(&vector.ck),
            Some(&vector.ik),
        )
    }
}

#[cfg(test)]
mod tests;
