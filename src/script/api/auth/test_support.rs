//! What the `require_ims_digest` tests share: a subscriber server that
//! answers Multimedia-Auth-Requests the way TS 29.228 clause 6.3.1 describes,
//! a REGISTER to run through the flow, and a SIP Digest client written from
//! RFC 7616 without the code under test.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyo3::prelude::*;
use serde_json::Value;
use sha2::Digest;

use super::ims::Register;
use super::PyAuth;
use crate::diameter::codec::{
    self, encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp,
    encode_avp_utf8, encode_avp_utf8_3gpp, DiameterMessage,
};
use crate::diameter::cx_test_support::{
    answer_scaffold, experimental_answer, finish_answer, MockHss as Server,
};
use crate::diameter::dictionary::{self, avp};
use crate::script::api::ipsec::auth_header_param;
use crate::script::api::request::{PyRequest, RequestAction};
use crate::sip::builder::SipMessageBuilder;
use crate::sip::message::Method;
use crate::sip::uri::SipUri;

pub(super) use crate::diameter::cx_test_support::REALM;

pub(super) const PUBLIC_IDENTITY: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
pub(super) const PRIVATE_IDENTITY: &str = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
/// The SIP URI of the S-CSCF, as a script passes it to `server_name=`.
pub(super) const SCSCF: &str = "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060";
/// The scheme names of TS 29.229 clause 6.3.9, spelled out here rather than
/// taken from the code under test.
pub(super) const IMS_AKA: &str = "Digest-AKAv1-MD5";
pub(super) const SIP_DIGEST: &str = "SIP Digest";
pub(super) const UNKNOWN: &str = "Unknown";
/// SIP-Item-Number (TS 29.229 clause 6.3.14).
const SIP_ITEM_NUMBER: u32 = 613;
/// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (TS 29.229 clause 6.2.2.6).
const AUTH_SCHEME_NOT_SUPPORTED: u32 = 5006;
pub(super) const AUTN: [u8; 16] = [0x22; 16];
pub(super) const AUTS: [u8; 14] = [0x44; 14];
/// The realm the subscriber server computed H(A1) with. Not the realm the
/// S-CSCF script passes, so a challenge that carries this one took it from
/// the answer.
pub(super) const DIGEST_REALM: &str = "digest.example.org";
/// The password of the SIP Digest subscriber. Only the client and the
/// subscriber server know it.
pub(super) const PASSWORD: &str = "a password for 001010000000001";

/// How the subscriber server at the far end answers a MAR.
#[derive(Clone, Copy)]
pub(super) enum Hss {
    /// A subscriber provisioned for IMS-AKA, and TS 29.228 clause 6.3.1 step
    /// 4: a vector for a request that names IMS-AKA,
    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED for one that names another
    /// scheme or "Unknown" (which only resolves to NASS-Bundled or SIP
    /// Digest).
    Conformant,
    /// A subscriber provisioned for SIP Digest, and the same step 4: H(A1)
    /// for "SIP Digest" and for "Unknown", 5006 for IMS-AKA. With
    /// `alternate` the answer also carries the SHA-256 hash.
    SipDigest { alternate: bool },
    /// A subscriber provisioned for NASS-Bundled: "Unknown" resolves to it.
    NassBundled,
    /// Success, with an IMS-AKA shaped item labelled as this scheme whatever
    /// was asked.
    AnswersScheme(&'static str),
    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED whatever was asked.
    RefusesScheme,
    /// DIAMETER_SUCCESS in IMS-AKA without this AVP: "SIP-Auth-Data-Item", or
    /// one of its members.
    Omits(&'static str),
    /// DIAMETER_SUCCESS in SIP Digest without this member of
    /// SIP-Digest-Authenticate, or without the grouped AVP itself.
    SipDigestOmits(&'static str),
}

/// A subscriber server on a loopback connection, with every MAR it received
/// as sent on the wire. It refuses a MAR without one of the AVPs TS 29.229
/// clause 6.1.7 makes mandatory before `behaviour` is consulted.
pub(super) struct MockHss {
    pub(super) server: Server,
}

impl MockHss {
    /// `rand_fill` fills the RAND of the vectors, so each test owns its
    /// nonces in the process-wide vector store. A vector answering a
    /// resynchronisation gets `rand_fill + 1`.
    pub(super) async fn start(behaviour: Hss, rand_fill: u8) -> Self {
        let server =
            Server::start(move |request| multimedia_auth_answer(request, behaviour, rand_fill))
                .await;
        Self { server }
    }

    /// The decoded AVPs of the MARs received so far.
    pub(super) fn requests(&self) -> Vec<Value> {
        self.server.requests()
    }

    /// The schemes the MARs received so far asked for.
    pub(super) fn schemes(&self) -> Vec<String> {
        self.requests()
            .iter()
            .map(|request| requested_scheme(request).unwrap_or("").to_string())
            .collect()
    }
}

pub(super) fn text<'a>(request: &'a Value, name: &str) -> Option<&'a str> {
    request.get(name)?.as_str()
}

pub(super) fn requested_scheme(request: &Value) -> Option<&str> {
    request
        .get("SIP-Auth-Data-Item")?
        .get("SIP-Authentication-Scheme")?
        .as_str()
}

/// The SIP-Authorization of the request's item, as octets.
pub(super) fn requested_authorization(request: &Value) -> Option<Vec<u8>> {
    let hex = request
        .get("SIP-Auth-Data-Item")?
        .get("SIP-Authorization")?
        .as_str()?;
    codec::hex::decode(hex)
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

fn sha256_hex(input: &str) -> String {
    sha2::Sha256::digest(input.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// H(A1) of the SIP Digest subscriber (RFC 7616 clause 3.4.2).
fn hash_a1(hash: fn(&str) -> String) -> String {
    hash(&format!("{PRIVATE_IDENTITY}:{DIGEST_REALM}:{PASSWORD}"))
}

/// A SIP-Auth-Data-Item in the SIP Digest scheme (TS 29.229 clause 6.3.36).
/// The digest attributes are the RFC 5090 ones: no vendor, M bit.
pub(super) fn sip_digest_item(alternate: bool, omitted: Option<&str>) -> Vec<u8> {
    let kept = |name: &str| omitted != Some(name);
    let mut digest = Vec::new();
    if kept("Digest-Realm") {
        digest.extend_from_slice(&encode_avp_utf8(avp::DIGEST_REALM, DIGEST_REALM));
    }
    digest.extend_from_slice(&encode_avp_utf8(avp::DIGEST_ALGORITHM, "MD5"));
    digest.extend_from_slice(&encode_avp_utf8(avp::DIGEST_QOP, "auth"));
    if kept("Digest-HA1") {
        digest.extend_from_slice(&encode_avp_utf8(avp::DIGEST_HA1, &hash_a1(md5_hex)));
    }
    if alternate {
        digest.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::ALTERNATE_DIGEST_ALGORITHM,
            "SHA-256",
        ));
        digest.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::ALTERNATE_DIGEST_HA1,
            &hash_a1(sha256_hex),
        ));
    }

    let mut item = Vec::new();
    item.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        SIP_DIGEST,
    ));
    if kept("SIP-Digest-Authenticate") {
        item.extend_from_slice(&encode_avp_grouped_3gpp(
            avp::SIP_DIGEST_AUTHENTICATE,
            &digest,
        ));
    }
    item
}

/// An IMS-AKA shaped item labelled `scheme`.
fn aka_item(
    request: &DiameterMessage,
    scheme: &str,
    omitted: Option<&str>,
    rand_fill: u8,
) -> Vec<u8> {
    let kept = |name: &str| omitted != Some(name);
    let resynchronised = requested_authorization(&request.avps).is_some();
    let mut authenticate = vec![rand_fill + u8::from(resynchronised); 16];
    authenticate.extend_from_slice(&AUTN);

    let mut item = Vec::new();
    item.extend_from_slice(&encode_avp_u32_3gpp(SIP_ITEM_NUMBER, 1));
    item.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        scheme,
    ));
    if kept("SIP-Authenticate") {
        item.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHENTICATE, &authenticate));
    }
    if kept("SIP-Authorization") {
        item.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHORIZATION, &[0x55; 8]));
    }
    item.extend_from_slice(&encode_avp_octet_3gpp(
        avp::CONFIDENTIALITY_KEY,
        &[0x66; 16],
    ));
    item.extend_from_slice(&encode_avp_octet_3gpp(avp::INTEGRITY_KEY, &[0x77; 16]));
    item
}

fn multimedia_auth_answer(request: &DiameterMessage, behaviour: Hss, rand_fill: u8) -> Vec<u8> {
    let asked = requested_scheme(&request.avps);
    let refuse = || experimental_answer(request, AUTH_SCHEME_NOT_SUPPORTED);
    let item = match behaviour {
        Hss::Conformant if asked == Some(IMS_AKA) => {
            Some(aka_item(request, IMS_AKA, None, rand_fill))
        }
        Hss::Conformant | Hss::RefusesScheme => return refuse(),
        Hss::SipDigest { alternate } if matches!(asked, Some(SIP_DIGEST | UNKNOWN)) => {
            Some(sip_digest_item(alternate, None))
        }
        Hss::SipDigest { .. } => return refuse(),
        Hss::NassBundled if asked == Some(UNKNOWN) => {
            Some(encode_avp_utf8_3gpp(avp::SIP_AUTHENTICATION_SCHEME, "NASS-Bundled").to_vec())
        }
        Hss::NassBundled => return refuse(),
        Hss::AnswersScheme(scheme) => Some(aka_item(request, scheme, None, rand_fill)),
        Hss::Omits("SIP-Auth-Data-Item") => None,
        Hss::Omits(name) => Some(aka_item(request, IMS_AKA, Some(name), rand_fill)),
        Hss::SipDigestOmits(name) => Some(sip_digest_item(false, Some(name))),
    };

    let mut avps = answer_scaffold(request);
    avps.extend_from_slice(&encode_avp_u32(
        avp::RESULT_CODE,
        dictionary::DIAMETER_SUCCESS,
    ));
    avps.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, PRIVATE_IDENTITY));
    avps.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, PUBLIC_IDENTITY));
    avps.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    if let Some(item) = item {
        avps.extend_from_slice(&encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &item));
    }
    finish_answer(request, &avps)
}

/// The Authorization header of an IMS UE's first REGISTER, as a P-CSCF
/// forwards it for IMS-AKA: no challenge response, `integrity-protected` "no".
pub(super) fn aka_first_authorization() -> String {
    format!(
        "Digest username=\"{PRIVATE_IDENTITY}\", realm=\"{REALM}\", nonce=\"\", \
         uri=\"sip:{REALM}\", response=\"\", integrity-protected=\"no\""
    )
}

/// One REGISTER to run through the flow.
pub(super) struct Registration {
    pub(super) to: String,
    pub(super) authorization: Option<String>,
    pub(super) server_name: Option<&'static str>,
    pub(super) call_id: String,
    pub(super) access_network_info: Option<&'static str>,
}

impl Registration {
    /// A REGISTER of [`PUBLIC_IDENTITY`] through an S-CSCF that passes its
    /// name.
    pub(super) fn new(authorization: Option<String>) -> Self {
        Self {
            to: format!("<{PUBLIC_IDENTITY}>"),
            authorization,
            server_name: Some(SCSCF),
            call_id: "ims-register@192.0.2.10".to_string(),
            access_network_info: None,
        }
    }

    /// Run the flow, as `require_ims_digest` does: the REGISTER is read and
    /// the flow is awaited.
    ///
    /// From and P-Asserted-Identity name somebody else than To does, so a
    /// request that carries their identity is one that read the wrong header.
    pub(super) async fn run(self, hss: &MockHss) -> Outcome {
        Python::initialize();
        let mut builder = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new(REALM.to_string()))
            .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-ims".to_string())
            .to(self.to)
            .from(format!("<sip:001010000000002@{REALM}>;tag=ims"))
            .call_id(self.call_id)
            .cseq("1 REGISTER".to_string())
            .header(
                "P-Asserted-Identity",
                format!("<sip:001010000000003@{REALM}>"),
            )
            .content_length(0);
        if let Some(value) = &self.authorization {
            builder = builder.header("Authorization", value.clone());
        }
        if let Some(value) = self.access_network_info {
            builder = builder.header("P-Access-Network-Info", value.to_string());
        }
        let message = builder.build().unwrap();
        let read = Register::read(&message, self.server_name);
        let request = PyRequest::new(
            Arc::new(Mutex::new(message)),
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
            Arc::clone(&hss.server.client),
            handle,
            REALM.to_string(),
            read,
            Duration::from_secs(3600),
        )
        .await;

        Python::attach(|python| {
            let mut request = kept.borrow_mut(python);
            let reply = match request.action() {
                RequestAction::Reply { code, .. } => Some(*code),
                _ => None,
            };
            let challenges = {
                let message = request.message();
                let message = message.lock().unwrap();
                message
                    .headers
                    .get_all("WWW-Authenticate")
                    .cloned()
                    .unwrap_or_default()
            };
            let authentication_info = request
                .take_reply_headers()
                .into_iter()
                .find(|(_, name, _)| name == "Authentication-Info")
                .map(|(_, _, value)| value);
            Outcome {
                result,
                reply,
                challenge: challenges.first().cloned(),
                challenges,
                authentication_info,
                auth_user: request.get_auth_user().map(str::to_string),
            }
        })
    }
}

/// Run one REGISTER of [`PUBLIC_IDENTITY`] with this Authorization header.
pub(super) async fn register(hss: &MockHss, authorization: Option<String>) -> Outcome {
    Registration::new(authorization).run(hss).await
}

/// What `require_ims_digest` left on the REGISTER.
pub(super) struct Outcome {
    pub(super) result: PyResult<bool>,
    pub(super) reply: Option<u16>,
    /// The first WWW-Authenticate.
    pub(super) challenge: Option<String>,
    pub(super) challenges: Vec<String>,
    /// The Authentication-Info queued for the 200.
    pub(super) authentication_info: Option<String>,
    pub(super) auth_user: Option<String>,
}

impl Outcome {
    /// Refused with 403: no challenge, nobody authenticated.
    pub(super) fn assert_forbidden(&self) {
        assert!(!self.result.as_ref().unwrap(), "refused, not verified");
        assert_eq!(self.reply, Some(403));
        assert!(self.challenges.is_empty(), "{:?}", self.challenges);
        assert_eq!(self.authentication_info, None);
        assert_eq!(self.auth_user, None);
    }
}

/// A SIP Digest client: RFC 7616 clause 3.4 for qop=auth, written out here.
pub(super) struct Client {
    pub(super) username: String,
    pub(super) password: String,
    pub(super) uri: String,
    pub(super) client_nonce: String,
    /// What goes after the digest parameters, `integrity-protected` included.
    pub(super) extra: String,
}

impl Client {
    pub(super) fn new() -> Self {
        Self {
            username: PRIVATE_IDENTITY.to_string(),
            password: PASSWORD.to_string(),
            uri: format!("sip:{REALM}"),
            client_nonce: "0a4f113b".to_string(),
            extra: ", integrity-protected=\"ip-assoc-pending\"".to_string(),
        }
    }

    fn hash(algorithm: &str) -> fn(&str) -> String {
        match algorithm {
            "MD5" => md5_hex,
            "SHA-256" => sha256_hex,
            other => panic!("the test client does not compute {other}"),
        }
    }

    fn keyed(&self, challenge: &str, count: u32, a2: &str) -> String {
        let parameter = |name: &str| auth_header_param(challenge, name).unwrap();
        let hash = Self::hash(&parameter("algorithm"));
        let a1 = hash(&format!(
            "{}:{}:{}",
            self.username,
            parameter("realm"),
            self.password
        ));
        hash(&format!(
            "{a1}:{}:{count:08x}:{}:auth:{}",
            parameter("nonce"),
            self.client_nonce,
            hash(a2)
        ))
    }

    /// The Authorization header answering `challenge`, one WWW-Authenticate
    /// value, with nonce count `count`.
    pub(super) fn authorization(&self, challenge: &str, count: u32) -> String {
        let parameter = |name: &str| auth_header_param(challenge, name).unwrap();
        let response = self.keyed(challenge, count, &format!("REGISTER:{}", self.uri));
        format!(
            "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", \
             algorithm={}, qop=auth, nc={count:08x}, cnonce=\"{}\", response=\"{response}\"{}",
            self.username,
            parameter("realm"),
            parameter("nonce"),
            self.uri,
            parameter("algorithm"),
            self.client_nonce,
            self.extra,
        )
    }

    /// The rspauth the server owes for that header (RFC 7616 clause 3.5).
    pub(super) fn response_auth(&self, challenge: &str, count: u32) -> String {
        self.keyed(challenge, count, &format!(":{}", self.uri))
    }
}
