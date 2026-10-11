//! What the `require_ims_digest` tests share: a subscriber server that
//! answers Multimedia-Auth-Requests the way TS 29.228 clause 6.3.1 describes,
//! and a REGISTER to run through the flow.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use serde_json::Value;

use super::ims::registration_of;
use super::PyAuth;
use crate::diameter::codec::{
    self, encode_avp_grouped_3gpp, encode_avp_octet_3gpp, encode_avp_u32, encode_avp_u32_3gpp,
    encode_avp_utf8, encode_avp_utf8_3gpp, DiameterMessage,
};
use crate::diameter::cx_test_support::{
    answer_scaffold, experimental_answer, finish_answer, MockHss as Server,
};
use crate::diameter::dictionary::{self, avp};
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
/// SIP-Item-Number (TS 29.229 clause 6.3.14).
const SIP_ITEM_NUMBER: u32 = 613;
/// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED (TS 29.229 clause 6.2.2.6).
const AUTH_SCHEME_NOT_SUPPORTED: u32 = 5006;
pub(super) const AUTN: [u8; 16] = [0x22; 16];
pub(super) const AUTS: [u8; 14] = [0x44; 14];

/// How the subscriber server at the far end answers a MAR.
#[derive(Clone, Copy)]
pub(super) enum Hss {
    /// A subscriber provisioned for IMS-AKA, and TS 29.228 clause 6.3.1 step
    /// 4: a vector for a request that names IMS-AKA,
    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED for one that names another
    /// scheme or "Unknown" (which only resolves to NASS-Bundled or SIP
    /// Digest).
    Conformant,
    /// Success, with an IMS-AKA shaped item labelled as this scheme whatever
    /// was asked.
    AnswersScheme(&'static str),
    /// DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED whatever was asked.
    RefusesScheme,
    /// DIAMETER_SUCCESS in IMS-AKA without this AVP: "SIP-Auth-Data-Item", or
    /// one of its members.
    Omits(&'static str),
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
        Hss::AnswersScheme(scheme) => Some(aka_item(request, scheme, None, rand_fill)),
        Hss::Omits("SIP-Auth-Data-Item") => None,
        Hss::Omits(name) => Some(aka_item(request, IMS_AKA, Some(name), rand_fill)),
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
}

impl Registration {
    /// A REGISTER of [`PUBLIC_IDENTITY`] through an S-CSCF that passes its
    /// name.
    pub(super) fn new(authorization: Option<String>) -> Self {
        Self {
            to: format!("<{PUBLIC_IDENTITY}>"),
            authorization,
            server_name: Some(SCSCF),
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
            .call_id("ims-register@192.0.2.10".to_string())
            .cseq("1 REGISTER".to_string())
            .header(
                "P-Asserted-Identity",
                format!("<sip:001010000000003@{REALM}>"),
            )
            .content_length(0);
        if let Some(value) = &self.authorization {
            builder = builder.header("Authorization", value.clone());
        }
        let message = builder.build().unwrap();
        let read = registration_of(&message.headers, self.server_name);
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
        )
        .await;

        Python::attach(|python| {
            let request = kept.borrow(python);
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
            Outcome {
                result,
                reply,
                challenge: challenges.first().cloned(),
                challenges,
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
    pub(super) auth_user: Option<String>,
}

impl Outcome {
    /// Refused with 403: no challenge, nobody authenticated.
    pub(super) fn assert_forbidden(&self) {
        assert!(!self.result.as_ref().unwrap(), "refused, not verified");
        assert_eq!(self.reply, Some(403));
        assert!(self.challenges.is_empty(), "{:?}", self.challenges);
        assert_eq!(self.auth_user, None);
    }
}
