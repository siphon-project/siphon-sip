//! The script side of the Cx requests an I-CSCF or S-CSCF sends: argument
//! checks, what `auth.require_ims_digest` puts in its Multimedia-Auth-Request,
//! and the dict a Multimedia-Auth-Answer becomes.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use crate::diameter::codec::{parse_avps, Avp, AvpData, DiameterMessage, DiameterMsg};
use crate::diameter::cx::{self, MultimediaAuth};
use crate::diameter::dictionary::{self, avp};

/// SIP-Item-Number (TS 29.229 clause 6.3.14).
const SIP_ITEM_NUMBER: u32 = 613;
/// SIP-Digest-Authenticate (TS 29.229 clause 6.3.36), grouped, vendor 10415.
const SIP_DIGEST_AUTHENTICATE: u32 = 635;
/// The members of SIP-Digest-Authenticate, which TS 29.229 clauses 6.3.37 to
/// 6.3.41 take from RFC 4740 with no vendor.
const DIGEST_REALM: u32 = 104;
const DIGEST_QOP: u32 = 110;
const DIGEST_ALGORITHM: u32 = 111;
const DIGEST_HA1: u32 = 121;

/// The User-Name of a UAR: the private identity the script gave, or the one
/// TS 24.229 clause 5.3.1.2 derives from the public identity.
pub(crate) fn uar_user_name(user_name: Option<&str>, public_identity: &str) -> String {
    match user_name {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => cx::derive_private_identity(public_identity),
    }
}

/// What a Multimedia-Auth-Request says about the registration it is for.
pub(crate) struct ImsRegistration {
    pub(crate) public_identity: String,
    /// The private user identity (User-Name).
    pub(crate) user_name: String,
    /// The S-CSCF's own SIP URI (Server-Name), when the script gave one.
    pub(crate) server_name: Option<String>,
    /// The Authorization header of the REGISTER, if it had one.
    pub(crate) authorization: Option<String>,
}

/// The private user identity of a REGISTER: the `username` of its
/// Authorization header, or without one the identity derived from the public
/// user identity (TS 24.229 clause 5.4.1.1).
pub(crate) fn ims_private_identity(authorization: Option<&str>, public_identity: &str) -> String {
    authorization
        .and_then(|value| super::auth::extract_digest_param(value, "username"))
        .filter(|username| !username.is_empty())
        .unwrap_or_else(|| cx::derive_private_identity(public_identity))
}

/// The peer a Cx request goes to: the one the `cx` route names, never a peer
/// of another application.
pub(crate) fn cx_client(
    diameter: &crate::diameter::DiameterManager,
) -> PyResult<std::sync::Arc<crate::diameter::DiameterClient>> {
    diameter
        .route_client(&crate::config::DiameterApplication::Cx, None)
        .ok_or_else(|| pyo3::exceptions::PyRuntimeError::new_err("no Diameter peer connected"))
}

/// The arguments of `diameter.cx_mar`, owned so they can cross an await.
#[derive(Debug)]
pub(crate) struct MarArguments {
    public_identity: String,
    user_name: String,
    server_name: String,
    scheme: String,
    number_auth_items: u32,
    authorization: Option<Vec<u8>>,
}

impl MarArguments {
    /// Refuses what TS 29.229 clause 6.1.7 does not let a MAR go without.
    pub(crate) fn new(
        public_identity: &str,
        user_name: &str,
        server_name: &str,
        scheme: Option<&str>,
        number_auth_items: u32,
        authorization: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        for (name, value) in [
            ("public_identity", public_identity),
            ("user_name", user_name),
            ("server_name", server_name),
        ] {
            if value.is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "cx_mar: {name} must not be empty"
                )));
            }
        }
        if number_auth_items == 0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "cx_mar: number_auth_items must be at least 1",
            ));
        }
        Ok(Self {
            public_identity: public_identity.to_string(),
            user_name: user_name.to_string(),
            server_name: server_name.to_string(),
            scheme: scheme.unwrap_or(cx::SCHEME_IMS_AKA).to_string(),
            number_auth_items,
            authorization,
        })
    }

    pub(crate) fn request(&self) -> MultimediaAuth<'_> {
        MultimediaAuth {
            public_identity: &self.public_identity,
            user_name: &self.user_name,
            server_name: Some(&self.server_name),
            sip_number_auth_items: self.number_auth_items,
            sip_auth_scheme: &self.scheme,
            sip_authorization: self.authorization.as_deref(),
        }
    }
}

/// The dict `diameter.cx_sar` resolves to: `result_code`, and `user_data`,
/// the iFC XML of the User-Data AVP (606, an OctetString) or `None`.
pub(crate) fn sar_answer_dict(
    python: Python<'_>,
    answer: &DiameterMessage,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item(
        "result_code",
        crate::diameter::rx::extract_result_code(&answer.avps),
    )?;
    dict.set_item(
        "user_data",
        cx::octet_string_as_utf8(&answer.avps, "User-Data"),
    )?;
    Ok(dict.unbind())
}

/// The dict `diameter.cx_uar` and `diameter.cx_lir` resolve to: `result_code`,
/// `server_name` (the top-level Server-Name, or `None`) and
/// `server_capabilities`, the Server-Capabilities AVP or `None` when the HSS
/// sent none (TS 29.229 clause 6.3.4). A UAA and a LIA carry the same two
/// AVPs (TS 29.228 clauses 6.1.1.1 and 6.1.4.1).
pub(crate) fn server_answer_dict(
    python: Python<'_>,
    answer: &DiameterMessage,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item(
        "result_code",
        crate::diameter::rx::extract_result_code(&answer.avps),
    )?;
    dict.set_item("server_name", cx::required_str(&answer.avps, "Server-Name"))?;
    dict.set_item("server_capabilities", server_capabilities(python, answer)?)?;
    Ok(dict.unbind())
}

/// Server-Capabilities as `{"mandatory": [int], "optional": [int],
/// "server_names": [str]}`, each list in the order the HSS sent it, or `None`
/// without the AVP.
fn server_capabilities<'py>(
    python: Python<'py>,
    answer: &DiameterMessage,
) -> PyResult<Option<Bound<'py, PyDict>>> {
    let vendor = dictionary::VENDOR_3GPP;
    let Ok(message) = DiameterMsg::from_wire(&answer.raw) else {
        return Ok(None);
    };
    let Some(group) = message.find(avp::SERVER_CAPABILITIES, vendor) else {
        return Ok(None);
    };
    let children = members(group);
    let of = |code: u32| {
        children
            .iter()
            .filter(move |c| c.code == code && c.vendor == vendor)
    };
    let mandatory: Vec<u32> = of(avp::MANDATORY_CAPABILITY)
        .filter_map(Avp::as_u32)
        .collect();
    let optional: Vec<u32> = of(avp::OPTIONAL_CAPABILITY)
        .filter_map(Avp::as_u32)
        .collect();
    let names: Vec<String> = of(avp::SERVER_NAME).filter_map(Avp::as_str).collect();
    let dict = PyDict::new(python);
    dict.set_item("mandatory", mandatory)?;
    dict.set_item("optional", optional)?;
    dict.set_item("server_names", names)?;
    Ok(Some(dict))
}

/// The members of a grouped AVP, whether or not the dictionary knew it was one.
fn members(group: &Avp) -> Vec<Avp> {
    match &group.value {
        AvpData::Grouped(children) => children.clone(),
        AvpData::Raw(bytes) => parse_avps(bytes).unwrap_or_default(),
    }
}

fn member(children: &[Avp], code: u32, vendor: u32) -> Option<&Avp> {
    children
        .iter()
        .find(|child| child.code == code && child.vendor == vendor)
}

/// One SIP-Auth-Data-Item as a dict. A key is absent when the HSS did not
/// send the AVP.
fn auth_item_dict<'py>(python: Python<'py>, item: &Avp) -> PyResult<Bound<'py, PyDict>> {
    let children = members(item);
    let dict = PyDict::new(python);
    let vendor = dictionary::VENDOR_3GPP;
    if let Some(number) = member(&children, SIP_ITEM_NUMBER, vendor).and_then(Avp::as_u32) {
        dict.set_item("item_number", number)?;
    }
    if let Some(scheme) =
        member(&children, avp::SIP_AUTHENTICATION_SCHEME, vendor).and_then(Avp::as_str)
    {
        dict.set_item("scheme", scheme)?;
    }
    for (key, code) in [
        ("authenticate", avp::SIP_AUTHENTICATE),
        ("authorization", avp::SIP_AUTHORIZATION),
        ("confidentiality_key", avp::CONFIDENTIALITY_KEY),
        ("integrity_key", avp::INTEGRITY_KEY),
    ] {
        if let Some(bytes) = member(&children, code, vendor).and_then(Avp::raw_bytes) {
            dict.set_item(key, PyBytes::new(python, bytes))?;
        }
    }
    if let Some(digest) = member(&children, SIP_DIGEST_AUTHENTICATE, vendor) {
        let digest_children = members(digest);
        for (key, code) in [
            ("digest_realm", DIGEST_REALM),
            ("digest_algorithm", DIGEST_ALGORITHM),
            ("digest_qop", DIGEST_QOP),
            ("digest_ha1", DIGEST_HA1),
        ] {
            if let Some(text) = member(&digest_children, code, 0).and_then(Avp::as_str) {
                dict.set_item(key, text)?;
            }
        }
    }
    Ok(dict)
}

/// The dict `diameter.cx_mar` resolves to: `result_code`, and `auth_items`,
/// one dict per SIP-Auth-Data-Item in the order the HSS sent them.
pub(crate) fn mar_answer_dict(
    python: Python<'_>,
    answer: &DiameterMessage,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item(
        "result_code",
        crate::diameter::rx::extract_result_code(&answer.avps),
    )?;
    dict.set_item("auth_items", auth_items(python, answer)?)?;
    Ok(dict.unbind())
}

/// One dict per SIP-Auth-Data-Item of a Multimedia-Auth-Answer, in the order
/// the HSS sent them. Cx and Zh answers carry the same item (TS 29.109 clause
/// 6.3: "The AVPs defined in 3GPP TS 29.229 [3] ... are used as they are").
pub(crate) fn auth_items<'py>(
    python: Python<'py>,
    answer: &DiameterMessage,
) -> PyResult<Bound<'py, PyList>> {
    let items = PyList::empty(python);
    if let Ok(message) = DiameterMsg::from_wire(&answer.raw) {
        for item in message.find_all(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP) {
            items.append(auth_item_dict(python, item)?)?;
        }
    }
    Ok(items)
}

/// The Cx features a SAR advertises: `SiFC` once this S-CSCF has a shared
/// iFC set to resolve ids against (TS 29.229 §7.1.1), else none, so an HSS
/// keeps sending the complete iFCs (TS 29.228 §6.1.2).
pub(super) fn sar_supported_features() -> u32 {
    let shared_sets = super::ifc_store_arc().is_some_and(|store| store.has_shared_sets());
    if shared_sets {
        crate::diameter::cx::FEATURE_SIFC
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{
        decode_diameter, encode_avp, encode_avp_grouped_3gpp, encode_avp_octet_3gpp,
        encode_avp_u32, encode_avp_u32_3gpp, encode_avp_utf8, encode_avp_utf8_3gpp,
        encode_diameter_message, AVP_FLAG_MANDATORY, FLAG_PROXIABLE,
    };
    use crate::diameter::cx_test_support::{
        mock_hss_client, MOCK_CONFIDENTIALITY_KEY, MOCK_INTEGRITY_KEY, MOCK_SIP_AUTHENTICATE,
        MOCK_SIP_AUTHORIZATION,
    };
    use crate::diameter::DiameterManager;
    use crate::script::api::diameter::PyDiameter;
    use std::sync::Arc;

    const PUBLIC_IDENTITY: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    const PRIVATE_IDENTITY: &str = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    const SCSCF_URI: &str = "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060";

    #[test]
    fn uar_user_name_is_the_given_identity_or_the_derived_one() {
        assert_eq!(
            uar_user_name(Some("private@example.com"), "sip:public@example.com"),
            "private@example.com"
        );
        assert_eq!(
            uar_user_name(None, "sip:public@example.com:5060"),
            "public@example.com"
        );
        assert_eq!(
            uar_user_name(Some(""), "sip:public@example.com"),
            "public@example.com"
        );
    }

    #[test]
    fn mar_arguments_refuse_what_the_command_requires() {
        pyo3::Python::initialize();
        for (public, user, server, items, expected) in [
            ("", "u@example.com", SCSCF_URI, 1, "public_identity"),
            (PUBLIC_IDENTITY, "", SCSCF_URI, 1, "user_name"),
            (PUBLIC_IDENTITY, PRIVATE_IDENTITY, "", 1, "server_name"),
            (
                PUBLIC_IDENTITY,
                PRIVATE_IDENTITY,
                SCSCF_URI,
                0,
                "number_auth_items",
            ),
        ] {
            let error = MarArguments::new(public, user, server, None, items, None).unwrap_err();
            pyo3::Python::attach(|python| {
                assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            });
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn mar_arguments_default_to_the_ims_aka_scheme() {
        let arguments =
            MarArguments::new(PUBLIC_IDENTITY, PRIVATE_IDENTITY, SCSCF_URI, None, 1, None).unwrap();
        assert_eq!(arguments.request().sip_auth_scheme, "Digest-AKAv1-MD5");
        assert_eq!(arguments.request().server_name, Some(SCSCF_URI));
    }

    /// A Multimedia-Auth-Answer written out AVP by AVP from TS 29.229 clause
    /// 6.1.8, with an IMS AKA item and a SIP Digest item.
    fn two_item_answer() -> DiameterMessage {
        let mut aka = Vec::new();
        aka.extend_from_slice(&encode_avp_u32_3gpp(613, 1));
        aka.extend_from_slice(&encode_avp_utf8_3gpp(608, "Digest-AKAv1-MD5"));
        aka.extend_from_slice(&encode_avp_octet_3gpp(609, &[0xaa; 32]));
        aka.extend_from_slice(&encode_avp_octet_3gpp(610, &[0xbb; 8]));
        aka.extend_from_slice(&encode_avp_octet_3gpp(625, &[0xcc; 16]));
        aka.extend_from_slice(&encode_avp_octet_3gpp(626, &[0xdd; 16]));

        let mut digest = Vec::new();
        digest.extend_from_slice(&encode_avp(104, AVP_FLAG_MANDATORY, b"example.com"));
        digest.extend_from_slice(&encode_avp(111, AVP_FLAG_MANDATORY, b"MD5"));
        digest.extend_from_slice(&encode_avp(110, AVP_FLAG_MANDATORY, b"auth"));
        digest.extend_from_slice(&encode_avp(
            121,
            AVP_FLAG_MANDATORY,
            b"0123456789abcdef0123456789abcdef",
        ));
        let mut sip_digest = Vec::new();
        sip_digest.extend_from_slice(&encode_avp_u32_3gpp(613, 2));
        sip_digest.extend_from_slice(&encode_avp_utf8_3gpp(608, "SIP Digest"));
        sip_digest.extend_from_slice(&encode_avp_grouped_3gpp(635, &digest));

        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(263, "scscf;1;1"));
        avps.extend_from_slice(&encode_avp_u32(268, 2001));
        avps.extend_from_slice(&encode_avp_u32_3gpp(607, 2));
        avps.extend_from_slice(&encode_avp_grouped_3gpp(612, &aka));
        avps.extend_from_slice(&encode_avp_grouped_3gpp(612, &sip_digest));
        let wire = encode_diameter_message(FLAG_PROXIABLE, 303, 16_777_216, 1, 1, &avps);
        decode_diameter(&wire).unwrap()
    }

    #[test]
    fn mar_answer_dict_lists_every_auth_item_in_order() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let dict = mar_answer_dict(python, &two_item_answer()).unwrap();
            let dict = dict.bind(python);
            let result_code: u32 = dict
                .get_item("result_code")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(result_code, 2001);
            let items = dict.get_item("auth_items").unwrap().unwrap();
            assert_eq!(items.len().unwrap(), 2);

            let aka = items.get_item(0).unwrap();
            let text = |item: &Bound<'_, PyAny>, key: &str| -> String {
                item.get_item(key).unwrap().extract().unwrap()
            };
            let bytes = |item: &Bound<'_, PyAny>, key: &str| -> Vec<u8> {
                item.get_item(key).unwrap().extract().unwrap()
            };
            assert_eq!(text(&aka, "scheme"), "Digest-AKAv1-MD5");
            assert_eq!(bytes(&aka, "authenticate"), vec![0xaa; 32]);
            assert_eq!(bytes(&aka, "authorization"), vec![0xbb; 8]);
            assert_eq!(bytes(&aka, "confidentiality_key"), vec![0xcc; 16]);
            assert_eq!(bytes(&aka, "integrity_key"), vec![0xdd; 16]);
            assert!(!aka.contains("digest_ha1").unwrap());

            let digest = items.get_item(1).unwrap();
            let number: u32 = digest.get_item("item_number").unwrap().extract().unwrap();
            assert_eq!(number, 2);
            assert_eq!(text(&digest, "scheme"), "SIP Digest");
            assert_eq!(text(&digest, "digest_realm"), "example.com");
            assert_eq!(text(&digest, "digest_algorithm"), "MD5");
            assert_eq!(text(&digest, "digest_qop"), "auth");
            assert_eq!(
                text(&digest, "digest_ha1"),
                "0123456789abcdef0123456789abcdef"
            );
            assert!(!digest.contains("authenticate").unwrap());
        });
    }

    /// Calls an awaitable method the way an `async def` handler does.
    const HELPER_SOURCE: &str = "import asyncio\ndef call(target, method, args, kwargs):\n    async def run():\n        return await getattr(target, method)(*args, **kwargs)\n    return asyncio.run(run())\n";

    fn call<'py>(
        python: Python<'py>,
        diameter: &Bound<'py, PyDiameter>,
        method: &str,
        arguments: Bound<'py, pyo3::types::PyTuple>,
        keywords: Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let helper = pyo3::types::PyModule::from_code(
            python,
            &std::ffi::CString::new(HELPER_SOURCE).expect("helper source"),
            &std::ffi::CString::new("_cx_test_helper.py").expect("file"),
            &std::ffi::CString::new("_cx_test_helper").expect("module"),
        )?;
        helper
            .getattr("call")?
            .call1((diameter, method, arguments, keywords))
    }

    async fn diameter_with_mock_hss() -> (PyDiameter, Arc<std::sync::Mutex<Vec<serde_json::Value>>>)
    {
        pyo3::Python::initialize();
        let (client, captured) = mock_hss_client().await;
        let manager = Arc::new(DiameterManager::new());
        manager.register("hss".to_string(), client);
        (PyDiameter::new(manager), captured)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cx_mar_sends_the_mandatory_avps_and_returns_the_vector() {
        let (diameter, captured) = diameter_with_mock_hss().await;
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let arguments = pyo3::types::PyTuple::new(
                    python,
                    [PUBLIC_IDENTITY, PRIVATE_IDENTITY, SCSCF_URI],
                )
                .unwrap();
                let result = call(
                    python,
                    diameter.bind(python),
                    "cx_mar",
                    arguments,
                    PyDict::new(python),
                )
                .unwrap();
                let code: u32 = result.get_item("result_code").unwrap().extract().unwrap();
                assert_eq!(code, 2001);
                let item = result.get_item("auth_items").unwrap().get_item(0).unwrap();
                let bytes =
                    |key: &str| -> Vec<u8> { item.get_item(key).unwrap().extract().unwrap() };
                assert_eq!(bytes("authenticate"), MOCK_SIP_AUTHENTICATE);
                assert_eq!(bytes("authorization"), MOCK_SIP_AUTHORIZATION);
                assert_eq!(bytes("confidentiality_key"), MOCK_CONFIDENTIALITY_KEY);
                assert_eq!(bytes("integrity_key"), MOCK_INTEGRITY_KEY);
            });
        })
        .await
        .unwrap();

        let requests = captured.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let mar = &requests[0];
        assert_eq!(mar["User-Name"], PRIVATE_IDENTITY);
        assert_eq!(mar["Server-Name"], SCSCF_URI);
        assert_eq!(mar["Public-Identity"], PUBLIC_IDENTITY);
        assert_eq!(mar["SIP-Number-Auth-Items"], 1);
        assert_eq!(
            mar["SIP-Auth-Data-Item"]["SIP-Authentication-Scheme"],
            "Digest-AKAv1-MD5"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cx_uar_sends_the_private_identity_given_or_derived() {
        let (diameter, captured) = diameter_with_mock_hss().await;
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let diameter = diameter.bind(python);
                let derived = pyo3::types::PyTuple::new(python, [PUBLIC_IDENTITY]).unwrap();
                call(python, diameter, "cx_uar", derived, PyDict::new(python)).unwrap();

                let given = pyo3::types::PyTuple::new(python, [PUBLIC_IDENTITY]).unwrap();
                let keywords = PyDict::new(python);
                keywords
                    .set_item("user_name", "private@example.com")
                    .unwrap();
                call(python, diameter, "cx_uar", given, keywords).unwrap();
            });
        })
        .await
        .unwrap();

        let requests = captured.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["User-Name"], PRIVATE_IDENTITY);
        assert_eq!(requests[1]["User-Name"], "private@example.com");
    }

    /// Server-Capabilities written out from TS 29.229 clause 6.3.4: two
    /// Mandatory-Capability, one Optional-Capability, two Server-Name.
    fn capabilities_avp() -> Vec<u8> {
        let mut group = Vec::new();
        group.extend_from_slice(&encode_avp_u32_3gpp(604, 7));
        group.extend_from_slice(&encode_avp_u32_3gpp(604, 3));
        group.extend_from_slice(&encode_avp_u32_3gpp(605, 9));
        group.extend_from_slice(&encode_avp_utf8_3gpp(602, "sip:scscf-a.example.net:6060"));
        group.extend_from_slice(&encode_avp_utf8_3gpp(602, "sip:scscf-b.example.net:6060"));
        encode_avp_grouped_3gpp(603, &group)
    }

    fn capabilities_answer(command_code: u32) -> DiameterMessage {
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(263, "icscf;1;1"));
        avps.extend_from_slice(&encode_avp_u32(268, 2001));
        avps.extend_from_slice(&capabilities_avp());
        let wire = encode_diameter_message(FLAG_PROXIABLE, command_code, 16_777_216, 1, 1, &avps);
        decode_diameter(&wire).unwrap()
    }

    fn assert_capabilities(dict: &Bound<'_, PyAny>) {
        let capabilities = dict.get_item("server_capabilities").unwrap();
        let mandatory: Vec<u32> = capabilities
            .get_item("mandatory")
            .unwrap()
            .extract()
            .unwrap();
        let optional: Vec<u32> = capabilities
            .get_item("optional")
            .unwrap()
            .extract()
            .unwrap();
        let names: Vec<String> = capabilities
            .get_item("server_names")
            .unwrap()
            .extract()
            .unwrap();
        assert_eq!(mandatory, vec![7, 3]);
        assert_eq!(optional, vec![9]);
        assert_eq!(
            names,
            vec![
                "sip:scscf-a.example.net:6060",
                "sip:scscf-b.example.net:6060"
            ]
        );
    }

    #[test]
    fn server_answer_dict_carries_the_capabilities_of_a_uaa_and_a_lia() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            for command_code in [300, 302] {
                let dict = server_answer_dict(python, &capabilities_answer(command_code)).unwrap();
                let dict = dict.bind(python).clone().into_any();
                let code: u32 = dict.get_item("result_code").unwrap().extract().unwrap();
                assert_eq!(code, 2001);
                // The names inside Server-Capabilities are candidates, not
                // the assigned S-CSCF.
                assert!(dict.get_item("server_name").unwrap().is_none());
                assert_capabilities(&dict);
            }
        });
    }

    #[test]
    fn server_answer_dict_without_capabilities_says_none() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let mut avps = Vec::new();
            avps.extend_from_slice(&encode_avp_utf8(263, "icscf;1;1"));
            avps.extend_from_slice(&encode_avp_u32(268, 2001));
            avps.extend_from_slice(&encode_avp_utf8_3gpp(602, SCSCF_URI));
            let wire = encode_diameter_message(FLAG_PROXIABLE, 300, 16_777_216, 1, 1, &avps);
            let dict = server_answer_dict(python, &decode_diameter(&wire).unwrap()).unwrap();
            let dict = dict.bind(python);
            let name: String = dict
                .get_item("server_name")
                .unwrap()
                .unwrap()
                .extract()
                .unwrap();
            assert_eq!(name, SCSCF_URI);
            assert!(dict
                .get_item("server_capabilities")
                .unwrap()
                .unwrap()
                .is_none());
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cx_uar_and_cx_lir_return_the_capabilities_the_hss_sent() {
        use crate::diameter::cx_test_support::{answer_scaffold, finish_answer, MockHss};
        pyo3::Python::initialize();
        let hss = MockHss::start(|request| {
            let mut avps = answer_scaffold(request);
            avps.extend_from_slice(&encode_avp_u32(268, 2001));
            avps.extend_from_slice(&capabilities_avp());
            finish_answer(request, &avps)
        })
        .await;
        let manager = Arc::new(DiameterManager::new());
        manager.register("hss".to_string(), Arc::clone(&hss.client));
        let diameter = PyDiameter::new(manager);
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let diameter = diameter.bind(python);
                let uar_keywords = PyDict::new(python);
                uar_keywords.set_item("user_auth_type", 2).unwrap();
                for (method, keywords) in
                    [("cx_uar", uar_keywords), ("cx_lir", PyDict::new(python))]
                {
                    let arguments = pyo3::types::PyTuple::new(python, [PUBLIC_IDENTITY]).unwrap();
                    let result = call(python, diameter, method, arguments, keywords).unwrap();
                    assert_capabilities(&result);
                }
            });
        })
        .await
        .unwrap();
        assert_eq!(hss.requests().len(), 2);
    }

    #[test]
    fn cx_mar_resolves_to_none_without_a_peer() {
        pyo3::Python::initialize();
        let diameter = PyDiameter::new(Arc::new(DiameterManager::new()));
        pyo3::Python::attach(|python| {
            let diameter = Py::new(python, diameter).unwrap();
            let arguments =
                pyo3::types::PyTuple::new(python, [PUBLIC_IDENTITY, PRIVATE_IDENTITY, SCSCF_URI])
                    .unwrap();
            let result = call(
                python,
                diameter.bind(python),
                "cx_mar",
                arguments,
                PyDict::new(python),
            )
            .unwrap();
            assert!(result.is_none());
        });
    }
}
