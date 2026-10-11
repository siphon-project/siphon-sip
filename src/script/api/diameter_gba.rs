//! The script side of GBA over Diameter (TS 29.109): the arguments of
//! `diameter.zh_mar` and `diameter.zn_bir`, and the dicts their answers
//! become.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};

use crate::diameter::codec::DiameterMessage;
use crate::diameter::cx::octet_string_as_utf8;
use crate::diameter::gba::{BootstrappingInfo, ZhMultimediaAuth, RESYNCHRONISATION_LENGTH};

fn value_error(message: String) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(message)
}

/// `None` for an argument left out or given empty.
fn given(value: Option<&str>) -> Option<String> {
    value.filter(|text| !text.is_empty()).map(str::to_string)
}

/// The arguments of `diameter.zh_mar`, owned so they can cross an await.
#[derive(Debug)]
pub(crate) struct ZhMarArguments {
    user_name: Option<String>,
    public_identity: Option<String>,
    scheme: Option<String>,
    authorization: Option<Vec<u8>>,
    guss_timestamp: Option<u64>,
}

impl ZhMarArguments {
    /// Refuses a request that names no user, and resynchronisation material
    /// that is not RAND || AUTS.
    pub(crate) fn new(
        user_name: Option<&str>,
        authorization: Option<Vec<u8>>,
        scheme: Option<&str>,
        public_identity: Option<&str>,
        guss_timestamp: Option<u64>,
    ) -> PyResult<Self> {
        let user_name = given(user_name);
        let public_identity = given(public_identity);
        if user_name.is_none() && public_identity.is_none() {
            return Err(value_error(
                "zh_mar: user_name or public_identity is required".to_string(),
            ));
        }
        if let Some(authorization) = &authorization {
            if authorization.len() != RESYNCHRONISATION_LENGTH {
                return Err(value_error(format!(
                    "zh_mar: authorization must be RAND || AUTS, {RESYNCHRONISATION_LENGTH} \
                     octets, got {}",
                    authorization.len()
                )));
            }
        }
        if scheme.is_some_and(str::is_empty) {
            return Err(value_error("zh_mar: scheme must not be empty".to_string()));
        }
        Ok(Self {
            user_name,
            public_identity,
            scheme: scheme.map(str::to_string),
            authorization,
            guss_timestamp,
        })
    }

    pub(crate) fn request(&self) -> ZhMultimediaAuth<'_> {
        ZhMultimediaAuth {
            user_name: self.user_name.as_deref(),
            public_identity: self.public_identity.as_deref(),
            sip_auth_scheme: self.scheme.as_deref(),
            sip_authorization: self.authorization.as_deref(),
            guss_timestamp: self.guss_timestamp,
        }
    }
}

/// An OctetString argument: `bytes`, or a `str` taken as its UTF-8 octets.
pub(crate) fn octets(name: &str, value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(text) = value.extract::<String>() {
        return Ok(text.into_bytes());
    }
    value.extract::<Vec<u8>>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(format!("zn_bir: {name} expects bytes or str"))
    })
}

/// The arguments of `diameter.zn_bir`, owned so they can cross an await.
#[derive(Debug)]
pub(crate) struct ZnBirArguments {
    transaction_identifier: Vec<u8>,
    naf_id: Vec<u8>,
    gaa_service_identifiers: Vec<Vec<u8>>,
    gba_u_aware: Option<bool>,
    destination_realm: Option<String>,
    destination_host: Option<String>,
}

impl ZnBirArguments {
    /// Refuses what TS 29.109 clause 5.2 puts in braces and the NAF left
    /// empty: `{ Transaction-Identifier }` and `{ NAF-Id }`.
    pub(crate) fn new(
        transaction_identifier: Vec<u8>,
        naf_id: Vec<u8>,
        gaa_service_identifiers: Vec<Vec<u8>>,
        gba_u_aware: Option<bool>,
        destination_realm: Option<&str>,
        destination_host: Option<&str>,
    ) -> PyResult<Self> {
        if transaction_identifier.is_empty() {
            return Err(value_error(
                "zn_bir: transaction_identifier must not be empty".to_string(),
            ));
        }
        if naf_id.is_empty() {
            return Err(value_error("zn_bir: naf_id must not be empty".to_string()));
        }
        Ok(Self {
            transaction_identifier,
            naf_id,
            gaa_service_identifiers,
            gba_u_aware,
            destination_realm: given(destination_realm),
            destination_host: given(destination_host),
        })
    }

    pub(crate) fn request(&self) -> BootstrappingInfo<'_> {
        BootstrappingInfo {
            transaction_identifier: &self.transaction_identifier,
            naf_id: &self.naf_id,
            gaa_service_identifiers: &self.gaa_service_identifiers,
            gba_u_aware: self.gba_u_aware,
            destination_realm: self.destination_realm.as_deref(),
            destination_host: self.destination_host.as_deref(),
        }
    }
}

/// `result_code`, by the rule `cx_mar` follows (the Result-Code, or without
/// one the Experimental-Result-Code), and `experimental_result_code`, which
/// is `None` unless the answer carried an Experimental-Result: TS 29.109
/// clause 6.2 reports 5401, 5402 and 5403 there, with no Result-Code.
fn set_result_codes(dict: &Bound<'_, PyDict>, answer: &DiameterMessage) -> PyResult<()> {
    dict.set_item(
        "result_code",
        crate::diameter::rx::extract_result_code(&answer.avps),
    )?;
    let experimental = answer
        .avps
        .get("Experimental-Result")
        .and_then(|group| group.get("Experimental-Result-Code"))
        .and_then(serde_json::Value::as_u64);
    dict.set_item("experimental_result_code", experimental)
}

/// A top-level AVP of a text type.
fn text(answer: &DiameterMessage, name: &str) -> Option<String> {
    answer
        .avps
        .get(name)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// A top-level OctetString AVP, which the decoded answer holds as hex.
fn octet_string(answer: &DiameterMessage, name: &str) -> Option<Vec<u8>> {
    answer
        .avps
        .get(name)
        .and_then(serde_json::Value::as_str)
        .and_then(crate::diameter::codec::hex::decode)
}

/// A top-level Unsigned32, Enumerated or Time AVP. A Time is Unix seconds.
fn number(answer: &DiameterMessage, name: &str) -> Option<u64> {
    answer.avps.get(name).and_then(serde_json::Value::as_u64)
}

/// The dict `diameter.zh_mar` resolves to: the result codes, `user_name`,
/// `auth_items` as `cx_mar` gives them, and `guss`, the GBA-UserSecSettings
/// (TS 29.109 clause 6.3.1.1, an XML document) as text.
pub(crate) fn zh_mar_answer_dict(
    python: Python<'_>,
    answer: &DiameterMessage,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(python);
    set_result_codes(&dict, answer)?;
    dict.set_item("user_name", text(answer, "User-Name"))?;
    dict.set_item(
        "auth_items",
        super::diameter_cx::auth_items(python, answer)?,
    )?;
    dict.set_item(
        "guss",
        octet_string_as_utf8(&answer.avps, "GBA-UserSecSettings"),
    )?;
    Ok(dict.unbind())
}

/// The dict `diameter.zn_bir` resolves to. A key whose AVP the BSF did not
/// send is `None`.
pub(crate) fn zn_bir_answer_dict(
    python: Python<'_>,
    answer: &DiameterMessage,
) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(python);
    set_result_codes(&dict, answer)?;
    dict.set_item("user_name", text(answer, "User-Name"))?;
    for (key, name) in [
        ("me_key_material", "ME-Key-Material"),
        ("uicc_key_material", "UICC-Key-Material"),
    ] {
        let value = octet_string(answer, name).map(|octets| PyBytes::new(python, &octets));
        dict.set_item(key, value)?;
    }
    for (key, name) in [
        ("key_expiry_time", "Key-ExpiryTime"),
        ("bootstrap_info_creation_time", "BootstrapInfoCreationTime"),
        ("gba_type", "GBA-Type"),
    ] {
        dict.set_item(key, number(answer, name))?;
    }
    dict.set_item(
        "user_sec_settings",
        octet_string_as_utf8(&answer.avps, "GBA-UserSecSettings"),
    )?;
    Ok(dict.unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::codec::{decode_diameter, DiameterMsg};
    use crate::diameter::gba::test_support::{answering_peer, bsf_peer_config, naf_peer_config};
    use crate::diameter::gba_test_vectors as vectors;
    use crate::diameter::DiameterManager;
    use crate::script::api::diameter::PyDiameter;
    use pyo3::types::PyTuple;
    use std::sync::Arc;

    fn decoded(octets: &[u8]) -> DiameterMessage {
        decode_diameter(octets).expect("a hand-written answer decodes")
    }

    fn bytes_of(dict: &Bound<'_, PyAny>, key: &str) -> Vec<u8> {
        dict.get_item(key).unwrap().extract().unwrap()
    }

    fn text_of(dict: &Bound<'_, PyAny>, key: &str) -> String {
        dict.get_item(key).unwrap().extract().unwrap()
    }

    fn number_of(dict: &Bound<'_, PyAny>, key: &str) -> u64 {
        dict.get_item(key).unwrap().extract().unwrap()
    }

    fn is_none(dict: &Bound<'_, PyAny>, key: &str) -> bool {
        dict.get_item(key).unwrap().is_none()
    }

    #[test]
    fn a_zh_answer_becomes_the_vector_and_the_guss() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let dict = zh_mar_answer_dict(python, &decoded(vectors::ZH_MAA)).unwrap();
            let dict = dict.bind(python).as_any();
            assert_eq!(number_of(dict, "result_code"), 2001);
            assert!(is_none(dict, "experimental_result_code"));
            assert_eq!(text_of(dict, "user_name"), vectors::IMPI);
            assert_eq!(text_of(dict, "guss"), vectors::GUSS);

            let items = dict.get_item("auth_items").unwrap();
            assert_eq!(items.len().unwrap(), 1);
            let item = items.get_item(0).unwrap();
            assert_eq!(number_of(&item, "item_number"), 1);
            assert_eq!(text_of(&item, "scheme"), "Digest-AKAv1-MD5");
            let mut challenge = vectors::RAND.to_vec();
            challenge.extend_from_slice(&vectors::AUTN);
            assert_eq!(bytes_of(&item, "authenticate"), challenge);
            assert_eq!(bytes_of(&item, "authorization"), vectors::XRES);
            assert_eq!(bytes_of(&item, "confidentiality_key"), vectors::CK);
            assert_eq!(bytes_of(&item, "integrity_key"), vectors::IK);
        });
    }

    #[test]
    fn a_zh_refusal_reports_the_experimental_result_and_no_vector() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let answer = decoded(vectors::ZH_MAA_IDENTITY_UNKNOWN);
            let dict = zh_mar_answer_dict(python, &answer).unwrap();
            let dict = dict.bind(python).as_any();
            // DIAMETER_ERROR_IDENTITY_UNKNOWN (TS 29.109 clause 6.2.2.1).
            assert_eq!(number_of(dict, "result_code"), 5401);
            assert_eq!(number_of(dict, "experimental_result_code"), 5401);
            assert_eq!(dict.get_item("auth_items").unwrap().len().unwrap(), 0);
            assert!(is_none(dict, "guss"));
            assert!(is_none(dict, "user_name"));
        });
    }

    #[test]
    fn a_zn_answer_becomes_the_key_material_and_its_lifetime() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let dict = zn_bir_answer_dict(python, &decoded(vectors::ZN_BIA)).unwrap();
            let dict = dict.bind(python).as_any();
            assert_eq!(number_of(dict, "result_code"), 2001);
            assert!(is_none(dict, "experimental_result_code"));
            assert_eq!(text_of(dict, "user_name"), vectors::IMPI);
            assert_eq!(bytes_of(dict, "me_key_material"), vectors::KS_EXT_NAF);
            assert_eq!(bytes_of(dict, "uicc_key_material"), vectors::KS_INT_NAF);
            assert_eq!(number_of(dict, "key_expiry_time"), vectors::KEY_EXPIRY_UNIX);
            assert_eq!(
                number_of(dict, "bootstrap_info_creation_time"),
                vectors::BOOTSTRAP_CREATION_UNIX
            );
            assert_eq!(text_of(dict, "user_sec_settings"), vectors::USS_LIST);
            assert_eq!(number_of(dict, "gba_type"), 0);
        });
    }

    #[test]
    fn a_zn_refusal_reports_the_experimental_result_and_no_key() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let answer = decoded(vectors::ZN_BIA_TRANSACTION_INVALID);
            let dict = zn_bir_answer_dict(python, &answer).unwrap();
            let dict = dict.bind(python).as_any();
            // DIAMETER_ERROR_TRANSACTION_IDENTIFIER_INVALID (clause 6.2.2.3).
            assert_eq!(number_of(dict, "result_code"), 5403);
            assert_eq!(number_of(dict, "experimental_result_code"), 5403);
            for key in [
                "user_name",
                "me_key_material",
                "uicc_key_material",
                "key_expiry_time",
                "bootstrap_info_creation_time",
                "user_sec_settings",
                "gba_type",
            ] {
                assert!(is_none(dict, key), "{key}");
            }
        });
    }

    #[test]
    fn zh_mar_arguments_refuse_what_cannot_be_a_request() {
        pyo3::Python::initialize();
        // user_name, authorization, scheme, public_identity, what the error names.
        type Case = (
            Option<&'static str>,
            Option<Vec<u8>>,
            Option<&'static str>,
            Option<&'static str>,
            &'static str,
        );
        let cases: [Case; 5] = [
            (None, None, None, None, "user_name or public_identity"),
            (
                Some(""),
                None,
                None,
                Some(""),
                "user_name or public_identity",
            ),
            (
                Some(vectors::IMPI),
                Some(vec![0; 29]),
                None,
                None,
                "30 octets",
            ),
            (
                Some(vectors::IMPI),
                Some(vec![0; 32]),
                None,
                None,
                "30 octets",
            ),
            (Some(vectors::IMPI), None, Some(""), None, "scheme"),
        ];
        for (user_name, authorization, scheme, public_identity, expected) in cases {
            let error =
                ZhMarArguments::new(user_name, authorization, scheme, public_identity, None)
                    .unwrap_err();
            pyo3::Python::attach(|python| {
                assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            });
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    #[test]
    fn zh_mar_arguments_name_no_scheme_unless_told() {
        let arguments = ZhMarArguments::new(Some(vectors::IMPI), None, None, None, None).unwrap();
        let request = arguments.request();
        assert_eq!(request.user_name, Some(vectors::IMPI));
        assert!(request.sip_auth_scheme.is_none());
        assert!(request.sip_authorization.is_none());
    }

    #[test]
    fn zn_bir_arguments_refuse_an_empty_transaction_or_naf() {
        pyo3::Python::initialize();
        for (transaction, naf, expected) in [
            (
                Vec::new(),
                vectors::NAF_ID.to_vec(),
                "transaction_identifier",
            ),
            (vectors::B_TID.as_bytes().to_vec(), Vec::new(), "naf_id"),
        ] {
            let error =
                ZnBirArguments::new(transaction, naf, Vec::new(), None, None, None).unwrap_err();
            pyo3::Python::attach(|python| {
                assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            });
            assert!(error.to_string().contains(expected), "{error}");
        }
    }

    /// Calls an awaitable method the way an `async def` handler does.
    const HELPER_SOURCE: &std::ffi::CStr = c"import asyncio\ndef call(target, method, args, kwargs):\n    async def run():\n        return await getattr(target, method)(*args, **kwargs)\n    return asyncio.run(run())\n";

    fn call<'py>(
        python: Python<'py>,
        diameter: &Bound<'py, PyDiameter>,
        method: &str,
        arguments: Bound<'py, PyTuple>,
        keywords: Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let helper = pyo3::types::PyModule::from_code(
            python,
            HELPER_SOURCE,
            c"_gba_test_helper.py",
            c"_gba_test_helper",
        )?;
        helper
            .getattr("call")?
            .call1((diameter, method, arguments, keywords))
    }

    fn diameter_with(client: Arc<crate::diameter::DiameterClient>) -> PyDiameter {
        pyo3::Python::initialize();
        let manager = Arc::new(DiameterManager::new());
        manager.register("peer".to_string(), client);
        PyDiameter::new(manager)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zh_mar_sends_a_zh_request_and_returns_the_vector_and_the_guss() {
        let (client, requests) = answering_peer(bsf_peer_config(), vectors::ZH_MAA).await;
        let diameter = diameter_with(client);
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let diameter = diameter.bind(python);

                let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
                let result = call(python, diameter, "zh_mar", arguments, PyDict::new(python))
                    .expect("zh_mar resolves");
                assert_eq!(number_of(&result, "result_code"), 2001);
                assert_eq!(text_of(&result, "guss"), vectors::GUSS);
                let item = result.get_item("auth_items").unwrap().get_item(0).unwrap();
                assert_eq!(bytes_of(&item, "authorization"), vectors::XRES);

                // After a synchronisation failure: RAND || AUTS.
                let mut authorization = vectors::RAND.to_vec();
                authorization.extend_from_slice(&vectors::AUTS);
                let keywords = PyDict::new(python);
                keywords
                    .set_item("authorization", PyBytes::new(python, &authorization))
                    .unwrap();
                keywords
                    .set_item("guss_timestamp", vectors::GUSS_TIMESTAMP_UNIX)
                    .unwrap();
                let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
                call(python, diameter, "zh_mar", arguments, keywords).expect("zh_mar resolves");
            });
        })
        .await
        .unwrap();

        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        // Apart from the session and the two identifiers the peer assigns,
        // the requests are the hand-written ones.
        for (sent, written) in [
            (&requests[0], vectors::ZH_MAR),
            (&requests[1], vectors::ZH_MAR_RESYNC),
        ] {
            let sent = DiameterMsg::from_wire(sent).expect("the MAR the HSS received");
            let written = DiameterMsg::from_wire(written).expect("the hand-written MAR");
            assert_eq!(sent.command_code, 303);
            assert_eq!(sent.application_id, 16_777_221);
            assert_eq!(sent.flags, written.flags);
            let without_session =
                |message: &DiameterMsg| crate::diameter::codec::encode_avps(&message.avps[1..]);
            assert_eq!(without_session(&sent), without_session(&written));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zn_bir_sends_a_zn_request_and_returns_the_key_material() {
        let (client, requests) = answering_peer(naf_peer_config(), vectors::ZN_BIA).await;
        let diameter = diameter_with(client);
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let arguments = PyTuple::new(
                    python,
                    [
                        vectors::B_TID.into_pyobject(python).unwrap().into_any(),
                        PyBytes::new(python, &vectors::NAF_ID).into_any(),
                    ],
                )
                .unwrap();
                let keywords = PyDict::new(python);
                keywords
                    .set_item("gaa_service_identifiers", vec!["1", "4"])
                    .unwrap();
                keywords.set_item("gba_u_aware", true).unwrap();
                keywords
                    .set_item("destination_realm", "mnc001.mcc001.pub.3gppnetwork.org")
                    .unwrap();
                let result = call(python, diameter.bind(python), "zn_bir", arguments, keywords)
                    .expect("zn_bir resolves");
                assert_eq!(number_of(&result, "result_code"), 2001);
                assert_eq!(bytes_of(&result, "me_key_material"), vectors::KS_EXT_NAF);
                assert_eq!(
                    number_of(&result, "key_expiry_time"),
                    vectors::KEY_EXPIRY_UNIX
                );
            });
        })
        .await
        .unwrap();

        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let sent = DiameterMsg::from_wire(&requests[0]).expect("the BIR the BSF received");
        let written = DiameterMsg::from_wire(vectors::ZN_BIR).expect("the hand-written BIR");
        assert_eq!(sent.command_code, 310);
        assert_eq!(sent.application_id, 16_777_220);
        assert_eq!(
            crate::diameter::codec::encode_avps(&sent.avps[1..]),
            crate::diameter::codec::encode_avps(&written.avps[1..])
        );
    }

    #[test]
    fn both_calls_resolve_to_none_without_a_peer_and_raise_on_bad_arguments() {
        pyo3::Python::initialize();
        let diameter = PyDiameter::new(Arc::new(DiameterManager::new()));
        pyo3::Python::attach(|python| {
            let diameter = Py::new(python, diameter).unwrap();
            let diameter = diameter.bind(python);

            let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
            let result = call(python, diameter, "zh_mar", arguments, PyDict::new(python)).unwrap();
            assert!(result.is_none());

            let arguments = PyTuple::new(
                python,
                [
                    vectors::B_TID.into_pyobject(python).unwrap().into_any(),
                    PyBytes::new(python, &vectors::NAF_ID).into_any(),
                ],
            )
            .unwrap();
            let result = call(python, diameter, "zn_bir", arguments, PyDict::new(python)).unwrap();
            assert!(result.is_none());

            let keywords = PyDict::new(python);
            keywords
                .set_item("authorization", PyBytes::new(python, &[0u8; 16]))
                .unwrap();
            let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
            let error = call(python, diameter, "zh_mar", arguments, keywords).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));

            let arguments = PyTuple::new(python, ["", "naf.example.com"]).unwrap();
            let error =
                call(python, diameter, "zn_bir", arguments, PyDict::new(python)).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }

    /// `diameter.send_request("Multimedia-Auth-Request", "Zh", ...)` with a
    /// SIP-Auth-Data-Item given as a dict, then the octets the peer received.
    fn generic_resynchronisation_request(python: Python<'_>, diameter: &Bound<'_, PyDiameter>) {
        let mut authorization = vectors::RAND.to_vec();
        authorization.extend_from_slice(&vectors::AUTS);
        let item = PyDict::new(python);
        item.set_item("sip_authentication_scheme", "Digest-AKAv1-MD5")
            .unwrap();
        item.set_item("sip_authorization", PyBytes::new(python, &authorization))
            .unwrap();
        let keywords = PyDict::new(python);
        keywords.set_item("user_name", vectors::IMPI).unwrap();
        keywords.set_item("sip_auth_data_item", item).unwrap();
        keywords
            .set_item("guss_timestamp", vectors::GUSS_TIMESTAMP_UNIX)
            .unwrap();
        let arguments = PyTuple::new(python, ["Multimedia-Auth-Request", "Zh"]).unwrap();
        let answer = call(python, diameter, "send_request", arguments, keywords)
            .expect("send_request resolves");

        // The answer of the generic call: every AVP by its name.
        assert_eq!(number_of(&answer, "result_code"), 2001);
        assert_eq!(
            text_of(&answer, "gba_usersecsettings"),
            crate::diameter::codec::hex::encode(vectors::GUSS.as_bytes())
        );
        let item = answer.get_item("sip_auth_data_item").unwrap();
        assert_eq!(
            text_of(&item, "sip_authorization"),
            crate::diameter::codec::hex::encode(&vectors::XRES)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_request_originates_a_zh_request_with_a_grouped_avp() {
        let (client, requests) = answering_peer(bsf_peer_config(), vectors::ZH_MAA).await;
        let diameter = diameter_with(client);
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                generic_resynchronisation_request(python, diameter.bind(python));
            });
        })
        .await
        .unwrap();

        let requests = requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        let sent = DiameterMsg::from_wire(&requests[0]).expect("the MAR the HSS received");
        let written = DiameterMsg::from_wire(vectors::ZH_MAR_RESYNC).expect("hand-written");
        assert!(sent.is_request());
        assert_eq!(sent.command_code, 303);
        assert_eq!(sent.application_id, 16_777_221);
        // The generic call orders the envelope its own way, so compare AVP by
        // AVP with the hand-written request: same set, same octets.
        let octets = |message: &DiameterMsg| {
            let mut avps: Vec<Vec<u8>> = message.avps[1..]
                .iter()
                .map(|avp| crate::diameter::codec::encode_avps(std::slice::from_ref(avp)))
                .collect();
            avps.sort();
            avps
        };
        assert_eq!(octets(&sent), octets(&written));
    }

    /// `text2pcap`'s hex-dump form: an offset, then the octets.
    fn hex_dump(wire: &[u8]) -> String {
        let mut dump = String::new();
        for (offset, chunk) in wire.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        dump.push_str(&format!("{:06x}\n", wire.len()));
        dump
    }

    /// Emit every GBA message this node builds, and the hand-written ones the
    /// tests read, as hex for `scripts/validate_diameter_gba.sh` to feed to
    /// tshark. The requests are the octets a peer received from the script
    /// calls, the answers the octets a script's handler produced.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn emit_gba_messages_for_external_dissection() {
        let Ok(directory) = std::env::var("SIPHON_GBA_HEX_DIR") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let write = |name: &str, wire: &[u8]| {
            std::fs::write(format!("{directory}/{name}.hex"), hex_dump(wire))
                .expect("hex dump must be writable");
        };

        // The capabilities exchange of a node with a zh and a zn route.
        let mut config = bsf_peer_config();
        config.application_ids = vec![(10415, 16_777_221), (10415, 16_777_220)];
        write("cer", &crate::diameter::peer::build_cer(&config, 1, 1));
        write(
            "cea",
            &crate::diameter::peer::build_cea(&config, 2001, 1, 1),
        );

        let (client, zh_requests) = answering_peer(bsf_peer_config(), vectors::ZH_MAA).await;
        let diameter = diameter_with(client);
        let (client, zn_requests) = answering_peer(naf_peer_config(), vectors::ZN_BIA).await;
        let naf = diameter_with(client);
        tokio::task::spawn_blocking(move || {
            pyo3::Python::attach(|python| {
                let diameter = Py::new(python, diameter).unwrap();
                let diameter = diameter.bind(python);
                let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
                call(python, diameter, "zh_mar", arguments, PyDict::new(python)).unwrap();

                let mut authorization = vectors::RAND.to_vec();
                authorization.extend_from_slice(&vectors::AUTS);
                let keywords = PyDict::new(python);
                keywords
                    .set_item("authorization", PyBytes::new(python, &authorization))
                    .unwrap();
                keywords
                    .set_item("guss_timestamp", vectors::GUSS_TIMESTAMP_UNIX)
                    .unwrap();
                let arguments = PyTuple::new(python, [vectors::IMPI]).unwrap();
                call(python, diameter, "zh_mar", arguments, keywords).unwrap();

                generic_resynchronisation_request(python, diameter);

                let naf = Py::new(python, naf).unwrap();
                let arguments = PyTuple::new(
                    python,
                    [
                        vectors::B_TID.into_pyobject(python).unwrap().into_any(),
                        PyBytes::new(python, &vectors::NAF_ID).into_any(),
                    ],
                )
                .unwrap();
                let keywords = PyDict::new(python);
                keywords
                    .set_item("gaa_service_identifiers", vec!["1", "4"])
                    .unwrap();
                keywords.set_item("gba_u_aware", true).unwrap();
                call(python, naf.bind(python), "zn_bir", arguments, keywords).unwrap();
            });
        })
        .await
        .unwrap();

        let zh_requests = zh_requests.lock().unwrap().clone();
        write("zh_mar", &zh_requests[0]);
        write("zh_mar_resync", &zh_requests[1]);
        write("zh_mar_generic", &zh_requests[2]);
        write("zn_bir", &zn_requests.lock().unwrap()[0]);

        // Zn served by a script.
        use crate::script::diameter_dispatch::zn_serving_tests as bsf;
        let answer = tokio::task::spawn_blocking(|| {
            (
                bsf::answer_wire(bsf::BSF_SCRIPT, vectors::ZN_BIR),
                bsf::answer_wire(bsf::BSF_SCRIPT, &bsf::bir_for_an_unknown_transaction()),
            )
        })
        .await
        .unwrap();
        write("zn_bia", &answer.0);
        write("zn_bia_unknown", &answer.1);

        // What the tests read, so its comments can be checked the same way.
        write("written_zh_maa", vectors::ZH_MAA);
        write("written_zh_maa_unknown", vectors::ZH_MAA_IDENTITY_UNKNOWN);
        write("written_zn_bir", vectors::ZN_BIR);
        write("written_zn_bia", vectors::ZN_BIA);
        write(
            "written_zn_bia_invalid",
            vectors::ZN_BIA_TRANSACTION_INVALID,
        );
    }
}
