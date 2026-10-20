//! `diameter.originate`: the arguments of a request this node starts, turned
//! into [`crate::diameter::originate`] and its answer into a `DiameterAnswer`.

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyList;

use super::diameter_server::{build_child_spec, PyDiameterAnswer};
use crate::diameter::codec::{Avp, DiameterMsg};
use crate::diameter::originate::{self, Failure, Refusal, Request};
use crate::diameter::{dictionary, DiameterManager};

/// Where a request goes: `peer` (None for any), `tenant`, Destination-Host
/// (None to route on the realm alone) and Destination-Realm.
pub(crate) struct Destination<'a> {
    pub peer: Option<&'a str>,
    pub tenant: &'a str,
    pub host: Option<&'a str>,
    pub realm: &'a str,
}

/// A command given by name (as `send_request` takes it) or by code.
fn command_code(command: &Bound<'_, PyAny>) -> PyResult<u32> {
    if let Ok(code) = command.extract::<u32>() {
        return Ok(code);
    }
    let name: String = command.extract().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("command must be a str name or an int code")
    })?;
    dictionary::command_code_by_name(&name).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("unknown Diameter command name: {name}"))
    })
}

/// The caller's AVPs, each a `(code_or_name, value[, vendor[, mandatory]])`
/// tuple as a grouped AVP's members are given to `set_avp`.
fn caller_avps(avps: &Bound<'_, PyAny>) -> PyResult<Vec<Avp>> {
    let list = avps.cast::<PyList>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "avps must be a list of (code_or_name, value) tuples",
        )
    })?;
    list.iter().map(|item| build_child_spec(&item)).collect()
}

/// Build the request and send it; the coroutine resolves to the answer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn originate<'py>(
    python: Python<'py>,
    manager: &DiameterManager,
    command: &Bound<'py, PyAny>,
    application: &str,
    avps: &Bound<'py, PyAny>,
    destination: Destination<'_>,
    session_id: Option<&str>,
    proxiable: bool,
    timeout: std::time::Duration,
) -> PyResult<Bound<'py, PyAny>> {
    let command_code = command_code(command)?;
    let (_, application_id) = dictionary::app_id_by_name(application).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "unknown Diameter application name: {application}"
        ))
    })?;
    let avps = caller_avps(avps)?;
    let connection = originate::connection(
        manager,
        destination.tenant,
        destination.peer,
        destination.host,
        destination.realm,
    )
    .ok_or_else(|| {
        pyo3::exceptions::PyLookupError::new_err(format!(
            "no open Diameter connection towards {}",
            destination.host.unwrap_or(destination.realm)
        ))
    })?;
    let request = Request {
        command_code,
        application_id,
        proxiable,
        session_id,
        destination_host: destination.host,
        destination_realm: destination.realm,
        avps,
    };
    let wire = originate::wire(&connection, request).map_err(|refusal| match refusal {
        Refusal::EmptyIdentity => {
            pyo3::exceptions::PyValueError::new_err("nonempty destination and session required")
        }
        Refusal::EnvelopeAvp(code) => pyo3::exceptions::PyValueError::new_err(format!(
            "AVP {code} is set by the request itself and cannot be passed in avps"
        )),
    })?;
    let connection = Arc::clone(&connection);
    crate::script::awaitable(python, async move {
        let answer = connection
            .send_request_timeout(wire, timeout)
            .await
            .map_err(|reason| match originate::failure(&reason) {
                Failure::Timeout => pyo3::exceptions::PyTimeoutError::new_err(reason),
                Failure::Connection => pyo3::exceptions::PyConnectionError::new_err(reason),
            })?;
        let message = DiameterMsg::from_wire(&answer.raw).map_err(|error| {
            pyo3::exceptions::PyConnectionError::new_err(format!("malformed answer: {error}"))
        })?;
        Ok(PyDiameterAnswer::from_msg(message))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::PyTuple;

    #[test]
    fn avps_take_names_codes_vendors_and_groups() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let avps = PyList::empty(python);
            avps.append(("User-Name", "001010000000001")).unwrap();
            // Cancellation-Type 1420 by code and vendor; its M bit is the
            // dictionary's.
            avps.append((1420u32, 2u32, 10415u32)).unwrap();
            // CLR-Flags 1638 with the M bit cleared (TS 29.272 table 7.3.1/1).
            avps.append((
                1638u32,
                pyo3::types::PyBytes::new(python, &[0, 0, 0, 2]),
                10415u32,
                false,
            ))
            .unwrap();
            let group = PyList::empty(python);
            group.append(("Vendor-Id", 10415u32)).unwrap();
            group.append(("Auth-Application-Id", 16777251u32)).unwrap();
            avps.append(("Vendor-Specific-Application-Id", group))
                .unwrap();
            let built = caller_avps(avps.as_any()).unwrap();
            let shape: Vec<(u32, u32, u8)> = built
                .iter()
                .map(|avp| (avp.code, avp.vendor, avp.flags))
                .collect();
            assert_eq!(
                shape,
                vec![
                    (1, 0, 0x40),
                    (1420, 10415, 0xC0),
                    (1638, 10415, 0x80),
                    (260, 0, 0x40)
                ]
            );
            assert!(matches!(
                &built[3].value,
                crate::diameter::codec::AvpData::Grouped(members) if members.len() == 2
            ));
        });
    }

    #[test]
    fn a_bad_shape_or_name_is_refused() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let not_a_list = PyTuple::new(python, [1u32]).unwrap();
            assert!(caller_avps(not_a_list.as_any())
                .unwrap_err()
                .is_instance_of::<pyo3::exceptions::PyTypeError>(python));
            let avps = PyList::empty(python);
            avps.append(("Not-An-Avp", 1u32)).unwrap();
            assert!(caller_avps(avps.as_any())
                .unwrap_err()
                .is_instance_of::<pyo3::exceptions::PyValueError>(python));
            assert_eq!(
                command_code(&"CLR".into_pyobject(python).unwrap().into_any()).unwrap(),
                317
            );
            assert_eq!(
                command_code(&322u32.into_pyobject(python).unwrap().into_any()).unwrap(),
                322
            );
            assert!(
                command_code(&"Not-A-Command".into_pyobject(python).unwrap().into_any()).is_err()
            );
        });
    }

    #[test]
    fn without_a_connection_nothing_is_sent_and_lookup_error_is_raised() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let manager = DiameterManager::new();
            let avps = PyList::empty(python);
            let error = originate(
                python,
                &manager,
                &"CLR".into_pyobject(python).unwrap().into_any(),
                "S6a",
                avps.as_any(),
                Destination {
                    peer: None,
                    tenant: "t-no-connection",
                    host: Some("mme1.epc.example"),
                    realm: "epc.example",
                },
                None,
                true,
                std::time::Duration::from_millis(100),
            )
            .unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyLookupError>(python));
        });
    }

    /// The AVP list a script would write, from its Python source.
    fn script_avps<'py>(python: Python<'py>, source: &str) -> Bound<'py, PyAny> {
        let source = std::ffi::CString::new(source).unwrap();
        python.eval(&source, None, None).unwrap()
    }

    /// The members of a grouped AVP.
    fn members(avp: &Avp) -> &[Avp] {
        match &avp.value {
            crate::diameter::codec::AvpData::Grouped(members) => members,
            crate::diameter::codec::AvpData::Raw(_) => panic!("AVP {} is not grouped", avp.code),
        }
    }

    /// A Gx rule installation as TS 29.212 clause 5.3.2 nests it: two
    /// Charging-Rule-Definitions in one Charging-Rule-Install, the first with
    /// two Flow-Information and a QoS-Information holding an
    /// Allocation-Retention-Priority, each level built from the dictionary
    /// and in the order given.
    #[test]
    fn nested_and_repeated_groups_keep_their_order_and_flags() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let built = caller_avps(&script_avps(python, GX_RULE_INSTALL)).unwrap();
            assert_eq!(built.len(), 3);
            assert_eq!(
                built.iter().map(|avp| avp.code).collect::<Vec<_>>(),
                vec![1006, 1006, 1001]
            );
            let definitions = members(&built[2]);
            assert_eq!(definitions.len(), 2);
            assert!(definitions.iter().all(|avp| avp.code == 1003));
            let first: Vec<(u32, u8)> = members(&definitions[0])
                .iter()
                .map(|avp| (avp.code, avp.flags))
                .collect();
            // Flow-Information is V without M (TS 29.212 table 5.3.1).
            assert_eq!(
                first,
                vec![
                    (1005, 0xC0),
                    (1058, 0x80),
                    (1058, 0x80),
                    (1016, 0xC0),
                    (1010, 0xC0)
                ]
            );
            let flow = members(&members(&definitions[0])[1]);
            assert_eq!(
                flow.iter()
                    .map(|avp| (avp.code, avp.flags))
                    .collect::<Vec<_>>(),
                vec![(507, 0xC0), (1080, 0x80)]
            );
            let qos = members(&members(&definitions[0])[3]);
            // Allocation-Retention-Priority and its members are V without M
            // (TS 29.212 table 5.3.1).
            let priority = qos.iter().find(|avp| avp.code == 1034).unwrap();
            assert_eq!(priority.flags, 0x80);
            assert_eq!(
                members(priority)
                    .iter()
                    .map(|avp| (avp.code, avp.flags))
                    .collect::<Vec<_>>(),
                vec![(1046, 0x80), (1047, 0x80), (1048, 0x80)]
            );
        });
    }

    /// A value of the wrong type for the dictionary is refused while the
    /// request is built, so nothing reaches the wire.
    #[test]
    fn a_value_of_the_wrong_type_is_refused_before_sending() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            for source in [
                // A grouped AVP given a leaf value.
                r#"[("Charging-Rule-Install", "rule-1")]"#,
                r#"[("Deregistration-Reason", 0)]"#,
                // A leaf AVP given members.
                r#"[("User-Name", [("Reason-Code", 0)])]"#,
                // A number given text, and text given a number.
                r#"[("CC-Request-Number", "0")]"#,
                r#"[("Origin-State-Id", -1)]"#,
                r#"[("Destination-Host", 7)]"#,
                // A bad member deep inside a group.
                r#"[("Charging-Rule-Install", [("Charging-Rule-Definition", [("Precedence", "high")])])]"#,
                // A vendor or M flag of the wrong type, a tuple of the wrong size.
                r#"[("User-Name", "001010000000001", "10415")]"#,
                r#"[("User-Name", "001010000000001", 0, "yes")]"#,
                r#"[("User-Name", "001010000000001", 0, True, None)]"#,
                r#"[("User-Name",)]"#,
                r#"["User-Name"]"#,
            ] {
                let error = caller_avps(&script_avps(python, source)).unwrap_err();
                assert!(
                    error.is_instance_of::<pyo3::exceptions::PyTypeError>(python)
                        || error.is_instance_of::<pyo3::exceptions::PyOverflowError>(python),
                    "{source}: {error}"
                );
            }
            // None stands for the dictionary's vendor.
            let built = caller_avps(&script_avps(python, r#"[("Abort-Cause", 0, None)]"#)).unwrap();
            assert_eq!(built[0].vendor, 10415);
            // Bytes stay accepted for a grouped AVP, as get_avp gives one back.
            assert!(
                caller_avps(&script_avps(python, r#"[("Charging-Rule-Install", b"")]"#)).is_ok()
            );
        });
    }

    /// A negative answer is an answer: its Result-Code, or the
    /// Experimental-Result-Code the 3GPP applications use, is read off it.
    #[test]
    fn a_negative_answer_carries_its_result() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            let answer = |avps| {
                Py::new(
                    python,
                    PyDiameterAnswer::from_msg(DiameterMsg {
                        flags: 0,
                        command_code: 304,
                        application_id: dictionary::CX_APP_ID,
                        hop_by_hop: 1,
                        end_to_end: 1,
                        avps,
                    }),
                )
                .unwrap()
            };
            let experimental = answer(vec![Avp {
                code: dictionary::avp::EXPERIMENTAL_RESULT,
                vendor: 0,
                flags: crate::diameter::codec::AVP_FLAG_MANDATORY,
                value: crate::diameter::codec::AvpData::Grouped(vec![
                    Avp::raw(266, 0, 10415u32.to_be_bytes().to_vec()),
                    Avp::raw(
                        dictionary::avp::EXPERIMENTAL_RESULT_CODE,
                        0,
                        5001u32.to_be_bytes().to_vec(),
                    ),
                ]),
            }]);
            let read = |answer: &Py<PyDiameterAnswer>, name: &str| {
                answer
                    .bind(python)
                    .getattr(name)
                    .unwrap()
                    .extract::<Option<u32>>()
                    .unwrap()
            };
            assert_eq!(read(&experimental, "experimental_result_code"), Some(5001));
            assert_eq!(read(&experimental, "result_code"), None);
            let unknown_session = answer(vec![Avp::raw(
                dictionary::avp::RESULT_CODE,
                0,
                5002u32.to_be_bytes().to_vec(),
            )]);
            assert_eq!(read(&unknown_session, "result_code"), Some(5002));
            assert_eq!(read(&unknown_session, "experimental_result_code"), None);
        });
    }

    /// A Gx RAR's AVPs: two Event-Triggers, then a Charging-Rule-Install.
    const GX_RULE_INSTALL: &str = r#"[
        ("Event-Trigger", 2),
        ("Event-Trigger", 13),
        ("Charging-Rule-Install", [
            ("Charging-Rule-Definition", [
                ("Charging-Rule-Name", b"ims-voice"),
                ("Flow-Information", [
                    ("Flow-Description", b"permit out 17 from 198.51.100.20 50000 to 198.51.100.7 40000"),
                    ("Flow-Direction", 1),
                ]),
                ("Flow-Information", [
                    ("Flow-Description", b"permit out 17 from 198.51.100.7 40000 to 198.51.100.20 50000"),
                    ("Flow-Direction", 2),
                ]),
                ("QoS-Information", [
                    ("QoS-Class-Identifier", 1),
                    ("Max-Requested-Bandwidth-UL", 64000),
                    ("Max-Requested-Bandwidth-DL", 64000),
                    ("Guaranteed-Bitrate-UL", 64000),
                    ("Guaranteed-Bitrate-DL", 64000),
                    ("Allocation-Retention-Priority", [
                        ("Priority-Level", 2),
                        ("Pre-emption-Capability", 0),
                        ("Pre-emption-Vulnerability", 1),
                    ]),
                ]),
                ("Precedence", 100),
            ]),
            ("Charging-Rule-Definition", [
                ("Charging-Rule-Name", b"ims-signalling"),
                ("Precedence", 50),
            ]),
        ]),
    ]"#;

    const IMS_REALM: &str = "ims.mnc001.mcc001.3gppnetwork.org";
    const EPC_REALM: &str = "epc.mnc001.mcc001.3gppnetwork.org";

    /// A connection whose own identity is `host` of `realm`.
    fn node(host: &str, realm: &str) -> crate::diameter::peer::DiameterPeer {
        let (sender, _) = tokio::sync::mpsc::channel(1);
        crate::diameter::peer::DiameterPeer::new_for_test(
            crate::diameter::peer::PeerConfig {
                host: "192.0.2.10".into(),
                port: 3868,
                origin_host: host.into(),
                origin_realm: realm.into(),
                destination_host: None,
                destination_realm: realm.into(),
                local_ip: "192.0.2.11".parse().unwrap(),
                application_ids: Vec::new(),
                watchdog_interval: 30,
                reconnect_delay: 5,
                product_name: "test".into(),
                firmware_revision: 1,
            },
            sender,
        )
    }

    /// Writes each request `diameter.originate` would send for the commands
    /// of TS 29.229, TS 29.329, TS 29.214, TS 29.212 and TS 29.272 that start
    /// at the node, built from the AVP lists a script passes, as one
    /// `text2pcap` hex dump for `scripts/validate_diameter_originate.sh`.
    /// tshark reads them back with its own dictionary.
    #[test]
    fn emit_originated_requests_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_DIAMETER_ORIGINATE_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let hss = node("hss.ims.mnc001.mcc001.3gppnetwork.org", IMS_REALM);
        let pcrf = node("pcrf.epc.mnc001.mcc001.3gppnetwork.org", EPC_REALM);
        let pgw = node("pgw.epc.mnc001.mcc001.3gppnetwork.org", EPC_REALM);
        let impi = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
        let rtr = format!(
            r#"[
            ("Vendor-Specific-Application-Id", [("Vendor-Id", 10415), ("Auth-Application-Id", 16777216)]),
            ("Auth-Session-State", 1),
            ("User-Name", "{impi}"),
            ("Public-Identity", "sip:{impi}"),
            ("Public-Identity", "sip:alice@ims.mnc001.mcc001.3gppnetwork.org"),
            ("Deregistration-Reason", [("Reason-Code", 0), ("Reason-Info", "subscription withdrawn")]),
        ]"#
        );
        let pnr = r#"[
            ("Vendor-Specific-Application-Id", [("Vendor-Id", 10415), ("Auth-Application-Id", 16777217)]),
            ("Auth-Session-State", 1),
            ("User-Identity", [("Public-Identity", "sip:alice@ims.mnc001.mcc001.3gppnetwork.org")]),
            ("User-Data-Sh", b"<Sh-Data><RepositoryData><ServiceIndication>simservs</ServiceIndication><SequenceNumber>1</SequenceNumber></RepositoryData></Sh-Data>"),
        ]"#;
        let asr = r#"[("Auth-Application-Id", 16777236), ("Abort-Cause", 0)]"#;
        let rx_rar = r#"[
            ("Auth-Application-Id", 16777236),
            ("Re-Auth-Request-Type", 0),
            ("Specific-Action", 2),
            ("Specific-Action", 4),
        ]"#;
        let gx_rar = format!(
            r#"[("Auth-Application-Id", 16777238), ("Re-Auth-Request-Type", 0)] + {GX_RULE_INSTALL}"#
        );
        let ccr = |request_type: u32, number: u32, tail: &str| {
            format!(
                r#"[("Auth-Application-Id", 16777238), ("CC-Request-Type", {request_type}),
                    ("CC-Request-Number", {number})] + {tail}"#
            )
        };
        let ccr_initial = ccr(
            1,
            0,
            r#"[
            ("Subscription-Id", [("Subscription-Id-Type", 1), ("Subscription-Id-Data", "001010000000001")]),
            ("Subscription-Id", [("Subscription-Id-Type", 3), ("Subscription-Id-Data", "001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org")]),
            ("IP-CAN-Type", 5),
            ("RAT-Type", 1004),
            ("Framed-IP-Address", bytes([198, 51, 100, 7])),
            ("Called-Station-Id", "ims"),
        ]"#,
        );
        let ccr_update = ccr(2, 1, r#"[("Event-Trigger", 13)]"#);
        let ccr_termination = ccr(3, 2, r#"[("Termination-Cause", 1)]"#);
        let s6a = |tail: &str| {
            format!(
                r#"[
                ("Vendor-Specific-Application-Id", [("Vendor-Id", 10415), ("Auth-Application-Id", 16777251)]),
                ("Auth-Session-State", 1),
                ("User-Name", "001010000000001"),
            ] + {tail}"#
            )
        };
        // CLR-Flags 1638, IDR-Flags 1490, DSR-Flags 1421 and Subscriber-Status
        // 1424 are not in the dictionary: by code, their octets, and the
        // M bit TS 29.272 table 7.3.1/1 gives them.
        let clr =
            s6a(r#"[("Cancellation-Type", 2), (1638, (2).to_bytes(4, "big"), 10415, False)]"#);
        let idr = s6a(
            r#"[("Subscription-Data", [(1424, (0).to_bytes(4, "big"), 10415), ("MSISDN", "0010100000001")]),
                (1490, (1).to_bytes(4, "big"), 10415)]"#,
        );
        let dsr = s6a(r#"[(1421, (8).to_bytes(4, "big"), 10415)]"#);
        let gx_session = "pgw.epc.mnc001.mcc001.3gppnetwork.org;1;1";
        let rx_session = "pcscf.ims.mnc001.mcc001.3gppnetwork.org;2;1";
        // From, command, application, AVPs, Session-Id, Destination-Host,
        // Destination-Realm.
        type Message<'a> = (
            &'a crate::diameter::peer::DiameterPeer,
            u32,
            u32,
            String,
            Option<&'a str>,
            Option<&'a str>,
            &'a str,
        );
        let messages: Vec<Message<'_>> = vec![
            (
                &hss,
                304,
                dictionary::CX_APP_ID,
                rtr,
                None,
                Some("scscf.ims.mnc001.mcc001.3gppnetwork.org"),
                IMS_REALM,
            ),
            (
                &hss,
                309,
                dictionary::SH_APP_ID,
                pnr.into(),
                None,
                Some("as.ims.mnc001.mcc001.3gppnetwork.org"),
                IMS_REALM,
            ),
            (
                &pcrf,
                274,
                dictionary::RX_APP_ID,
                asr.into(),
                Some(rx_session),
                Some("pcscf.ims.mnc001.mcc001.3gppnetwork.org"),
                IMS_REALM,
            ),
            (
                &pcrf,
                258,
                dictionary::RX_APP_ID,
                rx_rar.into(),
                Some(rx_session),
                Some("pcscf.ims.mnc001.mcc001.3gppnetwork.org"),
                IMS_REALM,
            ),
            (
                &pcrf,
                258,
                dictionary::GX_APP_ID,
                gx_rar,
                Some(gx_session),
                Some("pgw.epc.mnc001.mcc001.3gppnetwork.org"),
                EPC_REALM,
            ),
            (
                &pgw,
                272,
                dictionary::GX_APP_ID,
                ccr_initial,
                Some(gx_session),
                None,
                EPC_REALM,
            ),
            (
                &pgw,
                272,
                dictionary::GX_APP_ID,
                ccr_update,
                Some(gx_session),
                None,
                EPC_REALM,
            ),
            (
                &pgw,
                272,
                dictionary::GX_APP_ID,
                ccr_termination,
                Some(gx_session),
                None,
                EPC_REALM,
            ),
            (
                &hss,
                317,
                dictionary::S6A_APP_ID,
                clr,
                None,
                Some("mme.epc.mnc001.mcc001.3gppnetwork.org"),
                EPC_REALM,
            ),
            (
                &hss,
                319,
                dictionary::S6A_APP_ID,
                idr,
                None,
                Some("mme.epc.mnc001.mcc001.3gppnetwork.org"),
                EPC_REALM,
            ),
            (
                &hss,
                320,
                dictionary::S6A_APP_ID,
                dsr,
                None,
                Some("mme.epc.mnc001.mcc001.3gppnetwork.org"),
                EPC_REALM,
            ),
        ];
        pyo3::Python::initialize();
        let dump = pyo3::Python::attach(|python| {
            let mut dump = String::new();
            for (peer, command_code, application_id, avps, session_id, host, realm) in messages {
                let request = Request {
                    command_code,
                    application_id,
                    proxiable: true,
                    session_id,
                    destination_host: host,
                    destination_realm: realm,
                    avps: caller_avps(&script_avps(python, &avps)).unwrap(),
                };
                let wire = originate::wire(peer, request).unwrap();
                dump.push_str(&crate::diameter::cx_test_support::hex_dump(&wire));
            }
            dump
        });
        std::fs::write(path, dump).expect("hex dump must be writable");
    }
}
