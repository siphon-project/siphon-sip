//! Validate what siphon emits on X1 with an **independent** XSD validator.
//!
//! The runtime validator (`uppsala`) and the encoder are both ours. Checking
//! one against the other is a round-trip, and a round-trip passes a shared
//! bug: if the encoder and the validator agree on something the schema does
//! not, nothing in the crate notices.
//!
//! `xmllint` (libxml2) is a genuine third party. It does not share our bugs,
//! it is the reference implementation most ADMF vendors' tooling is built on,
//! and it enforces facets `uppsala` is known to miss — pattern facets
//! inherited through an empty `<xs:restriction base="…"/>`, which is exactly
//! how TS 103 221-1 derives `XId`, `DId` and `X1TransactionId` from the
//! dictionary's `UUID`.
//!
//! This is the same principle as validating SS7/GTP encoders against
//! Wireshark's dissectors rather than against our own reader.
//!
//! Skips (rather than fails) when `xmllint` is absent, matching how the other
//! third-party-tool tests behave.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use siphon::li::x1::codec::{encode_request_container, encode_response_container};
use siphon::li::x1::message::{
    DestinationDetails, DestinationResponseDetails, DestinationStatus, Envelope, MediationDetails,
    MessageKind, NeStatusDetails, RequestBody, RequestContainer, RequestMessage, ResponseBody,
    ResponseContainer, ResponseMessage, TaskDetails, TaskResponseDetails, TaskStatus,
};
use siphon::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, DestinationDeliveryStatus, IpAddressPort, Liid,
    MediationDeliveryType, NeStatus, OkValue, Port, ProvisioningStatus, ServiceType,
    TargetIdentifier, TaskReportType, Timestamp, Token, TypeOfNeIssueMessage, Version,
    X1TransactionId, XId, DEFAULT_VERSION,
};
use siphon::li::x1::X1Error;

/// The repository's shipped schema set.
fn schema_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/etsi")
}

/// Whether `xmllint` is on PATH.
fn have_xmllint() -> bool {
    Command::new("xmllint")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Validate a document with `xmllint` against the shipped XSDs.
///
/// Returns `Err` with xmllint's own diagnostics when it rejects the document.
fn xmllint_validate(xml: &str) -> Result<(), String> {
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let path = directory.path().join("message.xml");
    let mut file = std::fs::File::create(&path).map_err(|error| error.to_string())?;
    file.write_all(xml.as_bytes())
        .map_err(|error| error.to_string())?;

    let output = Command::new("xmllint")
        .arg("--noout")
        .arg("--schema")
        .arg(schema_dir().join("X1All.xsd"))
        .arg(&path)
        .output()
        .map_err(|error| format!("could not run xmllint: {error}"))?;

    if output.status.success() {
        return Ok(());
    }
    Err(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// Assert xmllint accepts a document siphon produced.
fn assert_independently_valid(label: &str, xml: &str) {
    match xmllint_validate(xml) {
        Ok(()) => {}
        Err(diagnostics) => panic!(
            "xmllint rejected the {label} siphon emitted:\n{diagnostics}\n--- document ---\n{xml}"
        ),
    }
}

fn envelope() -> Envelope {
    Envelope {
        admf_identifier: Token::parse("admf-id", "admfIdentifier").unwrap(),
        ne_identifier: Token::parse("siphon-ne", "neIdentifier").unwrap(),
        message_timestamp: Timestamp::now(),
        version: Version::parse(DEFAULT_VERSION).unwrap(),
        x1_transaction_id: X1TransactionId::generate(),
    }
}

fn destination(address: IpAddr) -> DestinationDetails {
    DestinationDetails {
        d_id: DId::generate(),
        friendly_name: Some("primary mediation function".to_string()),
        delivery_type: DeliveryType::X2AndX3,
        delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
            address,
            port: Port::Tcp(42069),
        }),
    }
}

/// A task exercising every optional element the encoder can emit.
fn maximal_task() -> TaskDetails {
    TaskDetails {
        x_id: XId::generate(),
        target_identifiers: vec![
            TargetIdentifier::SipUri("sip:alice@example.com".into()),
            TargetIdentifier::TelUri("tel:15551234567".into()),
            TargetIdentifier::E164Number("15551234567".into()),
            TargetIdentifier::Impu("sip:alice@ims.example.com".into()),
            TargetIdentifier::Impi("alice@ims.example.com".into()),
            TargetIdentifier::Imsi("001010000000001".into()),
            TargetIdentifier::Imei("01234567890123".into()),
            TargetIdentifier::Ipv4Address(Ipv4Addr::new(192, 0, 2, 7)),
            TargetIdentifier::Ipv6Address("2001:db8::1".parse().unwrap()),
        ],
        delivery_type: DeliveryType::X2AndX3,
        list_of_dids: vec![DId::generate(), DId::generate()],
        list_of_dsids: Vec::new(),
        list_of_mediation_details: vec![MediationDetails {
            liid: Liid::parse("LI-2026-0001").unwrap(),
            delivery_type: MediationDeliveryType::Hi2AndHi3,
            start_time: Some(Timestamp::parse("2026-08-01T00:00:00.000000Z").unwrap()),
            end_time: Some(Timestamp::parse("2026-09-01T00:00:00.000000Z").unwrap()),
            list_of_dids: vec![DId::generate()],
        }],
        correlation_id: Some(4242),
        implicit_deactivation_allowed: Some(true),
        product_id: Some(XId::generate()),
        list_of_service_types: vec![ServiceType::Voice, ServiceType::Messaging],
    }
}

fn request_document(body: RequestBody) -> String {
    encode_request_container(&RequestContainer {
        messages: vec![RequestMessage {
            envelope: envelope(),
            body,
        }],
    })
    .expect("encoding must succeed")
}

fn response_document(kind: MessageKind, body: ResponseBody) -> String {
    encode_response_container(&ResponseContainer {
        messages: vec![ResponseMessage {
            envelope: envelope(),
            kind,
            body,
        }],
    })
    .expect("encoding must succeed")
}

// ---------------------------------------------------------------------------

#[test]
fn the_shipped_schema_set_compiles_under_xmllint() {
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    // A trivially-invalid document proves the schema itself compiled: xmllint
    // reports a *validity* error rather than a schema parse failure.
    let error = xmllint_validate(
        r#"<?xml version="1.0"?>
<X1Request xmlns="http://uri.etsi.org/03221/X1/2017/10"/>"#,
    )
    .expect_err("an empty container is not valid");
    assert!(
        !error.contains("failed to compile"),
        "the shipped schema set does not compile under xmllint:\n{error}"
    );
}

#[test]
fn every_request_siphon_emits_is_accepted_by_xmllint() {
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let bodies: Vec<RequestBody> = vec![
        RequestBody::ActivateTask(Box::new(maximal_task())),
        RequestBody::ModifyTask(Box::new(maximal_task())),
        RequestBody::DeactivateTask(XId::generate()),
        RequestBody::DeactivateAllTasks,
        RequestBody::GetTaskDetails(XId::generate()),
        RequestBody::CreateDestination(Box::new(destination(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 50,
        ))))),
        RequestBody::ModifyDestination(Box::new(destination(IpAddr::V6(
            "2001:db8::1".parse().unwrap(),
        )))),
        RequestBody::RemoveDestination(DId::generate()),
        RequestBody::RemoveAllDestinations,
        RequestBody::GetDestinationDetails(DId::generate()),
        RequestBody::GetNEStatus,
        RequestBody::GetAllDetails,
        RequestBody::GetAllTaskDetails,
        RequestBody::GetAllDestinationDetails,
        RequestBody::ListAllDetails,
        RequestBody::Ping,
        RequestBody::Keepalive,
        RequestBody::ReportTaskIssue {
            x_id: XId::generate(),
            report_type: TaskReportType::FullyActionedAndSuccessful,
            error_code: Some(9040),
            details: Some("task activated".into()),
        },
        RequestBody::ReportDestinationIssue {
            d_id: DId::generate(),
            report_type: TaskReportType::TerminatingFault,
            error_code: Some(9030),
            details: Some("delivery connection lost".into()),
        },
        RequestBody::ReportNEIssue {
            issue_type: TypeOfNeIssueMessage::FaultReport,
            description: "media backend unavailable".into(),
            issue_code: Some(9020),
        },
    ];

    for body in bodies {
        let label = body.kind().request_type_name();
        assert_independently_valid(&label, &request_document(body));
    }
}

#[test]
fn every_response_siphon_emits_is_accepted_by_xmllint() {
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let task_details = TaskResponseDetails {
        task_details: maximal_task(),
        task_status: TaskStatus {
            provisioning_status: ProvisioningStatus::Complete,
            list_of_faults: vec![X1Error::new(
                siphon::li::x1::ErrorCode::GenericWarning,
                "a fault description",
            )],
            time_of_last_intercept: Some(Timestamp::now()),
            time_of_last_modification: Some(Timestamp::now()),
            number_of_modifications: Some(3),
        },
    };
    let destination_details = DestinationResponseDetails {
        destination_details: destination(IpAddr::V6("2001:db8::1".parse().unwrap())),
        destination_status: DestinationStatus {
            destination_delivery_status: DestinationDeliveryStatus::DeliveryFault,
            list_of_faults: Vec::new(),
        },
    };
    let ne_status = NeStatusDetails {
        ne_status: NeStatus::Faults,
        list_of_faults: vec![X1Error::new(
            siphon::li::x1::ErrorCode::TerminatingFault,
            "a node fault",
        )],
    };

    let cases: Vec<(MessageKind, ResponseBody)> = vec![
        (
            MessageKind::ActivateTask,
            ResponseBody::Ok(OkValue::AcknowledgedAndCompleted),
        ),
        (MessageKind::Ping, ResponseBody::Ok(OkValue::Acknowledged)),
        (
            MessageKind::GetTaskDetails,
            ResponseBody::TaskDetails(Box::new(task_details.clone())),
        ),
        (
            MessageKind::GetDestinationDetails,
            ResponseBody::DestinationDetails(Box::new(destination_details.clone())),
        ),
        (
            MessageKind::GetNEStatus,
            ResponseBody::NeStatus(ne_status.clone()),
        ),
        (
            MessageKind::GetAllDetails,
            ResponseBody::AllDetails {
                ne_status,
                tasks: vec![task_details.clone()],
                destinations: vec![destination_details.clone()],
            },
        ),
        (
            MessageKind::GetAllTaskDetails,
            ResponseBody::AllTaskDetails(vec![task_details]),
        ),
        (
            MessageKind::GetAllDestinationDetails,
            ResponseBody::AllDestinationDetails(vec![destination_details]),
        ),
        (
            MessageKind::ListAllDetails,
            ResponseBody::ListAllDetails {
                x_ids: vec![XId::generate(), XId::generate()],
                d_ids: vec![DId::generate()],
            },
        ),
        (
            MessageKind::ActivateTask,
            ResponseBody::Error {
                request_message_type: MessageKind::ActivateTask,
                error: X1Error::new(
                    siphon::li::x1::ErrorCode::XidAlreadyExists,
                    "already provisioned",
                ),
            },
        ),
    ];

    for (kind, body) in cases {
        assert_independently_valid(
            &format!("{} response", kind.as_str()),
            &response_document(kind, body),
        );
    }
}

#[test]
fn an_empty_details_response_is_accepted_by_xmllint() {
    // `listOfFaults` is mandatory even when empty, and the "nothing
    // provisioned" answer is the first thing an ADMF sees after a restart.
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    assert_independently_valid(
        "empty GetAllDetails response",
        &response_document(
            MessageKind::GetAllDetails,
            ResponseBody::AllDetails {
                ne_status: NeStatusDetails {
                    ne_status: NeStatus::Ok,
                    list_of_faults: Vec::new(),
                },
                tasks: Vec::new(),
                destinations: Vec::new(),
            },
        ),
    );
}

#[test]
fn the_ipv6_siphon_emits_is_accepted_by_xmllint() {
    // The single most likely first-interop failure, checked by the validator
    // an ADMF vendor is most likely to be using.
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let document = request_document(RequestBody::CreateDestination(Box::new(destination(
        IpAddr::V6("2001:db8:1c18:6b8c::1".parse().unwrap()),
    ))));
    assert!(
        document.contains("2001:0db8:1c18:6b8c:0000:0000:0000:0001"),
        "the address must be emitted fully expanded:\n{document}"
    );
    assert_independently_valid("IPv6 destination", &document);
}

#[test]
fn xmllint_rejects_the_compressed_ipv6_form_siphon_refuses_to_emit() {
    // Proves the gate above is load-bearing rather than vacuous: the form
    // siphon avoids emitting really is rejected by the independent validator.
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let document = request_document(RequestBody::CreateDestination(Box::new(destination(
        IpAddr::V6("2001:db8:1c18:6b8c::1".parse().unwrap()),
    ))))
    .replace(
        "2001:0db8:1c18:6b8c:0000:0000:0000:0001",
        "2001:db8:1c18:6b8c::1",
    );
    let error = xmllint_validate(&document)
        .expect_err("a compressed IPv6 address must be rejected by the schema");
    assert!(
        error.contains("pattern"),
        "expected a pattern-facet failure, got:\n{error}"
    );
}

#[test]
fn xmllint_catches_the_uuid_facet_uppsala_misses() {
    // The reason this file exists. `uppsala` does not inherit pattern facets
    // through an empty <xs:restriction base="UUID"/>, so it accepts a
    // malformed x1TransactionId; xmllint does not. The typed model is what
    // stops such a value ever being constructed, and this asserts the
    // independent validator agrees that it would be invalid.
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let document = request_document(RequestBody::Ping);
    let transaction_id = document
        .split("<x1TransactionId>")
        .nth(1)
        .and_then(|rest| rest.split('<').next())
        .expect("the document carries a transaction id");
    let corrupted = document.replace(transaction_id, "not-a-uuid");

    let error =
        xmllint_validate(&corrupted).expect_err("a malformed x1TransactionId must be rejected");
    assert!(
        error.contains("pattern"),
        "expected a pattern-facet failure, got:\n{error}"
    );
}

#[test]
fn xmllint_rejects_an_out_of_enumeration_delivery_type() {
    // Guards the lowercase 'a' in `X2andX3`: the natural-looking `X2AndX3`
    // would be refused by a real ADMF.
    if !have_xmllint() {
        eprintln!("skipping: xmllint is not installed");
        return;
    }
    let document = request_document(RequestBody::ActivateTask(Box::new(maximal_task())))
        .replace("X2andX3", "X2AndX3");
    assert!(
        xmllint_validate(&document).is_err(),
        "X2AndX3 is not a value the schema allows"
    );
}
