//! Cross-module Diameter integration tests.
//!
//! These tests verify that the codec, dictionary, and application modules
//! (Cx, Rx, Ro, Rf) work together correctly — building messages in one
//! module, encoding via codec, decoding, and verifying AVPs resolve
//! through the dictionary.

use siphon::diameter::codec::*;
use siphon::diameter::cx::{build_lia_success, build_saa_success, build_uaa_success};
use siphon::diameter::dictionary::{self, avp, lookup_avp};
use siphon::diameter::rf::AccountingRecordType;
use siphon::diameter::ro::{ImsChargingData, NodeFunctionality, NodeRole};

// ── Helpers ────────────────────────────────────────────────────────────

/// Build a Cx MAR on the wire.
fn build_mar_wire(public_identity: &str, auth_scheme: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(
        avp::SESSION_ID,
        "scscf.ims.mnc001.mcc001.3gppnetwork.org;mar;1",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_HOST,
        "scscf.ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    payload.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::CX_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
    payload.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));

    // SIP-Auth-Data-Item grouped AVP
    let mut auth_children = Vec::new();
    auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        auth_scheme,
    ));
    payload.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::SIP_AUTH_DATA_ITEM,
        &auth_children,
    ));

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_MULTIMEDIA_AUTH,
        dictionary::CX_APP_ID,
        100,
        200,
        &payload,
    )
}

/// Build an Ro CCR on the wire using raw AVP encoding (no private methods).
fn build_ccr_wire(request_type: u32, ims_data: Option<&ImsChargingData>) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "ocs;ccr;sess;1"));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_APPLICATION_ID,
        dictionary::RO_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_HOST,
        "scscf.ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_TYPE, request_type));
    payload.extend_from_slice(&encode_avp_u32(avp::CC_REQUEST_NUMBER, 0));

    // Subscription-Id (grouped, base AVP)
    let mut sub_children = Vec::new();
    sub_children.extend_from_slice(&encode_avp_u32(avp::SUBSCRIPTION_ID_TYPE, 0)); // E164
    sub_children.extend_from_slice(&encode_avp_utf8(avp::SUBSCRIPTION_ID_DATA, "+15551234567"));
    payload.extend_from_slice(&encode_avp_grouped(avp::SUBSCRIPTION_ID, &sub_children));

    if let Some(ims) = ims_data {
        payload.extend_from_slice(&ims.encode_service_information());
    }
    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_CREDIT_CONTROL,
        dictionary::RO_APP_ID,
        101,
        201,
        &payload,
    )
}

/// Build an Rf ACR on the wire.
fn build_acr_wire(
    record_type: AccountingRecordType,
    record_number: u32,
    ims_data: Option<&ImsChargingData>,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cdf;acr;sess;1"));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_HOST,
        "scscf.ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCT_APPLICATION_ID,
        dictionary::RF_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_TYPE,
        record_type as u32,
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_NUMBER,
        record_number,
    ));
    if let Some(ims) = ims_data {
        payload.extend_from_slice(&ims.encode_service_information());
    }
    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_ACCOUNTING,
        dictionary::RF_APP_ID,
        102,
        202,
        &payload,
    )
}

/// Build an Rx AAR on the wire using raw AVP encoding.
fn build_aar_wire() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "pcrf;aar;sess;1"));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_HOST,
        "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_APPLICATION_ID,
        dictionary::RX_APP_ID,
    ));

    // Media-Component-Description (grouped, 3GPP)
    let mut mcd_inner = Vec::new();
    mcd_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MEDIA_COMPONENT_NUMBER, 1));
    mcd_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MEDIA_TYPE, 0)); // AUDIO

    // Media-Sub-Component (grouped, 3GPP)
    let mut msc_inner = Vec::new();
    msc_inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_NUMBER, 1));
    msc_inner.extend_from_slice(&encode_avp_octet_3gpp(
        avp::FLOW_DESCRIPTION,
        b"permit in 17 from any to 10.0.0.1 49170",
    ));
    mcd_inner.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::MEDIA_SUB_COMPONENT,
        &msc_inner,
    ));

    payload.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::MEDIA_COMPONENT_DESCRIPTION,
        &mcd_inner,
    ));

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_AA,
        dictionary::RX_APP_ID,
        103,
        203,
        &payload,
    )
}

// ── Cross-module: Cx MAR encode → decode ───────────────────────────────

#[test]
fn cx_mar_encode_decode_roundtrip() {
    let wire = build_mar_wire("sip:alice@ims.mnc001.mcc001.3gppnetwork.org", "SIP Digest");
    let decoded = decode_diameter(&wire).unwrap();

    assert!(decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_MULTIMEDIA_AUTH);
    assert_eq!(decoded.application_id, dictionary::CX_APP_ID);
    assert_eq!(decoded.hop_by_hop, 100);
    assert_eq!(decoded.end_to_end, 200);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "MAR"
    );
}

#[test]
fn cx_mar_avps_resolve_through_dictionary() {
    let wire = build_mar_wire("sip:alice@ims.mnc001.mcc001.3gppnetwork.org", "SIP Digest");
    let decoded = decode_diameter(&wire).unwrap();

    // Standard AVPs resolve by name
    assert!(decoded.avps.get("Session-Id").is_some());
    assert!(decoded.avps.get("Origin-Host").is_some());
    assert!(decoded.avps.get("Origin-Realm").is_some());
    assert!(decoded.avps.get("Auth-Session-State").is_some());

    // 3GPP Cx AVPs resolve by name
    assert!(decoded.avps.get("Public-Identity").is_some());
    assert!(decoded.avps.get("SIP-Number-Auth-Items").is_some());

    // Grouped SIP-Auth-Data-Item resolves with children
    let auth_data = decoded.avps.get("SIP-Auth-Data-Item").unwrap();
    assert!(auth_data.get("SIP-Authentication-Scheme").is_some());
}

// ── Cross-module: Ro CCR with IMS charging data ────────────────────────

#[test]
fn ro_ccr_with_ims_data_encode_decode() {
    let ims = ImsChargingData {
        calling_party: vec!["sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()],
        called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
        sip_method: Some("INVITE".into()),
        role_of_node: Some(NodeRole::OriginatingRole),
        node_functionality: Some(NodeFunctionality::SCscf),
        ims_charging_identifier: Some("icid-integration-001".into()),
        ..Default::default()
    };

    let wire = build_ccr_wire(1, Some(&ims)); // INITIAL
    let decoded = decode_diameter(&wire).unwrap();

    assert!(decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_CREDIT_CONTROL);
    assert_eq!(decoded.application_id, dictionary::RO_APP_ID);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "CCR"
    );

    // Subscription-Id grouped AVP with children
    let sub_id = decoded.avps.get("Subscription-Id").unwrap();
    assert_eq!(
        sub_id.get("Subscription-Id-Type").and_then(|v| v.as_u64()),
        Some(0) // END_USER_E164
    );
    assert_eq!(
        sub_id.get("Subscription-Id-Data").and_then(|v| v.as_str()),
        Some("+15551234567")
    );

    // Service-Information → IMS-Information nested grouped AVPs
    let svc_info = decoded.avps.get("Service-Information").unwrap();
    let ims_info = svc_info.get("IMS-Information").unwrap();
    assert_eq!(
        ims_info.get("Role-of-Node").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(
        ims_info.get("Node-Functionality").and_then(|v| v.as_u64()),
        Some(0) // S-CSCF
    );
    assert!(ims_info.get("IMS-Charging-Identifier").is_some());
}

// ── Cross-module: Rf ACR with shared IMS charging data from Ro ─────────

#[test]
fn rf_acr_shares_ims_data_with_ro() {
    let ims = ImsChargingData {
        calling_party: vec!["sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()],
        called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
        sip_method: Some("BYE".into()),
        role_of_node: Some(NodeRole::TerminatingRole),
        node_functionality: Some(NodeFunctionality::PCscf),
        ims_charging_identifier: Some("icid-shared-001".into()),
        cause_code: Some(0),
        ..Default::default()
    };

    let acr_wire = build_acr_wire(AccountingRecordType::StopRecord, 3, Some(&ims));
    let decoded = decode_diameter(&acr_wire).unwrap();

    assert_eq!(decoded.command_code, dictionary::CMD_ACCOUNTING);
    assert_eq!(decoded.application_id, dictionary::RF_APP_ID);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "ACR"
    );

    let svc_info = decoded.avps.get("Service-Information").unwrap();
    let ims_info = svc_info.get("IMS-Information").unwrap();
    assert_eq!(
        ims_info.get("Role-of-Node").and_then(|v| v.as_u64()),
        Some(1) // Terminating
    );
    assert_eq!(
        ims_info.get("Node-Functionality").and_then(|v| v.as_u64()),
        Some(1) // P-CSCF
    );
}

// ── Cross-module: Ro and Rf use different app IDs for same IMS data ────

#[test]
fn ro_and_rf_different_app_ids_same_ims_data() {
    let ims = ImsChargingData {
        calling_party: vec!["sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()],
        called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
        sip_method: Some("INVITE".into()),
        role_of_node: Some(NodeRole::OriginatingRole),
        node_functionality: Some(NodeFunctionality::SCscf),
        ..Default::default()
    };

    let ccr_wire = build_ccr_wire(1, Some(&ims)); // INITIAL
    let acr_wire = build_acr_wire(AccountingRecordType::StartRecord, 0, Some(&ims));

    let ccr = decode_diameter(&ccr_wire).unwrap();
    let acr = decode_diameter(&acr_wire).unwrap();

    // Ro uses Auth-Application-Id = 4 (credit-control)
    assert_eq!(ccr.application_id, 4);
    assert_eq!(ccr.command_code, 272);

    // Rf uses Acct-Application-Id = 3 (base accounting)
    assert_eq!(acr.application_id, 3);
    assert_eq!(acr.command_code, 271);

    // Both carry identical Service-Information
    let ccr_svc = ccr.avps.get("Service-Information").unwrap();
    let acr_svc = acr.avps.get("Service-Information").unwrap();
    assert_eq!(
        ccr_svc
            .get("IMS-Information")
            .unwrap()
            .get("Calling-Party-Address"),
        acr_svc
            .get("IMS-Information")
            .unwrap()
            .get("Calling-Party-Address"),
    );
}

/// Build an Rx AAR whose Media-Component-Description matches the shape the
/// new `diameter.rx_aar` Python binding emits: per-m= component with paired
/// RTP + RTCP sub-components carrying full 5-tuple Flow-Descriptions and a
/// Flow-Usage AVP on the RTCP sub-component.
fn build_aar_wire_structured() -> Vec<u8> {
    use siphon::diameter::rx::{FlowStatus, FlowUsage, MediaComponent, MediaFlow, MediaType};

    let component = MediaComponent {
        number: 1,
        media_type: MediaType::Audio,
        flows: vec![
            MediaFlow {
                flow_number: 1,
                descriptions: vec![
                    "permit out 17 from 100.65.0.2 50000 to 100.64.0.10 30000".into(),
                    "permit in 17 from 100.64.0.10 30000 to 100.65.0.2 50000".into(),
                ],
                status: None,
                usage: None,
            },
            MediaFlow {
                flow_number: 2,
                descriptions: vec![
                    "permit out 17 from 100.65.0.2 50001 to 100.64.0.10 30001".into(),
                    "permit in 17 from 100.64.0.10 30001 to 100.65.0.2 50001".into(),
                ],
                status: None,
                usage: Some(FlowUsage::Rtcp),
            },
        ],
        max_bandwidth_ul: Some(64000),
        max_bandwidth_dl: Some(64000),
        flow_status: Some(FlowStatus::Enabled),
        codec_data: None,
    };

    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "pcrf;aar;structured;1"));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_HOST,
        "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::ORIGIN_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        "ims.mnc001.mcc001.3gppnetwork.org",
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_APPLICATION_ID,
        dictionary::RX_APP_ID,
    ));
    payload.extend_from_slice(&component.encode());

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_AA,
        dictionary::RX_APP_ID,
        103,
        203,
        &payload,
    )
}

#[test]
fn rx_aar_structured_components_roundtrip() {
    let wire = build_aar_wire_structured();
    let decoded = decode_diameter(&wire).unwrap();
    // The high-level decode resolves the grouped MCD container by name.
    // Duplicate-named children inside a grouped AVP flatten in the helper
    // map, so we don't depend on the decoded child shape for assertions —
    // the wire bytes are the ground truth.
    assert!(decoded.avps.get("Media-Component-Description").is_some());

    // Spec-critical: the wire MUST carry at least one Flow-Usage AVP for
    // the RTCP companion sub-component — without it the PCEF cannot gate
    // RTCP differently from RTP (TS 29.214 §7.3.10).
    let flow_usage_code = avp::FLOW_USAGE.to_be_bytes();
    assert!(
        wire.windows(4).any(|w| w == flow_usage_code),
        "AAR wire must include a Flow-Usage AVP (RTCP marker)"
    );

    // And the wire must carry the full 5-tuple, not a wildcard.
    let rtp_rule = b"permit out 17 from 100.65.0.2 50000 to 100.64.0.10 30000";
    assert!(
        wire.windows(rtp_rule.len()).any(|w| w == rtp_rule),
        "AAR wire must include the 5-tuple RTP Flow-Description"
    );

    let rtcp_rule = b"permit out 17 from 100.65.0.2 50001 to 100.64.0.10 30001";
    assert!(
        wire.windows(rtcp_rule.len()).any(|w| w == rtcp_rule),
        "AAR wire must include the 5-tuple RTCP Flow-Description"
    );
}

// ── Rx AAR encode → decode ─────────────────────────────────────────────

#[test]
fn rx_aar_encode_decode_roundtrip() {
    let wire = build_aar_wire();
    let decoded = decode_diameter(&wire).unwrap();

    assert!(decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_AA);
    assert_eq!(decoded.application_id, dictionary::RX_APP_ID);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "AAR"
    );

    // Nested Media-Component-Description
    let mcd = decoded.avps.get("Media-Component-Description").unwrap();
    assert_eq!(
        mcd.get("Media-Component-Number").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        mcd.get("Media-Type").and_then(|v| v.as_u64()),
        Some(0) // AUDIO
    );

    // Nested Media-Sub-Component inside MCD
    let msc = mcd.get("Media-Sub-Component").unwrap();
    assert_eq!(msc.get("Flow-Number").and_then(|v| v.as_u64()), Some(1));
}

// ── Dictionary lookup integration ──────────────────────────────────────

#[test]
fn dictionary_resolves_all_ims_interfaces() {
    // lookup_avp(code, vendor_id)

    // Cx AVPs
    assert!(lookup_avp(avp::PUBLIC_IDENTITY, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::SERVER_NAME, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::SIP_AUTH_DATA_ITEM, dictionary::VENDOR_3GPP).is_some());

    // Sh AVPs
    assert!(lookup_avp(avp::USER_DATA_SH, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::DATA_REFERENCE, dictionary::VENDOR_3GPP).is_some());

    // Rx AVPs
    assert!(lookup_avp(avp::MEDIA_COMPONENT_DESCRIPTION, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::MEDIA_TYPE, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::FLOW_DESCRIPTION, dictionary::VENDOR_3GPP).is_some());

    // Ro/Rf charging AVPs
    assert!(lookup_avp(avp::SERVICE_INFORMATION, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::IMS_INFORMATION, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::CALLING_PARTY_ADDRESS, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::IMS_CHARGING_IDENTIFIER, dictionary::VENDOR_3GPP).is_some());
    assert!(lookup_avp(avp::NODE_FUNCTIONALITY, dictionary::VENDOR_3GPP).is_some());

    // Base AVPs (vendor 0)
    assert!(lookup_avp(avp::SESSION_ID, 0).is_some());
    assert!(lookup_avp(avp::ORIGIN_HOST, 0).is_some());
    assert!(lookup_avp(avp::RESULT_CODE, 0).is_some());
    assert!(lookup_avp(avp::CC_REQUEST_TYPE, 0).is_some());
    assert!(lookup_avp(avp::ACCOUNTING_RECORD_TYPE, 0).is_some());
}

#[test]
fn dictionary_command_names_all_ims_interfaces() {
    // Cx
    assert_eq!(command_name(303, true), "MAR");
    assert_eq!(command_name(303, false), "MAA");
    assert_eq!(command_name(301, true), "SAR");
    assert_eq!(command_name(300, true), "UAR");
    assert_eq!(command_name(302, true), "LIR");

    // Ro
    assert_eq!(command_name(272, true), "CCR");
    assert_eq!(command_name(272, false), "CCA");

    // Rf
    assert_eq!(command_name(271, true), "ACR");
    assert_eq!(command_name(271, false), "ACA");

    // Base
    assert_eq!(command_name(257, true), "CER");
    assert_eq!(command_name(257, false), "CEA");
    assert_eq!(command_name(280, true), "DWR");
    assert_eq!(command_name(280, false), "DWA");
}

// ── Full IMS call flow: Cx auth → Ro charging → Rf accounting ──────────

#[test]
fn full_ims_call_flow_cx_ro_rf() {
    // Step 1: Cx MAR for authentication
    let mar_wire = build_mar_wire(
        "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
        "Digest-AKAv1-MD5",
    );
    let mar = decode_diameter(&mar_wire).unwrap();
    assert_eq!(mar.command_code, dictionary::CMD_MULTIMEDIA_AUTH);

    // Step 2: Ro CCR-Initial for online charging
    let ims = ImsChargingData {
        calling_party: vec!["sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()],
        called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
        sip_method: Some("INVITE".into()),
        role_of_node: Some(NodeRole::OriginatingRole),
        node_functionality: Some(NodeFunctionality::SCscf),
        ims_charging_identifier: Some("icid-flow-001".into()),
        ..Default::default()
    };
    let ccr_wire = build_ccr_wire(1, Some(&ims)); // INITIAL
    let ccr = decode_diameter(&ccr_wire).unwrap();
    assert_eq!(ccr.command_code, dictionary::CMD_CREDIT_CONTROL);

    // Step 3: Rf ACR-START for offline charging (same IMS data)
    let acr_wire = build_acr_wire(AccountingRecordType::StartRecord, 0, Some(&ims));
    let acr = decode_diameter(&acr_wire).unwrap();
    assert_eq!(acr.command_code, dictionary::CMD_ACCOUNTING);

    // All three messages are valid Diameter requests
    assert!(mar.is_request);
    assert!(ccr.is_request);
    assert!(acr.is_request);

    // Each uses the correct application ID
    assert_eq!(mar.application_id, dictionary::CX_APP_ID);
    assert_eq!(ccr.application_id, dictionary::RO_APP_ID);
    assert_eq!(acr.application_id, dictionary::RF_APP_ID);

    // Ro and Rf share the same IMS-Information content
    let ccr_ims = ccr
        .avps
        .get("Service-Information")
        .unwrap()
        .get("IMS-Information")
        .unwrap();
    let acr_ims = acr
        .avps
        .get("Service-Information")
        .unwrap()
        .get("IMS-Information")
        .unwrap();
    assert_eq!(
        ccr_ims.get("Calling-Party-Address"),
        acr_ims.get("Calling-Party-Address")
    );
    assert_eq!(
        ccr_ims.get("Called-Party-Address"),
        acr_ims.get("Called-Party-Address")
    );
}

// ── Full IMS call flow: Cx + Rx + Ro + Rf ──────────────────────────────

#[test]
fn full_ims_call_flow_all_four_interfaces() {
    let ims = ImsChargingData {
        calling_party: vec!["sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()],
        called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
        sip_method: Some("INVITE".into()),
        role_of_node: Some(NodeRole::OriginatingRole),
        node_functionality: Some(NodeFunctionality::SCscf),
        ims_charging_identifier: Some("icid-full-flow-001".into()),
        ..Default::default()
    };

    // Cx MAR (S-CSCF → HSS)
    let mar = decode_diameter(&build_mar_wire(
        "sip:alice@ims.mnc001.mcc001.3gppnetwork.org",
        "Digest-AKAv1-MD5",
    ))
    .unwrap();

    // Rx AAR (P-CSCF → PCRF)
    let aar = decode_diameter(&build_aar_wire()).unwrap();

    // Ro CCR (S-CSCF → OCS)
    let ccr = decode_diameter(&build_ccr_wire(1, Some(&ims))).unwrap();

    // Rf ACR (S-CSCF → CDF)
    let acr = decode_diameter(&build_acr_wire(
        AccountingRecordType::StartRecord,
        0,
        Some(&ims),
    ))
    .unwrap();

    // All four use different application IDs
    let app_ids: Vec<u32> = vec![
        mar.application_id,
        aar.application_id,
        ccr.application_id,
        acr.application_id,
    ];
    assert_eq!(app_ids[0], dictionary::CX_APP_ID); // 16777216
    assert_eq!(app_ids[1], dictionary::RX_APP_ID); // 16777236
    assert_eq!(app_ids[2], dictionary::RO_APP_ID); // 4
    assert_eq!(app_ids[3], dictionary::RF_APP_ID); // 3

    // All are unique
    let mut unique = app_ids.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 4);
}

// ── Wire format invariants ─────────────────────────────────────────────

#[test]
fn diameter_header_is_always_20_bytes() {
    let wire = build_mar_wire("sip:test@example.com", "SIP Digest");
    assert_eq!(wire[0], 1); // Version
    let length = u32::from_be_bytes([0, wire[1], wire[2], wire[3]]);
    assert_eq!(length as usize, wire.len());
    assert!(wire.len() >= 20);
}

#[test]
fn avp_padding_to_4_byte_boundary() {
    // Encode a 5-byte UTF-8 value — should pad to 8 bytes of data
    let encoded = encode_avp_utf8(avp::SESSION_ID, "hello");
    // AVP header (8 bytes) + 5 data bytes + 3 padding = 16
    assert_eq!(encoded.len() % 4, 0);
}

#[test]
fn vendor_specific_avps_have_vendor_flag() {
    let encoded = encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:alice@example.com");
    // Byte 4 has flags; vendor flag is 0x80
    assert_ne!(encoded[4] & AVP_FLAG_VENDOR, 0);
    // Vendor-Id at bytes 8..12
    let vendor_id = u32::from_be_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    assert_eq!(vendor_id, dictionary::VENDOR_3GPP);
}

#[test]
fn base_avps_have_no_vendor_flag() {
    let encoded = encode_avp_utf8(avp::SESSION_ID, "test;session;1");
    // Byte 4 has flags; vendor flag should NOT be set
    assert_eq!(encoded[4] & AVP_FLAG_VENDOR, 0);
}

// ── Cx Answer roundtrip tests ─────────────────────────────────────────

#[test]
fn cx_uaa_encode_decode_roundtrip() {
    let wire = build_uaa_success(
        "hss.ims.example.com",
        "ims.example.com",
        "scscf;uar;sess;1",
        Some("sip:scscf.ims.example.com:6060"),
        2001,
        500,
        600,
    );
    let decoded = decode_diameter(&wire).unwrap();

    assert!(!decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_USER_AUTHORIZATION);
    assert_eq!(decoded.hop_by_hop, 500);
    assert_eq!(decoded.end_to_end, 600);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "UAA"
    );

    // Server-Name AVP present
    let server_name = decoded.avps.get("Server-Name").and_then(|v| v.as_str());
    assert_eq!(server_name, Some("sip:scscf.ims.example.com:6060"));

    // Experimental-Result grouped AVP with result code
    let exp_result = decoded.avps.get("Experimental-Result").unwrap();
    let exp_code = exp_result
        .get("Experimental-Result-Code")
        .and_then(|v| v.as_u64());
    assert_eq!(exp_code, Some(2001));
}

#[test]
fn cx_saa_encode_decode_roundtrip() {
    let ifc_xml = "<IMSSubscription><ServiceProfile></ServiceProfile></IMSSubscription>";
    let wire = build_saa_success(
        "hss.ims.example.com",
        "ims.example.com",
        "scscf;sar;sess;1",
        Some(ifc_xml),
        501,
        601,
    );
    let decoded = decode_diameter(&wire).unwrap();

    assert!(!decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_SERVER_ASSIGNMENT);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "SAA"
    );

    // User-Data AVP (code 606) contains the iFC XML as hex-encoded OctetString
    let user_data_hex = decoded
        .avps
        .get("User-Data")
        .and_then(|v| v.as_str())
        .unwrap();
    let user_data_bytes = hex::decode(user_data_hex).unwrap();
    assert_eq!(std::str::from_utf8(&user_data_bytes).unwrap(), ifc_xml);

    // Experimental-Result
    let exp_result = decoded.avps.get("Experimental-Result").unwrap();
    let exp_code = exp_result
        .get("Experimental-Result-Code")
        .and_then(|v| v.as_u64());
    assert_eq!(
        exp_code,
        Some(dictionary::DIAMETER_FIRST_REGISTRATION as u64)
    );
}

#[test]
fn cx_saa_without_user_data() {
    let wire = build_saa_success(
        "hss.ims.example.com",
        "ims.example.com",
        "scscf;sar;sess;2",
        None,
        502,
        602,
    );
    let decoded = decode_diameter(&wire).unwrap();

    assert_eq!(decoded.command_code, dictionary::CMD_SERVER_ASSIGNMENT);
    // No User-Data AVP when None
    assert!(decoded.avps.get("User-Data").is_none());
}

#[test]
fn cx_lia_encode_decode_roundtrip() {
    let wire = build_lia_success(
        "hss.ims.example.com",
        "ims.example.com",
        "icscf;lir;sess;1",
        "sip:scscf.ims.example.com:6060",
        503,
        603,
    );
    let decoded = decode_diameter(&wire).unwrap();

    assert!(!decoded.is_request);
    assert_eq!(decoded.command_code, dictionary::CMD_LOCATION_INFO);
    assert_eq!(
        command_name(decoded.command_code, decoded.is_request),
        "LIA"
    );

    let server_name = decoded.avps.get("Server-Name").and_then(|v| v.as_str());
    assert_eq!(server_name, Some("sip:scscf.ims.example.com:6060"));
}
