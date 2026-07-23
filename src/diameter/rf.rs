//! Rf Diameter interface per 3GPP TS 32.299.
//!
//! Offline charging for IMS sessions between the CTF (S-CSCF/P-CSCF/AS)
//! and the CDF (Charging Data Function):
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | ACR/ACA | 271 | CTF → CDF | Accounting record (START/INTERIM/STOP/EVENT) |
//!
//! Rf uses the base Diameter accounting application (Acct-Application-Id = 3)
//! with 3GPP IMS-specific AVPs in the Service-Information grouped AVP.

use std::sync::Arc;
use std::time::SystemTime;

use tracing::info;

use crate::diameter::codec::*;
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::DiameterPeer;
use crate::diameter::ro::{ImsChargingData, SmsChargingData};

// ── Service-Context-Id (TS 32.260 §5.0) ────────────────────────────────

/// Default `Service-Context-Id` for IMS offline charging per TS 32.260
/// (release-agnostic).  Identifies the service category being charged.
pub const SERVICE_CONTEXT_ID_IMS: &str = "32260@3gpp.org";

// ── Termination-Cause (RFC 6733 §8.15) ─────────────────────────────────

/// `Termination-Cause` AVP enumerated values per RFC 6733 §8.15.
/// Required in ACR-STOP records.
pub mod termination_cause {
    pub const DIAMETER_LOGOUT: u32 = 1;
    pub const DIAMETER_SERVICE_NOT_PROVIDED: u32 = 2;
    pub const DIAMETER_BAD_ANSWER: u32 = 3;
    pub const DIAMETER_ADMINISTRATIVE: u32 = 4;
    pub const DIAMETER_LINK_BROKEN: u32 = 5;
    pub const DIAMETER_AUTH_EXPIRED: u32 = 6;
    pub const DIAMETER_USER_MOVED: u32 = 7;
    pub const DIAMETER_SESSION_TIMEOUT: u32 = 8;
}

/// Map a SIP final response code to a Cause-Code value suitable for the
/// IMS-Information `Cause-Code` AVP per TS 32.299 §5.2.5.  Successful
/// terminations (2xx) map to 0; failures pass through their negative SIP
/// code (e.g. 486 Busy → -486), matching the convention used by every
/// open-source IMS charging client.  Returns `None` for codes outside the
/// 100–699 range.
pub fn sip_status_to_cause_code(status: u16) -> Option<i32> {
    match status {
        100..=199 => None,
        200..=299 => Some(0),
        300..=699 => Some(-(status as i32)),
        _ => None,
    }
}

// ── Accounting-Record-Type (RFC 6733 §9.8.1) ───────────────────────────

/// Accounting record type per RFC 6733 table 9.8.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AccountingRecordType {
    EventRecord = 1,
    StartRecord = 2,
    InterimRecord = 3,
    StopRecord = 4,
}

impl AccountingRecordType {
    fn as_u32(self) -> u32 {
        self as u32
    }

    fn label(self) -> &'static str {
        match self {
            AccountingRecordType::EventRecord => "EVENT",
            AccountingRecordType::StartRecord => "START",
            AccountingRecordType::InterimRecord => "INTERIM",
            AccountingRecordType::StopRecord => "STOP",
        }
    }
}

// ── Accounting Answer (parsed) ──────────────────────────────────────────

/// Parsed Accounting-Answer from the CDF.
#[derive(Debug, Clone)]
pub struct AccountingAnswer {
    pub result_code: u32,
    pub record_type: Option<u32>,
    pub record_number: Option<u32>,
    pub session_id: Option<String>,
    /// `Acct-Interim-Interval` (RFC 6733 §8.19) returned by the CDF in
    /// ACA-START.  When present, the CTF must use this value for
    /// subsequent ACR-INTERIM cadence in preference to its local default.
    pub interim_interval: Option<u32>,
}

impl AccountingAnswer {
    pub fn is_success(&self) -> bool {
        self.result_code == dictionary::DIAMETER_SUCCESS
    }
}

fn parse_aca(avps: &serde_json::Value) -> AccountingAnswer {
    AccountingAnswer {
        result_code: avps
            .get("Result-Code")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32,
        record_type: avps
            .get("Accounting-Record-Type")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        record_number: avps
            .get("Accounting-Record-Number")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        session_id: avps
            .get("Session-Id")
            .and_then(|v| v.as_str())
            .map(String::from),
        interim_interval: avps
            .get("Acct-Interim-Interval")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
    }
}

// ── ACR parameters ──────────────────────────────────────────────────────

/// Full set of parameters for an Accounting-Request per TS 32.299 §6.2.2.
pub struct AccountingParams<'a> {
    pub record_type: AccountingRecordType,
    pub record_number: u32,
    pub session_id: Option<&'a str>,
    pub ims_data: Option<&'a ImsChargingData>,
    /// SMS-Information charging data per TS 32.299 §7.2.79.  When set,
    /// emits the `SMS-Information` grouped AVP under
    /// `Service-Information`.  May be combined with `ims_data` when a
    /// record needs both — most call sites use exactly one.
    pub sms_data: Option<&'a SmsChargingData>,

    /// `Event-Timestamp` AVP (RFC 6733 §8.21).  Defaults to the wall-clock
    /// time of `send_acr` when `None`.
    pub event_timestamp: Option<SystemTime>,
    /// `Service-Context-Id` AVP (TS 32.299 §7.2.91).  Defaults to
    /// [`SERVICE_CONTEXT_ID_IMS`] when `None`.
    pub service_context_id: Option<&'a str>,
    /// `User-Name` AVP (RFC 6733 §8.14) — typically a SIP URI / IMPU
    /// identifying the served subscriber.
    pub user_name: Option<&'a str>,
    /// `Termination-Cause` AVP (RFC 6733 §8.15).  Mandatory in ACR-STOP;
    /// must be `None` for START/INTERIM/EVENT.
    pub termination_cause: Option<u32>,
}

impl<'a> AccountingParams<'a> {
    /// Construct a parameter set with sensible defaults.  Only
    /// `record_type` is required; everything else is optional.
    pub fn new(record_type: AccountingRecordType) -> Self {
        Self {
            record_type,
            record_number: 0,
            session_id: None,
            ims_data: None,
            sms_data: None,
            event_timestamp: None,
            service_context_id: None,
            user_name: None,
            termination_cause: None,
        }
    }
}

// ── ACR encoder ─────────────────────────────────────────────────────────

/// Encode the AVP payload of an Accounting-Request per TS 32.299 §6.2.2.
///
/// Pure function — testable without a live peer.
pub fn encode_acr_payload(
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    destination_host: Option<&str>,
    session_id: &str,
    params: &AccountingParams<'_>,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        destination_realm,
    ));
    if let Some(host) = destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }

    // Acct-Application-Id = 3 (Rf uses base accounting, not Vendor-Specific-Application-Id).
    payload.extend_from_slice(&encode_avp_u32(avp::ACCT_APPLICATION_ID, dictionary::RF_APP_ID));

    // Service-Context-Id (TS 32.299 §7.2.91) — mandatory for IMS Rf.
    let service_context = params.service_context_id.unwrap_or(SERVICE_CONTEXT_ID_IMS);
    payload.extend_from_slice(&encode_avp_utf8(avp::SERVICE_CONTEXT_ID, service_context));

    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_TYPE,
        params.record_type.as_u32(),
    ));
    payload.extend_from_slice(&encode_avp_u32(
        avp::ACCOUNTING_RECORD_NUMBER,
        params.record_number,
    ));

    // User-Name (RFC 6733 §8.14) — IMS uses this to carry the served
    // subscriber's SIP URI / IMPU.
    if let Some(name) = params.user_name {
        payload.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, name));
    }

    // Event-Timestamp (RFC 6733 §8.21) — required for START/STOP/INTERIM
    // per TS 32.299 §6.2.2.
    let event_ts = params.event_timestamp.unwrap_or_else(SystemTime::now);
    payload.extend_from_slice(&encode_avp_time(avp::EVENT_TIMESTAMP, event_ts));

    // Termination-Cause (RFC 6733 §8.15) — mandatory in ACR-STOP per
    // TS 32.299 §6.2.2.
    if let Some(cause) = params.termination_cause {
        payload.extend_from_slice(&encode_avp_u32(avp::TERMINATION_CAUSE, cause));
    }

    // Service-Information → IMS-Information (shared with Ro) and/or
    // SMS-Information (TS 32.299 §7.2.79).  TS 32.299 §7.2.87 allows at most
    // ONE Service-Information per ACR, so when both are set they nest under a
    // single envelope (IMS-Information on the call tab, SMS-Information on the
    // SMS tab of a CDR collector).
    payload.extend_from_slice(&crate::diameter::ro::encode_service_information(
        params.ims_data,
        params.sms_data,
    ));

    payload
}

// ── ACR sender ──────────────────────────────────────────────────────────

/// Send an Accounting-Request to the CDF.
///
/// Per TS 32.299 §6.3.2, the CTF generates ACRs at session boundaries
/// (START/STOP) and optionally mid-session (INTERIM). EVENT records
/// are used for one-shot transactions (e.g., MESSAGE, REGISTER).
pub async fn send_acr(
    peer: &Arc<DiameterPeer>,
    params: &AccountingParams<'_>,
) -> Result<AccountingAnswer, String> {
    let config = peer.config();
    let hbh = peer.next_hbh();
    let e2e = peer.next_e2e();

    // Use provided session_id for continuity, or generate a new one
    let owned_session;
    let session_id = match params.session_id {
        Some(id) => id,
        None => {
            owned_session = peer.new_session_id();
            &owned_session
        }
    };

    let payload = encode_acr_payload(
        &config.origin_host,
        &config.origin_realm,
        &config.destination_realm,
        config.destination_host.as_deref(),
        session_id,
        params,
    );

    let wire = encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_ACCOUNTING,
        dictionary::RF_APP_ID,
        hbh,
        e2e,
        &payload,
    );

    info!(
        session = %session_id,
        record_type = %params.record_type.label(),
        record_number = params.record_number,
        "Rf: sending ACR"
    );
    let answer = peer.send_request(wire).await?;

    let mut parsed = parse_aca(&answer.avps);
    // Session-Id continuity (RFC 6733 §9.8): the request Session-Id is
    // authoritative for the whole START→INTERIM→STOP accounting session. If the
    // CDF's ACA omits it, fall back to the request's so the caller can key
    // INTERIM/STOP correctly instead of orphaning the session.
    if parsed.session_id.is_none() {
        parsed.session_id = Some(session_id.to_string());
    }
    Ok(parsed)
}

/// Send ACR-START (begin accounting session).  Record-Number is fixed at 0
/// per RFC 6733 §9.8.3.
pub async fn send_acr_start(
    peer: &Arc<DiameterPeer>,
    user_name: Option<&str>,
    ims_data: Option<&ImsChargingData>,
    sms_data: Option<&SmsChargingData>,
) -> Result<AccountingAnswer, String> {
    let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
    params.user_name = user_name;
    params.ims_data = ims_data;
    params.sms_data = sms_data;
    send_acr(peer, &params).await
}

/// Send ACR-INTERIM (mid-session accounting update).  `record_number` must
/// be a strictly increasing non-zero integer for the same Session-Id per
/// RFC 6733 §9.8.3.
pub async fn send_acr_interim(
    peer: &Arc<DiameterPeer>,
    session_id: &str,
    record_number: u32,
    user_name: Option<&str>,
    ims_data: Option<&ImsChargingData>,
    sms_data: Option<&SmsChargingData>,
) -> Result<AccountingAnswer, String> {
    let mut params = AccountingParams::new(AccountingRecordType::InterimRecord);
    params.record_number = record_number;
    params.session_id = Some(session_id);
    params.user_name = user_name;
    params.ims_data = ims_data;
    params.sms_data = sms_data;
    send_acr(peer, &params).await
}

/// Send ACR-STOP (end accounting session).  `termination_cause` should
/// match the actual termination reason per RFC 6733 §8.15
/// ([`termination_cause::DIAMETER_LOGOUT`] for normal BYE,
/// [`termination_cause::DIAMETER_SESSION_TIMEOUT`] for session-timer
/// expiry, etc.).
pub async fn send_acr_stop(
    peer: &Arc<DiameterPeer>,
    session_id: &str,
    record_number: u32,
    termination_cause: u32,
    user_name: Option<&str>,
    ims_data: Option<&ImsChargingData>,
    sms_data: Option<&SmsChargingData>,
) -> Result<AccountingAnswer, String> {
    let mut params = AccountingParams::new(AccountingRecordType::StopRecord);
    params.record_number = record_number;
    params.session_id = Some(session_id);
    params.user_name = user_name;
    params.ims_data = ims_data;
    params.sms_data = sms_data;
    params.termination_cause = Some(termination_cause);
    send_acr(peer, &params).await
}

/// Send ACR-EVENT (one-shot accounting, e.g., SIP MESSAGE or REGISTER).
/// Record-Number is fixed at 0 per RFC 6733 §9.8.3.
pub async fn send_acr_event(
    peer: &Arc<DiameterPeer>,
    user_name: Option<&str>,
    ims_data: Option<&ImsChargingData>,
    sms_data: Option<&SmsChargingData>,
) -> Result<AccountingAnswer, String> {
    let mut params = AccountingParams::new(AccountingRecordType::EventRecord);
    params.user_name = user_name;
    params.ims_data = ims_data;
    params.sms_data = sms_data;
    send_acr(peer, &params).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::ro::{ImsChargingData, NodeFunctionality, NodeRole};

    // ── Accounting-Record-Type compliance (RFC 6733 §9.8.1) ─────────────

    #[test]
    fn accounting_record_type_rfc6733_values() {
        assert_eq!(AccountingRecordType::EventRecord.as_u32(), 1);
        assert_eq!(AccountingRecordType::StartRecord.as_u32(), 2);
        assert_eq!(AccountingRecordType::InterimRecord.as_u32(), 3);
        assert_eq!(AccountingRecordType::StopRecord.as_u32(), 4);
    }

    #[test]
    fn accounting_record_type_labels() {
        assert_eq!(AccountingRecordType::EventRecord.label(), "EVENT");
        assert_eq!(AccountingRecordType::StartRecord.label(), "START");
        assert_eq!(AccountingRecordType::InterimRecord.label(), "INTERIM");
        assert_eq!(AccountingRecordType::StopRecord.label(), "STOP");
    }

    // ── ACA parsing ────────────────────────────────────────────────────

    #[test]
    fn aca_start_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 2,
            "Accounting-Record-Number": 0,
            "Session-Id": "cdf.ims.mnc001.mcc001.3gppnetwork.org;sess;42"
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(2));
        assert_eq!(answer.record_number, Some(0));
        assert_eq!(
            answer.session_id.as_deref(),
            Some("cdf.ims.mnc001.mcc001.3gppnetwork.org;sess;42")
        );
    }

    #[test]
    fn aca_interim_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 3,
            "Accounting-Record-Number": 5
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(3));
        assert_eq!(answer.record_number, Some(5));
        assert!(answer.session_id.is_none());
    }

    #[test]
    fn aca_stop_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 4,
            "Accounting-Record-Number": 10
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(4));
        assert_eq!(answer.record_number, Some(10));
    }

    #[test]
    fn aca_event_success() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 1,
            "Accounting-Record-Number": 0
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.record_type, Some(1));
    }

    #[test]
    fn aca_out_of_space() {
        // DIAMETER_OUT_OF_SPACE (4002) — CDF cannot store more records
        let json = serde_json::json!({
            "Result-Code": 4002,
            "Accounting-Record-Type": 2,
            "Accounting-Record-Number": 0
        });
        let answer = parse_aca(&json);
        assert!(!answer.is_success());
        assert_eq!(answer.result_code, 4002);
    }

    #[test]
    fn aca_unknown_session() {
        // DIAMETER_UNKNOWN_SESSION_ID (5002) — CDF lost the session
        let json = serde_json::json!({
            "Result-Code": 5002,
            "Accounting-Record-Type": 3,
            "Accounting-Record-Number": 3
        });
        let answer = parse_aca(&json);
        assert!(!answer.is_success());
        assert_eq!(answer.result_code, 5002);
    }

    #[test]
    fn aca_minimal_response() {
        let json = serde_json::json!({"Result-Code": 2001});
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert!(answer.record_type.is_none());
        assert!(answer.record_number.is_none());
        assert!(answer.session_id.is_none());
    }

    #[test]
    fn aca_missing_result_code_defaults_to_zero() {
        let json = serde_json::json!({});
        let answer = parse_aca(&json);
        assert_eq!(answer.result_code, 0);
        assert!(!answer.is_success());
    }

    // ── IMS charging data shared with Ro ────────────────────────────────

    #[test]
    fn ims_data_invite_originating() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-rf-test-001".into()),
            cause_code: Some(0),
            ..Default::default()
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
        // Outer AVP code must be Service-Information (873)
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::SERVICE_INFORMATION);
        // Substantial payload with nested IMS-Information
        assert!(encoded.len() > 100);
    }

    #[test]
    fn ims_data_register_event_pcscf() {
        let data = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("REGISTER".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::PCscf),
            ..Default::default()
        };
        let encoded = data.encode_service_information();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn ims_data_minimal_empty() {
        let data = ImsChargingData::default();
        let encoded = data.encode_service_information();
        // Even with no fields, the nested grouped structure is present
        assert!(!encoded.is_empty());
    }

    // ── ACR wire-format roundtrip ──────────────────────────────────────

    /// Helper: build an ACR on the wire for testing (bypasses peer).
    fn build_acr_wire_for_test(
        record_type: AccountingRecordType,
        record_number: u32,
        session_id: &str,
        ims_data: Option<&ImsChargingData>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
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
            record_type.as_u32(),
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
            1,
            2,
            &payload,
        )
    }

    #[test]
    fn acr_start_wire_roundtrip() {
        let ims = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: Some("sip:bob@ims.mnc001.mcc001.3gppnetwork.org".into()),
            sip_method: Some("INVITE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::SCscf),
            ims_charging_identifier: Some("icid-rf-roundtrip-001".into()),
            ..Default::default()
        };

        let wire = build_acr_wire_for_test(
            AccountingRecordType::StartRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            Some(&ims),
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_ACCOUNTING);
        assert_eq!(decoded.application_id, dictionary::RF_APP_ID);
        assert_eq!(
            decoded.avps.get("Session-Id").and_then(|v| v.as_str()),
            Some("cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1")
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(2) // START
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            decoded
                .avps
                .get("Acct-Application-Id")
                .and_then(|v| v.as_u64()),
            Some(3) // base accounting
        );

        // Verify nested Service-Information → IMS-Information
        let svc_info = decoded.avps.get("Service-Information").unwrap();
        let ims_info = svc_info.get("IMS-Information").unwrap();
        assert!(ims_info.get("Calling-Party-Address").is_some());
        assert!(ims_info.get("Called-Party-Address").is_some());
        assert!(ims_info.get("IMS-Charging-Identifier").is_some());
    }

    #[test]
    fn acr_interim_wire_roundtrip() {
        let wire = build_acr_wire_for_test(
            AccountingRecordType::InterimRecord,
            3,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(3) // INTERIM
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
    }

    #[test]
    fn acr_stop_wire_roundtrip() {
        let wire = build_acr_wire_for_test(
            AccountingRecordType::StopRecord,
            7,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;sess;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(4) // STOP
        );
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(7)
        );
    }

    #[test]
    fn acr_event_wire_roundtrip() {
        let ims = ImsChargingData {
            calling_party: Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org".into()),
            called_party: None,
            sip_method: Some("MESSAGE".into()),
            role_of_node: Some(NodeRole::OriginatingRole),
            node_functionality: Some(NodeFunctionality::ApplicationServer),
            ..Default::default()
        };

        let wire = build_acr_wire_for_test(
            AccountingRecordType::EventRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;event;1",
            Some(&ims),
        );
        let decoded = decode_diameter(&wire).unwrap();

        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Type")
                .and_then(|v| v.as_u64()),
            Some(1) // EVENT
        );
        // Event records use record_number = 0
        assert_eq!(
            decoded
                .avps
                .get("Accounting-Record-Number")
                .and_then(|v| v.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn acr_without_ims_data() {
        // Rf allows ACR without Service-Information (e.g., for non-IMS accounting)
        let wire = build_acr_wire_for_test(
            AccountingRecordType::EventRecord,
            0,
            "cdf.ims.mnc001.mcc001.3gppnetwork.org;rf;bare;1",
            None,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(decoded.avps.get("Service-Information").is_none());
    }

    // ── App ID and command code compliance ──────────────────────────────

    #[test]
    fn rf_app_id_is_base_accounting() {
        // Rf uses Acct-Application-Id = 3, NOT a vendor-specific application
        assert_eq!(dictionary::RF_APP_ID, 3);
    }

    #[test]
    fn rf_command_code_rfc6733() {
        // ACR/ACA uses command code 271 (base Diameter accounting)
        assert_eq!(dictionary::CMD_ACCOUNTING, 271);
    }

    #[test]
    fn rf_command_name_acr() {
        assert_eq!(command_name(271, true), "ACR");
    }

    #[test]
    fn rf_command_name_aca() {
        assert_eq!(command_name(271, false), "ACA");
    }

    #[test]
    fn rf_diameter_success_code() {
        assert_eq!(dictionary::DIAMETER_SUCCESS, 2001);
    }

    // ── Event-Timestamp / Service-Context-Id / User-Name (TS 32.299 §6.2.2) ─

    #[test]
    fn acr_encodes_event_timestamp() {
        use std::time::{Duration, UNIX_EPOCH};
        let event_time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
        params.event_timestamp = Some(event_time);

        let payload = encode_acr_payload(
            "scscf.ims.example.com",
            "example.com",
            "example.com",
            None,
            "sess;1",
            &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Event-Timestamp").and_then(|v| v.as_u64()),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn acr_encodes_service_context_id_default_ims() {
        let params = AccountingParams::new(AccountingRecordType::StartRecord);
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Service-Context-Id").and_then(|v| v.as_str()),
            Some("32260@3gpp.org")
        );
    }

    #[test]
    fn acr_encodes_service_context_id_override() {
        let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
        params.service_context_id = Some("32274@3gpp.org"); // MMTel SC
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Service-Context-Id").and_then(|v| v.as_str()),
            Some("32274@3gpp.org")
        );
    }

    #[test]
    fn acr_encodes_user_name_when_set() {
        let mut params = AccountingParams::new(AccountingRecordType::StartRecord);
        params.user_name = Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org");
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("User-Name").and_then(|v| v.as_str()),
            Some("sip:alice@ims.mnc001.mcc001.3gppnetwork.org")
        );
    }

    #[test]
    fn acr_omits_user_name_when_none() {
        let params = AccountingParams::new(AccountingRecordType::StartRecord);
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(decoded.avps.get("User-Name").is_none());
    }

    // ── Termination-Cause (RFC 6733 §8.15, mandatory in ACR-STOP) ────────

    #[test]
    fn acr_stop_encodes_termination_cause_logout() {
        let mut params = AccountingParams::new(AccountingRecordType::StopRecord);
        params.session_id = Some("sess;1");
        params.record_number = 1;
        params.termination_cause = Some(termination_cause::DIAMETER_LOGOUT);
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Termination-Cause").and_then(|v| v.as_u64()),
            Some(1) // DIAMETER_LOGOUT
        );
    }

    #[test]
    fn acr_stop_encodes_termination_cause_session_timeout() {
        let mut params = AccountingParams::new(AccountingRecordType::StopRecord);
        params.session_id = Some("sess;1");
        params.record_number = 5;
        params.termination_cause = Some(termination_cause::DIAMETER_SESSION_TIMEOUT);
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Termination-Cause").and_then(|v| v.as_u64()),
            Some(8) // DIAMETER_SESSION_TIMEOUT
        );
    }

    #[test]
    fn acr_start_omits_termination_cause() {
        let params = AccountingParams::new(AccountingRecordType::StartRecord);
        let payload = encode_acr_payload(
            "scscf.example.com", "example.com", "example.com", None, "sess;1", &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1, 2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(
            decoded.avps.get("Termination-Cause").is_none(),
            "Termination-Cause must NOT be present in ACR-START per TS 32.299 §6.2.2"
        );
    }

    #[test]
    fn termination_cause_constants_match_rfc6733() {
        // RFC 6733 §8.15 Termination-Cause enumerated values
        assert_eq!(termination_cause::DIAMETER_LOGOUT, 1);
        assert_eq!(termination_cause::DIAMETER_SERVICE_NOT_PROVIDED, 2);
        assert_eq!(termination_cause::DIAMETER_BAD_ANSWER, 3);
        assert_eq!(termination_cause::DIAMETER_ADMINISTRATIVE, 4);
        assert_eq!(termination_cause::DIAMETER_LINK_BROKEN, 5);
        assert_eq!(termination_cause::DIAMETER_AUTH_EXPIRED, 6);
        assert_eq!(termination_cause::DIAMETER_USER_MOVED, 7);
        assert_eq!(termination_cause::DIAMETER_SESSION_TIMEOUT, 8);
    }

    // ── Acct-Interim-Interval round-trip (RFC 6733 §8.19) ────────────────

    #[test]
    fn aca_with_interim_interval_returned_by_cdf() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 2,
            "Accounting-Record-Number": 0,
            "Acct-Interim-Interval": 600,
        });
        let answer = parse_aca(&json);
        assert!(answer.is_success());
        assert_eq!(answer.interim_interval, Some(600));
    }

    #[test]
    fn aca_without_interim_interval_is_none() {
        let json = serde_json::json!({
            "Result-Code": 2001,
            "Accounting-Record-Type": 2,
        });
        let answer = parse_aca(&json);
        assert!(answer.interim_interval.is_none());
    }

    // ── SIP → Diameter Cause-Code mapping (TS 32.299 §5.2.5) ─────────────

    #[test]
    fn sip_status_to_cause_code_2xx_is_zero() {
        assert_eq!(sip_status_to_cause_code(200), Some(0));
        assert_eq!(sip_status_to_cause_code(202), Some(0));
    }

    #[test]
    fn sip_status_to_cause_code_4xx_is_negative() {
        assert_eq!(sip_status_to_cause_code(486), Some(-486));
        assert_eq!(sip_status_to_cause_code(404), Some(-404));
    }

    #[test]
    fn sip_status_to_cause_code_5xx_6xx_is_negative() {
        assert_eq!(sip_status_to_cause_code(503), Some(-503));
        assert_eq!(sip_status_to_cause_code(603), Some(-603));
    }

    #[test]
    fn sip_status_to_cause_code_provisional_is_none() {
        assert_eq!(sip_status_to_cause_code(180), None);
        assert_eq!(sip_status_to_cause_code(100), None);
    }

    #[test]
    fn sip_status_to_cause_code_out_of_range_is_none() {
        assert_eq!(sip_status_to_cause_code(99), None);
        assert_eq!(sip_status_to_cause_code(700), None);
    }

    // ── Service-Context-Id constant (TS 32.260 §5.0) ──────────────────────

    #[test]
    fn service_context_id_ims_constant() {
        assert_eq!(SERVICE_CONTEXT_ID_IMS, "32260@3gpp.org");
    }

    // ── SMS-Information ACR wire-format (TS 32.299 §7.2.79) ──────────────

    #[test]
    fn acr_event_carries_sms_information() {
        let sms = SmsChargingData {
            originator_address: Some("0015551234001".into()),
            recipient_address: Some("0015551234002".into()),
            sm_message_type: Some(0), // SUBMISSION
            sms_node: Some(1),        // IP-SM-GW
            sms_result: Some(0),      // Success
            originating_ioi: Some("orig.example.com".into()),
            terminating_ioi: Some("term.example.com".into()),
            ..Default::default()
        };
        let mut params = AccountingParams::new(AccountingRecordType::EventRecord);
        params.sms_data = Some(&sms);

        let payload = encode_acr_payload(
            "ipsmgw.example.com",
            "example.com",
            "example.com",
            None,
            "cdf;sms;event;1",
            &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1,
            2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();

        // Service-Information must contain SMS-Information (not IMS-Information)
        let svc_info = decoded
            .avps
            .get("Service-Information")
            .expect("Service-Information present");
        let sms_info = svc_info
            .get("SMS-Information")
            .expect("SMS-Information emitted");
        assert!(
            svc_info.get("IMS-Information").is_none(),
            "pure SMS record must NOT also carry IMS-Information"
        );

        // Calling/called party reach the wire
        let orig_addr = sms_info
            .get("Originator-Received-Address")
            .expect("Originator-Received-Address");
        assert_eq!(
            orig_addr.get("Address-Data").and_then(|v| v.as_str()),
            Some("0015551234001")
        );
        let recip_addr = sms_info
            .get("Recipient-Info")
            .and_then(|r| r.get("Recipient-Address"))
            .expect("Recipient-Address inside Recipient-Info");
        assert_eq!(
            recip_addr.get("Address-Data").and_then(|v| v.as_str()),
            Some("0015551234002")
        );
        assert_eq!(
            sms_info.get("SM-Message-Type").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(sms_info.get("SMS-Node").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(sms_info.get("SMS-Result").and_then(|v| v.as_u64()), Some(0));
    }

    #[test]
    fn acr_can_carry_both_ims_and_sms() {
        // Hybrid record — when both ims_data and sms_data are set the encoder
        // nests IMS-Information and SMS-Information under a SINGLE
        // Service-Information envelope (TS 32.299 §7.2.87 permits at most one),
        // so a CDR collector surfaces both tabs from one record.
        let ims = ImsChargingData {
            sip_method: Some("MESSAGE".into()),
            node_functionality: Some(NodeFunctionality::ApplicationServer),
            cause_code: Some(0),
            ..Default::default()
        };
        let sms = SmsChargingData {
            originator_address: Some("0015551234001".into()),
            recipient_address: Some("0015551234002".into()),
            sm_message_type: Some(0),
            ..Default::default()
        };
        let mut params = AccountingParams::new(AccountingRecordType::EventRecord);
        params.ims_data = Some(&ims);
        params.sms_data = Some(&sms);

        let payload = encode_acr_payload(
            "ipsmgw.example.com",
            "example.com",
            "example.com",
            None,
            "cdf;hybrid;event;1",
            &params,
        );
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            1,
            2,
            &payload,
        );
        let decoded = decode_diameter(&wire).unwrap();

        // Exactly one Service-Information, carrying BOTH IMS-Information and
        // SMS-Information as sub-groups (not two separate envelopes).
        let svc = decoded
            .avps
            .get("Service-Information")
            .expect("Service-Information present");
        assert!(
            !svc.is_array(),
            "must be a single Service-Information, not an array of envelopes"
        );
        assert!(
            svc.get("IMS-Information").is_some(),
            "IMS-Information must nest under the single Service-Information"
        );
        assert!(
            svc.get("SMS-Information").is_some(),
            "SMS-Information must nest under the single Service-Information"
        );
    }
}
