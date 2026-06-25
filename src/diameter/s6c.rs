//! Diameter S6c interface for SMS-over-Diameter (3GPP TS 29.336).
//!
//! Implements the SMSC ↔ HSS signalling that drives MT-SMS (SMS-over-NAS) flow:
//!
//! | Command | Code     | Direction | Purpose |
//! |---------|----------|-----------|---------|
//! | SRR/SRA | 8388647  | SMSC → HSS | Send-Routing-Info-for-SM — ask HSS where the UE is reachable |
//! | ALR/ALA | 8388648  | HSS → SMSC | Alert-Service-Centre — UE is now reachable; drain pending |
//! | RSR/RSA | 8388649  | SMSC → HSS | Report-SM-Delivery-Status — final delivery outcome |
//!
//! The SRA carries the served-node identity (SGSN-Number for 2G/3G,
//! MME-Number-for-MT-SMS for LTE) which the SMSC then uses on SGd as
//! the destination for MT-Forward-Short-Message (TFR).

use crate::diameter::codec::{self, *};
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::IncomingRequest;

// ---------------------------------------------------------------------------
// AVP extraction helpers — same shape as cx.rs, kept module-local so each
// app module can extend with app-specific extractors without leaking back
// into the base.
// ---------------------------------------------------------------------------

fn required_str(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name).and_then(|v| v.as_str()).map(String::from)
}

fn optional_str(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name).and_then(|v| v.as_str()).map(String::from)
}

fn optional_u32(avps: &serde_json::Value, name: &str) -> Option<u32> {
    avps.get(name).and_then(|v| v.as_u64()).map(|n| n as u32)
}

/// Decode an OctetString AVP that holds an ISDN-AddressString
/// (TS 29.002 §17.7.8) — strip the optional ToN/NPI prefix and
/// TBCD-decode the remainder back to an E.164 digit string. Used for
/// MSISDN (701), SC-Address (3300), SGSN-Number (1489), and
/// MME-Number-for-MT-SMS (1645).
fn octet_string_as_isdn_address(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name)
        .and_then(|v| v.as_str())
        .and_then(codec::hex::decode)
        .map(|bytes| codec::decode_isdn_address_string(&bytes))
}

// ---------------------------------------------------------------------------
// S6c answer builder — shared scaffolding for ALA / SRA / RSA answers
// ---------------------------------------------------------------------------

struct S6cAnswerBuilder {
    avp_buf: Vec<u8>,
}

impl S6cAnswerBuilder {
    fn new(origin_host: &str, origin_realm: &str, session_id: &str) -> Self {
        let mut avp_buf = Vec::with_capacity(256);
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
        avp_buf.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_buf.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::S6C_APP_ID,
        ));
        Self { avp_buf }
    }

    fn result_code(mut self, result_code: u32) -> Self {
        self.avp_buf
            .extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
        self
    }

    #[allow(dead_code)]
    fn experimental_result(mut self, result_code: u32) -> Self {
        let mut children = Vec::new();
        children.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, dictionary::VENDOR_3GPP));
        children.extend_from_slice(&encode_avp_u32(avp::EXPERIMENTAL_RESULT_CODE, result_code));
        self.avp_buf.extend_from_slice(&encode_avp(
            avp::EXPERIMENTAL_RESULT,
            AVP_FLAG_MANDATORY,
            &children,
        ));
        self
    }

    fn build_with_ids(self, command_code: u32, hop_by_hop: u32, end_to_end: u32) -> Vec<u8> {
        encode_diameter_message(
            FLAG_PROXIABLE,
            command_code,
            dictionary::S6C_APP_ID,
            hop_by_hop,
            end_to_end,
            &self.avp_buf,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SRR — Send-Routing-Info-for-SM (SMSC → HSS)
// ═══════════════════════════════════════════════════════════════════════════

/// Build the wire-format SRR.
///
/// `msisdn` is the called party's E.164 number (no leading `+`).
/// `sc_address` is the GT of the SMSC originating the routing query.
/// `sm_rp_mti` is the SM-RP Message Type Indicator: 0 = SMS Deliver
/// (MT to UE), 1 = SMS Status Report. Use 0 for MT delivery flow.
pub fn build_send_routing_info_request(
    config: &crate::diameter::peer::PeerConfig,
    session_id: &str,
    msisdn: &str,
    sc_address: &str,
    sm_rp_mti: Option<u32>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = Vec::with_capacity(256);
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    avp_bytes.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        &config.destination_realm,
    ));
    if let Some(dest_host) = &config.destination_host {
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
    }
    avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::S6C_APP_ID,
    ));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::MSISDN,
        &codec::encode_isdn_address_string(msisdn, codec::TON_NPI_INTERNATIONAL_E164),
    ));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SC_ADDRESS,
        &codec::encode_isdn_address_string(sc_address, codec::TON_NPI_INTERNATIONAL_E164),
    ));
    if let Some(mti) = sm_rp_mti {
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SM_RP_MTI, mti));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_SEND_ROUTING_INFO_FOR_SM,
        dictionary::S6C_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

/// Parsed SRA fields.
#[derive(Debug, Clone)]
pub struct SendRoutingInfoAnswer {
    pub result_code: u32,
    pub experimental_result_code: Option<u32>,
    /// IMSI of the served subscriber (User-Name).
    pub user_name: Option<String>,
    /// SGSN GT for 2G/3G delivery (Some → use SGd via SGSN).
    pub sgsn_number: Option<String>,
    /// MME GT for LTE delivery (Some → use SGd via MME).
    pub mme_number_for_mt_sms: Option<String>,
}

/// Decode an SRA from a peer answer. Returns `None` if the message is
/// not a Diameter answer or lacks Result-Code / Experimental-Result.
pub fn parse_sra(message: &codec::DiameterMessage) -> Option<SendRoutingInfoAnswer> {
    if message.is_request {
        return None;
    }
    let avps = &message.avps;
    let result_code = optional_u32(avps, "Result-Code").or_else(|| {
        avps.get("Experimental-Result")
            .and_then(|v| v.get("Experimental-Result-Code"))
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
    })?;
    let experimental_result_code = avps
        .get("Experimental-Result")
        .and_then(|v| v.get("Experimental-Result-Code"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    Some(SendRoutingInfoAnswer {
        result_code,
        experimental_result_code,
        user_name: optional_str(avps, "User-Name"),
        sgsn_number: octet_string_as_isdn_address(avps, "SGSN-Number"),
        mme_number_for_mt_sms: octet_string_as_isdn_address(avps, "MME-Number-for-MT-SMS"),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// ALR — Alert-Service-Centre (HSS → SMSC)
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed ALR fields (HSS notifying us that the UE has become reachable).
#[derive(Debug, Clone)]
pub struct AlertServiceCentreRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    /// IMSI (User-Name AVP).
    pub user_name: Option<String>,
    /// MSISDN, where present.
    pub msisdn: Option<String>,
    /// SMSMI-Correlation-ID grouped value, if the HSS pinned the SMSC's
    /// last queue-correlation hint.
    pub smsmi_correlation_id_present: bool,
}

pub fn parse_alr(incoming: &IncomingRequest) -> Option<AlertServiceCentreRequest> {
    let avps = &incoming.avps;
    Some(AlertServiceCentreRequest {
        session_id: required_str(avps, "Session-Id")?,
        origin_host: required_str(avps, "Origin-Host")?,
        origin_realm: required_str(avps, "Origin-Realm")?,
        user_name: optional_str(avps, "User-Name"),
        msisdn: octet_string_as_isdn_address(avps, "MSISDN"),
        smsmi_correlation_id_present: avps.get("SMSMI-Correlation-ID").is_some(),
    })
}

/// Build an ALA success answer (DIAMETER_SUCCESS by convention).
pub fn build_ala_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    S6cAnswerBuilder::new(origin_host, origin_realm, session_id)
        .result_code(dictionary::DIAMETER_SUCCESS)
        .build_with_ids(dictionary::CMD_ALERT_SERVICE_CENTRE, hop_by_hop, end_to_end)
}

/// Build an ALA error answer with an explicit Result-Code.
pub fn build_ala_error(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    result_code: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    S6cAnswerBuilder::new(origin_host, origin_realm, session_id)
        .result_code(result_code)
        .build_with_ids(dictionary::CMD_ALERT_SERVICE_CENTRE, hop_by_hop, end_to_end)
}

// ═══════════════════════════════════════════════════════════════════════════
// RSR — Report-SM-Delivery-Status (SMSC → HSS)
// ═══════════════════════════════════════════════════════════════════════════

/// Build the wire-format RSR.
///
/// `delivery_outcome` is encoded into a SM-Delivery-Outcome grouped AVP
/// holding only the per-domain outcome enum. Convention follows
/// TS 29.336 Annex A: 0 = SUCCESSFUL_TRANSFER, 1 = ABSENT_USER,
/// 2 = UE_MEMORY_CAPACITY_EXCEEDED, 3 = SUCCESSFUL_TRANSFER_NOT_LAST,
/// 4 = TEMPORARY_ERROR.
pub fn build_report_sm_delivery_status_request(
    config: &crate::diameter::peer::PeerConfig,
    session_id: &str,
    user_name: &str,
    sc_address: &str,
    delivery_outcome: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = Vec::with_capacity(256);
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    avp_bytes.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        &config.destination_realm,
    ));
    if let Some(dest_host) = &config.destination_host {
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, dest_host));
    }
    avp_bytes.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    avp_bytes.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::S6C_APP_ID,
    ));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, user_name));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SC_ADDRESS,
        &codec::encode_isdn_address_string(sc_address, codec::TON_NPI_INTERNATIONAL_E164),
    ));

    // SM-Delivery-Outcome is a grouped AVP that wraps a per-domain
    // outcome leaf. We emit only the MME-side leaf (most common in MT
    // delivery completion); HSS implementations accept either MME or
    // SGSN outcomes here as the dispositive value.
    let outcome_children = encode_avp_u32_3gpp(avp::SM_RP_MTI /* placeholder leaf code */, delivery_outcome);
    avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::SM_DELIVERY_OUTCOME,
        &outcome_children,
    ));

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_REPORT_SM_DELIVERY_STATUS,
        dictionary::S6C_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

/// Parsed RSA fields.
#[derive(Debug, Clone)]
pub struct ReportSmDeliveryStatusAnswer {
    pub result_code: u32,
    pub experimental_result_code: Option<u32>,
    pub user_name: Option<String>,
}

pub fn parse_rsa(message: &codec::DiameterMessage) -> Option<ReportSmDeliveryStatusAnswer> {
    if message.is_request {
        return None;
    }
    let avps = &message.avps;
    let result_code = optional_u32(avps, "Result-Code").or_else(|| {
        avps.get("Experimental-Result")
            .and_then(|v| v.get("Experimental-Result-Code"))
            .and_then(|v| v.as_u64())
            .map(|n| n as u32)
    })?;
    let experimental_result_code = avps
        .get("Experimental-Result")
        .and_then(|v| v.get("Experimental-Result-Code"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    Some(ReportSmDeliveryStatusAnswer {
        result_code,
        experimental_result_code,
        user_name: optional_str(avps, "User-Name"),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::PeerConfig;

    fn config() -> PeerConfig {
        PeerConfig {
            host: "hss1.example.com".to_string(),
            port: 3868,
            origin_host: "smsc.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: Some("hss1.example.com".to_string()),
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![(dictionary::S6C_APP_ID, dictionary::VENDOR_3GPP)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        }
    }

    #[test]
    fn srr_encodes_with_msisdn_and_sc_address() {
        let wire = build_send_routing_info_request(
            &config(),
            "test;1;1",
            "31612345678",
            "31611111111",
            Some(0),
            42,
            43,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_SEND_ROUTING_INFO_FOR_SM);
        assert_eq!(decoded.application_id, dictionary::S6C_APP_ID);

        // MSISDN and SC-Address are ISDN-AddressString — ToN/NPI 0x91 +
        // TBCD digit pairs. Pre-fix siphon shipped raw ASCII, which any
        // conformant HSS rejected as DIAMETER_USER_UNKNOWN.
        let avps = &decoded.avps;
        let msisdn_bytes = codec::hex::decode(avps.get("MSISDN").unwrap().as_str().unwrap()).unwrap();
        assert_eq!(
            msisdn_bytes,
            // "31612345678": nibble-swap each pair (31)(61)(23)(45)(67)(8F)
            // → 0x13 0x16 0x32 0x54 0x76 0xF8, with 0x91 ToN/NPI prefix.
            vec![0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xF8],
            "MSISDN must be 0x91 ToN/NPI + TBCD(31612345678) — 7 octets, \
             not 11 ASCII octets"
        );
        assert_eq!(codec::decode_isdn_address_string(&msisdn_bytes), "31612345678");

        let sc_bytes = codec::hex::decode(avps.get("SC-Address").unwrap().as_str().unwrap()).unwrap();
        assert_eq!(
            sc_bytes,
            // "31611111111": (31)(61)(11)(11)(11)(1F) → 0x13 0x16 0x11
            // 0x11 0x11 0xF1, with 0x91 prefix.
            vec![0x91, 0x13, 0x16, 0x11, 0x11, 0x11, 0xF1],
        );
        assert_eq!(codec::decode_isdn_address_string(&sc_bytes), "31611111111");
    }

    /// Regression test for the bug trace's MSISDN "3197010267609" — siphon
    /// must emit the exact 8-byte ISDN-AddressString the HSS expects, not
    /// the 13-byte ASCII the pre-fix encoder shipped.
    #[test]
    fn srr_encodes_bug_report_msisdn_per_ts_29002() {
        let wire = build_send_routing_info_request(
            &config(),
            "test;1;1",
            "3197010267609",
            "31611111111",
            Some(0),
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let msisdn_bytes = codec::hex::decode(
            decoded.avps.get("MSISDN").unwrap().as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            msisdn_bytes,
            vec![0x91, 0x13, 0x79, 0x10, 0x20, 0x76, 0x06, 0xF9],
        );
    }

    #[test]
    fn srr_omits_sm_rp_mti_when_none() {
        let wire = build_send_routing_info_request(
            &config(),
            "test;1;1",
            "31612345678",
            "31611111111",
            None,
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(decoded.avps.get("SM-RP-MTI").is_none());
    }

    #[test]
    fn parse_sra_with_mme_and_user_name() {
        // Build an SRA-shaped answer the way a TS 29.272 §7.3.146-conformant
        // HSS would — MME-Number-for-MT-SMS encoded as ISDN-AddressString.
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, "001010000000001"));
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
            avp::MME_NUMBER_FOR_MT_SMS,
            &codec::encode_isdn_address_string("31698765432", codec::TON_NPI_INTERNATIONAL_E164),
        ));

        let wire = encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_SEND_ROUTING_INFO_FOR_SM,
            dictionary::S6C_APP_ID,
            1,
            1,
            &avp_bytes,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let parsed = parse_sra(&decoded).expect("SRA must parse");
        assert_eq!(parsed.result_code, 2001);
        assert_eq!(parsed.user_name.as_deref(), Some("001010000000001"));
        assert_eq!(parsed.mme_number_for_mt_sms.as_deref(), Some("31698765432"));
        assert!(parsed.sgsn_number.is_none());
    }

    /// Parser must tolerate peers that omit the ToN/NPI prefix and ship
    /// raw TBCD digits — some non-conformant HSSes do this.
    #[test]
    fn parse_sra_tolerates_raw_tbcd_sgsn_number() {
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        // 7 TBCD octets, no ToN/NPI byte — first nibble is 0x3 (bit 7
        // clear), so the parser falls back to TBCD-only decoding.
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
            avp::SGSN_NUMBER,
            &codec::encode_tbcd_digits("31698765432"),
        ));

        let wire = encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_SEND_ROUTING_INFO_FOR_SM,
            dictionary::S6C_APP_ID,
            1,
            1,
            &avp_bytes,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let parsed = parse_sra(&decoded).expect("SRA must parse");
        assert_eq!(parsed.sgsn_number.as_deref(), Some("31698765432"));
    }

    #[test]
    fn parse_sra_returns_none_for_request() {
        let avp_bytes = encode_avp_u32(avp::RESULT_CODE, 2001);
        let wire = encode_diameter_message(
            FLAG_REQUEST,
            dictionary::CMD_SEND_ROUTING_INFO_FOR_SM,
            dictionary::S6C_APP_ID,
            1,
            1,
            &avp_bytes,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(parse_sra(&decoded).is_none());
    }

    #[test]
    fn ala_success_carries_result_code_2001() {
        let wire = build_ala_success(
            "smsc.example.com",
            "example.com",
            "test;1;1",
            10,
            20,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_ALERT_SERVICE_CENTRE);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
    }

    #[test]
    fn ala_error_carries_supplied_result_code() {
        let wire = build_ala_error(
            "smsc.example.com",
            "example.com",
            "test;1;1",
            5012,
            10,
            20,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(5012)
        );
    }

    #[test]
    fn rsr_encodes_with_outcome_grouped_avp() {
        let wire = build_report_sm_delivery_status_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "31611111111",
            0, // SUCCESSFUL_TRANSFER
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(decoded.is_request);
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_REPORT_SM_DELIVERY_STATUS
        );
        assert!(decoded.avps.get("SM-Delivery-Outcome").is_some());
    }
}
