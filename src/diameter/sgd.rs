//! Diameter SGd interface for SMS-over-NAS (3GPP TS 29.338).
//!
//! Implements the SMSC ↔ MME (or SGSN/MSC) signalling that carries the
//! SMS PDU itself in both directions:
//!
//! | Command | Code     | Direction | Purpose |
//! |---------|----------|-----------|---------|
//! | OFR/OFA | 8388645  | MME → SMSC | MO-Forward-Short-Message — UE-originated SMS into the SMSC |
//! | TFR/TFA | 8388646  | SMSC → MME | MT-Forward-Short-Message — deliver SMS to the UE |
//!
//! The actual SMS payload travels in the SM-RP-UI AVP as a raw
//! OctetString — for MT this is a SMS-DELIVER PDU, for MO it is a
//! SMS-SUBMIT PDU. SIPhon never decodes the PDU; it just tunnels the
//! bytes between the SMSC application logic and the access network.

use crate::diameter::codec::{self, *};
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::IncomingRequest;

// ---------------------------------------------------------------------------
// AVP extraction helpers (module-local, mirror s6c.rs)
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

fn octet_string_as_utf8(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name)
        .and_then(|v| v.as_str())
        .map(|hex_str| {
            codec::hex::decode(hex_str)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| hex_str.to_string())
        })
}

/// Decode an ISDN-AddressString OctetString AVP (TS 29.002 §17.7.8) —
/// strip the optional ToN/NPI prefix and TBCD-decode the remainder.
fn octet_string_as_isdn_address(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name)
        .and_then(|v| v.as_str())
        .and_then(codec::hex::decode)
        .map(|bytes| codec::decode_isdn_address_string(&bytes))
}

/// Decode an OctetString AVP into raw bytes (no UTF-8 assumption — for
/// SM-RP-UI which carries TPDUs).
fn octet_string_as_bytes(avps: &serde_json::Value, name: &str) -> Option<Vec<u8>> {
    avps.get(name)
        .and_then(|v| v.as_str())
        .and_then(codec::hex::decode)
}

// ---------------------------------------------------------------------------
// SGd answer builder
// ---------------------------------------------------------------------------

struct SgdAnswerBuilder {
    avp_buf: Vec<u8>,
}

impl SgdAnswerBuilder {
    fn new(origin_host: &str, origin_realm: &str, session_id: &str) -> Self {
        let mut avp_buf = Vec::with_capacity(256);
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
        avp_buf.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_buf.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::SGD_APP_ID,
        ));
        Self { avp_buf }
    }

    fn result_code(mut self, result_code: u32) -> Self {
        self.avp_buf
            .extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
        self
    }

    fn build_with_ids(self, command_code: u32, hop_by_hop: u32, end_to_end: u32) -> Vec<u8> {
        encode_diameter_message(
            FLAG_PROXIABLE,
            command_code,
            dictionary::SGD_APP_ID,
            hop_by_hop,
            end_to_end,
            &self.avp_buf,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TFR — MT-Forward-Short-Message (SMSC → MME)
// ═══════════════════════════════════════════════════════════════════════════

/// Build a wire-format TFR.
///
/// `user_name` is the IMSI of the recipient UE.
/// `sc_address` is the originating SMSC's GT.
/// `sm_rp_ui` is the SMS-DELIVER TPDU (3GPP TS 23.040).
/// `smsmi_correlation_id_ref` is an optional opaque correlation id the
///   SMSC may use to bind a TFR to its own queueing state. Encoded as
///   the IMSI sub-AVP inside SMSMI-Correlation-ID grouped AVP.
/// `sm_rp_mti` is the SM-RP Message Type Indicator: 0 = SMS Deliver
///   (the standard MT case), 1 = SMS Status Report.
pub fn build_mt_forward_short_message_request(
    config: &crate::diameter::peer::PeerConfig,
    session_id: &str,
    user_name: &str,
    sc_address: &str,
    sm_rp_ui: &[u8],
    smsmi_correlation_id_ref: Option<&str>,
    sm_rp_mti: Option<u32>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = Vec::with_capacity(512);
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
        dictionary::SGD_APP_ID,
    ));
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, user_name));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SC_ADDRESS,
        &codec::encode_isdn_address_string(sc_address, codec::TON_NPI_INTERNATIONAL_E164),
    ));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(avp::SM_RP_UI, sm_rp_ui));
    if let Some(mti) = sm_rp_mti {
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::SM_RP_MTI, mti));
    }
    if let Some(correlation_imsi) = smsmi_correlation_id_ref {
        // SMSMI-Correlation-ID is a grouped AVP holding HSS-Identifier
        // and Originating-SIP-URI children plus an optional IMSI hint.
        // We emit the simplest useful shape: a single User-Name child
        // serving as the correlation reference. SMSC implementations
        // that don't need it ignore the AVP.
        let children = encode_avp_utf8(avp::USER_NAME, correlation_imsi);
        avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(
            avp::SMSMI_CORRELATION_ID,
            &children,
        ));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_MT_FORWARD_SHORT_MESSAGE,
        dictionary::SGD_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

/// Parsed TFA fields.
#[derive(Debug, Clone)]
pub struct MtForwardShortMessageAnswer {
    pub result_code: u32,
    pub experimental_result_code: Option<u32>,
    /// Absent-User-Diagnostic-SM enum, when the UE was unreachable.
    pub absent_user_diagnostic: Option<u32>,
}

pub fn parse_tfa(message: &codec::DiameterMessage) -> Option<MtForwardShortMessageAnswer> {
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
    let absent_user_diagnostic = optional_u32(avps, "Absent-User-Diagnostic-SM");
    Some(MtForwardShortMessageAnswer {
        result_code,
        experimental_result_code,
        absent_user_diagnostic,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// OFR — MO-Forward-Short-Message (MME → SMSC)
// ═══════════════════════════════════════════════════════════════════════════

/// Parsed OFR fields (incoming MO-SMS from the access network).
#[derive(Debug, Clone)]
pub struct MoForwardShortMessageRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    /// IMSI of the originating UE.
    pub user_name: Option<String>,
    /// SMS-GMSC-Address — the GT of the gateway forwarding this MO-SMS.
    pub sms_gmsc_address: Option<String>,
    /// Originating SC-Address as seen by the MME.
    pub sc_address: Option<String>,
    /// SMS-SUBMIT TPDU bytes (TS 23.040).
    pub sm_rp_ui: Option<Vec<u8>>,
}

pub fn parse_ofr(incoming: &IncomingRequest) -> Option<MoForwardShortMessageRequest> {
    let avps = &incoming.avps;
    Some(MoForwardShortMessageRequest {
        session_id: required_str(avps, "Session-Id")?,
        origin_host: required_str(avps, "Origin-Host")?,
        origin_realm: required_str(avps, "Origin-Realm")?,
        user_name: optional_str(avps, "User-Name"),
        // SMS-GMSC-Address is dictionary-typed Address (IPv4/IPv6) — leave
        // the UTF-8 fallback; the ISDN-AddressString variant of this AVP
        // is not the one used on standard SGd.
        sms_gmsc_address: octet_string_as_utf8(avps, "SMS-GMSC-Address"),
        sc_address: octet_string_as_isdn_address(avps, "SC-Address"),
        sm_rp_ui: octet_string_as_bytes(avps, "SM-RP-UI"),
    })
}

/// Build an OFA success answer.
pub fn build_ofa_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    SgdAnswerBuilder::new(origin_host, origin_realm, session_id)
        .result_code(dictionary::DIAMETER_SUCCESS)
        .build_with_ids(
            dictionary::CMD_MO_FORWARD_SHORT_MESSAGE,
            hop_by_hop,
            end_to_end,
        )
}

/// Build an OFA error answer with an explicit Result-Code.
pub fn build_ofa_error(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    result_code: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    SgdAnswerBuilder::new(origin_host, origin_realm, session_id)
        .result_code(result_code)
        .build_with_ids(
            dictionary::CMD_MO_FORWARD_SHORT_MESSAGE,
            hop_by_hop,
            end_to_end,
        )
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
            host: "mme1.example.com".to_string(),
            port: 3868,
            origin_host: "smsc.example.com".to_string(),
            origin_realm: "example.com".to_string(),
            destination_host: Some("mme1.example.com".to_string()),
            destination_realm: "example.com".to_string(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![(dictionary::SGD_APP_ID, dictionary::VENDOR_3GPP)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        }
    }

    #[test]
    fn tfr_encodes_with_pdu_payload() {
        let pdu: Vec<u8> = vec![0x04, 0x0B, 0x91, 0x12, 0x34]; // arbitrary TPDU prefix
        let wire = build_mt_forward_short_message_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "31611111111",
            &pdu,
            None,
            Some(0),
            42,
            43,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(decoded.is_request);
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_MT_FORWARD_SHORT_MESSAGE
        );
        assert_eq!(decoded.application_id, dictionary::SGD_APP_ID);
        let user_name = decoded.avps.get("User-Name").and_then(|v| v.as_str());
        assert_eq!(user_name, Some("001010000000001"));
        let sm_rp_ui_hex = decoded
            .avps
            .get("SM-RP-UI")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(codec::hex::decode(sm_rp_ui_hex).unwrap(), pdu);
    }

    /// SC-Address on the TFR wire must be ISDN-AddressString — same fix
    /// class as the S6c SRR. Asserts the exact bytes so a regression
    /// reintroducing the raw-ASCII encoder fails loudly.
    #[test]
    fn tfr_encodes_sc_address_as_isdn_address_string() {
        let wire = build_mt_forward_short_message_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "31611111111",
            &[0u8; 4],
            None,
            None,
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let sc_bytes = codec::hex::decode(
            decoded.avps.get("SC-Address").unwrap().as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            sc_bytes,
            // "31611111111": (31)(61)(11)(11)(11)(1F) → nibble-swapped
            // 0x13 0x16 0x11 0x11 0x11 0xF1, with 0x91 ToN/NPI prefix.
            vec![0x91, 0x13, 0x16, 0x11, 0x11, 0x11, 0xF1],
        );
    }

    #[test]
    fn tfr_with_correlation_id_carries_grouped_avp() {
        let wire = build_mt_forward_short_message_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "31611111111",
            &[0u8; 4],
            Some("001010000000001"),
            None,
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let correlation = decoded.avps.get("SMSMI-Correlation-ID").expect(
            "SMSMI-Correlation-ID must be present when a correlation ref was supplied",
        );
        assert!(correlation.get("User-Name").is_some());
    }

    #[test]
    fn parse_tfa_extracts_result_code() {
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "mme1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));

        let wire = encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_MT_FORWARD_SHORT_MESSAGE,
            dictionary::SGD_APP_ID,
            1,
            1,
            &avp_bytes,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        let parsed = parse_tfa(&decoded).expect("TFA must parse");
        assert_eq!(parsed.result_code, 2001);
        assert!(parsed.absent_user_diagnostic.is_none());
    }

    #[test]
    fn parse_ofr_extracts_pdu_bytes() {
        let pdu: Vec<u8> = vec![0x21, 0x09, 0x91, 0x12, 0x34];
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "mme1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, "001010000000001"));
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
            avp::SC_ADDRESS,
            &codec::encode_isdn_address_string("31611111111", codec::TON_NPI_INTERNATIONAL_E164),
        ));
        avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(avp::SM_RP_UI, &pdu));

        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MO_FORWARD_SHORT_MESSAGE,
            dictionary::SGD_APP_ID,
            1,
            1,
            &avp_bytes,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        // Build an IncomingRequest-shaped wrapper for the parser.
        let incoming = IncomingRequest {
            command_code: decoded.command_code,
            application_id: decoded.application_id,
            hop_by_hop: decoded.hop_by_hop,
            end_to_end: decoded.end_to_end,
            avps: decoded.avps.clone(),
            raw: wire.clone(),
        };
        let parsed = parse_ofr(&incoming).expect("OFR must parse");
        assert_eq!(parsed.user_name.as_deref(), Some("001010000000001"));
        assert_eq!(parsed.sc_address.as_deref(), Some("31611111111"));
        assert_eq!(parsed.sm_rp_ui.as_deref(), Some(pdu.as_slice()));
    }

    #[test]
    fn ofa_success_carries_2001() {
        let wire = build_ofa_success("smsc.example.com", "example.com", "test;1;1", 5, 6);
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_MO_FORWARD_SHORT_MESSAGE);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
    }

    #[test]
    fn ofa_error_carries_supplied_code() {
        let wire = build_ofa_error("smsc.example.com", "example.com", "test;1;1", 5012, 5, 6);
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(5012)
        );
    }
}
