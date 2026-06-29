//! Diameter S6a interface (3GPP TS 29.272) — MME ↔ HSS for LTE.
//!
//! Implements the client-side request builders + answer parsers for the
//! commands an MVNO core's MME/SGSN drives toward the HSS:
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | AIR/AIA | 318  | MME → HSS | Authentication-Information — fetch E-UTRAN auth vectors |
//! | ULR/ULA | 316  | MME → HSS | Update-Location — register the UE's serving MME |
//! | PUR/PUA | 321  | MME → HSS | Purge-UE — detach cleanup |
//!
//! As with the other app modules, request encoding uses the typed byte
//! builders and answer parsing reads the lossy JSON view; the Diameter server relay path
//! uses the lossless tree in `codec.rs` instead.

use crate::diameter::codec::{self, *};
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::PeerConfig;

/// `ULR-Flags` bit 1 (Single-Registration-Indication) + bit 2 (S6a/S6d
/// indicator) are the common attach flags; callers pass the raw value.
pub const ULR_FLAG_S6A_S6D_INDICATOR: u32 = 1 << 1;

fn request_preamble(config: &PeerConfig, session_id: &str) -> Vec<u8> {
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
        dictionary::S6A_APP_ID,
    ));
    avp_bytes
}

// ═══════════════════════════════════════════════════════════════════════════
// AIR — Authentication-Information-Request (MME → HSS)
// ═══════════════════════════════════════════════════════════════════════════

/// Build an AIR requesting `num_vectors` E-UTRAN authentication vectors for
/// `imsi`, served from `visited_plmn_id` (3-octet MCC/MNC, TS 23.003 §12.1).
/// When `resync_info` is set (RAND‖AUTS), it triggers SQN re-synchronisation.
#[allow(clippy::too_many_arguments)]
pub fn build_authentication_information_request(
    config: &PeerConfig,
    session_id: &str,
    imsi: &str,
    visited_plmn_id: &[u8],
    num_vectors: u32,
    immediate_response_preferred: bool,
    resync_info: Option<&[u8]>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = request_preamble(config, session_id);
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, imsi));

    // Requested-EUTRAN-Authentication-Info (grouped).
    let mut requested = Vec::new();
    requested.extend_from_slice(&encode_avp_u32_3gpp(
        avp::NUMBER_OF_REQUESTED_VECTORS,
        num_vectors,
    ));
    requested.extend_from_slice(&encode_avp_u32_3gpp(
        avp::IMMEDIATE_RESPONSE_PREFERRED,
        immediate_response_preferred as u32,
    ));
    if let Some(resync) = resync_info {
        requested.extend_from_slice(&encode_avp_octet_3gpp(avp::RE_SYNCHRONIZATION_INFO, resync));
    }
    avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::REQUESTED_EUTRAN_AUTHENTICATION_INFO,
        &requested,
    ));

    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(avp::VISITED_PLMN_ID, visited_plmn_id));

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_AUTHENTICATION_INFORMATION,
        dictionary::S6A_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

/// A single E-UTRAN authentication vector from an AIA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EutranVector {
    pub rand: Vec<u8>,
    pub xres: Vec<u8>,
    pub autn: Vec<u8>,
    pub kasme: Vec<u8>,
}

/// Parsed AIA.
#[derive(Debug, Clone)]
pub struct AuthenticationInformationAnswer {
    pub result_code: u32,
    pub experimental_result_code: Option<u32>,
    pub vectors: Vec<EutranVector>,
}

fn hex_to_bytes(value: &serde_json::Value, key: &str) -> Vec<u8> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .and_then(codec::hex::decode)
        .unwrap_or_default()
}

fn parse_vector(vector: &serde_json::Value) -> EutranVector {
    EutranVector {
        rand: hex_to_bytes(vector, "RAND"),
        xres: hex_to_bytes(vector, "XRES"),
        autn: hex_to_bytes(vector, "AUTN"),
        kasme: hex_to_bytes(vector, "KASME"),
    }
}

/// Decode an AIA. Returns `None` if the message is not an answer or lacks a
/// result code. The E-UTRAN vectors live under
/// `Authentication-Info → E-UTRAN-Vector` (one AVP, or an array of them).
pub fn parse_aia(message: &codec::DiameterMessage) -> Option<AuthenticationInformationAnswer> {
    if message.is_request {
        return None;
    }
    let avps = &message.avps;
    let experimental_result_code = avps
        .get("Experimental-Result")
        .and_then(|v| v.get("Experimental-Result-Code"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let result_code = avps
        .get("Result-Code")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .or(experimental_result_code)?;

    let mut vectors = Vec::new();
    if let Some(auth_info) = avps.get("Authentication-Info") {
        match auth_info.get("E-UTRAN-Vector") {
            Some(serde_json::Value::Array(items)) => {
                vectors.extend(items.iter().map(parse_vector));
            }
            Some(single) if single.is_object() => vectors.push(parse_vector(single)),
            _ => {}
        }
    }

    Some(AuthenticationInformationAnswer {
        result_code,
        experimental_result_code,
        vectors,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// ULR — Update-Location-Request (MME → HSS)
// ═══════════════════════════════════════════════════════════════════════════

/// Build a ULR registering `imsi` on this MME. `rat_type` per TS 29.272
/// §7.3.13 (1004 = EUTRAN). `ulr_flags` per §7.3.7.
#[allow(clippy::too_many_arguments)]
pub fn build_update_location_request(
    config: &PeerConfig,
    session_id: &str,
    imsi: &str,
    rat_type: u32,
    ulr_flags: u32,
    visited_plmn_id: &[u8],
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = request_preamble(config, session_id);
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, imsi));
    avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::RAT_TYPE, rat_type));
    avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::ULR_FLAGS, ulr_flags));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(avp::VISITED_PLMN_ID, visited_plmn_id));

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_UPDATE_LOCATION,
        dictionary::S6A_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

/// Parsed ULA.
#[derive(Debug, Clone)]
pub struct UpdateLocationAnswer {
    pub result_code: u32,
    pub experimental_result_code: Option<u32>,
    pub ula_flags: Option<u32>,
    /// Whether the answer carried a Subscription-Data AVP (the APN profile).
    pub has_subscription_data: bool,
}

/// Decode a ULA.
pub fn parse_ula(message: &codec::DiameterMessage) -> Option<UpdateLocationAnswer> {
    if message.is_request {
        return None;
    }
    let avps = &message.avps;
    let experimental_result_code = avps
        .get("Experimental-Result")
        .and_then(|v| v.get("Experimental-Result-Code"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let result_code = avps
        .get("Result-Code")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)
        .or(experimental_result_code)?;
    Some(UpdateLocationAnswer {
        result_code,
        experimental_result_code,
        ula_flags: avps.get("ULA-Flags").and_then(|v| v.as_u64()).map(|n| n as u32),
        has_subscription_data: avps.get("Subscription-Data").is_some(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// PUR — Purge-UE-Request (MME → HSS)
// ═══════════════════════════════════════════════════════════════════════════

/// Build a PUR detaching `imsi` from this MME.
pub fn build_purge_ue_request(
    config: &PeerConfig,
    session_id: &str,
    imsi: &str,
    pur_flags: Option<u32>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_bytes = request_preamble(config, session_id);
    avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, imsi));
    if let Some(flags) = pur_flags {
        avp_bytes.extend_from_slice(&encode_avp_u32_3gpp(avp::PUR_FLAGS, flags));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_PURGE_UE,
        dictionary::S6A_APP_ID,
        hop_by_hop,
        end_to_end,
        &avp_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PeerConfig {
        PeerConfig {
            host: "hss.epc.example.org".into(),
            port: 3868,
            origin_host: "mme.epc.example.org".into(),
            origin_realm: "epc.example.org".into(),
            destination_host: None,
            destination_realm: "epc.example.org".into(),
            local_ip: "10.0.0.1".parse().unwrap(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".into(),
            firmware_revision: 1,
        }
    }

    // MCC 001 / MNC 01 (3GPP test PLMN) encoded per TS 23.003 §12.1.
    const TEST_PLMN: [u8; 3] = [0x00, 0xF1, 0x10];

    #[test]
    fn air_encodes_requested_vectors_and_plmn() {
        let air = build_authentication_information_request(
            &config(),
            "mme;1;1",
            "001010000000001",
            &TEST_PLMN,
            3,
            true,
            None,
            10,
            20,
        );
        let decoded = codec::decode_diameter(&air).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_AUTHENTICATION_INFORMATION);
        assert_eq!(decoded.application_id, dictionary::S6A_APP_ID);
        assert_eq!(
            decoded.avps.get("User-Name").and_then(|v| v.as_str()),
            Some("001010000000001")
        );
        let requested = decoded
            .avps
            .get("Requested-EUTRAN-Authentication-Info")
            .expect("grouped AVP present");
        assert_eq!(
            requested
                .get("Number-Of-Requested-Vectors")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
    }

    #[test]
    fn air_resync_info_included() {
        let resync = vec![0xABu8; 30]; // RAND(16) ‖ AUTS(14)
        let air = build_authentication_information_request(
            &config(),
            "mme;1;1",
            "001010000000001",
            &TEST_PLMN,
            1,
            false,
            Some(&resync),
            1,
            2,
        );
        let decoded = codec::decode_diameter(&air).unwrap();
        let requested = decoded
            .avps
            .get("Requested-EUTRAN-Authentication-Info")
            .unwrap();
        assert!(requested.get("Re-Synchronization-Info").is_some());
    }

    #[test]
    fn ulr_encodes_rat_and_flags() {
        let ulr = build_update_location_request(
            &config(),
            "mme;2;2",
            "001010000000001",
            1004, // EUTRAN
            ULR_FLAG_S6A_S6D_INDICATOR,
            &TEST_PLMN,
            3,
            4,
        );
        let decoded = codec::decode_diameter(&ulr).unwrap();
        assert_eq!(decoded.command_code, dictionary::CMD_UPDATE_LOCATION);
        assert_eq!(decoded.avps.get("RAT-Type").and_then(|v| v.as_u64()), Some(1004));
        assert_eq!(
            decoded.avps.get("ULR-Flags").and_then(|v| v.as_u64()),
            Some(ULR_FLAG_S6A_S6D_INDICATOR as u64)
        );
    }

    #[test]
    fn pur_minimal() {
        let pur = build_purge_ue_request(&config(), "mme;3;3", "001010000000001", None, 5, 6);
        let decoded = codec::decode_diameter(&pur).unwrap();
        assert_eq!(decoded.command_code, dictionary::CMD_PURGE_UE);
        assert!(decoded.avps.get("PUR-Flags").is_none());
    }

    #[test]
    fn parse_aia_extracts_vectors() {
        // Build an AIA by hand: Authentication-Info → E-UTRAN-Vector{RAND,XRES,AUTN,KASME}.
        let mut vector = Vec::new();
        vector.extend_from_slice(&encode_avp_octet_3gpp(avp::RAND, &[0x11u8; 16]));
        vector.extend_from_slice(&encode_avp_octet_3gpp(avp::XRES, &[0x22u8; 8]));
        vector.extend_from_slice(&encode_avp_octet_3gpp(avp::AUTN, &[0x33u8; 16]));
        vector.extend_from_slice(&encode_avp_octet_3gpp(avp::KASME, &[0x44u8; 32]));
        let eutran = encode_avp_grouped_3gpp(avp::E_UTRAN_VECTOR, &vector);
        let auth_info = encode_avp_grouped_3gpp(avp::AUTHENTICATION_INFO, &eutran);

        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "mme;1;1"));
        avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, dictionary::DIAMETER_SUCCESS));
        avps.extend_from_slice(&auth_info);
        let aia = encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_AUTHENTICATION_INFORMATION,
            dictionary::S6A_APP_ID,
            10,
            20,
            &avps,
        );

        let decoded = codec::decode_diameter(&aia).unwrap();
        let parsed = parse_aia(&decoded).unwrap();
        assert_eq!(parsed.result_code, dictionary::DIAMETER_SUCCESS);
        assert_eq!(parsed.vectors.len(), 1);
        assert_eq!(parsed.vectors[0].rand, vec![0x11u8; 16]);
        assert_eq!(parsed.vectors[0].kasme, vec![0x44u8; 32]);
    }

    #[test]
    fn parse_ula_reads_flags_and_subscription_data() {
        let subscription = encode_avp_grouped_3gpp(avp::SUBSCRIPTION_DATA, &[]);
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "mme;2;2"));
        avps.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, dictionary::DIAMETER_SUCCESS));
        avps.extend_from_slice(&encode_avp_u32_3gpp(avp::ULA_FLAGS, 1));
        avps.extend_from_slice(&subscription);
        let ula = encode_diameter_message(
            FLAG_PROXIABLE,
            dictionary::CMD_UPDATE_LOCATION,
            dictionary::S6A_APP_ID,
            3,
            4,
            &avps,
        );
        let decoded = codec::decode_diameter(&ula).unwrap();
        let parsed = parse_ula(&decoded).unwrap();
        assert_eq!(parsed.result_code, dictionary::DIAMETER_SUCCESS);
        assert_eq!(parsed.ula_flags, Some(1));
        assert!(parsed.has_subscription_data);
    }
}
