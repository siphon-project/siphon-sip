//! Diameter Cx interface for IMS registration and authentication.
//!
//! Implements the S-CSCF ↔ HSS signaling defined in 3GPP TS 29.228/229:
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | UAR/UAA | 300 | I-CSCF → HSS | Query S-CSCF assignment |
//! | SAR/SAA | 301 | S-CSCF → HSS | Register/deregister with HSS |
//! | LIR/LIA | 302 | I-CSCF → HSS | Locate serving S-CSCF |
//! | MAR/MAA | 303 | S-CSCF → HSS | Request auth vectors |
//! | RTR/RTA | 304 | HSS → S-CSCF | Force deregistration |

use crate::diameter::codec::{self, *};
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::IncomingRequest;

/// SIP-Item-Number AVP code (613, 3GPP vendor) — not in base dictionary.
const AVP_SIP_ITEM_NUMBER: u32 = 613;

/// User-Data AVP code (606, 3GPP vendor) — carries iFC XML in Cx.
pub const AVP_USER_DATA_CX: u32 = 606;

// ---------------------------------------------------------------------------
// AVP extraction helpers
// ---------------------------------------------------------------------------

/// Pull a required string AVP from decoded JSON.
pub(crate) fn required_str(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name).and_then(|v| v.as_str()).map(String::from)
}

/// Pull an optional u32 AVP from decoded JSON.
pub(crate) fn optional_u32(avps: &serde_json::Value, name: &str) -> Option<u32> {
    avps.get(name).and_then(|v| v.as_u64()).map(|n| n as u32)
}

/// Pull a required u32 AVP from decoded JSON.
fn required_u32(avps: &serde_json::Value, name: &str) -> Option<u32> {
    optional_u32(avps, name)
}

/// Decode an OctetString AVP that is actually UTF-8 text (hex-encoded by the codec).
pub(crate) fn octet_string_as_utf8(avps: &serde_json::Value, name: &str) -> Option<String> {
    avps.get(name)
        .and_then(|v| v.as_str())
        .map(|hex_str| {
            codec::hex::decode(hex_str)
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .unwrap_or_else(|| hex_str.to_string())
        })
}

// ---------------------------------------------------------------------------
// Cx answer builder — shared scaffolding for all Cx answers
// ---------------------------------------------------------------------------

/// Accumulates AVPs for a Cx answer message and serializes them.
struct CxAnswerBuilder {
    avp_buf: Vec<u8>,
}

impl CxAnswerBuilder {
    /// Start a new Cx answer with the standard mandatory AVPs.
    fn new(origin_host: &str, origin_realm: &str, session_id: &str) -> Self {
        let mut avp_buf = Vec::with_capacity(256);
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
        avp_buf.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
        avp_buf.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
        avp_buf.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        Self { avp_buf }
    }

    /// Append a 3GPP Experimental-Result grouped AVP.
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

    /// Append raw AVP bytes.
    fn raw_avps(mut self, data: &[u8]) -> Self {
        self.avp_buf.extend_from_slice(data);
        self
    }

    /// Finalize into a wire-format Diameter answer with explicit identifiers.
    #[allow(dead_code)]
    fn build(self, command_code: u32) -> Vec<u8> {
        encode_diameter_message(
            FLAG_PROXIABLE,
            command_code,
            dictionary::CX_APP_ID,
            0, 0, // hbh/e2e filled by caller
            &self.avp_buf,
        )
    }

    /// Finalize with explicit hop-by-hop and end-to-end IDs.
    fn build_with_ids(self, command_code: u32, hop_by_hop: u32, end_to_end: u32) -> Vec<u8> {
        encode_diameter_message(
            FLAG_PROXIABLE,
            command_code,
            dictionary::CX_APP_ID,
            hop_by_hop,
            end_to_end,
            &self.avp_buf,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// User-Authorization (UAR/UAA) — I-CSCF → HSS
// ═══════════════════════════════════════════════════════════════════════════

/// Deserialized UAR fields from an incoming Diameter request.
#[derive(Debug, Clone)]
pub struct UserAuthorizationRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub public_identity: String,
    pub visited_network_id: String,
    pub user_authorization_type: Option<u32>,
}

/// Extract a UAR from a decoded incoming request.
pub fn parse_uar(incoming: &IncomingRequest) -> Option<UserAuthorizationRequest> {
    let a = &incoming.avps;
    Some(UserAuthorizationRequest {
        session_id: required_str(a, "Session-Id")?,
        origin_host: required_str(a, "Origin-Host")?,
        origin_realm: required_str(a, "Origin-Realm")?,
        public_identity: required_str(a, "Public-Identity")?,
        visited_network_id: octet_string_as_utf8(a, "Visited-Network-Identifier")?,
        user_authorization_type: optional_u32(a, "User-Authorization-Type"),
    })
}

/// Encode a UAA success — optionally includes the assigned S-CSCF name.
pub fn build_uaa_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    server_name: Option<&str>,
    experimental_result_code: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut extra = Vec::new();
    if let Some(name) = server_name {
        extra.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, name));
    }

    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(experimental_result_code)
        .raw_avps(&extra)
        .build_with_ids(dictionary::CMD_USER_AUTHORIZATION, hop_by_hop, end_to_end)
}

/// Encode a UAA error (same structure, different result code).
pub fn build_uaa_error(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    experimental_result_code: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(experimental_result_code)
        .build_with_ids(dictionary::CMD_USER_AUTHORIZATION, hop_by_hop, end_to_end)
}

// ═══════════════════════════════════════════════════════════════════════════
// Server-Assignment (SAR/SAA) — S-CSCF → HSS
// ═══════════════════════════════════════════════════════════════════════════

/// Deserialized SAR fields.
#[derive(Debug, Clone)]
pub struct ServerAssignmentRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub public_identity: Option<String>,
    pub server_name: String,
    pub assignment_type: u32,
    pub user_data_already_available: Option<u32>,
}

/// Extract a SAR from a decoded incoming request.
pub fn parse_sar(incoming: &IncomingRequest) -> Option<ServerAssignmentRequest> {
    let a = &incoming.avps;
    Some(ServerAssignmentRequest {
        session_id: required_str(a, "Session-Id")?,
        origin_host: required_str(a, "Origin-Host")?,
        origin_realm: required_str(a, "Origin-Realm")?,
        public_identity: a.get("Public-Identity").and_then(|v| v.as_str()).map(String::from),
        server_name: required_str(a, "Server-Name")?,
        assignment_type: required_u32(a, "Server-Assignment-Type")?,
        user_data_already_available: optional_u32(a, "User-Data-Already-Available"),
    })
}

/// Encode a SAA success, optionally carrying the subscriber's iFC XML profile.
pub fn build_saa_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    user_data_xml: Option<&str>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut extra = Vec::new();
    if let Some(xml) = user_data_xml {
        extra.extend_from_slice(&encode_avp_octet_3gpp(avp::USER_DATA_CX, xml.as_bytes()));
    }

    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(dictionary::DIAMETER_FIRST_REGISTRATION)
        .raw_avps(&extra)
        .build_with_ids(dictionary::CMD_SERVER_ASSIGNMENT, hop_by_hop, end_to_end)
}

// ═══════════════════════════════════════════════════════════════════════════
// Location-Info (LIR/LIA) — I-CSCF → HSS
// ═══════════════════════════════════════════════════════════════════════════

/// Deserialized LIR fields.
#[derive(Debug, Clone)]
pub struct LocationInfoRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub public_identity: String,
}

/// Extract a LIR from a decoded incoming request.
pub fn parse_lir(incoming: &IncomingRequest) -> Option<LocationInfoRequest> {
    let a = &incoming.avps;
    Some(LocationInfoRequest {
        session_id: required_str(a, "Session-Id")?,
        origin_host: required_str(a, "Origin-Host")?,
        origin_realm: required_str(a, "Origin-Realm")?,
        public_identity: required_str(a, "Public-Identity")?,
    })
}

/// Encode a LIA success with the serving S-CSCF name.
pub fn build_lia_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    server_name: &str,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let server_avp = encode_avp_utf8_3gpp(avp::SERVER_NAME, server_name);

    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(dictionary::DIAMETER_FIRST_REGISTRATION)
        .raw_avps(&server_avp)
        .build_with_ids(dictionary::CMD_LOCATION_INFO, hop_by_hop, end_to_end)
}

// ═══════════════════════════════════════════════════════════════════════════
// Multimedia-Auth (MAR/MAA) — S-CSCF → HSS
// ═══════════════════════════════════════════════════════════════════════════

/// Deserialized MAR fields.
#[derive(Debug, Clone)]
pub struct MultimediaAuthRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub public_identity: String,
    pub num_auth_items: u32,
    pub auth_scheme: Option<String>,
}

/// Extract a MAR from a decoded incoming request.
pub fn parse_mar(incoming: &IncomingRequest) -> Option<MultimediaAuthRequest> {
    let a = &incoming.avps;

    // The auth scheme lives inside the SIP-Auth-Data-Item grouped AVP
    let auth_scheme = a
        .get("SIP-Auth-Data-Item")
        .and_then(|group| group.get("SIP-Authentication-Scheme"))
        .and_then(|v| v.as_str())
        .map(String::from);

    Some(MultimediaAuthRequest {
        session_id: required_str(a, "Session-Id")?,
        origin_host: required_str(a, "Origin-Host")?,
        origin_realm: required_str(a, "Origin-Realm")?,
        public_identity: required_str(a, "Public-Identity")?,
        num_auth_items: required_u32(a, "SIP-Number-Auth-Items")?,
        auth_scheme,
    })
}

/// IMS authentication vector for MAA responses.
pub struct AuthVector<'a> {
    pub sip_authenticate: &'a [u8],
    pub sip_authorization: &'a [u8],
    pub confidentiality_key: &'a [u8],
    pub integrity_key: &'a [u8],
}

/// Encode a MAA success carrying IMS-AKA authentication vectors.
pub fn build_maa_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    public_identity: &str,
    vector: &AuthVector<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    // Assemble the SIP-Auth-Data-Item grouped AVP
    let mut auth_children = Vec::with_capacity(128);
    auth_children.extend_from_slice(&encode_avp_u32_3gpp(AVP_SIP_ITEM_NUMBER, 1));
    auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        "Digest-AKAv1-MD5",
    ));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHENTICATE, vector.sip_authenticate));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHORIZATION, vector.sip_authorization));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::CONFIDENTIALITY_KEY, vector.confidentiality_key));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::INTEGRITY_KEY, vector.integrity_key));
    let auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

    // Extra AVPs beyond the standard answer scaffold
    let mut extra = Vec::with_capacity(128);
    extra.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
    extra.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    extra.extend_from_slice(&auth_data_item);

    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(dictionary::DIAMETER_FIRST_REGISTRATION)
        .raw_avps(&extra)
        .build_with_ids(dictionary::CMD_MULTIMEDIA_AUTH, hop_by_hop, end_to_end)
}

// ═══════════════════════════════════════════════════════════════════════════
// Registration-Termination (RTR) — HSS → S-CSCF
// ═══════════════════════════════════════════════════════════════════════════

/// Reason codes for deregistration (TS 29.228 §6.3.17).
pub mod deregistration_reason {
    pub const PERMANENT_TERMINATION: u32 = 0;
    pub const NEW_SERVER_ASSIGNED: u32 = 1;
    pub const SERVER_CHANGE: u32 = 2;
    pub const REMOVE_SCSCF: u32 = 3;
}

/// Deserialized RTR fields from an incoming Diameter request.
pub struct RegistrationTerminationRequest {
    pub session_id: String,
    pub origin_host: String,
    pub origin_realm: String,
    pub public_identity: String,
    pub reason_code: u32,
    pub reason_info: Option<String>,
}

/// Parse an incoming RTR (command 304) from its decoded AVPs.
pub fn parse_rtr(incoming: &IncomingRequest) -> Option<RegistrationTerminationRequest> {
    let a = &incoming.avps;
    let session_id = required_str(a, "Session-Id")?;
    let origin_host = required_str(a, "Origin-Host")?;
    let origin_realm = required_str(a, "Origin-Realm")?;
    let public_identity = required_str(a, "Public-Identity")?;

    // Deregistration-Reason is a grouped AVP containing Reason-Code + Reason-Info
    let dereg_reason = a.get("Deregistration-Reason")?;
    let reason_code = dereg_reason
        .get("Reason-Code")
        .and_then(|v| v.as_u64())
        .map(|n| n as u32)?;
    let reason_info = dereg_reason
        .get("Reason-Info")
        .and_then(|v| v.as_str())
        .map(String::from);

    Some(RegistrationTerminationRequest {
        session_id,
        origin_host,
        origin_realm,
        public_identity,
        reason_code,
        reason_info,
    })
}

/// Build an RTA (Registration-Termination-Answer) with success result code.
pub fn build_rta(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .experimental_result(dictionary::DIAMETER_SUCCESS)
        .build_with_ids(dictionary::CMD_REGISTRATION_TERMINATION, hop_by_hop, end_to_end)
}

/// Encode an RTR (Registration-Termination-Request) — HSS-initiated push.
pub fn build_rtr(
    origin_host: &str,
    origin_realm: &str,
    destination_host: &str,
    destination_realm: &str,
    session_id: &str,
    public_identity: &str,
    reason_code: u32,
    reason_info: Option<&str>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    // Deregistration-Reason grouped AVP
    let mut reason_avps = Vec::new();
    reason_avps.extend_from_slice(&encode_avp_u32_3gpp(avp::REASON_CODE, reason_code));
    if let Some(info) = reason_info {
        reason_avps.extend_from_slice(&encode_avp_utf8_3gpp(avp::REASON_INFO, info));
    }
    let dereg_reason = encode_avp_grouped_3gpp(avp::DEREGISTRATION_REASON, &reason_avps);

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, destination_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_REALM, destination_realm));
    payload.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    payload.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::CX_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
    payload.extend_from_slice(&dereg_reason);

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_REGISTRATION_TERMINATION,
        dictionary::CX_APP_ID,
        hop_by_hop,
        end_to_end,
        &payload,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthesize an IncomingRequest from hand-built AVP bytes.
    fn synthesize_request(command_code: u32, avp_bytes: &[u8]) -> IncomingRequest {
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            command_code,
            dictionary::CX_APP_ID,
            100,
            200,
            avp_bytes,
        );
        let decoded = decode_diameter(&wire).unwrap();
        IncomingRequest {
            command_code: decoded.command_code,
            application_id: decoded.application_id,
            hop_by_hop: decoded.hop_by_hop,
            end_to_end: decoded.end_to_end,
            avps: decoded.avps,
            raw: wire,
        }
    }

    #[test]
    fn parse_and_verify_uar() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cx;uar;1"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "icscf.ims.mnc001.mcc001.3gppnetwork.org"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.mnc001.mcc001.3gppnetwork.org"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:+15551234@ims.mnc001.mcc001.3gppnetwork.org"));
        raw.extend_from_slice(&encode_avp_octet_3gpp(avp::VISITED_NETWORK_IDENTIFIER, b"ims.mnc001.mcc001.3gppnetwork.org"));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_AUTHORIZATION_TYPE, 0));

        let incoming = synthesize_request(dictionary::CMD_USER_AUTHORIZATION, &raw);
        let uar = parse_uar(&incoming).expect("UAR parsing failed");

        assert_eq!(uar.session_id, "cx;uar;1");
        assert_eq!(uar.origin_host, "icscf.ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uar.public_identity, "sip:+15551234@ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uar.visited_network_id, "ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uar.user_authorization_type, Some(0));
    }

    #[test]
    fn parse_and_verify_sar() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cx;sar;1"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:alice@ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, "sip:scscf1.ims.example.com:6060"));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::SERVER_ASSIGNMENT_TYPE, 1));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_DATA_ALREADY_AVAILABLE, 0));

        let incoming = synthesize_request(dictionary::CMD_SERVER_ASSIGNMENT, &raw);
        let sar = parse_sar(&incoming).expect("SAR parsing failed");

        assert_eq!(sar.session_id, "cx;sar;1");
        assert_eq!(sar.public_identity.as_deref(), Some("sip:alice@ims.example.com"));
        assert_eq!(sar.server_name, "sip:scscf1.ims.example.com:6060");
        assert_eq!(sar.assignment_type, 1);
        assert_eq!(sar.user_data_already_available, Some(0));
    }

    #[test]
    fn parse_and_verify_lir() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cx;lir;1"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "icscf.ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:bob@ims.example.com"));

        let incoming = synthesize_request(dictionary::CMD_LOCATION_INFO, &raw);
        let lir = parse_lir(&incoming).expect("LIR parsing failed");

        assert_eq!(lir.session_id, "cx;lir;1");
        assert_eq!(lir.public_identity, "sip:bob@ims.example.com");
    }

    #[test]
    fn parse_and_verify_mar() {
        let mut auth_children = Vec::new();
        auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SIP_AUTHENTICATION_SCHEME,
            "Digest-AKAv1-MD5",
        ));
        let auth_data = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cx;mar;1"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, "sip:carol@ims.example.com"));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
        raw.extend_from_slice(&auth_data);

        let incoming = synthesize_request(dictionary::CMD_MULTIMEDIA_AUTH, &raw);
        let mar = parse_mar(&incoming).expect("MAR parsing failed");

        assert_eq!(mar.session_id, "cx;mar;1");
        assert_eq!(mar.public_identity, "sip:carol@ims.example.com");
        assert_eq!(mar.num_auth_items, 1);
        assert_eq!(mar.auth_scheme.as_deref(), Some("Digest-AKAv1-MD5"));
    }

    #[test]
    fn build_and_decode_maa() {
        let vector = AuthVector {
            sip_authenticate: &[0xAA; 32],
            sip_authorization: &[0xBB; 16],
            confidentiality_key: &[0xCC; 16],
            integrity_key: &[0xDD; 16],
        };

        let maa = build_maa_success(
            "hss.ims.example.com",
            "ims.example.com",
            "cx;mar;2",
            "sip:dave@ims.example.com",
            &vector,
            42, 99,
        );

        let decoded = decode_diameter(&maa).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_MULTIMEDIA_AUTH);
        assert_eq!(decoded.application_id, dictionary::CX_APP_ID);

        // Verify standard fields
        assert_eq!(decoded.avps.get("Session-Id").and_then(|v| v.as_str()), Some("cx;mar;2"));
        assert_eq!(decoded.avps.get("Origin-Host").and_then(|v| v.as_str()), Some("hss.ims.example.com"));

        // Verify auth vector
        let auth_item = decoded.avps.get("SIP-Auth-Data-Item").unwrap();
        assert_eq!(
            auth_item.get("SIP-Authentication-Scheme").and_then(|v| v.as_str()),
            Some("Digest-AKAv1-MD5")
        );
        assert!(auth_item.get("SIP-Authenticate").is_some());
        assert!(auth_item.get("Confidentiality-Key").is_some());
        assert!(auth_item.get("Integrity-Key").is_some());
    }

    #[test]
    fn build_and_decode_uaa() {
        let uaa = build_uaa_success(
            "hss.ims.example.com",
            "ims.example.com",
            "cx;uar;2",
            Some("sip:scscf2.ims.example.com:6060"),
            dictionary::DIAMETER_FIRST_REGISTRATION,
            10, 20,
        );

        let decoded = decode_diameter(&uaa).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_USER_AUTHORIZATION);
        assert_eq!(
            decoded.avps.get("Server-Name").and_then(|v| v.as_str()),
            Some("sip:scscf2.ims.example.com:6060")
        );
    }

    #[test]
    fn build_and_decode_lia() {
        let lia = build_lia_success(
            "hss.ims.example.com",
            "ims.example.com",
            "cx;lir;2",
            "sip:scscf3.ims.example.com:6060",
            30, 40,
        );

        let decoded = decode_diameter(&lia).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_LOCATION_INFO);
        assert_eq!(
            decoded.avps.get("Server-Name").and_then(|v| v.as_str()),
            Some("sip:scscf3.ims.example.com:6060")
        );
    }

    #[test]
    fn build_and_decode_rtr() {
        let rtr = build_rtr(
            "hss.ims.example.com",
            "ims.example.com",
            "scscf.ims.example.com",
            "ims.example.com",
            "cx;rtr;1",
            "sip:eve@ims.example.com",
            deregistration_reason::PERMANENT_TERMINATION,
            Some("Admin-initiated removal"),
            50, 60,
        );

        let decoded = decode_diameter(&rtr).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_REGISTRATION_TERMINATION);
        assert_eq!(decoded.avps.get("Destination-Host").and_then(|v| v.as_str()), Some("scscf.ims.example.com"));
        assert_eq!(decoded.avps.get("Public-Identity").and_then(|v| v.as_str()), Some("sip:eve@ims.example.com"));

        let dr = decoded.avps.get("Deregistration-Reason").unwrap();
        assert_eq!(dr.get("Reason-Code").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(dr.get("Reason-Info").and_then(|v| v.as_str()), Some("Admin-initiated removal"));
    }

    #[test]
    fn parse_rtr_extracts_fields() {
        // Build an RTR on the wire, then parse it via parse_rtr()
        let rtr_bytes = build_rtr(
            "hss.ims.example.com",
            "ims.example.com",
            "scscf.ims.example.com",
            "ims.example.com",
            "cx;rtr;42",
            "sip:alice@ims.example.com",
            deregistration_reason::NEW_SERVER_ASSIGNED,
            Some("HSS migration"),
            70, 80,
        );

        let decoded = decode_diameter(&rtr_bytes).unwrap();
        let incoming = IncomingRequest {
            command_code: decoded.command_code,
            application_id: decoded.application_id,
            hop_by_hop: decoded.hop_by_hop,
            end_to_end: decoded.end_to_end,
            avps: decoded.avps,
            raw: rtr_bytes,
        };

        let rtr = parse_rtr(&incoming).expect("parse_rtr failed");
        assert_eq!(rtr.session_id, "cx;rtr;42");
        assert_eq!(rtr.origin_host, "hss.ims.example.com");
        assert_eq!(rtr.origin_realm, "ims.example.com");
        assert_eq!(rtr.public_identity, "sip:alice@ims.example.com");
        assert_eq!(rtr.reason_code, deregistration_reason::NEW_SERVER_ASSIGNED);
        assert_eq!(rtr.reason_info.as_deref(), Some("HSS migration"));
    }

    #[test]
    fn parse_rtr_without_reason_info() {
        let rtr_bytes = build_rtr(
            "hss.ims.example.com",
            "ims.example.com",
            "scscf.ims.example.com",
            "ims.example.com",
            "cx;rtr;99",
            "sip:bob@ims.example.com",
            deregistration_reason::PERMANENT_TERMINATION,
            None,
            90, 100,
        );

        let decoded = decode_diameter(&rtr_bytes).unwrap();
        let incoming = IncomingRequest {
            command_code: decoded.command_code,
            application_id: decoded.application_id,
            hop_by_hop: decoded.hop_by_hop,
            end_to_end: decoded.end_to_end,
            avps: decoded.avps,
            raw: rtr_bytes,
        };

        let rtr = parse_rtr(&incoming).expect("parse_rtr failed");
        assert_eq!(rtr.public_identity, "sip:bob@ims.example.com");
        assert_eq!(rtr.reason_code, deregistration_reason::PERMANENT_TERMINATION);
        assert!(rtr.reason_info.is_none());
    }

    #[test]
    fn build_and_decode_rta() {
        let rta = build_rta(
            "scscf.ims.example.com",
            "ims.example.com",
            "cx;rtr;42",
            70, 80,
        );

        let decoded = decode_diameter(&rta).unwrap();
        assert!(!decoded.is_request, "RTA should not have request flag");
        assert_eq!(decoded.command_code, dictionary::CMD_REGISTRATION_TERMINATION);
        assert_eq!(decoded.hop_by_hop, 70);
        assert_eq!(decoded.end_to_end, 80);

        // Verify Experimental-Result contains success code
        let er = decoded.avps.get("Experimental-Result").unwrap();
        let rc = er.get("Experimental-Result-Code")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32);
        assert_eq!(rc, Some(dictionary::DIAMETER_SUCCESS));
    }
}
