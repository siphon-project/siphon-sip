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
use crate::diameter::peer::{IncomingRequest, PeerConfig};

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
    avps.get(name).and_then(|v| v.as_str()).map(|hex_str| {
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

    /// Append Result-Code DIAMETER_SUCCESS. Success is a base protocol result
    /// (RFC 6733 clause 7.1), so it is not an Experimental-Result: TS 29.229
    /// clause 6.2 puts only the codes it defines itself there.
    fn success(mut self) -> Self {
        self.avp_buf.extend_from_slice(&encode_avp_u32(
            avp::RESULT_CODE,
            dictionary::DIAMETER_SUCCESS,
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
            0,
            0, // hbh/e2e filled by caller
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
        public_identity: a
            .get("Public-Identity")
            .and_then(|v| v.as_str())
            .map(String::from),
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
        .success()
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
        .success()
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
///
/// The result is Result-Code DIAMETER_SUCCESS, and both identities are
/// present, as TS 29.228 table 6.3.4 requires of a successful answer.
pub fn build_maa_success(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    user_name: &str,
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
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SIP_AUTHENTICATE,
        vector.sip_authenticate,
    ));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SIP_AUTHORIZATION,
        vector.sip_authorization,
    ));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(
        avp::CONFIDENTIALITY_KEY,
        vector.confidentiality_key,
    ));
    auth_children.extend_from_slice(&encode_avp_octet_3gpp(
        avp::INTEGRITY_KEY,
        vector.integrity_key,
    ));
    let auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

    // Extra AVPs beyond the standard answer scaffold
    let mut extra = Vec::with_capacity(128);
    extra.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, user_name));
    extra.extend_from_slice(&encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, public_identity));
    extra.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
    extra.extend_from_slice(&auth_data_item);

    CxAnswerBuilder::new(origin_host, origin_realm, session_id)
        .success()
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
        .success()
        .build_with_ids(
            dictionary::CMD_REGISTRATION_TERMINATION,
            hop_by_hop,
            end_to_end,
        )
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

// ---------------------------------------------------------------------------
// Requests this node sends to the HSS (I-CSCF / S-CSCF side)
// ---------------------------------------------------------------------------

/// The AVPs every Cx request starts with, in the order TS 29.229 lists them.
fn append_request_header(payload: &mut Vec<u8>, config: &PeerConfig, session_id: &str) {
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        &config.destination_realm,
    ));
    if let Some(destination_host) = &config.destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, destination_host));
    }
    payload.extend_from_slice(&encode_avp_u32(avp::AUTH_SESSION_STATE, 1));
    payload.extend_from_slice(&encode_vendor_specific_app_id(
        dictionary::VENDOR_3GPP,
        dictionary::CX_APP_ID,
    ));
}

/// IMS AKA, the scheme `Digest-AKAv1-MD5` of TS 29.229 clause 6.3.9.
pub const SCHEME_IMS_AKA: &str = "Digest-AKAv1-MD5";

/// SIP Digest, the scheme `SIP Digest` of TS 29.229 clause 6.3.9: the answer
/// carries H(A1) in SIP-Digest-Authenticate.
pub const SCHEME_SIP_DIGEST: &str = "SIP Digest";

/// The scheme `Unknown` of TS 29.229 clause 6.3.9: "the authentication scheme
/// to be used is unknown at this point", so the HSS answers in the scheme it
/// has stored.
pub const SCHEME_UNKNOWN: &str = "Unknown";

/// "The authentication scheme indicated in an authentication request is not
/// supported" (TS 29.229 clause 6.2.2.6), carried in Experimental-Result.
pub const DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED: u32 = 5006;

/// The private user identity a REGISTER without an Authorization header
/// implies.
///
/// TS 24.229 clause 5.3.1.2 (I-CSCF) and clause 5.4.1.1 (S-CSCF): the node
/// "shall derive the private user identity from the public user identity
/// being registered [...] by removing URI scheme and the following parts of
/// the URI if present: port number, URI parameters, and To header field
/// parameters".
pub fn derive_private_identity(public_identity: &str) -> String {
    let uri = public_identity.trim();
    let uri = uri.strip_prefix('<').unwrap_or(uri);
    let uri = uri.split('>').next().unwrap_or(uri);
    let uri = uri.split(';').next().unwrap_or(uri);
    let without_scheme = ["sips:", "sip:", "tel:"]
        .iter()
        .find_map(|scheme| {
            uri.get(..scheme.len())
                .filter(|prefix| prefix.eq_ignore_ascii_case(scheme))
                .map(|_| &uri[scheme.len()..])
        })
        .unwrap_or(uri);
    // The port follows the host, which an IPv6 reference closes with ']'.
    let host_start = without_scheme.rfind('@').map_or(0, |at| at + 1);
    let host = &without_scheme[host_start..];
    let port_search_from = host.rfind(']').map_or(0, |bracket| bracket + 1);
    match host[port_search_from..].find(':') {
        Some(colon) => without_scheme[..host_start + port_search_from + colon].to_string(),
        None => without_scheme.to_string(),
    }
}

/// What a User-Authorization-Request carries besides the routing AVPs.
#[derive(Debug, Clone, Copy)]
pub struct UserAuthorization<'a> {
    pub public_identity: &'a str,
    /// The private user identity, sent as User-Name. TS 29.229 clause 6.1.1
    /// has `{ User-Name }` in the command, and TS 29.228 Table 6.1.1.1 makes
    /// the Private User Identity mandatory.
    pub user_name: &'a str,
    pub visited_network_id: &'a str,
    pub user_auth_type: Option<u32>,
}

/// Encode a UAR (User-Authorization-Request), I-CSCF to HSS.
pub fn build_uar(
    config: &PeerConfig,
    session_id: &str,
    request: &UserAuthorization<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    append_request_header(&mut payload, config, session_id);
    payload.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, request.user_name));
    payload.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::PUBLIC_IDENTITY,
        request.public_identity,
    ));
    payload.extend_from_slice(&encode_avp_octet_3gpp(
        avp::VISITED_NETWORK_IDENTIFIER,
        request.visited_network_id.as_bytes(),
    ));
    if let Some(auth_type) = request.user_auth_type {
        payload.extend_from_slice(&encode_avp_u32_3gpp(
            avp::USER_AUTHORIZATION_TYPE,
            auth_type,
        ));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_USER_AUTHORIZATION,
        dictionary::CX_APP_ID,
        hop_by_hop,
        end_to_end,
        &payload,
    )
}

/// What a Server-Assignment-Request carries besides the routing AVPs.
#[derive(Debug, Clone, Copy)]
pub struct ServerAssignment<'a> {
    pub public_identity: &'a str,
    /// The private user identity, sent as User-Name. TS 29.229 clause 6.1.3
    /// has `[ User-Name ]`, and TS 29.228 Table 6.1.2.1 says it "shall be
    /// present if it is available when the S-CSCF issues the request".
    /// `None` leaves the AVP out.
    pub user_name: Option<&'a str>,
    pub server_name: &'a str,
    pub server_assignment_type: u32,
    /// User-Data-Already-Available (TS 29.229 §6.3.26): `0`
    /// USER_DATA_NOT_AVAILABLE, `1` USER_DATA_ALREADY_AVAILABLE. A refresh of
    /// the S-CSCF restoration information sends `1` (TS 23.380 §4.6.2).
    pub user_data_already_available: u32,
    /// The Cx features of Feature-List-ID 1 this S-CSCF supports (TS 29.229
    /// §7.1.1 Table 7.1.1), sent as Supported-Features; `0` sends none.
    pub supported_features: u32,
    /// SCSCF-Restoration-Info to back up in the HSS (TS 23.380 §4.6).
    pub restoration: Option<&'a ScscfRestorationInfo>,
    /// Multiple-Registration-Indication (TS 29.229 §6.3.51).
    pub multiple_registration_indication: Option<u32>,
    /// SAR-Flags (TS 29.229 §6.3.63); bit 0 is the P-CSCF Restoration
    /// Indication.
    pub sar_flags: Option<u32>,
    /// Failed-PCSCF (TS 29.229 §6.3.74), only with the P-CSCF Restoration
    /// Indication (TS 29.228 §7.31).
    pub failed_pcscf: Option<&'a FailedPcscf>,
}

/// Feature bit 2 of Cx Feature-List-ID 1, `IMSRestorationInd` (TS 29.229
/// §7.1.1 Table 7.1.1): the S-CSCF sends S-CSCF restoration information and
/// the HSS returns it when required.
pub const FEATURE_IMS_RESTORATION: u32 = 1 << 2;

/// Feature bit 3 of Cx Feature-List-ID 1, `P-CSCF-Restoration-mechanism`
/// (TS 29.229 §7.1.1 Table 7.1.1).
pub const FEATURE_PCSCF_RESTORATION: u32 = 1 << 3;

/// SAR-Flags bit 0, P-CSCF Restoration Indication (TS 29.229 Table 6.3.63.1).
pub const SAR_FLAG_PCSCF_RESTORATION: u32 = 1 << 0;

/// Subscription-Info (TS 29.229 §6.3.49): the reg-event subscription of a UE.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SubscriptionInfo {
    pub call_id: String,
    pub from: String,
    pub to: String,
    /// Comma separated Record-Route header field values.
    pub record_route: String,
    pub contact: String,
}

/// P-CSCF-Subscription-Info (TS 29.229 §6.3.70): the reg-event subscription
/// of a P-CSCF.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PcscfSubscriptionInfo {
    pub call_id: String,
    pub from: String,
    pub to: String,
    pub contact: String,
}

/// Restoration-Info (TS 29.229 §6.3.52): one registered contact.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestorationInfo {
    /// Comma separated Path header field values (RFC 3327).
    pub path: String,
    /// Contact address and parameters of the registration (RFC 3261).
    pub contact: String,
    pub initial_cseq_sequence_number: Option<u32>,
    pub call_id: Option<String>,
    pub subscription_info: Option<SubscriptionInfo>,
    pub pcscf_subscription_info: Option<PcscfSubscriptionInfo>,
}

/// SCSCF-Restoration-Info (TS 29.229 §6.3.46): what an S-CSCF needs to serve
/// the registrations of one private user identity.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScscfRestorationInfo {
    pub user_name: String,
    pub restoration_info: Vec<RestorationInfo>,
    /// Registration-Time-Out (TS 29.229 §6.3.71) as Unix seconds.
    pub registration_time_out: Option<u64>,
    pub sip_authentication_scheme: Option<String>,
}

/// Failed-PCSCF (TS 29.229 §6.3.74).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FailedPcscf {
    pub fqdn: Option<String>,
    pub ip_addresses: Vec<std::net::IpAddr>,
}

/// A 3GPP AVP whose M bit TS 29.229 Table 6.3.1 has as "must not": every AVP
/// of IMS restoration, so a node without the feature skips them (RFC 6733
/// §4.1).
fn optional_3gpp(code: u32, data: &[u8]) -> Vec<u8> {
    encode_avp_vendor(code, 0, dictionary::VENDOR_3GPP, data)
}

fn subscription_info_avp(info: &SubscriptionInfo) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend(optional_3gpp(
        avp::CALL_ID_SIP_HEADER,
        info.call_id.as_bytes(),
    ));
    children.extend(optional_3gpp(avp::FROM_SIP_HEADER, info.from.as_bytes()));
    children.extend(optional_3gpp(avp::TO_SIP_HEADER, info.to.as_bytes()));
    children.extend(optional_3gpp(
        avp::RECORD_ROUTE,
        info.record_route.as_bytes(),
    ));
    children.extend(optional_3gpp(avp::CONTACT, info.contact.as_bytes()));
    optional_3gpp(avp::SUBSCRIPTION_INFO, &children)
}

fn pcscf_subscription_info_avp(info: &PcscfSubscriptionInfo) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend(optional_3gpp(
        avp::CALL_ID_SIP_HEADER,
        info.call_id.as_bytes(),
    ));
    children.extend(optional_3gpp(avp::FROM_SIP_HEADER, info.from.as_bytes()));
    children.extend(optional_3gpp(avp::TO_SIP_HEADER, info.to.as_bytes()));
    children.extend(optional_3gpp(avp::CONTACT, info.contact.as_bytes()));
    optional_3gpp(avp::PCSCF_SUBSCRIPTION_INFO, &children)
}

fn restoration_info_avp(info: &RestorationInfo) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend(optional_3gpp(avp::PATH, info.path.as_bytes()));
    children.extend(optional_3gpp(avp::CONTACT, info.contact.as_bytes()));
    if let Some(cseq) = info.initial_cseq_sequence_number {
        children.extend(optional_3gpp(
            avp::INITIAL_CSEQ_SEQUENCE_NUMBER,
            &cseq.to_be_bytes(),
        ));
    }
    if let Some(call_id) = &info.call_id {
        children.extend(optional_3gpp(avp::CALL_ID_SIP_HEADER, call_id.as_bytes()));
    }
    if let Some(subscription) = &info.subscription_info {
        children.extend(subscription_info_avp(subscription));
    }
    if let Some(subscription) = &info.pcscf_subscription_info {
        children.extend(pcscf_subscription_info_avp(subscription));
    }
    optional_3gpp(avp::RESTORATION_INFO, &children)
}

/// The SCSCF-Restoration-Info AVP (TS 29.229 §6.3.46):
/// `{ User-Name } 1*{ Restoration-Info } [ Registration-Time-Out ]
/// [ SIP-Authentication-Scheme ]`. User-Name and SIP-Authentication-Scheme
/// keep the flags they carry everywhere else (M set, Table 6.3.1).
pub fn scscf_restoration_info_avp(info: &ScscfRestorationInfo) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend(encode_avp_utf8(avp::USER_NAME, &info.user_name));
    for restoration in &info.restoration_info {
        children.extend(restoration_info_avp(restoration));
    }
    if let Some(unix_secs) = info.registration_time_out {
        let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix_secs);
        children.extend(optional_3gpp(
            avp::REGISTRATION_TIME_OUT,
            &system_time_to_diameter_time(time).to_be_bytes(),
        ));
    }
    if let Some(scheme) = &info.sip_authentication_scheme {
        children.extend(encode_avp_utf8_3gpp(avp::SIP_AUTHENTICATION_SCHEME, scheme));
    }
    optional_3gpp(avp::SCSCF_RESTORATION_INFO, &children)
}

fn failed_pcscf_avp(failed: &FailedPcscf) -> Vec<u8> {
    let mut children = Vec::new();
    if let Some(fqdn) = &failed.fqdn {
        children.extend(optional_3gpp(avp::PCSCF_FQDN, fqdn.as_bytes()));
    }
    for address in &failed.ip_addresses {
        let mut data = Vec::with_capacity(18);
        match address {
            std::net::IpAddr::V4(v4) => {
                data.extend_from_slice(&1u16.to_be_bytes());
                data.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                data.extend_from_slice(&2u16.to_be_bytes());
                data.extend_from_slice(&v6.octets());
            }
        }
        children.extend(optional_3gpp(avp::PCSCF_IP_ADDRESS, &data));
    }
    optional_3gpp(avp::FAILED_PCSCF, &children)
}

/// Feature bit 0 of Cx Feature-List-ID 1, `SiFC`: shared iFC sets (TS 29.229
/// §7.1.1 Table 7.1.1). With it advertised, an HSS that supports it too sends
/// the SharedIFCSetIDs of a profile rather than the iFCs (TS 29.228 §6.1.2).
pub const FEATURE_SIFC: u32 = 1 << 0;

/// The Supported-Features AVP for Feature-List-ID 1 (TS 29.229 §6.3.29):
/// Vendor-Id 3GPP, Feature-List-ID, Feature-List. TS 29.229 Table 6.3.1 has
/// the V bit on all three and the M bit off on Feature-List-ID and
/// Feature-List; it is left off the group too, where it may be set.
fn supported_features_avp(feature_list: u32) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend_from_slice(&encode_avp_u32(avp::VENDOR_ID, dictionary::VENDOR_3GPP));
    children.extend_from_slice(&encode_avp_vendor(
        avp::FEATURE_LIST_ID,
        0,
        dictionary::VENDOR_3GPP,
        &1u32.to_be_bytes(),
    ));
    children.extend_from_slice(&encode_avp_vendor(
        avp::FEATURE_LIST,
        0,
        dictionary::VENDOR_3GPP,
        &feature_list.to_be_bytes(),
    ));
    encode_avp_vendor(
        avp::SUPPORTED_FEATURES,
        0,
        dictionary::VENDOR_3GPP,
        &children,
    )
}

/// The members of a grouped AVP, whether or not the dictionary knew it was one.
fn group_members(group: &Avp) -> Vec<Avp> {
    match &group.value {
        AvpData::Grouped(children) => children.clone(),
        AvpData::Raw(bytes) => parse_avps(bytes).unwrap_or_default(),
    }
}

fn member_text(children: &[Avp], code: u32, vendor: u32) -> Option<String> {
    children
        .iter()
        .find(|child| child.code == code && child.vendor == vendor)
        .and_then(Avp::as_str)
}

fn member_u32(children: &[Avp], code: u32) -> Option<u32> {
    children
        .iter()
        .find(|child| child.code == code && child.vendor == dictionary::VENDOR_3GPP)
        .and_then(Avp::as_u32)
}

/// A Diameter Time (RFC 6733 §4.3.1, NTP seconds) as Unix seconds. Values
/// below the 1970 offset are read in the era that begins in 2036, as the RFC
/// asks of times past the 32-bit wrap.
fn diameter_time_to_unix(ntp: u32) -> u64 {
    let ntp = u64::from(ntp);
    if ntp >= NTP_UNIX_EPOCH_OFFSET {
        ntp - NTP_UNIX_EPOCH_OFFSET
    } else {
        ntp + (1u64 << 32) - NTP_UNIX_EPOCH_OFFSET
    }
}

fn read_subscription_info(group: &Avp) -> Option<SubscriptionInfo> {
    let children = group_members(group);
    let vendor = dictionary::VENDOR_3GPP;
    Some(SubscriptionInfo {
        call_id: member_text(&children, avp::CALL_ID_SIP_HEADER, vendor)?,
        from: member_text(&children, avp::FROM_SIP_HEADER, vendor)?,
        to: member_text(&children, avp::TO_SIP_HEADER, vendor)?,
        record_route: member_text(&children, avp::RECORD_ROUTE, vendor)?,
        contact: member_text(&children, avp::CONTACT, vendor)?,
    })
}

fn read_pcscf_subscription_info(group: &Avp) -> Option<PcscfSubscriptionInfo> {
    let children = group_members(group);
    let vendor = dictionary::VENDOR_3GPP;
    Some(PcscfSubscriptionInfo {
        call_id: member_text(&children, avp::CALL_ID_SIP_HEADER, vendor)?,
        from: member_text(&children, avp::FROM_SIP_HEADER, vendor)?,
        to: member_text(&children, avp::TO_SIP_HEADER, vendor)?,
        contact: member_text(&children, avp::CONTACT, vendor)?,
    })
}

fn read_restoration_info(group: &Avp) -> Option<RestorationInfo> {
    let children = group_members(group);
    let vendor = dictionary::VENDOR_3GPP;
    let find = |code: u32| {
        children
            .iter()
            .find(move |child| child.code == code && child.vendor == vendor)
    };
    Some(RestorationInfo {
        // `{ Path }` and `{ Contact }` are required (TS 29.229 §6.3.52).
        path: member_text(&children, avp::PATH, vendor)?,
        contact: member_text(&children, avp::CONTACT, vendor)?,
        initial_cseq_sequence_number: member_u32(&children, avp::INITIAL_CSEQ_SEQUENCE_NUMBER),
        call_id: member_text(&children, avp::CALL_ID_SIP_HEADER, vendor),
        subscription_info: find(avp::SUBSCRIPTION_INFO).and_then(read_subscription_info),
        pcscf_subscription_info: find(avp::PCSCF_SUBSCRIPTION_INFO)
            .and_then(read_pcscf_subscription_info),
    })
}

/// One SCSCF-Restoration-Info AVP (TS 29.229 §6.3.46), or `None` when it
/// lacks its User-Name or holds no complete Restoration-Info.
pub fn read_scscf_restoration_info(group: &Avp) -> Option<ScscfRestorationInfo> {
    let children = group_members(group);
    let vendor = dictionary::VENDOR_3GPP;
    let restoration_info: Vec<RestorationInfo> = children
        .iter()
        .filter(|child| child.code == avp::RESTORATION_INFO && child.vendor == vendor)
        .filter_map(read_restoration_info)
        .collect();
    if restoration_info.is_empty() {
        return None;
    }
    Some(ScscfRestorationInfo {
        user_name: member_text(&children, avp::USER_NAME, 0)?,
        restoration_info,
        registration_time_out: member_u32(&children, avp::REGISTRATION_TIME_OUT)
            .map(diameter_time_to_unix),
        sip_authentication_scheme: member_text(&children, avp::SIP_AUTHENTICATION_SCHEME, vendor),
    })
}

/// Every SCSCF-Restoration-Info of a Server-Assignment-Answer, in order
/// (`*[ SCSCF-Restoration-Info ]`, TS 29.229 §6.1.4: one group per private
/// user identity).
pub fn scscf_restoration_infos(message: &DiameterMsg) -> Vec<ScscfRestorationInfo> {
    message
        .find_all(avp::SCSCF_RESTORATION_INFO, dictionary::VENDOR_3GPP)
        .filter_map(read_scscf_restoration_info)
        .collect()
}

/// The User-Names of Associated-Registered-Identities (TS 29.229 §6.3.50):
/// the private identities registered with the public identity.
pub fn associated_registered_identities(message: &DiameterMsg) -> Vec<String> {
    message
        .find(
            avp::ASSOCIATED_REGISTERED_IDENTITIES,
            dictionary::VENDOR_3GPP,
        )
        .map(|group| {
            group_members(group)
                .iter()
                .filter(|child| child.code == avp::USER_NAME && child.vendor == 0)
                .filter_map(Avp::as_str)
                .collect()
        })
        .unwrap_or_default()
}

/// Feature-List of the Supported-Features for Feature-List-ID 1 (TS 29.229
/// §6.3.29) in a message, `0` without one.
pub fn supported_feature_list(message: &DiameterMsg) -> u32 {
    let vendor = dictionary::VENDOR_3GPP;
    message
        .find_all(avp::SUPPORTED_FEATURES, vendor)
        .map(group_members)
        .find(|children| member_u32(children, avp::FEATURE_LIST_ID) == Some(1))
        .and_then(|children| member_u32(&children, avp::FEATURE_LIST))
        .unwrap_or(0)
}

/// Encode a SAR (Server-Assignment-Request), S-CSCF to HSS.
pub fn build_sar(
    config: &PeerConfig,
    session_id: &str,
    request: &ServerAssignment<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(512);
    append_request_header(&mut payload, config, session_id);
    if let Some(user_name) = request.user_name {
        payload.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, user_name));
    }
    payload.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::PUBLIC_IDENTITY,
        request.public_identity,
    ));
    payload.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, request.server_name));
    payload.extend_from_slice(&encode_avp_u32_3gpp(
        avp::SERVER_ASSIGNMENT_TYPE,
        request.server_assignment_type,
    ));
    payload.extend_from_slice(&encode_avp_u32_3gpp(
        avp::USER_DATA_ALREADY_AVAILABLE,
        request.user_data_already_available,
    ));
    if request.supported_features != 0 {
        // TS 29.229 §6.1.3: `*[ Supported-Features ]`.
        payload.extend_from_slice(&supported_features_avp(request.supported_features));
    }
    // TS 29.229 §6.1.3, in the order of the command:
    // `[ SCSCF-Restoration-Info ] [ Multiple-Registration-Indication ]
    // [ Session-Priority ] [ SAR-Flags ] [ Failed-PCSCF ]`.
    if let Some(restoration) = request.restoration {
        payload.extend_from_slice(&scscf_restoration_info_avp(restoration));
    }
    if let Some(indication) = request.multiple_registration_indication {
        payload.extend_from_slice(&optional_3gpp(
            avp::MULTIPLE_REGISTRATION_INDICATION,
            &indication.to_be_bytes(),
        ));
    }
    if let Some(flags) = request.sar_flags {
        payload.extend_from_slice(&optional_3gpp(avp::SAR_FLAGS, &flags.to_be_bytes()));
    }
    if let Some(failed) = request.failed_pcscf {
        payload.extend_from_slice(&failed_pcscf_avp(failed));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_SERVER_ASSIGNMENT,
        dictionary::CX_APP_ID,
        hop_by_hop,
        end_to_end,
        &payload,
    )
}

/// What a Multimedia-Auth-Request carries besides the routing AVPs.
#[derive(Debug, Clone, Copy)]
pub struct MultimediaAuth<'a> {
    pub public_identity: &'a str,
    /// The private user identity, sent as User-Name (TS 29.229 clause 6.1.7,
    /// `{ User-Name }`; TS 29.228 Table 6.3.1, category M).
    pub user_name: &'a str,
    /// The SIP URI of this S-CSCF, sent as Server-Name (TS 29.229 clause
    /// 6.1.7, `{ Server-Name }`; TS 29.228 Table 6.3.1, category M). The HSS
    /// stores it as the S-CSCF serving the user (TS 29.228 clause 6.3.1).
    /// `None` leaves the AVP out, which a conforming HSS refuses.
    pub server_name: Option<&'a str>,
    pub sip_number_auth_items: u32,
    pub sip_auth_scheme: &'a str,
    /// RAND || AUTS, only on a request after an IMS AKA synchronisation
    /// failure (TS 29.228 Table 6.3.2).
    pub sip_authorization: Option<&'a [u8]>,
}

/// Encode a MAR (Multimedia-Auth-Request), S-CSCF to HSS.
pub fn build_mar(
    config: &PeerConfig,
    session_id: &str,
    request: &MultimediaAuth<'_>,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut auth_children = Vec::new();
    auth_children.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::SIP_AUTHENTICATION_SCHEME,
        request.sip_auth_scheme,
    ));
    if let Some(auth_data) = request.sip_authorization {
        auth_children.extend_from_slice(&encode_avp_octet_3gpp(avp::SIP_AUTHORIZATION, auth_data));
    }
    let sip_auth_data_item = encode_avp_grouped_3gpp(avp::SIP_AUTH_DATA_ITEM, &auth_children);

    let mut payload = Vec::with_capacity(512);
    append_request_header(&mut payload, config, session_id);
    payload.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, request.user_name));
    payload.extend_from_slice(&encode_avp_utf8_3gpp(
        avp::PUBLIC_IDENTITY,
        request.public_identity,
    ));
    payload.extend_from_slice(&encode_avp_u32_3gpp(
        avp::SIP_NUMBER_AUTH_ITEMS,
        request.sip_number_auth_items,
    ));
    payload.extend_from_slice(&sip_auth_data_item);
    if let Some(server_name) = request.server_name {
        payload.extend_from_slice(&encode_avp_utf8_3gpp(avp::SERVER_NAME, server_name));
    }

    encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_MULTIMEDIA_AUTH,
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
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_HOST,
            "icscf.ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::PUBLIC_IDENTITY,
            "sip:+15551234@ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_octet_3gpp(
            avp::VISITED_NETWORK_IDENTIFIER,
            b"ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_AUTHORIZATION_TYPE, 0));

        let incoming = synthesize_request(dictionary::CMD_USER_AUTHORIZATION, &raw);
        let uar = parse_uar(&incoming).expect("UAR parsing failed");

        assert_eq!(uar.session_id, "cx;uar;1");
        assert_eq!(uar.origin_host, "icscf.ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(
            uar.public_identity,
            "sip:+15551234@ims.mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(uar.visited_network_id, "ims.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(uar.user_authorization_type, Some(0));
    }

    #[test]
    fn parse_and_verify_sar() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "cx;sar;1"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "scscf.ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "ims.example.com"));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::PUBLIC_IDENTITY,
            "sip:alice@ims.example.com",
        ));
        raw.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::SERVER_NAME,
            "sip:scscf1.ims.example.com:6060",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::SERVER_ASSIGNMENT_TYPE, 1));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::USER_DATA_ALREADY_AVAILABLE, 0));

        let incoming = synthesize_request(dictionary::CMD_SERVER_ASSIGNMENT, &raw);
        let sar = parse_sar(&incoming).expect("SAR parsing failed");

        assert_eq!(sar.session_id, "cx;sar;1");
        assert_eq!(
            sar.public_identity.as_deref(),
            Some("sip:alice@ims.example.com")
        );
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
        raw.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::PUBLIC_IDENTITY,
            "sip:bob@ims.example.com",
        ));

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
        raw.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::PUBLIC_IDENTITY,
            "sip:carol@ims.example.com",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(avp::SIP_NUMBER_AUTH_ITEMS, 1));
        raw.extend_from_slice(&auth_data);

        let incoming = synthesize_request(dictionary::CMD_MULTIMEDIA_AUTH, &raw);
        let mar = parse_mar(&incoming).expect("MAR parsing failed");

        assert_eq!(mar.session_id, "cx;mar;1");
        assert_eq!(mar.public_identity, "sip:carol@ims.example.com");
        assert_eq!(mar.num_auth_items, 1);
        assert_eq!(mar.auth_scheme.as_deref(), Some("Digest-AKAv1-MD5"));
    }

    fn sample_maa() -> Vec<u8> {
        let vector = AuthVector {
            sip_authenticate: &[0xAA; 32],
            sip_authorization: &[0xBB; 16],
            confidentiality_key: &[0xCC; 16],
            integrity_key: &[0xDD; 16],
        };
        build_maa_success(
            "hss.ims.example.com",
            "ims.example.com",
            "cx;mar;2",
            "dave@ims.example.com",
            "sip:dave@ims.example.com",
            &vector,
            42,
            99,
        )
    }

    fn sample_rta() -> Vec<u8> {
        build_rta(
            "scscf.ims.example.com",
            "ims.example.com",
            "cx;rtr;42",
            70,
            80,
        )
    }

    #[test]
    fn build_and_decode_maa() {
        let maa = sample_maa();

        let decoded = decode_diameter(&maa).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_MULTIMEDIA_AUTH);
        assert_eq!(decoded.application_id, dictionary::CX_APP_ID);

        // Verify standard fields
        assert_eq!(
            decoded.avps.get("Session-Id").and_then(|v| v.as_str()),
            Some("cx;mar;2")
        );
        assert_eq!(
            decoded.avps.get("Origin-Host").and_then(|v| v.as_str()),
            Some("hss.ims.example.com")
        );

        // Verify auth vector
        let auth_item = decoded.avps.get("SIP-Auth-Data-Item").unwrap();
        assert_eq!(
            auth_item
                .get("SIP-Authentication-Scheme")
                .and_then(|v| v.as_str()),
            Some("Digest-AKAv1-MD5")
        );
        assert!(auth_item.get("SIP-Authenticate").is_some());
        assert!(auth_item.get("Confidentiality-Key").is_some());
        assert!(auth_item.get("Integrity-Key").is_some());

        // TS 29.228 clause 6.3.1: "The Result-Code shall be set to
        // DIAMETER_SUCCESS", which is what the S-CSCF side reads.
        assert_base_success(&decoded.avps);
        // Table 6.3.4: both identities "shall be present when the result is
        // DIAMETER_SUCCESS".
        assert_eq!(
            decoded.avps.get("User-Name").and_then(|v| v.as_str()),
            Some("dave@ims.example.com")
        );
        assert_eq!(
            decoded.avps.get("Public-Identity").and_then(|v| v.as_str()),
            Some("sip:dave@ims.example.com")
        );
    }

    /// RFC 6733 clause 7.1 carries DIAMETER_SUCCESS (2001) in Result-Code.
    /// TS 29.229 clause 6.2 reserves Experimental-Result for the codes it
    /// defines, where 2001 is DIAMETER_FIRST_REGISTRATION and means something
    /// else, and "Result-Code AVP shall be absent" next to one.
    fn assert_base_success(avps: &serde_json::Value) {
        assert_eq!(avps.get("Result-Code").and_then(|v| v.as_u64()), Some(2001));
        assert!(avps.get("Experimental-Result").is_none());
    }

    fn sample_saa() -> Vec<u8> {
        build_saa_success("hss.example.org", "example.org", "cx;sar;1", None, 1, 2)
    }

    fn sample_lia() -> Vec<u8> {
        build_lia_success(
            "hss.example.org",
            "example.org",
            "cx;lir;1",
            "sip:scscf.example.org",
            1,
            2,
        )
    }

    /// TS 29.228 clauses 6.1.2.1 and 6.1.4.1: "The Result-Code shall be set to
    /// DIAMETER_SUCCESS" for a server assignment and a location query.
    #[test]
    fn saa_and_lia_success_is_a_result_code() {
        assert_base_success(&decode_diameter(&sample_saa()).unwrap().avps);
        assert_base_success(&decode_diameter(&sample_lia()).unwrap().avps);
    }

    #[test]
    fn build_and_decode_uaa() {
        let uaa = build_uaa_success(
            "hss.ims.example.com",
            "ims.example.com",
            "cx;uar;2",
            Some("sip:scscf2.ims.example.com:6060"),
            dictionary::DIAMETER_FIRST_REGISTRATION,
            10,
            20,
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
            30,
            40,
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
            50,
            60,
        );

        let decoded = decode_diameter(&rtr).unwrap();
        assert!(decoded.is_request);
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_REGISTRATION_TERMINATION
        );
        assert_eq!(
            decoded
                .avps
                .get("Destination-Host")
                .and_then(|v| v.as_str()),
            Some("scscf.ims.example.com")
        );
        assert_eq!(
            decoded.avps.get("Public-Identity").and_then(|v| v.as_str()),
            Some("sip:eve@ims.example.com")
        );

        let dr = decoded.avps.get("Deregistration-Reason").unwrap();
        assert_eq!(dr.get("Reason-Code").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            dr.get("Reason-Info").and_then(|v| v.as_str()),
            Some("Admin-initiated removal")
        );
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
            70,
            80,
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
            90,
            100,
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
        assert_eq!(
            rtr.reason_code,
            deregistration_reason::PERMANENT_TERMINATION
        );
        assert!(rtr.reason_info.is_none());
    }

    #[test]
    fn build_and_decode_rta() {
        let rta = sample_rta();

        let decoded = decode_diameter(&rta).unwrap();
        assert!(!decoded.is_request, "RTA should not have request flag");
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_REGISTRATION_TERMINATION
        );
        assert_eq!(decoded.hop_by_hop, 70);
        assert_eq!(decoded.end_to_end, 80);

        assert_base_success(&decoded.avps);
    }

    // ── Requests this node sends: UAR and MAR ───────────────────────────

    const PRIVATE_IDENTITY: &str = "001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    const PUBLIC_IDENTITY: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
    const SCSCF_URI: &str = "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org:6060";

    fn client_config() -> PeerConfig {
        PeerConfig {
            host: "hss.example.com".to_string(),
            port: 3868,
            origin_host: "scscf.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            origin_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            destination_host: None,
            destination_realm: "ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            local_ip: "192.0.2.10".parse().unwrap(),
            application_ids: vec![(dictionary::VENDOR_3GPP, dictionary::CX_APP_ID)],
            watchdog_interval: 30,
            reconnect_delay: 5,
            product_name: "SIPhon".to_string(),
            firmware_revision: 100,
        }
    }

    fn sample_uar() -> Vec<u8> {
        build_uar(
            &client_config(),
            "icscf;1;1",
            &UserAuthorization {
                public_identity: PUBLIC_IDENTITY,
                user_name: PRIVATE_IDENTITY,
                visited_network_id: "ims.mnc001.mcc001.3gppnetwork.org",
                user_auth_type: Some(0),
            },
            0x10e,
            0x10e,
        )
    }

    fn sample_mar(server_name: Option<&str>, sip_authorization: Option<&[u8]>) -> Vec<u8> {
        sample_mar_in(SCHEME_IMS_AKA, server_name, sip_authorization)
    }

    fn sample_mar_in(
        sip_auth_scheme: &str,
        server_name: Option<&str>,
        sip_authorization: Option<&[u8]>,
    ) -> Vec<u8> {
        build_mar(
            &client_config(),
            "scscf;1;1",
            &MultimediaAuth {
                public_identity: PUBLIC_IDENTITY,
                user_name: PRIVATE_IDENTITY,
                server_name,
                sip_number_auth_items: 1,
                sip_auth_scheme,
                sip_authorization,
            },
            0x2d6,
            0x2d6,
        )
    }

    /// User-Name as RFC 6733 clause 8.14 and its AVP table give it: code 1,
    /// the M bit and no vendor, so an 8-octet header. The identity is 49
    /// octets, the length 57 (0x39), then 3 octets of padding.
    fn user_name_octets() -> Vec<u8> {
        let mut octets = vec![0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x39];
        octets.extend_from_slice(PRIVATE_IDENTITY.as_bytes());
        octets.extend_from_slice(&[0, 0, 0]);
        octets
    }

    /// Server-Name as TS 29.229 Table 6.3.1 gives it: code 602 (0x25a), the V
    /// and M bits, vendor 10415 (0x28af), so a 12-octet header. The URI is 48
    /// octets, the length 60 (0x3c), no padding.
    fn server_name_octets() -> Vec<u8> {
        let mut octets = vec![
            0x00, 0x00, 0x02, 0x5a, 0xc0, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x28, 0xaf,
        ];
        octets.extend_from_slice(SCSCF_URI.as_bytes());
        octets
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn uar_carries_the_private_identity_as_user_name() {
        let wire = sample_uar();
        assert!(
            contains(&wire, &user_name_octets()),
            "TS 29.229 6.1.1 has {{ User-Name }} in the UAR"
        );
        let message = DiameterMsg::from_wire(&wire).unwrap();
        assert_eq!(message.find_all(avp::USER_NAME, 0).count(), 1);
    }

    #[test]
    fn uar_keeps_the_avps_it_already_sent() {
        let decoded = decode_diameter(&sample_uar()).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_USER_AUTHORIZATION);
        assert_eq!(decoded.application_id, dictionary::CX_APP_ID);
        assert_eq!(decoded.avps["Session-Id"], "icscf;1;1");
        assert_eq!(decoded.avps["Public-Identity"], PUBLIC_IDENTITY);
        assert_eq!(decoded.avps["User-Authorization-Type"], 0);
        assert_eq!(decoded.avps["Auth-Session-State"], 1);
    }

    fn sample_sar(user_name: Option<&str>) -> Vec<u8> {
        build_sar(
            &client_config(),
            "scscf;2;1",
            &ServerAssignment {
                public_identity: PUBLIC_IDENTITY,
                user_name,
                server_name: SCSCF_URI,
                server_assignment_type: 1,
                user_data_already_available: 0,
                supported_features: 0,
                restoration: None,
                multiple_registration_indication: None,
                sar_flags: None,
                failed_pcscf: None,
            },
            0x12d,
            0x12d,
        )
    }

    /// TS 29.228 Table 6.1.2.1: the private identity "shall be present if it
    /// is available when the S-CSCF issues the request". TS 29.229 clause
    /// 6.1.3 has it as `[ User-Name ]`, so the request is complete without.
    #[test]
    fn sar_carries_the_private_identity_when_it_is_given() {
        let wire = sample_sar(Some(PRIVATE_IDENTITY));
        assert!(contains(&wire, &user_name_octets()));
        assert!(contains(&wire, &server_name_octets()));
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(decoded.command_code, dictionary::CMD_SERVER_ASSIGNMENT);
        assert_eq!(decoded.avps["Public-Identity"], PUBLIC_IDENTITY);
        assert_eq!(decoded.avps["Server-Assignment-Type"], 1);
        assert_eq!(decoded.avps["User-Data-Already-Available"], 0);

        let without = DiameterMsg::from_wire(&sample_sar(None)).unwrap();
        assert!(without.find(avp::USER_NAME, 0).is_none());
        assert!(without
            .find(avp::SERVER_NAME, dictionary::VENDOR_3GPP)
            .is_some());
    }

    /// TS 29.229 §6.3.29 / §7.1.1: an S-CSCF with shared iFC sets says so
    /// with Supported-Features { Vendor-Id 10415, Feature-List-ID 1,
    /// Feature-List bit 0 (SiFC) }, the V bit set and, on Feature-List-ID and
    /// Feature-List, the M bit clear (Table 6.3.1). Without, nothing is sent.
    #[test]
    fn sar_advertises_shared_ifc_sets_only_when_asked() {
        let wire = build_sar(
            &client_config(),
            "scscf;2;2",
            &ServerAssignment {
                public_identity: PUBLIC_IDENTITY,
                user_name: Some(PRIVATE_IDENTITY),
                server_name: SCSCF_URI,
                server_assignment_type: 1,
                user_data_already_available: 0,
                supported_features: FEATURE_SIFC,
                restoration: None,
                multiple_registration_indication: None,
                sar_flags: None,
                failed_pcscf: None,
            },
            0x12e,
            0x12e,
        );
        let message = DiameterMsg::from_wire(&wire).unwrap();
        let features = message
            .find(avp::SUPPORTED_FEATURES, dictionary::VENDOR_3GPP)
            .expect("Supported-Features is sent");
        assert_eq!(features.flags & AVP_FLAG_VENDOR, AVP_FLAG_VENDOR);
        let children = match &features.value {
            AvpData::Grouped(children) => children.clone(),
            AvpData::Raw(bytes) => parse_avps(bytes).unwrap(),
        };
        let child = |code: u32, vendor: u32| {
            children
                .iter()
                .find(|avp| avp.code == code && avp.vendor == vendor)
                .unwrap_or_else(|| panic!("AVP {code} in Supported-Features"))
                .clone()
        };
        assert_eq!(
            child(avp::VENDOR_ID, 0).as_u32(),
            Some(dictionary::VENDOR_3GPP)
        );
        for (code, value) in [(avp::FEATURE_LIST_ID, 1), (avp::FEATURE_LIST, 1)] {
            let avp = child(code, dictionary::VENDOR_3GPP);
            assert_eq!(avp.as_u32(), Some(value), "AVP {code}");
            assert_eq!(avp.flags & AVP_FLAG_MANDATORY, 0, "AVP {code} M bit");
        }

        let without = DiameterMsg::from_wire(&sample_sar(None)).unwrap();
        assert!(without
            .find(avp::SUPPORTED_FEATURES, dictionary::VENDOR_3GPP)
            .is_none());
    }

    #[test]
    fn mar_carries_user_name_and_server_name() {
        let wire = sample_mar(Some(SCSCF_URI), None);
        assert!(
            contains(&wire, &user_name_octets()),
            "TS 29.229 6.1.7 has {{ User-Name }} in the MAR"
        );
        assert!(
            contains(&wire, &server_name_octets()),
            "TS 29.229 6.1.7 has {{ Server-Name }} in the MAR"
        );
        let message = DiameterMsg::from_wire(&wire).unwrap();
        assert_eq!(message.find_all(avp::USER_NAME, 0).count(), 1);
        assert_eq!(
            message
                .find_all(avp::SERVER_NAME, dictionary::VENDOR_3GPP)
                .count(),
            1
        );
    }

    #[test]
    fn mar_without_a_server_name_leaves_the_avp_out() {
        let wire = sample_mar(None, None);
        let message = DiameterMsg::from_wire(&wire).unwrap();
        assert!(message
            .find(avp::SERVER_NAME, dictionary::VENDOR_3GPP)
            .is_none());
        assert!(contains(&wire, &user_name_octets()));
    }

    #[test]
    fn mar_names_the_scheme_and_carries_the_resynchronisation_data() {
        let resync = [0xabu8; 30];
        let decoded = decode_diameter(&sample_mar(Some(SCSCF_URI), Some(&resync))).unwrap();
        let item = &decoded.avps["SIP-Auth-Data-Item"];
        assert_eq!(item["SIP-Authentication-Scheme"], "Digest-AKAv1-MD5");
        assert_eq!(
            item["SIP-Authorization"].as_str().unwrap(),
            codec::hex::encode(&resync)
        );
        assert_eq!(decoded.avps["SIP-Number-Auth-Items"], 1);
    }

    #[test]
    fn private_identity_is_derived_from_the_public_identity() {
        // TS 24.229 5.3.1.2 and 5.4.1.1: remove the URI scheme and, if
        // present, the port number and the URI parameters.
        assert_eq!(
            derive_private_identity("sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"),
            PRIVATE_IDENTITY
        );
        assert_eq!(
            derive_private_identity("sip:alice@example.com:5060;transport=tcp"),
            "alice@example.com"
        );
        assert_eq!(
            derive_private_identity("sips:alice@example.com;user=phone"),
            "alice@example.com"
        );
        assert_eq!(
            derive_private_identity("<sip:alice@example.com>"),
            "alice@example.com"
        );
        assert_eq!(
            derive_private_identity("sip:alice@[2001:db8::1]:5060"),
            "alice@[2001:db8::1]"
        );
        assert_eq!(
            derive_private_identity("alice@example.com"),
            "alice@example.com"
        );
    }

    // ── IMS restoration (TS 23.380 clause 4, TS 29.229) ──────────────────

    /// 2026-10-18T08:00:00Z, as Unix seconds.
    const TIME_OUT_UNIX: u64 = 1_792_310_400;

    fn sample_restoration() -> ScscfRestorationInfo {
        ScscfRestorationInfo {
            user_name: "001010000000001@ims.example.net".to_string(),
            restoration_info: vec![RestorationInfo {
                path: "<sip:pcscf.example.net;lr>".to_string(),
                contact: "<sip:192.0.2.1:5060>;expires=600000".to_string(),
                initial_cseq_sequence_number: Some(2),
                call_id: Some("reg-1@192.0.2.1".to_string()),
                subscription_info: None,
                pcscf_subscription_info: None,
            }],
            registration_time_out: Some(TIME_OUT_UNIX),
            sip_authentication_scheme: Some("Digest-AKAv1-MD5".to_string()),
        }
    }

    /// SCSCF-Restoration-Info written out by hand from TS 29.229: codes 639
    /// (group), 1 (User-Name, base, M), 649 (Restoration-Info), 640 (Path),
    /// 641 (Contact), 654 (Initial-CSeq-Sequence-Number), 643
    /// (Call-ID-SIP-Header), 661 (Registration-Time-Out, NTP seconds
    /// 0xee7efb00) and 608 (SIP-Authentication-Scheme, V and M). Table 6.3.1
    /// has the restoration AVPs with V under Must and M under Must not, so
    /// their flags octet is 0x80.
    const RESTORATION_KAT: &str = concat!(
        "0000027f800000f0000028af",
        "000000014000002730303130313030303030303030303140696d732e6578616d706c652e6e657400",
        "0000028980000090000028af",
        "0000028080000026000028af3c7369703a70637363662e6578616d706c652e6e65743b6c723e0000",
        "0000028180",
        "00002f000028af3c7369703a3139322e302e322e313a353036303e3b657870697265733d36303030303000",
        "0000028e80000010000028af00000002",
        "000002838000001b000028af7265672d31403139322e302e322e3100",
        "0000029580000010000028afee7efb00",
        "00000260c000001c000028af4469676573742d414b4176312d4d4435",
    );

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn scscf_restoration_info_matches_the_hand_written_vector() {
        assert_eq!(
            hex(&scscf_restoration_info_avp(&sample_restoration())),
            RESTORATION_KAT
        );
    }

    #[test]
    fn scscf_restoration_info_is_read_from_the_hand_written_vector() {
        let group = parse_avps(&unhex(RESTORATION_KAT)).unwrap().remove(0);
        assert_eq!(
            read_scscf_restoration_info(&group),
            Some(sample_restoration())
        );
    }

    #[test]
    fn restoration_info_without_path_or_contact_is_not_read() {
        // `{ Path }` and `{ Contact }` are required (TS 29.229 §6.3.52); a
        // group whose only Restoration-Info lacks one restores nothing.
        let mut children = Vec::new();
        children.extend(encode_avp_utf8(
            avp::USER_NAME,
            "001010000000001@ims.example.net",
        ));
        children.extend(optional_3gpp(
            avp::RESTORATION_INFO,
            &optional_3gpp(avp::CONTACT, b"<sip:192.0.2.1>"),
        ));
        let group = parse_avps(&optional_3gpp(avp::SCSCF_RESTORATION_INFO, &children))
            .unwrap()
            .remove(0);
        assert_eq!(read_scscf_restoration_info(&group), None);
    }

    fn restoration_sar(request: &ServerAssignment<'_>) -> DiameterMsg {
        DiameterMsg::from_wire(&build_sar(&client_config(), "scscf;2;9", request, 9, 9)).unwrap()
    }

    fn sar_with<'a>(
        restoration: Option<&'a ScscfRestorationInfo>,
        failed: Option<&'a FailedPcscf>,
    ) -> ServerAssignment<'a> {
        ServerAssignment {
            public_identity: PUBLIC_IDENTITY,
            user_name: Some(PRIVATE_IDENTITY),
            server_name: SCSCF_URI,
            server_assignment_type: 2,
            user_data_already_available: 1,
            supported_features: FEATURE_IMS_RESTORATION,
            restoration,
            multiple_registration_indication: Some(1),
            sar_flags: Some(SAR_FLAG_PCSCF_RESTORATION),
            failed_pcscf: failed,
        }
    }

    /// TS 23.380 §4.6.2: an update of the restoration information is a
    /// RE_REGISTRATION with USER_DATA_ALREADY_AVAILABLE; the SAR carries the
    /// group as given, after Supported-Features (TS 29.229 §6.1.3).
    #[test]
    fn sar_carries_the_restoration_information_and_its_companions() {
        let restoration = sample_restoration();
        let failed = FailedPcscf {
            fqdn: Some("pcscf.example.net".to_string()),
            ip_addresses: vec!["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()],
        };
        let message = restoration_sar(&sar_with(Some(&restoration), Some(&failed)));
        let vendor = dictionary::VENDOR_3GPP;
        assert_eq!(
            message
                .find(avp::USER_DATA_ALREADY_AVAILABLE, vendor)
                .and_then(Avp::as_u32),
            Some(1)
        );
        let group = message.find(avp::SCSCF_RESTORATION_INFO, vendor).unwrap();
        assert_eq!(group.flags, AVP_FLAG_VENDOR, "M bit must not be set");
        assert_eq!(read_scscf_restoration_info(group), Some(restoration));
        assert_eq!(
            message
                .find(avp::MULTIPLE_REGISTRATION_INDICATION, vendor)
                .and_then(Avp::as_u32),
            Some(1)
        );
        assert_eq!(
            message.find(avp::SAR_FLAGS, vendor).and_then(Avp::as_u32),
            Some(1)
        );
        let failed_avp = message.find(avp::FAILED_PCSCF, vendor).unwrap();
        let members = group_members(failed_avp);
        assert_eq!(
            member_text(&members, avp::PCSCF_FQDN, vendor).as_deref(),
            Some("pcscf.example.net")
        );
        let addresses: Vec<Vec<u8>> = members
            .iter()
            .filter(|child| child.code == avp::PCSCF_IP_ADDRESS)
            .filter_map(|child| child.raw_bytes().map(<[u8]>::to_vec))
            .collect();
        assert_eq!(
            addresses,
            vec![
                vec![0, 1, 192, 0, 2, 1],
                [
                    vec![0, 2],
                    "2001:db8::1"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec()
                ]
                .concat(),
            ]
        );
        assert_eq!(supported_feature_list(&message), FEATURE_IMS_RESTORATION);
        // The order of TS 29.229 §6.1.3.
        let order: Vec<u32> = message.avps.iter().map(|avp| avp.code).collect();
        let at = |code: u32| order.iter().position(|c| *c == code).unwrap();
        assert!(at(avp::SUPPORTED_FEATURES) < at(avp::SCSCF_RESTORATION_INFO));
        assert!(at(avp::SCSCF_RESTORATION_INFO) < at(avp::MULTIPLE_REGISTRATION_INDICATION));
        assert!(at(avp::MULTIPLE_REGISTRATION_INDICATION) < at(avp::SAR_FLAGS));
        assert!(at(avp::SAR_FLAGS) < at(avp::FAILED_PCSCF));
    }

    #[test]
    fn sar_without_restoration_sends_none_of_it() {
        let message = restoration_sar(&ServerAssignment {
            restoration: None,
            multiple_registration_indication: None,
            sar_flags: None,
            failed_pcscf: None,
            user_data_already_available: 0,
            ..sar_with(None, None)
        });
        let vendor = dictionary::VENDOR_3GPP;
        for code in [
            avp::SCSCF_RESTORATION_INFO,
            avp::MULTIPLE_REGISTRATION_INDICATION,
            avp::SAR_FLAGS,
            avp::FAILED_PCSCF,
        ] {
            assert!(message.find(code, vendor).is_none(), "AVP {code}");
        }
        assert_eq!(
            message
                .find(avp::USER_DATA_ALREADY_AVAILABLE, vendor)
                .and_then(Avp::as_u32),
            Some(0)
        );
    }

    /// A subscription in Restoration-Info (TS 29.229 §6.3.49, §6.3.70): every
    /// member is required, and both kinds come back as they went.
    #[test]
    fn restoration_info_carries_the_reg_event_subscriptions() {
        let mut restoration = sample_restoration();
        restoration.restoration_info[0].subscription_info = Some(SubscriptionInfo {
            call_id: "sub-1@192.0.2.1".to_string(),
            from: "<sip:001010000000001@ims.example.net>;tag=ue".to_string(),
            to: "<sip:001010000000001@ims.example.net>;tag=scscf".to_string(),
            record_route: "<sip:pcscf.example.net;lr>".to_string(),
            contact: "<sip:192.0.2.1:5060>".to_string(),
        });
        restoration.restoration_info[0].pcscf_subscription_info = Some(PcscfSubscriptionInfo {
            call_id: "sub-2@198.51.100.1".to_string(),
            from: "<sip:pcscf.example.net>;tag=p".to_string(),
            to: "<sip:001010000000001@ims.example.net>;tag=s".to_string(),
            contact: "<sip:198.51.100.1:5060>".to_string(),
        });
        let group = parse_avps(&scscf_restoration_info_avp(&restoration))
            .unwrap()
            .remove(0);
        assert_eq!(read_scscf_restoration_info(&group), Some(restoration));
    }

    fn restoration_saa() -> Vec<u8> {
        let mut second = sample_restoration();
        second.user_name = "alice.desk@ims.example.net".to_string();
        second.sip_authentication_scheme = Some("SIP Digest".to_string());
        second.registration_time_out = None;
        let mut extra = unhex(RESTORATION_KAT);
        extra.extend(scscf_restoration_info_avp(&second));
        let mut associated = Vec::new();
        associated.extend(encode_avp_utf8(
            avp::USER_NAME,
            "001010000000001@ims.example.net",
        ));
        associated.extend(encode_avp_utf8(
            avp::USER_NAME,
            "alice.desk@ims.example.net",
        ));
        extra.extend(optional_3gpp(
            avp::ASSOCIATED_REGISTERED_IDENTITIES,
            &associated,
        ));
        extra.extend(supported_features_avp(FEATURE_IMS_RESTORATION));
        // DIAMETER_ERROR_IN_ASSIGNMENT_TYPE: the answer to UNREGISTERED_USER
        // for a registered identity with restoration information (TS 29.228
        // §6.1.2.1, TS 23.380 §4.3.2).
        CxAnswerBuilder::new("hss.example.org", "example.org", "cx;sar;9")
            .experimental_result(5007)
            .raw_avps(&extra)
            .build_with_ids(dictionary::CMD_SERVER_ASSIGNMENT, 9, 9)
    }

    #[test]
    fn saa_yields_every_restoration_group_and_the_registered_identities() {
        let message = DiameterMsg::from_wire(&restoration_saa()).unwrap();
        let groups = scscf_restoration_infos(&message);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], sample_restoration());
        assert_eq!(groups[1].user_name, "alice.desk@ims.example.net");
        assert_eq!(
            groups[1].sip_authentication_scheme.as_deref(),
            Some("SIP Digest")
        );
        assert_eq!(
            associated_registered_identities(&message),
            vec![
                "001010000000001@ims.example.net".to_string(),
                "alice.desk@ims.example.net".to_string()
            ]
        );
        assert_eq!(supported_feature_list(&message), FEATURE_IMS_RESTORATION);
    }

    /// RFC 6733 §4.3.1: Time is NTP seconds, and a value with the high bit
    /// clear is in the era that starts in 2036.
    #[test]
    fn diameter_time_reads_both_eras() {
        assert_eq!(diameter_time_to_unix(0xee7e_fb00), TIME_OUT_UNIX);
        assert_eq!(diameter_time_to_unix(0x83aa_7e80), 0);
        assert_eq!(
            diameter_time_to_unix(0),
            (1u64 << 32) - NTP_UNIX_EPOCH_OFFSET
        );
    }

    fn capabilities_lir() -> Vec<u8> {
        // As DiameterClient::send_lir writes it with User-Authorization-Type.
        let config = client_config();
        let mut payload = Vec::new();
        append_request_header(&mut payload, &config, "icscf;3;1");
        payload.extend(encode_avp_utf8_3gpp(avp::PUBLIC_IDENTITY, PUBLIC_IDENTITY));
        payload.extend(encode_avp_u32_3gpp(avp::USER_AUTHORIZATION_TYPE, 2));
        encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_LOCATION_INFO,
            dictionary::CX_APP_ID,
            3,
            3,
            &payload,
        )
    }

    /// Writes the requests and the answer helpers' output as `text2pcap` hex dumps for
    /// `scripts/validate_diameter_cx_requests.sh` to feed to tshark, which
    /// reads them with its own dictionary.
    #[test]
    fn emit_cx_requests_for_external_dissection() {
        let Ok(directory) = std::env::var("SIPHON_CX_REQUESTS_HEX_DIR") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let resync = [0xabu8; 30];
        for (name, wire) in [
            ("uar", sample_uar()),
            ("mar", sample_mar(Some(SCSCF_URI), None)),
            ("mar_resync", sample_mar(Some(SCSCF_URI), Some(&resync))),
            ("sar", sample_sar(Some(PRIVATE_IDENTITY))),
            (
                "mar_unknown",
                sample_mar_in(SCHEME_UNKNOWN, Some(SCSCF_URI), None),
            ),
            (
                "mar_sip_digest",
                sample_mar_in(SCHEME_SIP_DIGEST, Some(SCSCF_URI), None),
            ),
            ("saa", sample_saa()),
            ("lia", sample_lia()),
            ("maa", sample_maa()),
            ("rta", sample_rta()),
            (
                "sar_restoration",
                build_sar(
                    &client_config(),
                    "scscf;2;9",
                    &sar_with(
                        Some(&sample_restoration()),
                        Some(&FailedPcscf {
                            fqdn: Some("pcscf.example.net".to_string()),
                            ip_addresses: vec!["192.0.2.1".parse().unwrap()],
                        }),
                    ),
                    9,
                    9,
                ),
            ),
            ("saa_restoration", restoration_saa()),
            ("lir_capabilities", capabilities_lir()),
        ] {
            let mut dump = String::new();
            for (offset, chunk) in wire.chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
            std::fs::write(format!("{directory}/{name}.hex"), dump)
                .expect("hex dump must be writable");
        }
    }
}
