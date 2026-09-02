//! Rx Diameter interface per 3GPP TS 29.214.
//!
//! QoS policy control between the P-CSCF and the PCRF/PCF:
//!
//! | Command | Code | Direction | Purpose |
//! |---------|------|-----------|---------|
//! | AAR/AAA | 265 | P-CSCF → PCRF | Authorize media session |
//! | STR/STA | 275 | P-CSCF → PCRF | Terminate Rx session |
//! | RAR/RAA | 258 | PCRF → P-CSCF | Policy change notification |
//! | ASR/ASA | 274 | PCRF → P-CSCF | Abort session |

use std::sync::Arc;

use tracing::info;

use crate::diameter::codec::*;
use crate::diameter::dictionary::{self, avp};
use crate::diameter::peer::{DiameterPeer, IncomingRequest};

// ── Media Type (TS 29.214 §7.3.2) ──────────────────────────────────────

/// SDP media type per TS 29.214 table 7.3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MediaType {
    Audio = 0,
    Video = 1,
    Data = 2,
    Application = 3,
    Control = 4,
    Text = 5,
    Message = 6,
    Other = 0xFFFFFFFF,
}

impl MediaType {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Flow Status (TS 29.214 §7.3.3) ─────────────────────────────────────

/// IP flow gating status per TS 29.214 table 7.3.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowStatus {
    EnabledUplink = 0,
    EnabledDownlink = 1,
    Enabled = 2,
    Disabled = 3,
    Removed = 4,
}

impl FlowStatus {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Abort Cause (TS 29.214 §7.3.27) ────────────────────────────────────

/// Reason the PCRF aborts an Rx session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AbortCause {
    BearerReleased = 0,
    InsufficientServerResources = 1,
    InsufficientBearerResources = 2,
    PsToCsHandover = 3,
    SponsoredDataConnectivityDisallowed = 4,
}

impl AbortCause {
    #[cfg(test)]
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Flow Usage (TS 29.214 §7.3.10) ─────────────────────────────────────

/// What an IP flow carries — separates RTCP/AF-signalling from media.
///
/// `NoInformation` is the default: the PCRF cannot make any assumption.
/// `Rtcp` flags an RTCP companion flow so the PCRF/PCEF doesn't gate it
/// like media; `AfSignalling` is for signalling-bearer flows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowUsage {
    NoInformation = 0,
    Rtcp = 1,
    AfSignalling = 2,
}

impl FlowUsage {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Specific-Action (TS 29.214 §7.3.13) ────────────────────────────────

/// Events the AF subscribes to via Specific-Action in AAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpecificAction {
    ChargingCorrelationExchange = 1,
    IndicationOfLossOfBearer = 2,
    IndicationOfRecoveryOfBearer = 3,
    IndicationOfReleaseOfBearer = 4,
    IndicationOfEstablishmentOfBearer = 6,
    IpCanChange = 7,
    AccessNetworkInfoReport = 12,
}

impl SpecificAction {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Rx-Request-Type (TS 29.214 §7.3.33) ────────────────────────────────

/// Rx-Request-Type identifies the type of AAR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RxRequestType {
    InitialRequest = 0,
    UpdateRequest = 1,
    PcscfRestoration = 2,
}

impl RxRequestType {
    fn as_u32(self) -> u32 {
        self as u32
    }
}

// ── Media model ─────────────────────────────────────────────────────────

/// A single IP flow within a media component (TS 29.214 §7.3.4).
#[derive(Debug, Clone)]
pub struct MediaFlow {
    pub flow_number: u32,
    pub descriptions: Vec<String>,
    pub status: Option<FlowStatus>,
    pub usage: Option<FlowUsage>,
}

impl MediaFlow {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_NUMBER, self.flow_number));
        for description in &self.descriptions {
            inner.extend_from_slice(&encode_avp_octet_3gpp(
                avp::FLOW_DESCRIPTION,
                description.as_bytes(),
            ));
        }
        if let Some(status) = self.status {
            inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_STATUS, status.as_u32()));
        }
        if let Some(usage) = self.usage {
            inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_USAGE, usage.as_u32()));
        }
        encode_avp_grouped_3gpp(avp::MEDIA_SUB_COMPONENT, &inner)
    }
}

/// One SDP media line — audio, video, etc. (TS 29.214 §7.3.5).
#[derive(Debug, Clone)]
pub struct MediaComponent {
    pub number: u32,
    pub media_type: MediaType,
    pub flows: Vec<MediaFlow>,
    pub max_bandwidth_ul: Option<u32>,
    pub max_bandwidth_dl: Option<u32>,
    pub flow_status: Option<FlowStatus>,
    pub codec_data: Option<Vec<u8>>,
}

impl MediaComponent {
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&encode_avp_u32_3gpp(
            avp::MEDIA_COMPONENT_NUMBER,
            self.number,
        ));
        inner.extend_from_slice(&encode_avp_u32_3gpp(
            avp::MEDIA_TYPE,
            self.media_type.as_u32(),
        ));
        for flow in &self.flows {
            inner.extend_from_slice(&flow.encode());
        }
        if let Some(bw) = self.max_bandwidth_ul {
            inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MAX_REQUESTED_BANDWIDTH_UL, bw));
        }
        if let Some(bw) = self.max_bandwidth_dl {
            inner.extend_from_slice(&encode_avp_u32_3gpp(avp::MAX_REQUESTED_BANDWIDTH_DL, bw));
        }
        if let Some(status) = self.flow_status {
            inner.extend_from_slice(&encode_avp_u32_3gpp(avp::FLOW_STATUS, status.as_u32()));
        }
        if let Some(ref codec) = self.codec_data {
            inner.extend_from_slice(&encode_avp_octet_3gpp(avp::CODEC_DATA, codec));
        }
        encode_avp_grouped_3gpp(avp::MEDIA_COMPONENT_DESCRIPTION, &inner)
    }
}

// ── AAR parameters ──────────────────────────────────────────────────────

/// Parameters for an AA-Request (P-CSCF → PCRF).
pub struct RxSessionRequest<'a> {
    /// Reuse an existing Rx session ID (modification AAR per TS 29.214
    /// §4.4.5).  `None` allocates a fresh one — the initial AAR.
    pub session_id: Option<&'a str>,
    pub af_application_id: &'a [u8],
    pub media_components: &'a [MediaComponent],
    pub specific_actions: &'a [SpecificAction],
    pub rx_request_type: RxRequestType,
    pub framed_ip: Option<&'a [u8]>,
    pub framed_ipv6: Option<&'a [u8]>,
    pub subscription_id: Option<(&'a str, u32)>,
}

/// Parsed AA-Answer from the PCRF.
#[derive(Debug, Clone)]
pub struct RxSessionAnswer {
    pub result_code: u32,
    pub session_id: Option<String>,
}

impl RxSessionAnswer {
    pub fn is_success(&self) -> bool {
        self.result_code == dictionary::DIAMETER_SUCCESS
    }
}

// ── Parsed incoming requests from PCRF ──────────────────────────────────

/// Parsed Re-Auth-Request from PCRF (policy change notification).
#[derive(Debug, Clone)]
pub struct PolicyChangeNotification {
    pub session_id: Option<String>,
    pub abort_cause: Option<u32>,
    pub specific_actions: Vec<u32>,
}

/// Parsed Abort-Session-Request from PCRF.
#[derive(Debug, Clone)]
pub struct SessionAbortRequest {
    pub session_id: Option<String>,
    pub abort_cause: Option<u32>,
    pub origin_host: Option<String>,
}

// ── Client operations (P-CSCF → PCRF) ──────────────────────────────────

/// Send an AA-Request to authorize an IMS media session.
///
/// Per TS 29.214 §4.4.1, the P-CSCF sends AAR when SDP is negotiated
/// during SIP session establishment (INVITE/200 OK/UPDATE).
pub async fn send_aar(
    peer: &Arc<DiameterPeer>,
    params: &RxSessionRequest<'_>,
) -> Result<RxSessionAnswer, String> {
    let config = peer.config();
    let hbh = peer.next_hbh();
    let e2e = peer.next_e2e();
    let session_id = params
        .session_id
        .map(String::from)
        .unwrap_or_else(|| peer.new_session_id());

    let mut payload = Vec::with_capacity(512);
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, &session_id));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_APPLICATION_ID,
        dictionary::RX_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        &config.destination_realm,
    ));
    if let Some(ref host) = config.destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }

    // AF-Application-Identifier
    payload.extend_from_slice(&encode_avp_octet_3gpp(
        avp::AF_APPLICATION_IDENTIFIER,
        params.af_application_id,
    ));

    // Media-Component-Description (one per SDP m= line)
    for component in params.media_components {
        payload.extend_from_slice(&component.encode());
    }

    // Specific-Action subscriptions
    for action in params.specific_actions {
        payload.extend_from_slice(&encode_avp_u32_3gpp(avp::SPECIFIC_ACTION, action.as_u32()));
    }

    // Rx-Request-Type
    payload.extend_from_slice(&encode_avp_u32_3gpp(
        avp::RX_REQUEST_TYPE,
        params.rx_request_type.as_u32(),
    ));

    // Framed-IP-Address / Framed-IPv6-Prefix (subscriber addressing)
    if let Some(ip) = params.framed_ip {
        payload.extend_from_slice(&encode_avp_octet(avp::FRAMED_IP_ADDRESS, ip));
    }
    if let Some(ipv6) = params.framed_ipv6 {
        payload.extend_from_slice(&encode_avp_octet(avp::FRAMED_IPV6_PREFIX, ipv6));
    }

    // Subscription-Id (identifies the IMS subscriber)
    if let Some((id_data, id_type)) = params.subscription_id {
        let mut sub_inner = Vec::new();
        sub_inner.extend_from_slice(&encode_avp_u32(avp::SUBSCRIPTION_ID_TYPE, id_type));
        sub_inner.extend_from_slice(&encode_avp_utf8(avp::SUBSCRIPTION_ID_DATA, id_data));
        payload.extend_from_slice(&encode_avp_grouped(avp::SUBSCRIPTION_ID, &sub_inner));
    }

    let wire = encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_AA,
        dictionary::RX_APP_ID,
        hbh,
        e2e,
        &payload,
    );

    info!(session = %session_id, "Rx: sending AAR");
    let answer = peer.send_request(wire).await?;

    Ok(RxSessionAnswer {
        result_code: extract_result_code(&answer.avps),
        session_id: Some(session_id),
    })
}

/// Send a Session-Termination-Request to tear down an Rx session.
///
/// Per TS 29.214 §4.4.5, the P-CSCF sends STR when the SIP session
/// terminates (BYE, CANCEL, or registration timeout).
pub async fn send_str(
    peer: &Arc<DiameterPeer>,
    session_id: &str,
    termination_cause: u32,
) -> Result<u32, String> {
    let config = peer.config();
    let hbh = peer.next_hbh();
    let e2e = peer.next_e2e();

    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, session_id));
    payload.extend_from_slice(&encode_avp_u32(
        avp::AUTH_APPLICATION_ID,
        dictionary::RX_APP_ID,
    ));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, &config.origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, &config.origin_realm));
    payload.extend_from_slice(&encode_avp_utf8(
        avp::DESTINATION_REALM,
        &config.destination_realm,
    ));
    if let Some(ref host) = config.destination_host {
        payload.extend_from_slice(&encode_avp_utf8(avp::DESTINATION_HOST, host));
    }
    // Termination-Cause (295, base)
    payload.extend_from_slice(&encode_avp_u32(295, termination_cause));

    let wire = encode_diameter_message(
        FLAG_REQUEST | FLAG_PROXIABLE,
        dictionary::CMD_SESSION_TERMINATION,
        dictionary::RX_APP_ID,
        hbh,
        e2e,
        &payload,
    );

    info!(session = %session_id, "Rx: sending STR");
    let answer = peer.send_request(wire).await?;

    Ok(extract_result_code(&answer.avps))
}

// ── Server-side handlers (PCRF → P-CSCF) ───────────────────────────────

/// Parse an incoming Re-Auth-Request from the PCRF.
///
/// The PCRF sends RAR when PCC rules change (e.g., bearer modification,
/// loss of resources). Per TS 29.214 §4.4.6.
pub fn parse_policy_change(incoming: &IncomingRequest) -> PolicyChangeNotification {
    let avps = &incoming.avps;

    let specific_actions = match avps.get("Specific-Action") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_u64().map(|n| n as u32))
            .collect(),
        Some(single) => single.as_u64().map(|n| vec![n as u32]).unwrap_or_default(),
        None => Vec::new(),
    };

    PolicyChangeNotification {
        session_id: avps
            .get("Session-Id")
            .and_then(|v| v.as_str())
            .map(String::from),
        abort_cause: avps
            .get("Abort-Cause")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        specific_actions,
    }
}

/// Build a Re-Auth-Answer for an incoming RAR.
pub fn build_policy_change_answer(
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(
        FLAG_PROXIABLE,
        dictionary::CMD_RE_AUTH,
        dictionary::RX_APP_ID,
        hbh,
        e2e,
        &payload,
    )
}

/// Parse an incoming Abort-Session-Request from the PCRF.
///
/// Per TS 29.214 §4.4.7, the PCRF sends ASR when it determines
/// the AF session must be torn down.
pub fn parse_session_abort(incoming: &IncomingRequest) -> SessionAbortRequest {
    let avps = &incoming.avps;
    SessionAbortRequest {
        session_id: avps
            .get("Session-Id")
            .and_then(|v| v.as_str())
            .map(String::from),
        abort_cause: avps
            .get("Abort-Cause")
            .and_then(|v| v.as_u64())
            .map(|n| n as u32),
        origin_host: avps
            .get("Origin-Host")
            .and_then(|v| v.as_str())
            .map(String::from),
    }
}

/// Build an Abort-Session-Answer for an incoming ASR.
pub fn build_session_abort_answer(
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
    hbh: u32,
    e2e: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, result_code));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, origin_host));
    payload.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, origin_realm));

    encode_diameter_message(
        FLAG_PROXIABLE,
        dictionary::CMD_ABORT_SESSION,
        dictionary::RX_APP_ID,
        hbh,
        e2e,
        &payload,
    )
}

// ── Helpers ─────────────────────────────────────────────────────────────

pub(crate) fn extract_result_code(avps: &serde_json::Value) -> u32 {
    avps.get("Result-Code")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            avps.get("Experimental-Result")
                .and_then(|g| g.get("Experimental-Result-Code"))
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0) as u32
}

/// Termination-Cause: DIAMETER_LOGOUT (RFC 6733 §8.15).
pub const TERMINATION_CAUSE_LOGOUT: u32 = 1;
/// Termination-Cause: DIAMETER_SERVICE_NOT_PROVIDED.
pub const TERMINATION_CAUSE_SERVICE_NOT_PROVIDED: u32 = 2;
/// Termination-Cause: DIAMETER_BAD_ANSWER.
pub const TERMINATION_CAUSE_BAD_ANSWER: u32 = 3;
/// Termination-Cause: DIAMETER_ADMINISTRATIVE.
pub const TERMINATION_CAUSE_ADMINISTRATIVE: u32 = 4;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diameter::peer::IncomingRequest;

    // ── 3GPP enum value compliance (TS 29.214) ──────────────────────────

    #[test]
    fn media_type_3gpp_values() {
        assert_eq!(MediaType::Audio.as_u32(), 0);
        assert_eq!(MediaType::Video.as_u32(), 1);
        assert_eq!(MediaType::Data.as_u32(), 2);
        assert_eq!(MediaType::Application.as_u32(), 3);
        assert_eq!(MediaType::Control.as_u32(), 4);
        assert_eq!(MediaType::Text.as_u32(), 5);
        assert_eq!(MediaType::Message.as_u32(), 6);
        assert_eq!(MediaType::Other.as_u32(), 0xFFFFFFFF);
    }

    #[test]
    fn flow_status_3gpp_values() {
        assert_eq!(FlowStatus::EnabledUplink.as_u32(), 0);
        assert_eq!(FlowStatus::EnabledDownlink.as_u32(), 1);
        assert_eq!(FlowStatus::Enabled.as_u32(), 2);
        assert_eq!(FlowStatus::Disabled.as_u32(), 3);
        assert_eq!(FlowStatus::Removed.as_u32(), 4);
    }

    #[test]
    fn abort_cause_3gpp_values() {
        assert_eq!(AbortCause::BearerReleased.as_u32(), 0);
        assert_eq!(AbortCause::InsufficientServerResources.as_u32(), 1);
        assert_eq!(AbortCause::InsufficientBearerResources.as_u32(), 2);
        assert_eq!(AbortCause::PsToCsHandover.as_u32(), 3);
        assert_eq!(AbortCause::SponsoredDataConnectivityDisallowed.as_u32(), 4);
    }

    #[test]
    fn specific_action_3gpp_values() {
        assert_eq!(SpecificAction::ChargingCorrelationExchange.as_u32(), 1);
        assert_eq!(SpecificAction::IndicationOfLossOfBearer.as_u32(), 2);
        assert_eq!(SpecificAction::IndicationOfRecoveryOfBearer.as_u32(), 3);
        assert_eq!(SpecificAction::IndicationOfReleaseOfBearer.as_u32(), 4);
        assert_eq!(SpecificAction::AccessNetworkInfoReport.as_u32(), 12);
    }

    #[test]
    fn rx_request_type_3gpp_values() {
        assert_eq!(RxRequestType::InitialRequest.as_u32(), 0);
        assert_eq!(RxRequestType::UpdateRequest.as_u32(), 1);
        assert_eq!(RxRequestType::PcscfRestoration.as_u32(), 2);
    }

    // ── Media flow encoding ─────────────────────────────────────────────

    #[test]
    fn single_flow_encoding() {
        let flow = MediaFlow {
            flow_number: 1,
            descriptions: vec!["permit in ip from 10.45.1.100 49152 to 10.45.1.200 50000".into()],
            status: Some(FlowStatus::Enabled),
            usage: None,
        };
        let encoded = flow.encode();
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::MEDIA_SUB_COMPONENT);
    }

    #[test]
    fn bidirectional_flow_encoding() {
        // TS 29.214 §5.3.11: uplink + downlink flow descriptions
        let flow = MediaFlow {
            flow_number: 1,
            descriptions: vec![
                "permit in ip from 10.45.1.100 49152 to 10.45.1.200 50000".into(),
                "permit out ip from 10.45.1.200 50000 to 10.45.1.100 49152".into(),
            ],
            status: Some(FlowStatus::Enabled),
            usage: None,
        };
        let encoded = flow.encode();
        assert!(encoded.len() > 100); // Must be larger with two descriptions
    }

    #[test]
    fn flow_without_status() {
        let flow = MediaFlow {
            flow_number: 3,
            descriptions: vec!["permit in ip from any to any".into()],
            status: None,
            usage: None,
        };
        let encoded = flow.encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn rtcp_flow_encoding_includes_flow_usage() {
        // RTCP companion flow — Flow-Usage = 1 (TS 29.214 §7.3.10).
        let flow = MediaFlow {
            flow_number: 2,
            descriptions: vec![
                "permit out 17 from 10.0.0.1 50001 to 10.0.0.2 30001".into(),
                "permit in 17 from 10.0.0.2 30001 to 10.0.0.1 50001".into(),
            ],
            status: None,
            usage: Some(FlowUsage::Rtcp),
        };
        let encoded = flow.encode();
        // The inner-most u32 representation of FlowUsage::Rtcp is 1, but
        // verifying that bytes for the AVP code 512 appear is what
        // actually matters — search for it.
        let code_bytes = avp::FLOW_USAGE.to_be_bytes();
        let mut found = false;
        for window in encoded.windows(4) {
            if window == code_bytes {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "Flow-Usage AVP (512) must be present in RTCP sub-component"
        );
    }

    // ── Media component encoding ────────────────────────────────────────

    #[test]
    fn audio_component_full_encoding() {
        let component = MediaComponent {
            number: 1,
            media_type: MediaType::Audio,
            flows: vec![
                MediaFlow {
                    flow_number: 1,
                    descriptions: vec![
                        "permit in ip from 10.45.1.100 49152 to 10.45.1.200 50000".into(),
                        "permit out ip from 10.45.1.200 50000 to 10.45.1.100 49152".into(),
                    ],
                    status: Some(FlowStatus::Enabled),
                    usage: None,
                },
                MediaFlow {
                    flow_number: 2,
                    descriptions: vec![
                        "permit in ip from 10.45.1.100 49153 to 10.45.1.200 50001".into(),
                        "permit out ip from 10.45.1.200 50001 to 10.45.1.100 49153".into(),
                    ],
                    status: Some(FlowStatus::Enabled),
                    usage: Some(FlowUsage::Rtcp),
                },
            ],
            max_bandwidth_ul: Some(64000),
            max_bandwidth_dl: Some(64000),
            flow_status: Some(FlowStatus::Enabled),
            codec_data: Some(b"uplink\noffer\nm=audio 49152 RTP/AVP 0 8".to_vec()),
        };
        let encoded = component.encode();
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::MEDIA_COMPONENT_DESCRIPTION);
        // Audio with 2 flows + bandwidth + codec data should be substantial
        assert!(encoded.len() > 200);
    }

    #[test]
    fn video_component_minimal() {
        let component = MediaComponent {
            number: 2,
            media_type: MediaType::Video,
            flows: vec![],
            max_bandwidth_ul: Some(384000),
            max_bandwidth_dl: Some(384000),
            flow_status: None,
            codec_data: None,
        };
        let encoded = component.encode();
        let code = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]);
        assert_eq!(code, avp::MEDIA_COMPONENT_DESCRIPTION);
    }

    // ── RAR parsing (PCRF → P-CSCF) ────────────────────────────────────

    fn synthesize_rx_request(command_code: u32, app_id: u32, avp_bytes: &[u8]) -> IncomingRequest {
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            command_code,
            app_id,
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
    fn parse_rar_with_specific_actions() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "pcscf;rx;sess;42"));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_HOST,
            "pcrf.ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(
            avp::SPECIFIC_ACTION,
            SpecificAction::IndicationOfLossOfBearer.as_u32(),
        ));

        let incoming = synthesize_rx_request(dictionary::CMD_RE_AUTH, dictionary::RX_APP_ID, &raw);
        let rar = parse_policy_change(&incoming);

        assert_eq!(rar.session_id.as_deref(), Some("pcscf;rx;sess;42"));
        assert!(rar.abort_cause.is_none());
        assert_eq!(rar.specific_actions.len(), 1);
        assert_eq!(
            rar.specific_actions[0],
            SpecificAction::IndicationOfLossOfBearer.as_u32()
        );
    }

    #[test]
    fn parse_rar_with_abort_cause() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "pcscf;rx;sess;99"));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_HOST,
            "pcrf.ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(
            avp::ABORT_CAUSE,
            AbortCause::InsufficientBearerResources.as_u32(),
        ));

        let incoming = synthesize_rx_request(dictionary::CMD_RE_AUTH, dictionary::RX_APP_ID, &raw);
        let rar = parse_policy_change(&incoming);

        assert_eq!(
            rar.abort_cause,
            Some(AbortCause::InsufficientBearerResources.as_u32())
        );
    }

    // ── ASR parsing (PCRF → P-CSCF) ────────────────────────────────────

    #[test]
    fn parse_asr_from_pcrf() {
        let mut raw = Vec::new();
        raw.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "pcscf;rx;abort;7"));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_HOST,
            "pcrf.ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_utf8(
            avp::ORIGIN_REALM,
            "ims.mnc001.mcc001.3gppnetwork.org",
        ));
        raw.extend_from_slice(&encode_avp_u32_3gpp(
            avp::ABORT_CAUSE,
            AbortCause::BearerReleased.as_u32(),
        ));

        let incoming =
            synthesize_rx_request(dictionary::CMD_ABORT_SESSION, dictionary::RX_APP_ID, &raw);
        let asr = parse_session_abort(&incoming);

        assert_eq!(asr.session_id.as_deref(), Some("pcscf;rx;abort;7"));
        assert_eq!(asr.abort_cause, Some(AbortCause::BearerReleased.as_u32()));
        assert_eq!(
            asr.origin_host.as_deref(),
            Some("pcrf.ims.mnc001.mcc001.3gppnetwork.org")
        );
    }

    // ── RAA/ASA answer roundtrips ───────────────────────────────────────

    #[test]
    fn raa_roundtrip() {
        let wire = build_policy_change_answer(
            "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            dictionary::DIAMETER_SUCCESS,
            10,
            20,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_RE_AUTH);
        assert_eq!(decoded.application_id, dictionary::RX_APP_ID);
        assert_eq!(decoded.hop_by_hop, 10);
        assert_eq!(decoded.end_to_end, 20);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
        assert_eq!(
            decoded.avps.get("Origin-Host").and_then(|v| v.as_str()),
            Some("pcscf.ims.mnc001.mcc001.3gppnetwork.org")
        );
    }

    #[test]
    fn asa_roundtrip() {
        let wire = build_session_abort_answer(
            "pcscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            dictionary::DIAMETER_SUCCESS,
            30,
            40,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_ABORT_SESSION);
        assert_eq!(decoded.application_id, dictionary::RX_APP_ID);
        assert_eq!(decoded.hop_by_hop, 30);
        assert_eq!(decoded.end_to_end, 40);
    }

    #[test]
    fn raa_failure_result_code() {
        let wire = build_policy_change_answer(
            "pcscf.ims.example.net",
            "ims.example.net",
            dictionary::DIAMETER_UNABLE_TO_COMPLY,
            1,
            2,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(5012)
        );
    }

    // ── RxSessionAnswer logic ───────────────────────────────────────────

    #[test]
    fn rx_session_answer_success_and_failure() {
        let ok = RxSessionAnswer {
            result_code: dictionary::DIAMETER_SUCCESS,
            session_id: Some("pcscf;sess;1".into()),
        };
        assert!(ok.is_success());

        let fail = RxSessionAnswer {
            result_code: 5012,
            session_id: None,
        };
        assert!(!fail.is_success());
    }

    // ── Termination cause constants ─────────────────────────────────────

    #[test]
    fn termination_cause_rfc6733_values() {
        assert_eq!(TERMINATION_CAUSE_LOGOUT, 1);
        assert_eq!(TERMINATION_CAUSE_SERVICE_NOT_PROVIDED, 2);
        assert_eq!(TERMINATION_CAUSE_BAD_ANSWER, 3);
        assert_eq!(TERMINATION_CAUSE_ADMINISTRATIVE, 4);
    }

    // ── Command code and app ID compliance ──────────────────────────────

    #[test]
    fn rx_app_id_is_3gpp_registered() {
        assert_eq!(dictionary::RX_APP_ID, 16777236);
    }

    #[test]
    fn rx_command_codes_rfc_compliant() {
        assert_eq!(dictionary::CMD_AA, 265);
        assert_eq!(dictionary::CMD_SESSION_TERMINATION, 275);
        assert_eq!(dictionary::CMD_RE_AUTH, 258);
        assert_eq!(dictionary::CMD_ABORT_SESSION, 274);
    }
}
