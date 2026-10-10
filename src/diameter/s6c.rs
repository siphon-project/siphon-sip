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
        &codec::encode_tbcd_digits(msisdn),
    ));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SC_ADDRESS,
        &codec::encode_tbcd_digits(sc_address),
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
    /// Diameter identity of the serving MME, from the grouped `Serving-Node`. For a UE registered
    /// for SMS over NAS on 5G the HSS puts the **SMSF** identity here (TS 29.338 §6.3.2.4), so
    /// this names whichever node terminates SMS, not necessarily an MME.
    pub mme_name: Option<String>,
    /// Realm of [`Self::mme_name`].
    pub mme_realm: Option<String>,
    /// Diameter identity of the serving SGSN, from the grouped `Serving-Node`.
    pub sgsn_name: Option<String>,
    /// Realm of [`Self::sgsn_name`].
    pub sgsn_realm: Option<String>,
    /// MSC GT for 2G/3G circuit-switched delivery (SS7/MAP, not SGd).
    pub msc_number: Option<String>,
}

impl SendRoutingInfoAnswer {
    /// The `(Destination-Host, Destination-Realm)` an SGd MT-Forward-Short-Message must be
    /// addressed to, when the HSS located a Diameter serving node.
    ///
    /// This is the whole point of the SRI-SM. Addressing the TFR from static peer config instead
    /// sends it to whatever the relay's catch-all route resolves to — in a deployed core, the HSS
    /// — and the message is never delivered.
    pub fn sgd_destination(&self) -> Option<(&str, Option<&str>)> {
        if let Some(name) = self.mme_name.as_deref() {
            return Some((name, self.mme_realm.as_deref()));
        }
        self.sgsn_name
            .as_deref()
            .map(|name| (name, self.sgsn_realm.as_deref()))
    }
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
    // TS 29.338 §6.3.2 puts the located node in the grouped `Serving-Node`, not at the top level.
    // Reading only the top level is why a conformant SRA parsed as "no serving node": an HSS that
    // names the node sets MME-Name/MME-Realm inside the group and nothing outside it. The top
    // level is still consulted as a fallback for peers that flatten it.
    let serving_node = avps.get("Serving-Node");
    let in_serving_node = |name: &str| {
        serving_node
            .and_then(|sn| sn.get(name))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let anywhere = |name: &str| in_serving_node(name).or_else(|| optional_str(avps, name));

    Some(SendRoutingInfoAnswer {
        result_code,
        experimental_result_code,
        user_name: optional_str(avps, "User-Name"),
        sgsn_number: anywhere("SGSN-Number"),
        mme_number_for_mt_sms: anywhere("MME-Number-for-MT-SMS"),
        mme_name: anywhere("MME-Name"),
        mme_realm: anywhere("MME-Realm"),
        sgsn_name: anywhere("SGSN-Name"),
        sgsn_realm: anywhere("SGSN-Realm"),
        msc_number: anywhere("MSC-Number"),
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
        msisdn: optional_str(avps, "MSISDN"),
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

/// SM-Delivery-Cause (TS 29.338 clause 5.3.3.19): why the HSS is to set, or
/// clear, its message waiting data. The discriminants are the wire values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmDeliveryCause {
    UeMemoryCapacityExceeded = 0,
    AbsentUser = 1,
    SuccessfulTransfer = 2,
}

impl SmDeliveryCause {
    /// The Enumerated value carried in the SM-Delivery-Cause AVP.
    pub fn code(self) -> u32 {
        self as u32
    }

    /// The cause for the `delivery_outcome` number a script passes to
    /// `diameter.s6c_rsr`: 0 successful transfer, 1 absent user, 2 UE memory
    /// capacity exceeded. That numbering is the script API's own and is not
    /// the wire enumeration; any other number has no SM-Delivery-Cause.
    pub fn from_script_outcome(delivery_outcome: u32) -> Option<Self> {
        match delivery_outcome {
            0 => Some(Self::SuccessfulTransfer),
            1 => Some(Self::AbsentUser),
            2 => Some(Self::UeMemoryCapacityExceeded),
            _ => None,
        }
    }
}

impl std::fmt::Display for SmDeliveryCause {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UeMemoryCapacityExceeded => "UE_MEMORY_CAPACITY_EXCEEDED",
            Self::AbsentUser => "ABSENT_USER",
            Self::SuccessfulTransfer => "SUCCESSFUL_TRANSFER",
        })
    }
}

/// The node a delivery was attempted through (TS 29.338 clause 5.3.3.14).
///
/// The HSS keeps its message waiting data per node type, so an outcome
/// reported under the wrong one sets or clears the wrong flag: an absent
/// subscriber reported under the MME when the message went to an SGSN is
/// marked unreachable through a node that never saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmDeliveryNode {
    Mme,
    Msc,
    Sgsn,
    IpSmGw,
}

impl SmDeliveryNode {
    /// The grouped AVP of SM-Delivery-Outcome this node reports in
    /// (clauses 5.3.3.15 to 5.3.3.18).
    pub fn outcome_avp(self) -> u32 {
        match self {
            Self::Mme => avp::MME_SM_DELIVERY_OUTCOME,
            Self::Msc => avp::MSC_SM_DELIVERY_OUTCOME,
            Self::Sgsn => avp::SGSN_SM_DELIVERY_OUTCOME,
            Self::IpSmGw => avp::IP_SM_GW_SM_DELIVERY_OUTCOME,
        }
    }

    /// The node for the `node` name a script passes to `diameter.s6c_rsr`:
    /// `mme`, `msc`, `sgsn` or `ip_sm_gw`, compared without case.
    pub fn from_script_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "mme" => Some(Self::Mme),
            "msc" => Some(Self::Msc),
            "sgsn" => Some(Self::Sgsn),
            "ip_sm_gw" => Some(Self::IpSmGw),
            _ => None,
        }
    }
}

impl std::fmt::Display for SmDeliveryNode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Mme => "mme",
            Self::Msc => "msc",
            Self::Sgsn => "sgsn",
            Self::IpSmGw => "ip_sm_gw",
        })
    }
}

/// An Absent-User-Diagnostic-SM was given for a delivery that did not end in
/// ABSENT_USER, the only cause it accompanies (TS 29.338 clause 5.3.2.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an absent user diagnostic accompanies ABSENT_USER only, not {0}")]
pub struct DiagnosticWithoutAbsentUser(pub SmDeliveryCause);

/// What an RSR reports: through which node the delivery was attempted, how it
/// ended and, for an absent user, why the node found the user absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmDeliveryOutcome {
    node: SmDeliveryNode,
    cause: SmDeliveryCause,
    absent_user_diagnostic: Option<u32>,
}

impl SmDeliveryOutcome {
    /// `absent_user_diagnostic` is the Absent-User-Diagnostic-SM value
    /// (clause 5.3.3.20, numbered by TS 23.040 clause 3.3.2) and is refused
    /// with any cause other than [`SmDeliveryCause::AbsentUser`].
    pub fn new(
        node: SmDeliveryNode,
        cause: SmDeliveryCause,
        absent_user_diagnostic: Option<u32>,
    ) -> Result<Self, DiagnosticWithoutAbsentUser> {
        if absent_user_diagnostic.is_some() && cause != SmDeliveryCause::AbsentUser {
            return Err(DiagnosticWithoutAbsentUser(cause));
        }
        Ok(Self {
            node,
            cause,
            absent_user_diagnostic,
        })
    }

    /// The outcome for the arguments a script passes to `diameter.s6c_rsr`,
    /// or the message of the `ValueError` it gets for ones that name nothing
    /// the interface defines.
    pub fn from_script(
        delivery_outcome: u32,
        node: &str,
        absent_user_diagnostic: Option<u32>,
    ) -> Result<Self, String> {
        let cause = SmDeliveryCause::from_script_outcome(delivery_outcome).ok_or_else(|| {
            format!(
                "invalid delivery_outcome: {delivery_outcome} — expected 0 (successful \
                 transfer), 1 (absent user) or 2 (UE memory capacity exceeded)"
            )
        })?;
        let node = SmDeliveryNode::from_script_name(node).ok_or_else(|| {
            format!("invalid node: {node:?} — expected \"mme\", \"sgsn\", \"msc\" or \"ip_sm_gw\"")
        })?;
        Self::new(node, cause, absent_user_diagnostic).map_err(|_| {
            format!(
                "absent_user_diagnostic is only sent with delivery_outcome 1 (absent user), \
                 not {delivery_outcome}"
            )
        })
    }

    /// The SM-Delivery-Outcome AVP: the node's group holding the cause and,
    /// when there is one, the diagnostic (clause 5.3.3.14).
    fn encode(&self) -> Vec<u8> {
        let mut members = encode_avp_u32_3gpp(avp::SM_DELIVERY_CAUSE, self.cause.code());
        if let Some(diagnostic) = self.absent_user_diagnostic {
            members.extend_from_slice(&encode_avp_u32_3gpp(
                avp::ABSENT_USER_DIAGNOSTIC_SM,
                diagnostic,
            ));
        }
        encode_avp_grouped_3gpp(
            avp::SM_DELIVERY_OUTCOME,
            &encode_avp_grouped_3gpp(self.node.outcome_avp(), &members),
        )
    }
}

/// Build the wire-format RSR (TS 29.338 clause 5.3.2.7, where the command is
/// abbreviated RDR).
///
/// The subscriber goes in the mandatory User-Identifier group, as a
/// User-Name. The outcome goes in SM-Delivery-Outcome, inside the group of
/// the node the delivery was attempted through (clauses 5.3.3.14 to
/// 5.3.3.20).
pub fn build_report_sm_delivery_status_request(
    config: &crate::diameter::peer::PeerConfig,
    session_id: &str,
    user_name: &str,
    sc_address: &str,
    delivery_outcome: &SmDeliveryOutcome,
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
    avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(
        avp::USER_IDENTIFIER,
        &encode_avp_utf8(avp::USER_NAME, user_name),
    ));
    avp_bytes.extend_from_slice(&encode_avp_octet_3gpp(
        avp::SC_ADDRESS,
        &codec::encode_tbcd_digits(sc_address),
    ));
    avp_bytes.extend_from_slice(&delivery_outcome.encode());

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

    /// MSISDN (701, V and M, vendor 10415) for 31612345678, written out by
    /// hand: a 12-octet header, then per TS 29.329 clause 6.3.2 "digits from
    /// 0 through 9 are encoded 0000 to 1001; 1111 is used as a filler when
    /// there is an odd number of digits; bits 8 to 5 of octet n encode digit
    /// 2n; bits 4 to 1 of octet n encode digit 2(n-1)+1". Length 18 (0x12),
    /// two octets of padding.
    const MSISDN_31612345678: [u8; 20] = [
        0x00, 0x00, 0x02, 0xbd, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, // header
        0x13, 0x16, 0x32, 0x54, 0x76, 0xf8, // 31 61 23 45 67 8F, nibbles swapped
        0x00, 0x00, // padding
    ];

    /// SC-Address (3300, V and M, vendor 10415) for 31611111111. TS 29.338
    /// clause 6.3.3.2: "This AVP shall not include leading indicators for the
    /// nature of address and the numbering plan; it shall contain only the
    /// TBCD-encoded digits of the address."
    const SC_ADDRESS_31611111111: [u8; 20] = [
        0x00, 0x00, 0x0c, 0xe4, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, // header
        0x13, 0x16, 0x11, 0x11, 0x11, 0xf1, // 31 61 11 11 11 1F, nibbles swapped
        0x00, 0x00, // padding
    ];

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
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_SEND_ROUTING_INFO_FOR_SM
        );
        assert_eq!(decoded.application_id, dictionary::S6C_APP_ID);

        // TS 29.329 clause 6.3.2 (MSISDN) and TS 29.338 clause 6.3.3.2
        // (SC-Address): the digits as a TBCD-string and nothing else. The
        // whole AVP is pinned, header included, so an extra leading octet
        // shows as a wrong length.
        assert!(
            contains(&wire, &MSISDN_31612345678),
            "MSISDN must be the 6 TBCD octets of 31612345678 and nothing else"
        );
        assert!(
            contains(&wire, &SC_ADDRESS_31611111111),
            "SC-Address must be the 6 TBCD octets of 31611111111 and nothing else"
        );

        let avps = &decoded.avps;
        assert_eq!(
            avps.get("MSISDN").and_then(|v| v.as_str()),
            Some("31612345678")
        );
        assert_eq!(
            avps.get("SC-Address").and_then(|v| v.as_str()),
            Some("31611111111")
        );
    }

    /// A number whose second digit is 8 or 9 starts with an octet that has
    /// its top bit set: 19995550100 is `91 99 55 05 01 f0`. That first octet
    /// is two digits, not an indicator.
    #[test]
    fn srr_encodes_an_msisdn_whose_first_octet_reads_like_an_indicator() {
        let wire = build_send_routing_info_request(
            &config(),
            "test;1;1",
            "19995550100",
            "31611111111",
            Some(0),
            1,
            1,
        );
        let msisdn_avp = [
            0x00, 0x00, 0x02, 0xbd, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, // header
            0x91, 0x99, 0x55, 0x05, 0x01, 0xf0, // 19 99 55 50 10 0F, nibbles swapped
            0x00, 0x00, // padding
        ];
        assert!(contains(&wire, &msisdn_avp));
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("MSISDN").and_then(|v| v.as_str()),
            Some("19995550100"),
        );
    }

    /// The Report-SM-Delivery-Status request carries SC-Address the same way.
    #[test]
    fn rsr_encodes_sc_address_as_bare_tbcd() {
        let wire = build_report_sm_delivery_status_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "31611111111",
            &SmDeliveryOutcome::new(
                SmDeliveryNode::Mme,
                SmDeliveryCause::SuccessfulTransfer,
                None,
            )
            .unwrap(),
            1,
            1,
        );
        assert!(contains(&wire, &SC_ADDRESS_31611111111));
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
        // An SRA the way TS 29.272 clause 7.3.159 has it: MME-Number-for-MT-SMS
        // is a TBCD-string with no leading indicator. Written out by hand for
        // 49000000001, whose first octet (0x94) has its top bit set.
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, "001010000000001"));
        avp_bytes.extend_from_slice(&[
            0x00, 0x00, 0x06, 0x6d, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, // 1645
            0x94, 0x00, 0x00, 0x00, 0x00, 0xf1, // 49 00 00 00 00 1F, nibbles swapped
            0x00, 0x00, // padding
        ]);

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
        assert_eq!(parsed.mme_number_for_mt_sms.as_deref(), Some("49000000001"));
        assert!(parsed.sgsn_number.is_none());
    }

    /// TS 29.338 §6.3.2 carries the located node inside the grouped `Serving-Node`. Reading only
    /// the top level made every conformant SRA look like "no serving node", so MT-SMS never took
    /// the SGd path at all and fell through to the off-net trunk instead.
    #[test]
    fn parse_sra_reads_the_grouped_serving_node() {
        let mut serving = Vec::new();
        serving.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::MME_NAME,
            "smsf-0.epc.mnc001.mcc001.3gppnetwork.org",
        ));
        serving.extend_from_slice(&encode_avp_utf8_3gpp(
            avp::MME_REALM,
            "epc.mnc001.mcc001.3gppnetwork.org",
        ));
        serving.extend_from_slice(&encode_avp_octet_3gpp(
            avp::MME_NUMBER_FOR_MT_SMS,
            &codec::encode_tbcd_digits("999000000001"),
        ));

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::USER_NAME, "001010000000001"));
        avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(avp::SERVING_NODE, &serving));

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

        assert_eq!(
            parsed.mme_name.as_deref(),
            Some("smsf-0.epc.mnc001.mcc001.3gppnetwork.org"),
            "an SMSF identity arrives in MME-Name per TS 29.338 §6.3.2.4"
        );
        assert_eq!(
            parsed.mme_realm.as_deref(),
            Some("epc.mnc001.mcc001.3gppnetwork.org")
        );
        assert_eq!(
            parsed.mme_number_for_mt_sms.as_deref(),
            Some("999000000001")
        );
        assert_eq!(
            parsed.sgd_destination(),
            Some((
                "smsf-0.epc.mnc001.mcc001.3gppnetwork.org",
                Some("epc.mnc001.mcc001.3gppnetwork.org")
            )),
            "this is what the TFR must be addressed to"
        );
    }

    /// An SGSN-served subscriber resolves to the SGSN, and only when no MME/SMSF was named.
    #[test]
    fn the_sgd_destination_prefers_the_packet_core_node() {
        let mut serving = Vec::new();
        serving.extend_from_slice(&encode_avp_utf8_3gpp(avp::SGSN_NAME, "sgsn-0.example.com"));
        serving.extend_from_slice(&encode_avp_utf8_3gpp(avp::SGSN_REALM, "example.com"));

        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        avp_bytes.extend_from_slice(&encode_avp_grouped_3gpp(avp::SERVING_NODE, &serving));

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
        assert_eq!(parsed.mme_name, None);
        assert_eq!(
            parsed.sgd_destination(),
            Some(("sgsn-0.example.com", Some("example.com")))
        );
    }

    /// A success with no Serving-Node at all: nothing to address a TFR to, and the caller has to
    /// treat that as "not reachable over SGd" rather than sending to peer config.
    #[test]
    fn an_sra_without_a_serving_node_has_no_sgd_destination() {
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));

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
        assert_eq!(parsed.sgd_destination(), None);
    }

    /// SGSN-Number is a TBCD-string with no leading indicator (TS 29.272
    /// clause 7.3.102). Written out by hand for 39000000001, whose first
    /// octet (0x93) has its top bit set: the country code must survive.
    #[test]
    fn parse_sra_reads_an_sgsn_number_as_bare_tbcd() {
        let mut avp_bytes = Vec::new();
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::SESSION_ID, "test;1;1"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_HOST, "hss1.example.com"));
        avp_bytes.extend_from_slice(&encode_avp_utf8(avp::ORIGIN_REALM, "example.com"));
        avp_bytes.extend_from_slice(&encode_avp_u32(avp::RESULT_CODE, 2001));
        avp_bytes.extend_from_slice(&[
            0x00, 0x00, 0x05, 0xd1, 0xc0, 0x00, 0x00, 0x12, 0x00, 0x00, 0x28, 0xaf, // 1489
            0x93, 0x00, 0x00, 0x00, 0x00, 0xf1, // 39 00 00 00 00 1F, nibbles swapped
            0x00, 0x00, // padding
        ]);

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
        assert_eq!(parsed.sgsn_number.as_deref(), Some("39000000001"));
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
        let wire = build_ala_success("smsc.example.com", "example.com", "test;1;1", 10, 20);
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
        let wire = build_ala_error("smsc.example.com", "example.com", "test;1;1", 5012, 10, 20);
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(5012)
        );
    }

    /// Top-level AVP codes of an encoded message, read straight off the
    /// AVP headers (RFC 6733 section 4.1) without the decoder under test.
    fn top_level_avp_codes(wire: &[u8]) -> Vec<u32> {
        let mut codes = Vec::new();
        let mut offset = 20;
        while offset + 8 <= wire.len() {
            codes.push(u32::from_be_bytes(
                wire[offset..offset + 4].try_into().unwrap(),
            ));
            let length =
                u32::from_be_bytes(wire[offset + 4..offset + 8].try_into().unwrap()) & 0x00ff_ffff;
            offset += (length as usize).div_ceil(4) * 4;
        }
        codes
    }

    fn contains(wire: &[u8], expected: &[u8]) -> bool {
        wire.windows(expected.len())
            .any(|window| window == expected)
    }

    /// SM-Delivery-Outcome { MME-SM-Delivery-Outcome { SM-Delivery-Cause } }
    /// as TS 29.338 clauses 5.3.3.14, 5.3.3.15 and 5.3.3.19 lay it out, all
    /// three with the V and M bits and vendor 10415 (table 5.3.3.1/1).
    fn sm_delivery_outcome_bytes(cause: u8) -> Vec<u8> {
        vec![
            0x00, 0x00, 0x0c, 0xf4, 0xc0, 0x00, 0x00, 0x28, 0x00, 0x00, 0x28,
            0xaf, // 3316, 40
            0x00, 0x00, 0x0c, 0xf5, 0xc0, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x28,
            0xaf, // 3317, 28
            0x00, 0x00, 0x0c, 0xf9, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28,
            0xaf, // 3321, 16
            0x00, 0x00, 0x00, cause,
        ]
    }

    /// A delivery through the MME that ended in `cause`, with no diagnostic.
    fn through_the_mme(cause: SmDeliveryCause) -> SmDeliveryOutcome {
        SmDeliveryOutcome::new(SmDeliveryNode::Mme, cause, None).unwrap()
    }

    fn rsr(outcome: &SmDeliveryOutcome) -> Vec<u8> {
        build_report_sm_delivery_status_request(
            &config(),
            "smsc.example.com;1;1",
            "001010000000001",
            "441632960000",
            outcome,
            1,
            1,
        )
    }

    #[test]
    fn rsr_known_answer_bytes() {
        let wire = build_report_sm_delivery_status_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "441632960000",
            &through_the_mme(SmDeliveryCause::SuccessfulTransfer),
            1,
            1,
        );

        // TS 29.338 clause 5.3.2.7: command 8388649, request and proxiable,
        // application 16777312.
        assert_eq!(wire[0], 1);
        assert_eq!(wire[4], 0xc0);
        assert_eq!(&wire[5..8], &[0x80, 0x00, 0x29]);
        assert_eq!(&wire[8..12], &[0x01, 0x00, 0x00, 0x60]);

        // User-Identifier (3102, TS 29.336) holding User-Name (1): the
        // subscriber is named inside the group, as the command requires,
        // and not by a User-Name at command level.
        let user_identifier: &[u8] = &[
            0x00, 0x00, 0x0c, 0x1e, 0xc0, 0x00, 0x00, 0x24, 0x00, 0x00, 0x28,
            0xaf, // 3102, 36
            0x00, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x17, // User-Name, 23
            b'0', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
            b'1', 0x00,
        ];
        assert!(contains(&wire, user_identifier));
        assert!(contains(&wire, &sm_delivery_outcome_bytes(2)));

        assert_eq!(
            top_level_avp_codes(&wire),
            vec![263, 264, 296, 283, 293, 277, 260, 3102, 3300, 3316]
        );
    }

    #[test]
    fn rsr_decodes_to_the_nested_delivery_outcome() {
        let wire = build_report_sm_delivery_status_request(
            &config(),
            "test;1;1",
            "001010000000001",
            "441632960000",
            &through_the_mme(SmDeliveryCause::AbsentUser),
            1,
            1,
        );
        let decoded = codec::decode_diameter(&wire).unwrap();
        assert!(decoded.is_request);
        assert_eq!(
            decoded.command_code,
            dictionary::CMD_REPORT_SM_DELIVERY_STATUS
        );
        assert_eq!(
            decoded
                .avps
                .get("SM-Delivery-Outcome")
                .and_then(|outcome| outcome.get("MME-SM-Delivery-Outcome"))
                .and_then(|outcome| outcome.get("SM-Delivery-Cause"))
                .and_then(|cause| cause.as_u64()),
            Some(1)
        );
        assert_eq!(
            decoded
                .avps
                .get("User-Identifier")
                .and_then(|identifier| identifier.get("User-Name"))
                .and_then(|name| name.as_str()),
            Some("001010000000001")
        );
        assert!(decoded.avps.get("User-Name").is_none());
    }

    #[test]
    fn rsr_carries_each_cause_with_its_wire_value() {
        // TS 29.338 clause 5.3.3.19.
        for (cause, value) in [
            (SmDeliveryCause::UeMemoryCapacityExceeded, 0),
            (SmDeliveryCause::AbsentUser, 1),
            (SmDeliveryCause::SuccessfulTransfer, 2),
        ] {
            assert_eq!(cause.code(), u32::from(value));
            let wire = build_report_sm_delivery_status_request(
                &config(),
                "test;1;1",
                "001010000000001",
                "441632960000",
                &through_the_mme(cause),
                1,
                1,
            );
            assert!(
                contains(&wire, &sm_delivery_outcome_bytes(value)),
                "{cause}"
            );
        }
    }

    #[test]
    fn script_outcome_numbers_map_to_causes() {
        assert_eq!(
            SmDeliveryCause::from_script_outcome(0),
            Some(SmDeliveryCause::SuccessfulTransfer)
        );
        assert_eq!(
            SmDeliveryCause::from_script_outcome(1),
            Some(SmDeliveryCause::AbsentUser)
        );
        assert_eq!(
            SmDeliveryCause::from_script_outcome(2),
            Some(SmDeliveryCause::UeMemoryCapacityExceeded)
        );
        for undefined in [3, 4, 5, u32::MAX] {
            assert_eq!(SmDeliveryCause::from_script_outcome(undefined), None);
        }
    }

    #[test]
    fn sm_delivery_cause_display() {
        assert_eq!(
            SmDeliveryCause::UeMemoryCapacityExceeded.to_string(),
            "UE_MEMORY_CAPACITY_EXCEEDED"
        );
        assert_eq!(SmDeliveryCause::AbsentUser.to_string(), "ABSENT_USER");
        assert_eq!(
            SmDeliveryCause::SuccessfulTransfer.to_string(),
            "SUCCESSFUL_TRANSFER"
        );
    }

    /// Each node reports in its own group (TS 29.338 clauses 5.3.3.15 to
    /// 5.3.3.18): 3317 MME, 3318 MSC, 3319 SGSN, 3320 IP-SM-GW. The group
    /// header is written out by hand, V and M bits, vendor 10415, and holds
    /// the 16-octet SM-Delivery-Cause.
    #[test]
    fn rsr_reports_in_the_group_of_the_node_it_was_delivered_through() {
        for (node, code_low_octet) in [
            (SmDeliveryNode::Mme, 0xf5),
            (SmDeliveryNode::Msc, 0xf6),
            (SmDeliveryNode::Sgsn, 0xf7),
            (SmDeliveryNode::IpSmGw, 0xf8),
        ] {
            let outcome =
                SmDeliveryOutcome::new(node, SmDeliveryCause::SuccessfulTransfer, None).unwrap();
            let expected = [
                0x00,
                0x00,
                0x0c,
                0xf4,
                0xc0,
                0x00,
                0x00,
                0x28,
                0x00,
                0x00,
                0x28,
                0xaf, // 3316, 40
                0x00,
                0x00,
                0x0c,
                code_low_octet,
                0xc0,
                0x00,
                0x00,
                0x1c,
                0x00,
                0x00,
                0x28,
                0xaf, // the node's group, 28
                0x00,
                0x00,
                0x0c,
                0xf9,
                0xc0,
                0x00,
                0x00,
                0x10,
                0x00,
                0x00,
                0x28,
                0xaf, // 3321, 16
                0x00,
                0x00,
                0x00,
                0x02,
            ];
            assert!(contains(&rsr(&outcome), &expected), "{node}");
        }
    }

    /// Absent-User-Diagnostic-SM (3322, clause 5.3.3.20) follows the cause
    /// inside the node's group, which grows by its 16 octets.
    #[test]
    fn rsr_carries_the_absent_user_diagnostic_beside_the_cause() {
        let outcome =
            SmDeliveryOutcome::new(SmDeliveryNode::Sgsn, SmDeliveryCause::AbsentUser, Some(6))
                .unwrap();
        let expected = [
            0x00, 0x00, 0x0c, 0xf4, 0xc0, 0x00, 0x00, 0x38, 0x00, 0x00, 0x28,
            0xaf, // 3316, 56
            0x00, 0x00, 0x0c, 0xf7, 0xc0, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x28,
            0xaf, // 3319, 44
            0x00, 0x00, 0x0c, 0xf9, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28,
            0xaf, // 3321, 16
            0x00, 0x00, 0x00, 0x01, // ABSENT_USER
            0x00, 0x00, 0x0c, 0xfa, 0xc0, 0x00, 0x00, 0x10, 0x00, 0x00, 0x28,
            0xaf, // 3322, 16
            0x00, 0x00, 0x00, 0x06, // GPRS detached
        ];
        assert!(contains(&rsr(&outcome), &expected));

        let decoded = codec::decode_diameter(&rsr(&outcome)).unwrap();
        let group = &decoded.avps["SM-Delivery-Outcome"]["SGSN-SM-Delivery-Outcome"];
        assert_eq!(group["SM-Delivery-Cause"].as_u64(), Some(1));
        assert_eq!(group["Absent-User-Diagnostic-SM"].as_u64(), Some(6));
        assert!(decoded.avps["SM-Delivery-Outcome"]
            .get("MME-SM-Delivery-Outcome")
            .is_none());
    }

    #[test]
    fn a_diagnostic_is_refused_unless_the_user_was_absent() {
        for cause in [
            SmDeliveryCause::SuccessfulTransfer,
            SmDeliveryCause::UeMemoryCapacityExceeded,
        ] {
            assert_eq!(
                SmDeliveryOutcome::new(SmDeliveryNode::Mme, cause, Some(1)),
                Err(DiagnosticWithoutAbsentUser(cause))
            );
        }
        assert_eq!(
            DiagnosticWithoutAbsentUser(SmDeliveryCause::SuccessfulTransfer).to_string(),
            "an absent user diagnostic accompanies ABSENT_USER only, not SUCCESSFUL_TRANSFER"
        );
        assert!(
            SmDeliveryOutcome::new(SmDeliveryNode::Mme, SmDeliveryCause::AbsentUser, Some(1))
                .is_ok()
        );
    }

    #[test]
    fn node_names_map_to_nodes_and_their_groups() {
        for (name, node, code) in [
            ("mme", SmDeliveryNode::Mme, 3317),
            ("msc", SmDeliveryNode::Msc, 3318),
            ("sgsn", SmDeliveryNode::Sgsn, 3319),
            ("ip_sm_gw", SmDeliveryNode::IpSmGw, 3320),
        ] {
            assert_eq!(SmDeliveryNode::from_script_name(name), Some(node));
            assert_eq!(
                SmDeliveryNode::from_script_name(&name.to_ascii_uppercase()),
                Some(node)
            );
            assert_eq!(node.outcome_avp(), code);
            assert_eq!(node.to_string(), name);
        }
        for unknown in ["", "smsf", "ip-sm-gw", "mme "] {
            assert_eq!(
                SmDeliveryNode::from_script_name(unknown),
                None,
                "{unknown:?}"
            );
        }
    }

    #[test]
    fn script_arguments_become_an_outcome_or_name_what_is_wrong() {
        assert_eq!(
            SmDeliveryOutcome::from_script(0, "mme", None),
            Ok(through_the_mme(SmDeliveryCause::SuccessfulTransfer))
        );
        assert_eq!(
            SmDeliveryOutcome::from_script(1, "ip_sm_gw", Some(12)),
            Ok(SmDeliveryOutcome::new(
                SmDeliveryNode::IpSmGw,
                SmDeliveryCause::AbsentUser,
                Some(12)
            )
            .unwrap())
        );
        assert!(SmDeliveryOutcome::from_script(3, "mme", None)
            .unwrap_err()
            .starts_with("invalid delivery_outcome: 3"));
        assert!(SmDeliveryOutcome::from_script(0, "smsf", None)
            .unwrap_err()
            .starts_with("invalid node: \"smsf\""));
        assert!(SmDeliveryOutcome::from_script(0, "mme", Some(1))
            .unwrap_err()
            .starts_with("absent_user_diagnostic is only sent with delivery_outcome 1"));
    }

    /// The outcomes [`emit_rsr_for_external_dissection`] writes, in order;
    /// `scripts/validate_s6c_rsr.sh` expects exactly these.
    fn outcomes_for_external_dissection() -> Vec<SmDeliveryOutcome> {
        let outcome =
            |node, cause, diagnostic| SmDeliveryOutcome::new(node, cause, diagnostic).unwrap();
        vec![
            through_the_mme(SmDeliveryCause::UeMemoryCapacityExceeded),
            through_the_mme(SmDeliveryCause::AbsentUser),
            through_the_mme(SmDeliveryCause::SuccessfulTransfer),
            outcome(SmDeliveryNode::Msc, SmDeliveryCause::AbsentUser, Some(1)),
            outcome(SmDeliveryNode::Sgsn, SmDeliveryCause::AbsentUser, Some(6)),
            outcome(
                SmDeliveryNode::IpSmGw,
                SmDeliveryCause::AbsentUser,
                Some(12),
            ),
            outcome(
                SmDeliveryNode::Sgsn,
                SmDeliveryCause::SuccessfulTransfer,
                None,
            ),
        ]
    }

    /// Emit one RSR per outcome as hex for [`scripts/validate_s6c_rsr.sh`] to
    /// feed to tshark.
    ///
    /// The known-answer tests pin bytes we chose, so they share whatever we
    /// misread of TS 29.338. tshark decodes the same bytes with its own
    /// dictionary.
    #[test]
    fn emit_rsr_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_S6C_RSR_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };

        // `text2pcap`'s hex-dump form: an offset, then the octets. An offset
        // of zero starts the next packet.
        let mut dump = String::new();
        for outcome in outcomes_for_external_dissection() {
            for (offset, chunk) in rsr(&outcome).chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
            dump.push('\n');
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }

    /// Emit an SRR, an RSR and an SGd MT-Forward-Short-Message request as hex
    /// for [`scripts/validate_diameter_sms_addresses.sh`] to feed to tshark,
    /// which reads the MSISDN and the SC-Address with its own dissector. The
    /// MSISDN is one whose first octet has its top bit set.
    #[test]
    fn emit_sms_addresses_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_SMS_ADDRESSES_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };
        let packets = [
            build_send_routing_info_request(
                &config(),
                "smsc.example.com;1;1",
                "19995550100",
                "31611111111",
                Some(0),
                1,
                1,
            ),
            rsr(&through_the_mme(SmDeliveryCause::SuccessfulTransfer)),
            crate::diameter::sgd::build_mt_forward_short_message_request(
                &config(),
                "smsc.example.com;1;2",
                "001010000000001",
                "31611111111",
                // An SMS-DELIVER from 31612345678 saying "hi" (TS 23.040).
                &[
                    0x04, 0x0b, 0x91, 0x13, 0x16, 0x32, 0x54, 0x76, 0xf8, 0x00, 0x00, 0x62, 0x01,
                    0x01, 0x21, 0x00, 0x00, 0x00, 0x02, 0xe8, 0x34,
                ],
                None,
                Some(0),
                None,
                2,
                2,
            ),
        ];

        // `text2pcap`'s hex-dump form: an offset, then the octets. An offset
        // of zero starts the next packet.
        let mut dump = String::new();
        for packet in packets {
            for (offset, chunk) in packet.chunks(16).enumerate() {
                dump.push_str(&format!("{:06x}", offset * 16));
                for byte in chunk {
                    dump.push_str(&format!(" {byte:02x}"));
                }
                dump.push('\n');
            }
            dump.push('\n');
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }
}
