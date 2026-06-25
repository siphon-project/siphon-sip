//! ASN.1/BER codec for ETSI TS 102 232 IRI-PDU and CC-PDU.
//!
//! Implements the ETSI LI ASN.1 schema using the `rasn` crate:
//! - PS-PDU (Packet-Switched PDU) — top-level envelope (TS 102 232-1)
//! - IRI-PDU — Intercept Related Information for VoIP (TS 102 232-5)
//! - CC-PDU — Content of Communication (TS 102 232-1)
//!
//! All types derive `AsnType`, `Encode`, `Decode` for full BER roundtrip.

use rasn::prelude::*;
use std::time::SystemTime;

// Re-export chrono (transitive dep of rasn) for GeneralizedTime construction.
use chrono::TimeZone;

// ---------------------------------------------------------------------------
// ETSI TS 102 232-1: PS-PDU envelope
// ---------------------------------------------------------------------------

/// PS-PDU — the outermost envelope sent over X2/X3 TCP connections.
///
/// Per TS 102 232-1 §5: version + pduType + payload.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct PsPdu {
    /// Protocol version (always 1).
    #[rasn(tag(explicit(context, 0)))]
    pub version: Integer,
    /// PDU type: 1 = IRI, 2 = CC.
    #[rasn(tag(explicit(context, 1)))]
    pub pdu_type: Integer,
    /// Inner payload (BER-encoded IRI-PDU or CC-PDU).
    #[rasn(tag(explicit(context, 2)))]
    pub payload: OctetString,
}

// ---------------------------------------------------------------------------
// ETSI TS 102 232-5: IRI types for VoIP
// ---------------------------------------------------------------------------

/// IRI event type per TS 102 232-5 §5.
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum IriType {
    Begin = 1,
    Continue = 2,
    End = 3,
    Report = 4,
}

/// Party qualifier — originating vs terminating party.
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum PartyQualifier {
    Originating = 0,
    Terminating = 1,
}

/// Payload direction for CC-PDU.
#[derive(AsnType, Encode, Decode, Debug, Clone, Copy, PartialEq, Eq)]
#[rasn(enumerated)]
pub enum PayloadDirection {
    FromTarget = 0,
    ToTarget = 1,
    Unknown = 2,
}

/// Party identity — SIP URI, tel URI, or IP address.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct PartyIdentity {
    #[rasn(tag(explicit(context, 0)))]
    pub sip_uri: Option<Utf8String>,
    #[rasn(tag(explicit(context, 1)))]
    pub tel_uri: Option<Utf8String>,
    #[rasn(tag(explicit(context, 2)))]
    pub ip_address: Option<OctetString>,
}

/// Party information — qualifier + identity.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct PartyInformation {
    #[rasn(tag(explicit(context, 0)))]
    pub party_qualifier: PartyQualifier,
    #[rasn(tag(explicit(context, 1)))]
    pub party_identity: PartyIdentity,
}

/// Communication identity — correlation ID + optional network identifier.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct CommunicationIdentity {
    /// Correlation ID (typically Call-ID).
    #[rasn(tag(explicit(context, 0)))]
    pub communication_identity_number: OctetString,
    /// Network identifier (optional).
    #[rasn(tag(explicit(context, 1)))]
    pub network_identifier: Option<OctetString>,
}

/// IRI payload per TS 102 232-5 — VoIP intercept related information.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct IriPayload {
    /// IRI event type (begin/continue/end/report).
    #[rasn(tag(explicit(context, 0)))]
    pub iri_type: IriType,
    /// Lawful interception identifier (LIID).
    #[rasn(tag(explicit(context, 1)))]
    pub lawful_interception_identifier: OctetString,
    /// Communication identity (correlation).
    #[rasn(tag(explicit(context, 2)))]
    pub communication_identity: CommunicationIdentity,
    /// Timestamp of the event.
    #[rasn(tag(explicit(context, 3)))]
    pub timestamp: GeneralizedTime,
    /// SIP method (INVITE, BYE, etc.).
    #[rasn(tag(explicit(context, 4)))]
    pub sip_method: Utf8String,
    /// SIP status code (for responses).
    #[rasn(tag(explicit(context, 5)))]
    pub status_code: Option<Integer>,
    /// Originating party information.
    #[rasn(tag(explicit(context, 6)))]
    pub originating_party: PartyInformation,
    /// Terminating party information.
    #[rasn(tag(explicit(context, 7)))]
    pub terminating_party: PartyInformation,
    /// Request-URI (for requests).
    #[rasn(tag(explicit(context, 8)))]
    pub request_uri: Option<Utf8String>,
    /// Raw SIP message (full signaling capture).
    #[rasn(tag(explicit(context, 9)))]
    pub sip_message: Option<OctetString>,
}

/// CC payload per TS 102 232-1 — content of communication.
#[derive(AsnType, Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[rasn(tag(universal, 16))] // SEQUENCE
pub struct CcPayload {
    /// Lawful interception identifier (LIID).
    #[rasn(tag(explicit(context, 0)))]
    pub lawful_interception_identifier: OctetString,
    /// Communication identity (correlation).
    #[rasn(tag(explicit(context, 1)))]
    pub communication_identity: CommunicationIdentity,
    /// Timestamp.
    #[rasn(tag(explicit(context, 2)))]
    pub timestamp: GeneralizedTime,
    /// Payload direction.
    #[rasn(tag(explicit(context, 3)))]
    pub payload_direction: PayloadDirection,
    /// CC contents (raw IP/RTP packet).
    #[rasn(tag(explicit(context, 4)))]
    pub cc_contents: OctetString,
}

// ---------------------------------------------------------------------------
// Encoding helpers — public API
// ---------------------------------------------------------------------------

/// Encode an IRI-PDU per ETSI TS 102 232-5, wrapped in a PS-PDU envelope.
pub fn encode_iri_pdu(
    liid: &str,
    correlation_id: &str,
    iri_type: IriType,
    timestamp: SystemTime,
    sip_method: &str,
    status_code: Option<u16>,
    from_uri: &str,
    to_uri: &str,
    request_uri: Option<&str>,
    raw_sip_message: Option<&[u8]>,
) -> Vec<u8> {
    let iri = IriPayload {
        iri_type,
        lawful_interception_identifier: OctetString::from(liid.as_bytes().to_vec()),
        communication_identity: CommunicationIdentity {
            communication_identity_number: OctetString::from(
                correlation_id.as_bytes().to_vec(),
            ),
            network_identifier: None,
        },
        timestamp: system_time_to_generalized(timestamp),
        sip_method: Utf8String::from(sip_method),
        status_code: status_code.map(|code| Integer::from(code as i64)),
        originating_party: PartyInformation {
            party_qualifier: PartyQualifier::Originating,
            party_identity: PartyIdentity {
                sip_uri: Some(Utf8String::from(from_uri)),
                tel_uri: None,
                ip_address: None,
            },
        },
        terminating_party: PartyInformation {
            party_qualifier: PartyQualifier::Terminating,
            party_identity: PartyIdentity {
                sip_uri: Some(Utf8String::from(to_uri)),
                tel_uri: None,
                ip_address: None,
            },
        },
        request_uri: request_uri.map(Utf8String::from),
        sip_message: raw_sip_message.map(|raw| OctetString::from(raw.to_vec())),
    };

    let iri_bytes = match rasn::ber::encode(&iri) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!("IRI-PDU encoding failed: {error}");
            return Vec::new();
        }
    };

    let ps_pdu = PsPdu {
        version: Integer::from(1),
        pdu_type: Integer::from(1), // IRI
        payload: OctetString::from(iri_bytes),
    };

    match rasn::ber::encode(&ps_pdu) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!("PS-PDU encoding failed: {error}");
            Vec::new()
        }
    }
}

/// Encode a CC-PDU per ETSI TS 102 232-1, wrapped in a PS-PDU envelope.
pub fn encode_cc_pdu(
    liid: &str,
    correlation_id: &str,
    timestamp: SystemTime,
    payload: &[u8],
) -> Vec<u8> {
    let cc = CcPayload {
        lawful_interception_identifier: OctetString::from(liid.as_bytes().to_vec()),
        communication_identity: CommunicationIdentity {
            communication_identity_number: OctetString::from(
                correlation_id.as_bytes().to_vec(),
            ),
            network_identifier: None,
        },
        timestamp: system_time_to_generalized(timestamp),
        payload_direction: PayloadDirection::Unknown,
        cc_contents: OctetString::from(payload.to_vec()),
    };

    let cc_bytes = match rasn::ber::encode(&cc) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!("CC-PDU encoding failed: {error}");
            return Vec::new();
        }
    };

    let ps_pdu = PsPdu {
        version: Integer::from(1),
        pdu_type: Integer::from(2), // CC
        payload: OctetString::from(cc_bytes),
    };

    match rasn::ber::encode(&ps_pdu) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::error!("PS-PDU encoding failed: {error}");
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// Decoding helpers — public API
// ---------------------------------------------------------------------------

/// Decode a PS-PDU envelope, returning (version, pdu_type, inner_payload).
///
/// The inner_payload is the raw BER bytes of the IRI-PDU or CC-PDU,
/// which can be further decoded with `decode_iri_payload()` or `decode_cc_payload()`.
pub fn decode_ps_pdu(data: &[u8]) -> Option<(u8, u8, Vec<u8>)> {
    let ps_pdu: PsPdu = rasn::ber::decode(data).ok()?;

    let version = u8::try_from(&ps_pdu.version).ok()?;
    let pdu_type = u8::try_from(&ps_pdu.pdu_type).ok()?;

    Some((version, pdu_type, ps_pdu.payload.to_vec()))
}

/// Decode an IRI payload from BER bytes (the inner payload from a PS-PDU with pdu_type=1).
pub fn decode_iri_payload(data: &[u8]) -> Option<IriPayload> {
    rasn::ber::decode(data).ok()
}

/// Decode a CC payload from BER bytes (the inner payload from a PS-PDU with pdu_type=2).
pub fn decode_cc_payload(data: &[u8]) -> Option<CcPayload> {
    rasn::ber::decode(data).ok()
}

// ---------------------------------------------------------------------------
// Time conversion
// ---------------------------------------------------------------------------

/// Convert `SystemTime` to `rasn::types::GeneralizedTime` (chrono DateTime).
fn system_time_to_generalized(timestamp: SystemTime) -> GeneralizedTime {
    let duration = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs() as i64;
    let nanos = duration.subsec_nanos();
    chrono::Utc
        .timestamp_opt(secs, nanos)
        .single()
        .unwrap_or(chrono::DateTime::UNIX_EPOCH)
        .fixed_offset()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_iri_pdu_roundtrip() {
        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let encoded = encode_iri_pdu(
            "LI-001",
            "call-123@example.com",
            IriType::Begin,
            timestamp,
            "INVITE",
            None,
            "sip:alice@example.com",
            "sip:bob@example.com",
            Some("sip:bob@example.com"),
            None,
        );

        // Decode PS-PDU envelope
        let (version, pdu_type, inner) = decode_ps_pdu(&encoded).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 1); // IRI

        // Decode inner IRI payload
        let iri = decode_iri_payload(&inner).unwrap();
        assert_eq!(iri.iri_type, IriType::Begin);
        assert_eq!(
            iri.lawful_interception_identifier.as_ref(),
            b"LI-001"
        );
        assert_eq!(
            iri.communication_identity.communication_identity_number.as_ref(),
            b"call-123@example.com"
        );
        assert_eq!(
            iri.sip_method,
            Utf8String::from("INVITE")
        );
        assert!(iri.status_code.is_none());

        // Verify party information
        assert_eq!(iri.originating_party.party_qualifier, PartyQualifier::Originating);
        assert_eq!(
            iri.originating_party.party_identity.sip_uri.as_ref().unwrap(),
            &Utf8String::from("sip:alice@example.com")
        );
        assert_eq!(iri.terminating_party.party_qualifier, PartyQualifier::Terminating);
        assert_eq!(
            iri.terminating_party.party_identity.sip_uri.as_ref().unwrap(),
            &Utf8String::from("sip:bob@example.com")
        );

        // Verify request URI
        assert_eq!(
            iri.request_uri.as_ref().unwrap(),
            &Utf8String::from("sip:bob@example.com")
        );
    }

    #[test]
    fn encode_decode_cc_pdu_roundtrip() {
        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let rtp_payload = vec![0x80, 0x00, 0x01, 0x02, 0x03]; // fake RTP

        let encoded = encode_cc_pdu(
            "LI-001",
            "call-123@example.com",
            timestamp,
            &rtp_payload,
        );

        let (version, pdu_type, inner) = decode_ps_pdu(&encoded).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 2); // CC

        // Decode inner CC payload
        let cc = decode_cc_payload(&inner).unwrap();
        assert_eq!(
            cc.lawful_interception_identifier.as_ref(),
            b"LI-001"
        );
        assert_eq!(
            cc.communication_identity.communication_identity_number.as_ref(),
            b"call-123@example.com"
        );
        assert_eq!(cc.payload_direction, PayloadDirection::Unknown);
        assert_eq!(cc.cc_contents.as_ref(), &rtp_payload);
    }

    #[test]
    fn iri_with_status_code() {
        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let encoded = encode_iri_pdu(
            "LI-002",
            "call-456@example.com",
            IriType::End,
            timestamp,
            "BYE",
            Some(200),
            "sip:alice@example.com",
            "sip:bob@example.com",
            None,
            None,
        );

        let (version, pdu_type, inner) = decode_ps_pdu(&encoded).unwrap();
        assert_eq!(version, 1);
        assert_eq!(pdu_type, 1);

        let iri = decode_iri_payload(&inner).unwrap();
        assert_eq!(iri.iri_type, IriType::End);
        assert_eq!(
            iri.status_code.as_ref().unwrap(),
            &Integer::from(200)
        );
    }

    #[test]
    fn iri_with_raw_sip_message() {
        let timestamp = SystemTime::now();
        let raw_sip = b"INVITE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP pc33.atlanta.com\r\n\r\n";

        let encoded = encode_iri_pdu(
            "LI-003",
            "call-789@example.com",
            IriType::Report,
            timestamp,
            "INVITE",
            None,
            "sip:alice@example.com",
            "sip:bob@example.com",
            Some("sip:bob@example.com"),
            Some(raw_sip),
        );

        let (_, _, inner) = decode_ps_pdu(&encoded).unwrap();
        let iri = decode_iri_payload(&inner).unwrap();
        assert_eq!(iri.sip_message.as_ref().unwrap().as_ref(), raw_sip);
    }

    #[test]
    fn all_iri_types_roundtrip() {
        let timestamp = SystemTime::now();
        for iri_type in [IriType::Begin, IriType::Continue, IriType::End, IriType::Report] {
            let encoded = encode_iri_pdu(
                "LI-ALL",
                "call-all@example.com",
                iri_type,
                timestamp,
                "INVITE",
                None,
                "sip:a@example.com",
                "sip:b@example.com",
                None,
                None,
            );
            let (_, _, inner) = decode_ps_pdu(&encoded).unwrap();
            let iri = decode_iri_payload(&inner).unwrap();
            assert_eq!(iri.iri_type, iri_type);
        }
    }

    #[test]
    fn generalized_time_roundtrip() {
        // Verify that a known timestamp encodes/decodes correctly
        let timestamp = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let gt = system_time_to_generalized(timestamp);
        // 2023-11-14T22:13:20Z
        assert_eq!(gt.format("%Y%m%d%H%M%S").to_string(), "20231114221320");
    }

    #[test]
    fn cc_pdu_preserves_payload_bytes() {
        let payload = (0..255u8).collect::<Vec<u8>>();
        let encoded = encode_cc_pdu("LI-BIN", "corr-1", SystemTime::now(), &payload);
        let (_, _, inner) = decode_ps_pdu(&encoded).unwrap();
        let cc = decode_cc_payload(&inner).unwrap();
        assert_eq!(cc.cc_contents.as_ref(), &payload);
    }

    #[test]
    fn ps_pdu_decode_rejects_garbage() {
        assert!(decode_ps_pdu(b"").is_none());
        assert!(decode_ps_pdu(b"\x00\x00").is_none());
        assert!(decode_ps_pdu(b"not BER at all").is_none());
    }
}
