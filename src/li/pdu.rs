//! X2/X3 PDU framing — ETSI TS 103 221-2 clause 5.
//!
//! The network element delivers over two interfaces, and they are not the same
//! shape as the ones further downstream. X2 carries signalling and X3 carries
//! content, both from the NE to the Mediation and Delivery Function, both in
//! the PDU defined here. TS 102 232 — which [`super::asn1`] encodes — is the
//! *handover* format the MDF emits onwards to the LEMF, so an NE that speaks it
//! on X2 is speaking a peer's language on its own interface.
//!
//! The PDU is a fixed 40-octet mandatory header, then a run of conditional
//! attribute TLVs, then the payload:
//!
//! ```text
//! octet  0        1        2        3
//!      +--------+--------+--------+--------+
//!    0 | major  | minor  |    PDU type     |
//!      +--------+--------+--------+--------+
//!    4 |          header length            |
//!      +--------+--------+--------+--------+
//!    8 |          payload length           |
//!      +--------+--------+--------+--------+
//!   12 | payload format  |    direction    |
//!      +--------+--------+--------+--------+
//!   16 |         XID (16 octets)           |
//!      +--------+--------+--------+--------+
//!   32 |   correlation ID (8 octets)       |
//!      +--------+--------+--------+--------+
//!   40 | conditional attribute TLVs ...    |
//!      +--------+--------+--------+--------+
//!      | payload ...                       |
//!      +--------+--------+--------+--------+
//! ```
//!
//! `header length` counts the mandatory header *and* the attributes, so it is
//! 40 when there are none. Every multi-octet field is network byte order.

use std::net::IpAddr;
use std::time::SystemTime;

/// Major version of the PDU format (clause 5.2.1). Fixed at 0.
pub const MAJOR_VERSION: u8 = 0;

/// Minor version of the PDU format (clause 5.2.1).
///
/// 5 is what TS 103 221-2 v1.x specifies, and a peer rejects anything else
/// outright, so it is a constant rather than a setting.
pub const MINOR_VERSION: u8 = 5;

/// Octets in the mandatory header, before any conditional attributes.
pub const MANDATORY_HEADER_LENGTH: u32 = 40;

/// Which interface a PDU belongs to (clause 5.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    /// Signalling — the X2 interface.
    X2 = 1,
    /// Content of communication — the X3 interface.
    X3 = 2,
    /// Idle-connection keepalive.
    Keepalive = 3,
    /// Response to a keepalive.
    KeepaliveAck = 4,
}

/// What the payload contains (clause 5.2.5).
///
/// Each format is permitted on some interfaces and not others; [`
/// PayloadFormat::allowed_on`] encodes that so a caller cannot frame, say, RTP
/// as X2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// ETSI TS 102 232-1 defined payload.
    Etsi102232 = 1,
    /// 3GPP TS 33.128 defined payload.
    ThreeGpp33128 = 2,
    /// 3GPP TS 33.108 defined payload.
    ThreeGpp33108 = 3,
    /// Vendor-defined.
    Proprietary = 4,
    /// A complete IPv4 packet.
    IpV4 = 5,
    /// A complete IPv6 packet.
    IpV6 = 6,
    /// An Ethernet frame.
    Ethernet = 7,
    /// An RTP packet.
    Rtp = 8,
    /// A SIP message, as it appeared on the wire.
    Sip = 9,
    /// A DHCP message.
    Dhcp = 10,
    /// A RADIUS message.
    Radius = 11,
    /// A GTP-U packet.
    GtpU = 12,
    /// An MSRP message.
    Msrp = 13,
    /// 3GPP TS 33.108 EPS IRI content.
    ThreeGpp33108EpsIri = 14,
    /// A MIME entity.
    Mime = 15,
    /// A 3GPP unstructured PDU.
    ThreeGppUnstructured = 16,
}

impl PayloadFormat {
    /// Whether this format may be carried on the given interface.
    ///
    /// Clause 5.2.5's table is not symmetric — SIP is signalling and never
    /// content, RTP is content and never signalling — and a peer refuses the
    /// combination rather than ignoring it.
    pub fn allowed_on(self, pdu_type: PduType) -> bool {
        match pdu_type {
            PduType::X2 => !matches!(
                self,
                PayloadFormat::Ethernet
                    | PayloadFormat::Rtp
                    | PayloadFormat::GtpU
                    | PayloadFormat::Msrp
                    | PayloadFormat::ThreeGppUnstructured
            ),
            PduType::X3 => !matches!(
                self,
                PayloadFormat::Sip
                    | PayloadFormat::Dhcp
                    | PayloadFormat::Radius
                    | PayloadFormat::ThreeGpp33108EpsIri
            ),
            // Keepalives carry no payload, so no format is meaningful.
            PduType::Keepalive | PduType::KeepaliveAck => false,
        }
    }
}

/// The payload's direction relative to the *target* (clause 5.2.6).
///
/// Target-relative, not network-relative: the same message is "to target" or
/// "from target" depending on which party the warrant names, which is why this
/// is derived from the match and not from the socket the bytes arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadDirection {
    /// Reserved; the value keepalive PDUs carry.
    ReservedForKeepalive = 0,
    /// Direction could not be determined.
    Unknown = 1,
    /// Travelling towards the target.
    SentToTarget = 2,
    /// Originated by the target.
    SentFromTarget = 3,
    /// Multiple directions in one payload.
    MoreThanOneDirection = 4,
    /// Direction is not a meaningful notion for this payload.
    NotApplicable = 5,
}

/// Conditional attribute type codes (clause 5.3).
pub mod attribute_type {
    /// ETSI TS 102 232-1 defined attribute.
    pub const ETSI_102_232_1: u16 = 1;
    /// 3GPP TS 33.128 defined attribute.
    pub const THREE_GPP_33_128: u16 = 2;
    /// ETSI TS 133 108 defined attribute.
    pub const ETSI_133_108: u16 = 3;
    /// Vendor-defined attribute.
    pub const PROPRIETARY: u16 = 4;
    /// Domain ID (DID).
    pub const DOMAIN_ID: u16 = 5;
    /// Network Function ID (NFID).
    pub const NETWORK_FUNCTION_ID: u16 = 6;
    /// Interception Point ID (IPID).
    pub const INTERCEPTION_POINT_ID: u16 = 7;
    /// Per-stream sequence number.
    pub const SEQUENCE_NUMBER: u16 = 8;
    /// Capture timestamp.
    pub const TIMESTAMP: u16 = 9;
    /// Source IPv4 address.
    pub const SOURCE_IPV4: u16 = 10;
    /// Destination IPv4 address.
    pub const DESTINATION_IPV4: u16 = 11;
    /// Source IPv6 address.
    pub const SOURCE_IPV6: u16 = 12;
    /// Destination IPv6 address.
    pub const DESTINATION_IPV6: u16 = 13;
    /// Source port.
    pub const SOURCE_PORT: u16 = 14;
    /// Destination port.
    pub const DESTINATION_PORT: u16 = 15;
    /// IP protocol number.
    pub const IP_PROTOCOL: u16 = 16;
    /// The target identifier the traffic matched.
    pub const MATCHED_TARGET_IDENTIFIER: u16 = 17;
    /// A further target identifier seen in the traffic.
    pub const OTHER_TARGET_IDENTIFIER: u16 = 18;
}

/// One conditional attribute, ready to serialise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    /// Type code from [`attribute_type`].
    pub attribute_type: u16,
    /// Value octets, already in the encoding clause 5.3 gives for the type.
    pub value: Vec<u8>,
}

impl Attribute {
    /// An attribute with an arbitrary value.
    pub fn raw(attribute_type: u16, value: impl Into<Vec<u8>>) -> Self {
        Self {
            attribute_type,
            value: value.into(),
        }
    }

    /// A text-valued attribute (NFID, IPID, target identifiers).
    pub fn text(attribute_type: u16, value: &str) -> Self {
        Self::raw(attribute_type, value.as_bytes().to_vec())
    }

    /// The timestamp attribute: seconds then nanoseconds, both 32-bit.
    ///
    /// A time before the epoch cannot be represented, and is clamped to the
    /// epoch rather than wrapping into the far future — an obviously-wrong
    /// timestamp on a lawful-intercept record beats a plausibly-wrong one.
    pub fn timestamp(at: SystemTime) -> Self {
        let since_epoch = at
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let mut value = Vec::with_capacity(8);
        // Seconds is a 32-bit field, so this is the format's own 2106 limit,
        // not a narrowing we chose.
        let seconds = u32::try_from(since_epoch.as_secs()).unwrap_or(u32::MAX);
        value.extend_from_slice(&seconds.to_be_bytes());
        value.extend_from_slice(&since_epoch.subsec_nanos().to_be_bytes());
        Self::raw(attribute_type::TIMESTAMP, value)
    }

    /// The sequence-number attribute.
    pub fn sequence_number(sequence: u32) -> Self {
        Self::raw(
            attribute_type::SEQUENCE_NUMBER,
            sequence.to_be_bytes().to_vec(),
        )
    }

    /// The source-address attribute matching the address family.
    pub fn source_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(v4) => Self::raw(attribute_type::SOURCE_IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => Self::raw(attribute_type::SOURCE_IPV6, v6.octets().to_vec()),
        }
    }

    /// The destination-address attribute matching the address family.
    pub fn destination_address(address: IpAddr) -> Self {
        match address {
            IpAddr::V4(v4) => Self::raw(attribute_type::DESTINATION_IPV4, v4.octets().to_vec()),
            IpAddr::V6(v6) => Self::raw(attribute_type::DESTINATION_IPV6, v6.octets().to_vec()),
        }
    }

    /// Octets this attribute occupies once serialised, TLV header included.
    fn encoded_length(&self) -> usize {
        4 + self.value.len()
    }

    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.attribute_type.to_be_bytes());
        // Clause 5.3 gives the length field two octets. An over-long value is
        // refused in `Pdu::encode`, before anything reaches here, because
        // truncating it silently would corrupt the stream for every following
        // PDU rather than just this one.
        let length = u16::try_from(self.value.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.value);
    }
}

/// A PDU that could not be built as specified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduError {
    /// The payload format is not permitted on this interface (clause 5.2.5).
    FormatNotAllowed {
        /// The offending format.
        format: PayloadFormat,
        /// The interface it was offered on.
        pdu_type: PduType,
    },
    /// An attribute value exceeds the two-octet length field.
    AttributeTooLong {
        /// Type code of the offending attribute.
        attribute_type: u16,
        /// Its length in octets.
        length: usize,
    },
    /// The payload exceeds the four-octet length field.
    PayloadTooLong {
        /// Its length in octets.
        length: usize,
    },
}

impl std::fmt::Display for PduError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PduError::FormatNotAllowed { format, pdu_type } => write!(
                formatter,
                "payload format {format:?} is not permitted on {pdu_type:?}"
            ),
            PduError::AttributeTooLong {
                attribute_type,
                length,
            } => write!(
                formatter,
                "conditional attribute {attribute_type} is {length} octets, over the 65535 its length field holds"
            ),
            PduError::PayloadTooLong { length } => write!(
                formatter,
                "payload is {length} octets, over what its length field holds"
            ),
        }
    }
}

impl std::error::Error for PduError {}

/// An X2 or X3 PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    /// Which interface this belongs to.
    pub pdu_type: PduType,
    /// What the payload holds.
    pub payload_format: PayloadFormat,
    /// Direction relative to the target.
    pub payload_direction: PayloadDirection,
    /// The task identifier, as 16 raw octets.
    pub x_id: [u8; 16],
    /// The session correlation, as 8 raw octets.
    pub correlation_id: [u8; 8],
    /// Conditional attributes, in the order they should appear.
    pub attributes: Vec<Attribute>,
    /// The payload itself.
    pub payload: Vec<u8>,
}

impl Pdu {
    /// Serialise to the wire.
    ///
    /// Refuses rather than emitting a PDU a conformant peer would reject: the
    /// element is strict in what it sends, because a malformed frame here does
    /// not merely lose one record — the receiver reads the next PDU's header
    /// from the middle of this one and the connection never recovers.
    pub fn encode(&self) -> Result<Vec<u8>, PduError> {
        // A keepalive carries no payload, so no format describes anything and
        // clause 5.2.5's table has nothing to say about it. Only the two
        // interfaces that carry data are checked against it.
        let carries_payload = matches!(self.pdu_type, PduType::X2 | PduType::X3);
        if carries_payload && !self.payload_format.allowed_on(self.pdu_type) {
            return Err(PduError::FormatNotAllowed {
                format: self.payload_format,
                pdu_type: self.pdu_type,
            });
        }
        for attribute in &self.attributes {
            if attribute.value.len() > usize::from(u16::MAX) {
                return Err(PduError::AttributeTooLong {
                    attribute_type: attribute.attribute_type,
                    length: attribute.value.len(),
                });
            }
        }
        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| PduError::PayloadTooLong {
                length: self.payload.len(),
            })?;

        let attributes_length: usize = self.attributes.iter().map(Attribute::encoded_length).sum();
        let header_length = MANDATORY_HEADER_LENGTH
            + u32::try_from(attributes_length).map_err(|_| PduError::PayloadTooLong {
                length: attributes_length,
            })?;

        let mut out = Vec::with_capacity(header_length as usize + self.payload.len());
        out.push(MAJOR_VERSION);
        out.push(MINOR_VERSION);
        out.extend_from_slice(&(self.pdu_type as u16).to_be_bytes());
        out.extend_from_slice(&header_length.to_be_bytes());
        out.extend_from_slice(&payload_length.to_be_bytes());
        out.extend_from_slice(&(self.payload_format as u16).to_be_bytes());
        out.extend_from_slice(&(self.payload_direction as u16).to_be_bytes());
        out.extend_from_slice(&self.x_id);
        out.extend_from_slice(&self.correlation_id);
        for attribute in &self.attributes {
            attribute.write_to(&mut out);
        }
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// A keepalive PDU for an idle delivery connection (clause 5.2.2).
    ///
    /// Carries no payload and no correlation: an all-zero correlation is
    /// reserved for exactly this, which is why a session's correlation is
    /// never allowed to be zero.
    pub fn keepalive(sequence: u32) -> Self {
        Self {
            pdu_type: PduType::Keepalive,
            // A keepalive has no payload to describe. The encoder never
            // consults the format table for this PDU type, so the value is
            // inert; it is here because the field exists.
            payload_format: PayloadFormat::Etsi102232,
            payload_direction: PayloadDirection::ReservedForKeepalive,
            x_id: [0u8; 16],
            correlation_id: [0u8; 8],
            attributes: vec![Attribute::sequence_number(sequence)],
            payload: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    fn sip_pdu() -> Pdu {
        Pdu {
            pdu_type: PduType::X2,
            payload_format: PayloadFormat::Sip,
            payload_direction: PayloadDirection::SentFromTarget,
            x_id: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            correlation_id: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            attributes: Vec::new(),
            payload: b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n".to_vec(),
        }
    }

    /// A hand-computed vector, byte for byte, from clause 5.2's field table.
    ///
    /// Written out rather than round-tripped: a decoder of our own would agree
    /// with whatever the encoder does, including a wrong field order, which is
    /// exactly the defect a round-trip cannot see.
    #[test]
    fn mandatory_header_matches_the_specified_octets() {
        let encoded = sip_pdu().encode().expect("well-formed PDU must encode");

        assert_eq!(&encoded[0..2], &[0x00, 0x05], "major/minor version");
        assert_eq!(&encoded[2..4], &[0x00, 0x01], "PDU type X2");
        assert_eq!(
            &encoded[4..8],
            &[0x00, 0x00, 0x00, 0x28],
            "header length 40"
        );
        assert_eq!(
            &encoded[8..12],
            &[0x00, 0x00, 0x00, 0x26],
            "payload length 38"
        );
        assert_eq!(&encoded[12..14], &[0x00, 0x09], "payload format SIP");
        assert_eq!(
            &encoded[14..16],
            &[0x00, 0x03],
            "direction sent-from-target"
        );
        assert_eq!(
            &encoded[16..32],
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ],
            "XID"
        );
        assert_eq!(
            &encoded[32..40],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            "correlation ID"
        );
        assert_eq!(
            &encoded[40..],
            b"INVITE sip:bob@example.com SIP/2.0\r\n\r\n",
            "payload follows the header immediately"
        );
        assert_eq!(encoded.len(), 40 + 38);
    }

    #[test]
    fn header_length_counts_the_attributes_too() {
        let mut pdu = sip_pdu();
        // 4 + 8 timestamp, 4 + 4 sequence number, 4 + 3 NFID = 27 octets.
        pdu.attributes = vec![
            Attribute::timestamp(
                SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
            ),
            Attribute::sequence_number(7),
            Attribute::text(attribute_type::NETWORK_FUNCTION_ID, "abc"),
        ];
        let encoded = pdu.encode().expect("well-formed PDU must encode");

        let header_length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(header_length, 40 + 27);
        // The payload starts where the header says it does, not 40 in.
        assert_eq!(&encoded[header_length as usize..], &pdu.payload[..]);
        assert_eq!(encoded.len(), header_length as usize + pdu.payload.len());
    }

    #[test]
    fn timestamp_attribute_is_seconds_then_nanoseconds() {
        let at = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789);
        let attribute = Attribute::timestamp(at);

        assert_eq!(attribute.attribute_type, 9);
        assert_eq!(attribute.value.len(), 8);
        assert_eq!(&attribute.value[0..4], &1_700_000_000u32.to_be_bytes());
        assert_eq!(&attribute.value[4..8], &123_456_789u32.to_be_bytes());
    }

    #[test]
    fn timestamp_before_the_epoch_clamps_rather_than_wrapping() {
        let attribute = Attribute::timestamp(SystemTime::UNIX_EPOCH - Duration::from_secs(60));
        assert_eq!(attribute.value, vec![0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn address_attributes_follow_the_family() {
        let v4 = Attribute::source_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(v4.attribute_type, attribute_type::SOURCE_IPV4);
        assert_eq!(v4.value, vec![192, 0, 2, 1]);

        let v6 = Attribute::destination_address(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(v6.attribute_type, attribute_type::DESTINATION_IPV6);
        assert_eq!(v6.value.len(), 16);
        assert_eq!(v6.value[15], 1);
    }

    #[test]
    fn attribute_tlv_is_type_length_value() {
        let mut pdu = sip_pdu();
        pdu.attributes = vec![Attribute::text(
            attribute_type::INTERCEPTION_POINT_ID,
            "ipid-1",
        )];
        let encoded = pdu.encode().expect("well-formed PDU must encode");

        assert_eq!(&encoded[40..42], &7u16.to_be_bytes(), "attribute type");
        assert_eq!(&encoded[42..44], &6u16.to_be_bytes(), "value length");
        assert_eq!(&encoded[44..50], b"ipid-1", "value");
    }

    /// Clause 5.2.5's table is not symmetric, and a peer enforces it.
    #[test]
    fn payload_format_is_refused_on_the_wrong_interface() {
        let mut pdu = sip_pdu();
        pdu.pdu_type = PduType::X3;
        assert_eq!(
            pdu.encode(),
            Err(PduError::FormatNotAllowed {
                format: PayloadFormat::Sip,
                pdu_type: PduType::X3,
            }),
            "SIP is signalling and must not frame as content"
        );

        let mut rtp = sip_pdu();
        rtp.payload_format = PayloadFormat::Rtp;
        assert!(
            rtp.encode().is_err(),
            "RTP is content and must not frame as X2"
        );

        rtp.pdu_type = PduType::X3;
        assert!(
            rtp.encode().is_ok(),
            "RTP on X3 is the permitted combination"
        );
    }

    #[test]
    fn format_table_matches_the_specified_values() {
        // Spot-checked against clause 5.2.5 rather than against our own reader.
        assert_eq!(PayloadFormat::Etsi102232 as u16, 1);
        assert_eq!(PayloadFormat::IpV4 as u16, 5);
        assert_eq!(PayloadFormat::Rtp as u16, 8);
        assert_eq!(PayloadFormat::Sip as u16, 9);
        assert_eq!(PayloadFormat::Mime as u16, 15);

        assert_eq!(PduType::X2 as u16, 1);
        assert_eq!(PduType::X3 as u16, 2);
        assert_eq!(PduType::Keepalive as u16, 3);
        assert_eq!(PduType::KeepaliveAck as u16, 4);

        assert_eq!(PayloadDirection::SentToTarget as u16, 2);
        assert_eq!(PayloadDirection::SentFromTarget as u16, 3);

        assert_eq!(attribute_type::DOMAIN_ID, 5);
        assert_eq!(attribute_type::NETWORK_FUNCTION_ID, 6);
        assert_eq!(attribute_type::INTERCEPTION_POINT_ID, 7);
        assert_eq!(attribute_type::SEQUENCE_NUMBER, 8);
        assert_eq!(attribute_type::TIMESTAMP, 9);
        assert_eq!(attribute_type::MATCHED_TARGET_IDENTIFIER, 17);
    }

    #[test]
    fn keepalive_carries_no_payload_and_a_zero_correlation() {
        let encoded = Pdu::keepalive(42).encode().expect("keepalive must encode");

        assert_eq!(&encoded[2..4], &[0x00, 0x03], "PDU type keepalive");
        assert_eq!(&encoded[8..12], &[0, 0, 0, 0], "no payload");
        assert_eq!(&encoded[14..16], &[0x00, 0x00], "direction reserved");
        assert_eq!(&encoded[32..40], &[0u8; 8], "correlation zero");
        // 40 mandatory + one 8-octet sequence-number TLV.
        assert_eq!(encoded.len(), 48);
    }

    /// Emit a PDU as hex for [`scripts/validate_x2_pdu.sh`] to feed to a
    /// third-party dissector.
    ///
    /// Every other test here is our own reading of clause 5 checking our own
    /// encoder, so they all share whatever we misread. The script pipes these
    /// bytes through somebody else's decoder, which does not.
    #[test]
    fn emit_x2_pdu_for_external_dissection() {
        let Ok(path) = std::env::var("SIPHON_X2_PDU_HEX_OUT") else {
            // Nothing to do in an ordinary test run.
            return;
        };

        let mut pdu = sip_pdu();
        pdu.attributes = vec![
            Attribute::timestamp(
                SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_789),
            ),
            Attribute::sequence_number(1),
            Attribute::text(attribute_type::MATCHED_TARGET_IDENTIFIER, "LI-001"),
        ];
        let encoded = pdu.encode().expect("well-formed PDU must encode");

        // `text2pcap`'s hex-dump form: an offset, then the octets.
        let mut dump = String::new();
        for (offset, chunk) in encoded.chunks(16).enumerate() {
            dump.push_str(&format!("{:06x}", offset * 16));
            for byte in chunk {
                dump.push_str(&format!(" {byte:02x}"));
            }
            dump.push('\n');
        }
        std::fs::write(&path, dump).expect("hex dump must be writable");
    }

    #[test]
    fn an_empty_payload_still_produces_a_readable_header() {
        let mut pdu = sip_pdu();
        pdu.payload = Vec::new();
        let encoded = pdu.encode().expect("empty payload is legal");
        assert_eq!(encoded.len(), 40);
        assert_eq!(&encoded[8..12], &[0, 0, 0, 0]);
    }
}
