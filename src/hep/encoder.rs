//! HEP v3 (EEP) binary packet encoder.
//!
//! Implements the chunk-based TLV format used by Homer/heplify-server
//! for SIP message capture and correlation.

use std::net::{IpAddr, SocketAddr};

use bytes::{BufMut, BytesMut};

use crate::transport::Transport;

// --- HEP v3 constants ---

const HEP3_MAGIC: &[u8; 4] = b"HEP3";
const CHUNK_HEADER_LEN: u16 = 6; // vendor_id(2) + type_id(2) + length(2)
const GENERIC_VENDOR: u16 = 0x0000;

// Chunk type IDs (generic vendor)
const CHUNK_IP_FAMILY: u16 = 0x0001;
const CHUNK_IP_PROTOCOL: u16 = 0x0002;
const CHUNK_IPV4_SRC: u16 = 0x0003;
const CHUNK_IPV4_DST: u16 = 0x0004;
const CHUNK_IPV6_SRC: u16 = 0x0005;
const CHUNK_IPV6_DST: u16 = 0x0006;
const CHUNK_SRC_PORT: u16 = 0x0007;
const CHUNK_DST_PORT: u16 = 0x0008;
const CHUNK_TIMESTAMP_SEC: u16 = 0x0009;
const CHUNK_TIMESTAMP_USEC: u16 = 0x000a;
const CHUNK_PROTOCOL_TYPE: u16 = 0x000b;
const CHUNK_AGENT_ID: u16 = 0x000c;
const CHUNK_PAYLOAD: u16 = 0x000f;
const CHUNK_CORRELATION_ID: u16 = 0x0011;

// IP protocol numbers
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_SCTP: u8 = 132;

// Address family
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// Protocol type
const PROTO_SIP: u8 = 1;

/// Metadata for a captured SIP message.
pub struct CaptureInfo<'a> {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub transport: Transport,
    pub timestamp_secs: u32,
    pub timestamp_usecs: u32,
    pub agent_id: u32,
    pub payload: &'a [u8],
    pub call_id: Option<&'a str>,
}

/// Encode a SIP message capture into a HEP v3 packet.
///
/// Returns the complete HEP v3 binary packet ready to send to a collector.
pub fn encode_hep3(info: &CaptureInfo<'_>) -> BytesMut {
    // Pre-calculate total length
    let is_ipv6 = info.source.is_ipv6();
    let addr_chunks_len = if is_ipv6 {
        2 * (CHUNK_HEADER_LEN + 16) // two IPv6 address chunks (16 bytes each)
    } else {
        2 * (CHUNK_HEADER_LEN + 4) // two IPv4 address chunks (4 bytes each)
    };

    let fixed_chunks_len =
        (CHUNK_HEADER_LEN + 1)  // IP family
        + (CHUNK_HEADER_LEN + 1)  // IP protocol
        + addr_chunks_len
        + (CHUNK_HEADER_LEN + 2)  // src port
        + (CHUNK_HEADER_LEN + 2)  // dst port
        + (CHUNK_HEADER_LEN + 4)  // timestamp sec
        + (CHUNK_HEADER_LEN + 4)  // timestamp usec
        + (CHUNK_HEADER_LEN + 1)  // protocol type
        + (CHUNK_HEADER_LEN + 4); // agent ID

    let payload_chunk_len = CHUNK_HEADER_LEN + info.payload.len() as u16;
    let correlation_chunk_len = info
        .call_id
        .map(|cid| CHUNK_HEADER_LEN + cid.len() as u16)
        .unwrap_or(0);

    let total_len: u16 =
        4 + 2 // magic + total_length field
        + fixed_chunks_len
        + payload_chunk_len
        + correlation_chunk_len;

    let mut buffer = BytesMut::with_capacity(total_len as usize);

    // --- Header ---
    buffer.put_slice(HEP3_MAGIC);
    buffer.put_u16(total_len);

    // --- Chunks ---

    // IP protocol family
    let family = if is_ipv6 { AF_INET6 } else { AF_INET };
    put_chunk_u8(&mut buffer, CHUNK_IP_FAMILY, family);

    // IP protocol (transport layer)
    let ip_proto = match info.transport {
        Transport::Tcp | Transport::Tls | Transport::WebSocket | Transport::WebSocketSecure => {
            IPPROTO_TCP
        }
        Transport::Sctp => IPPROTO_SCTP,
        Transport::Udp => IPPROTO_UDP,
    };
    put_chunk_u8(&mut buffer, CHUNK_IP_PROTOCOL, ip_proto);

    // Source and destination addresses
    match (info.source.ip(), info.destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            put_chunk_bytes(&mut buffer, CHUNK_IPV4_SRC, &src.octets());
            put_chunk_bytes(&mut buffer, CHUNK_IPV4_DST, &dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_SRC, &src.octets());
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_DST, &dst.octets());
        }
        // Mixed v4/v6: map v4 to v6
        (IpAddr::V4(src), IpAddr::V6(dst)) => {
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_SRC, &src.to_ipv6_mapped().octets());
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_DST, &dst.octets());
        }
        (IpAddr::V6(src), IpAddr::V4(dst)) => {
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_SRC, &src.octets());
            put_chunk_bytes(&mut buffer, CHUNK_IPV6_DST, &dst.to_ipv6_mapped().octets());
        }
    }

    // Ports
    put_chunk_u16(&mut buffer, CHUNK_SRC_PORT, info.source.port());
    put_chunk_u16(&mut buffer, CHUNK_DST_PORT, info.destination.port());

    // Timestamps
    put_chunk_u32(&mut buffer, CHUNK_TIMESTAMP_SEC, info.timestamp_secs);
    put_chunk_u32(&mut buffer, CHUNK_TIMESTAMP_USEC, info.timestamp_usecs);

    // Protocol type (SIP)
    put_chunk_u8(&mut buffer, CHUNK_PROTOCOL_TYPE, PROTO_SIP);

    // Capture agent ID
    put_chunk_u32(&mut buffer, CHUNK_AGENT_ID, info.agent_id);

    // SIP payload
    put_chunk_bytes(&mut buffer, CHUNK_PAYLOAD, info.payload);

    // Correlation ID (Call-ID)
    if let Some(call_id) = info.call_id {
        put_chunk_bytes(&mut buffer, CHUNK_CORRELATION_ID, call_id.as_bytes());
    }

    buffer
}

/// Write a chunk with a single u8 value.
fn put_chunk_u8(buffer: &mut BytesMut, type_id: u16, value: u8) {
    buffer.put_u16(GENERIC_VENDOR);
    buffer.put_u16(type_id);
    buffer.put_u16(CHUNK_HEADER_LEN + 1);
    buffer.put_u8(value);
}

/// Write a chunk with a u16 value.
fn put_chunk_u16(buffer: &mut BytesMut, type_id: u16, value: u16) {
    buffer.put_u16(GENERIC_VENDOR);
    buffer.put_u16(type_id);
    buffer.put_u16(CHUNK_HEADER_LEN + 2);
    buffer.put_u16(value);
}

/// Write a chunk with a u32 value.
fn put_chunk_u32(buffer: &mut BytesMut, type_id: u16, value: u32) {
    buffer.put_u16(GENERIC_VENDOR);
    buffer.put_u16(type_id);
    buffer.put_u16(CHUNK_HEADER_LEN + 4);
    buffer.put_u32(value);
}

/// Write a chunk with raw bytes.
fn put_chunk_bytes(buffer: &mut BytesMut, type_id: u16, value: &[u8]) {
    buffer.put_u16(GENERIC_VENDOR);
    buffer.put_u16(type_id);
    buffer.put_u16(CHUNK_HEADER_LEN + value.len() as u16);
    buffer.put_slice(value);
}

/// Extract the Call-ID from a raw SIP message for correlation.
///
/// Does a simple line scan — avoids full SIP parse overhead in the capture path.
pub fn extract_call_id(payload: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(payload).ok()?;
    for line in text.split("\r\n") {
        // Check for "Call-ID:" or compact form "i:"
        let value = if let Some(rest) = line.strip_prefix("Call-ID:") {
            Some(rest)
        } else if let Some(rest) = line.strip_prefix("call-id:") {
            Some(rest)
        } else if let Some(rest) = line.strip_prefix("Call-Id:") {
            Some(rest)
        } else if line.starts_with("i:") && line.len() > 2 {
            Some(&line[2..])
        } else {
            None
        };
        if let Some(v) = value {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    fn sample_sip_payload() -> &'static [u8] {
        concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776\r\n",
            "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes()
    }

    fn make_capture_info(payload: &[u8]) -> CaptureInfo<'_> {
        CaptureInfo {
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 5060),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            transport: Transport::Udp,
            timestamp_secs: 1700000000,
            timestamp_usecs: 123456,
            agent_id: 42,
            payload,
            call_id: Some("a84b4c76e66710@pc33.atlanta.com"),
        }
    }

    #[test]
    fn encode_hep3_magic_and_length() {
        let payload = sample_sip_payload();
        let info = make_capture_info(payload);
        let packet = encode_hep3(&info);

        // Magic bytes
        assert_eq!(&packet[0..4], b"HEP3");

        // Total length matches actual buffer size
        let total_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
        assert_eq!(total_len, packet.len());
    }

    #[test]
    fn encode_hep3_ipv4_chunks() {
        let payload = sample_sip_payload();
        let info = make_capture_info(payload);
        let packet = encode_hep3(&info);

        // Parse chunks after the 6-byte header
        let chunks = parse_chunks(&packet[6..]);

        // IP family = AF_INET (2)
        assert_eq!(chunks.get(&CHUNK_IP_FAMILY).unwrap(), &[AF_INET]);

        // IP protocol = UDP (17)
        assert_eq!(chunks.get(&CHUNK_IP_PROTOCOL).unwrap(), &[IPPROTO_UDP]);

        // Source IPv4
        assert_eq!(
            chunks.get(&CHUNK_IPV4_SRC).unwrap(),
            &[192, 168, 1, 10]
        );

        // Destination IPv4
        assert_eq!(
            chunks.get(&CHUNK_IPV4_DST).unwrap(),
            &[10, 0, 0, 1]
        );

        // Source port
        let src_port = u16::from_be_bytes(
            chunks.get(&CHUNK_SRC_PORT).unwrap()[..2].try_into().unwrap(),
        );
        assert_eq!(src_port, 5060);

        // Destination port
        let dst_port = u16::from_be_bytes(
            chunks.get(&CHUNK_DST_PORT).unwrap()[..2].try_into().unwrap(),
        );
        assert_eq!(dst_port, 5060);
    }

    #[test]
    fn encode_hep3_wildcard_local_resolves_to_advertised() {
        use crate::uac::resolve_via_addr;
        use std::collections::HashMap;

        let payload = sample_sip_payload();

        // siphon bound to the wildcard address — the usual production `listen`
        // config. The raw bind/recv address is unspecified.
        let wildcard = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 5060);

        // The encoder is a faithful writer: hand it the raw wildcard and it emits
        // `0.0.0.0`, which is exactly the leak the pre-fix HEP path produced.
        let raw = CaptureInfo { source: wildcard, ..make_capture_info(payload) };
        let raw_chunks = parse_chunks(&encode_hep3(&raw)[6..]);
        assert_eq!(raw_chunks.get(&CHUNK_IPV4_SRC).unwrap(), &[0, 0, 0, 0]);

        // The dispatcher/uac resolve the local addr through `resolve_via_addr`
        // before encoding, substituting the advertised address for the wildcard
        // and preserving the port.
        let mut advertised = HashMap::new();
        advertised.insert(Transport::Udp, "203.0.113.7".to_string());
        let resolved = resolve_via_addr(wildcard, &Transport::Udp, &advertised, None);
        assert_eq!(resolved.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)));
        assert_eq!(resolved.port(), 5060);

        let fixed = CaptureInfo { source: resolved, ..make_capture_info(payload) };
        let fixed_chunks = parse_chunks(&encode_hep3(&fixed)[6..]);
        assert_eq!(fixed_chunks.get(&CHUNK_IPV4_SRC).unwrap(), &[203, 0, 113, 7]);
    }

    #[test]
    fn encode_hep3_ipv6_chunks() {
        let payload = sample_sip_payload();
        let source = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5060);
        let destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)), 5061);
        let info = CaptureInfo {
            source,
            destination,
            transport: Transport::Tcp,
            timestamp_secs: 1700000000,
            timestamp_usecs: 0,
            agent_id: 1,
            payload,
            call_id: None,
        };
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);

        // IP family = AF_INET6 (10)
        assert_eq!(chunks.get(&CHUNK_IP_FAMILY).unwrap(), &[AF_INET6]);

        // IP protocol = TCP (6)
        assert_eq!(chunks.get(&CHUNK_IP_PROTOCOL).unwrap(), &[IPPROTO_TCP]);

        // IPv6 source
        let src_bytes = chunks.get(&CHUNK_IPV6_SRC).unwrap();
        assert_eq!(src_bytes.len(), 16);
        assert_eq!(src_bytes, &Ipv6Addr::LOCALHOST.octets());

        // IPv6 destination
        let dst_bytes = chunks.get(&CHUNK_IPV6_DST).unwrap();
        assert_eq!(dst_bytes.len(), 16);

        // No correlation chunk when call_id is None
        assert!(!chunks.contains_key(&CHUNK_CORRELATION_ID));
    }

    #[test]
    fn encode_hep3_timestamps_and_agent_id() {
        let payload = sample_sip_payload();
        let info = make_capture_info(payload);
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);

        let ts_sec = u32::from_be_bytes(
            chunks.get(&CHUNK_TIMESTAMP_SEC).unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(ts_sec, 1700000000);

        let ts_usec = u32::from_be_bytes(
            chunks.get(&CHUNK_TIMESTAMP_USEC).unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(ts_usec, 123456);

        let agent = u32::from_be_bytes(
            chunks.get(&CHUNK_AGENT_ID).unwrap()[..4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(agent, 42);
    }

    #[test]
    fn encode_hep3_payload_and_correlation() {
        let payload = sample_sip_payload();
        let info = make_capture_info(payload);
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);

        // SIP payload chunk
        assert_eq!(chunks.get(&CHUNK_PAYLOAD).unwrap(), payload);

        // Protocol type = SIP (1)
        assert_eq!(chunks.get(&CHUNK_PROTOCOL_TYPE).unwrap(), &[PROTO_SIP]);

        // Correlation ID = Call-ID
        let corr = chunks.get(&CHUNK_CORRELATION_ID).unwrap();
        assert_eq!(
            std::str::from_utf8(corr).unwrap(),
            "a84b4c76e66710@pc33.atlanta.com"
        );
    }

    #[test]
    fn encode_hep3_transport_mapping() {
        let payload = b"SIP/2.0 200 OK\r\n\r\n";

        // TLS → TCP protocol
        let info = CaptureInfo {
            source: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5061),
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5061),
            transport: Transport::Tls,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            agent_id: 0,
            payload,
            call_id: None,
        };
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);
        assert_eq!(chunks.get(&CHUNK_IP_PROTOCOL).unwrap(), &[IPPROTO_TCP]);

        // WebSocket → TCP protocol
        let info = CaptureInfo {
            transport: Transport::WebSocket,
            ..info
        };
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);
        assert_eq!(chunks.get(&CHUNK_IP_PROTOCOL).unwrap(), &[IPPROTO_TCP]);

        // SCTP → SCTP protocol
        let info = CaptureInfo {
            transport: Transport::Sctp,
            ..info
        };
        let packet = encode_hep3(&info);
        let chunks = parse_chunks(&packet[6..]);
        assert_eq!(chunks.get(&CHUNK_IP_PROTOCOL).unwrap(), &[IPPROTO_SCTP]);
    }

    #[test]
    fn extract_call_id_standard() {
        let payload = concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com\r\n",
            "Call-ID: abc123@host\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        assert_eq!(extract_call_id(payload.as_bytes()), Some("abc123@host"));
    }

    #[test]
    fn extract_call_id_compact_form() {
        let payload = concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "i: compact-id@host\r\n",
            "\r\n",
        );
        assert_eq!(
            extract_call_id(payload.as_bytes()),
            Some("compact-id@host")
        );
    }

    #[test]
    fn extract_call_id_missing() {
        let payload = concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com\r\n",
            "\r\n",
        );
        assert_eq!(extract_call_id(payload.as_bytes()), None);
    }

    #[test]
    fn extract_call_id_case_variations() {
        // Mixed case "Call-Id:"
        let payload = "Call-Id: mixed-case@host\r\n\r\n";
        assert_eq!(
            extract_call_id(payload.as_bytes()),
            Some("mixed-case@host")
        );

        // Lowercase "call-id:"
        let payload = "call-id: lower@host\r\n\r\n";
        assert_eq!(extract_call_id(payload.as_bytes()), Some("lower@host"));
    }

    /// Helper: parse HEP v3 chunks into a map of type_id → value bytes.
    fn parse_chunks(data: &[u8]) -> std::collections::HashMap<u16, Vec<u8>> {
        let mut map = std::collections::HashMap::new();
        let mut offset = 0;
        while offset + 6 <= data.len() {
            let _vendor = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let type_id = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            let length = u16::from_be_bytes([data[offset + 4], data[offset + 5]]) as usize;
            if offset + length > data.len() {
                break;
            }
            let value = data[offset + 6..offset + length].to_vec();
            map.insert(type_id, value);
            offset += length;
        }
        map
    }
}
