//! Diameter message framing, decoding, and encoding.
//!
//! Wire format (RFC 6733):
//!   Header: 20 bytes
//!     [0]     Version (1)
//!     [1..4]  Message Length (24-bit, includes header)
//!     [4]     Flags (R=request, P=proxiable, E=error, T=retransmit)
//!     [5..8]  Command-Code (24-bit)
//!     [8..12] Application-Id
//!     [12..16] Hop-by-Hop Identifier
//!     [16..20] End-to-End Identifier
//!   AVPs: variable length, padded to 4-byte boundary

use crate::diameter::dictionary::{self, AvpType};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt};

// ── Diameter flags ─────────────────────────────────────────────────────────

pub const FLAG_REQUEST: u8 = 0x80;
pub const FLAG_PROXIABLE: u8 = 0x40;
pub const FLAG_ERROR: u8 = 0x20;

/// AVP flag: Vendor-Id field is present
pub const AVP_FLAG_VENDOR: u8 = 0x80;
/// AVP flag: Mandatory
pub const AVP_FLAG_MANDATORY: u8 = 0x40;

// ── Decoded message ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DiameterMessage {
    pub version: u8,
    pub length: u32,
    pub flags: u8,
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop: u32,
    pub end_to_end: u32,
    pub is_request: bool,
    pub avps: Value,
}

// ── Framing ────────────────────────────────────────────────────────────────

/// Read one complete Diameter message from an async reader.
pub async fn read_diameter_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    reader.read_exact(&mut hdr).await?;

    let version = hdr[0];
    if version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported Diameter version: {}", version),
        ));
    }

    let msg_len = ((hdr[1] as u32) << 16) | ((hdr[2] as u32) << 8) | (hdr[3] as u32);
    if !(20..=1_048_576).contains(&msg_len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid Diameter message length: {}", msg_len),
        ));
    }

    let mut buf = vec![0u8; msg_len as usize];
    buf[..4].copy_from_slice(&hdr);
    reader.read_exact(&mut buf[4..]).await?;

    Ok(buf)
}

// ── Decode ─────────────────────────────────────────────────────────────────

/// Decode a complete Diameter message (header + AVPs).
pub fn decode_diameter(msg: &[u8]) -> Option<DiameterMessage> {
    if msg.len() < 20 {
        return None;
    }

    let version = msg[0];
    let length = ((msg[1] as u32) << 16) | ((msg[2] as u32) << 8) | (msg[3] as u32);
    let flags = msg[4];
    let command_code = ((msg[5] as u32) << 16) | ((msg[6] as u32) << 8) | (msg[7] as u32);
    let application_id = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let hop_by_hop = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
    let end_to_end = u32::from_be_bytes([msg[16], msg[17], msg[18], msg[19]]);

    let is_request = (flags & FLAG_REQUEST) != 0;
    let avps = decode_avps(&msg[20..]);

    Some(DiameterMessage {
        version,
        length,
        flags,
        command_code,
        application_id,
        hop_by_hop,
        end_to_end,
        is_request,
        avps,
    })
}

/// Walk AVPs and produce a JSON object with decoded values.
fn decode_avps(data: &[u8]) -> Value {
    let mut map = serde_json::Map::new();
    let mut pos = 0;

    while pos + 8 <= data.len() {
        let avp_code = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let avp_flags = data[pos + 4];
        let avp_len =
            ((data[pos + 5] as u32) << 16) | ((data[pos + 6] as u32) << 8) | (data[pos + 7] as u32);

        if avp_len < 8 || (pos + avp_len as usize) > data.len() {
            break;
        }

        let has_vendor = (avp_flags & AVP_FLAG_VENDOR) != 0;
        let hdr_size: usize = if has_vendor { 12 } else { 8 };

        if avp_len < hdr_size as u32 {
            break;
        }

        let vendor_id = if has_vendor && pos + 12 <= data.len() {
            u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
        } else {
            0
        };

        let value_start = pos + hdr_size;
        let value_end = pos + avp_len as usize;
        let value_data = if value_start <= value_end && value_end <= data.len() {
            &data[value_start..value_end]
        } else {
            &[]
        };

        let (name, decoded) = match dictionary::lookup_avp(avp_code, vendor_id) {
            Some(def) => {
                let val = decode_avp_value(def.data_type, value_data);
                (def.name.to_string(), val)
            }
            None => {
                let name = if vendor_id != 0 {
                    format!("AVP-{}-v{}", avp_code, vendor_id)
                } else {
                    format!("AVP-{}", avp_code)
                };
                (name, Value::String(hex::encode(value_data)))
            }
        };

        // Handle duplicate AVP names by making an array
        if let Some(existing) = map.get(&name) {
            let arr = match existing {
                Value::Array(a) => {
                    let mut a = a.clone();
                    a.push(decoded);
                    a
                }
                other => vec![other.clone(), decoded],
            };
            map.insert(name, Value::Array(arr));
        } else {
            map.insert(name, decoded);
        }

        let padded = (avp_len as usize + 3) & !3;
        pos += padded;
    }

    Value::Object(map)
}

fn decode_avp_value(avp_type: AvpType, data: &[u8]) -> Value {
    match avp_type {
        AvpType::UTF8String | AvpType::DiameterIdentity => {
            Value::String(String::from_utf8_lossy(data).into_owned())
        }
        AvpType::Unsigned32 | AvpType::Enumerated => {
            if data.len() >= 4 {
                let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                Value::Number(v.into())
            } else {
                Value::String(hex::encode(data))
            }
        }
        AvpType::Integer32 => {
            if data.len() >= 4 {
                let v = i32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                json!(v)
            } else {
                Value::String(hex::encode(data))
            }
        }
        AvpType::Unsigned64 => {
            if data.len() >= 8 {
                let v = u64::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                json!(v)
            } else {
                Value::String(hex::encode(data))
            }
        }
        AvpType::OctetString => Value::String(hex::encode(data)),
        AvpType::Address => decode_address(data),
        AvpType::Time => {
            if data.len() >= 4 {
                let ntp = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                let unix = ntp.wrapping_sub(2_208_988_800);
                json!(unix)
            } else {
                Value::String(hex::encode(data))
            }
        }
        AvpType::Grouped => decode_avps(data),
    }
}

fn decode_address(data: &[u8]) -> Value {
    if data.len() < 2 {
        return Value::String(hex::encode(data));
    }
    let family = u16::from_be_bytes([data[0], data[1]]);
    match family {
        1 if data.len() >= 6 => {
            Value::String(format!("{}.{}.{}.{}", data[2], data[3], data[4], data[5]))
        }
        2 if data.len() >= 18 => {
            let addr = std::net::Ipv6Addr::new(
                u16::from_be_bytes([data[2], data[3]]),
                u16::from_be_bytes([data[4], data[5]]),
                u16::from_be_bytes([data[6], data[7]]),
                u16::from_be_bytes([data[8], data[9]]),
                u16::from_be_bytes([data[10], data[11]]),
                u16::from_be_bytes([data[12], data[13]]),
                u16::from_be_bytes([data[14], data[15]]),
                u16::from_be_bytes([data[16], data[17]]),
            );
            Value::String(addr.to_string())
        }
        _ => Value::String(hex::encode(data)),
    }
}

// ── Encode ─────────────────────────────────────────────────────────────────

/// Encode a single AVP (no vendor ID).
pub fn encode_avp(code: u32, flags: u8, data: &[u8]) -> Vec<u8> {
    let avp_len = 8 + data.len();
    let padded_len = (avp_len + 3) & !3;
    let mut buf = Vec::with_capacity(padded_len);

    buf.extend_from_slice(&code.to_be_bytes());
    buf.push(flags);
    buf.push(((avp_len >> 16) & 0xff) as u8);
    buf.push(((avp_len >> 8) & 0xff) as u8);
    buf.push((avp_len & 0xff) as u8);
    buf.extend_from_slice(data);

    // Pad to 4-byte boundary
    while buf.len() < padded_len {
        buf.push(0);
    }
    buf
}

/// Encode a single AVP with vendor ID (sets V flag).
pub fn encode_avp_vendor(code: u32, flags: u8, vendor_id: u32, data: &[u8]) -> Vec<u8> {
    let avp_len = 12 + data.len();
    let padded_len = (avp_len + 3) & !3;
    let mut buf = Vec::with_capacity(padded_len);

    buf.extend_from_slice(&code.to_be_bytes());
    buf.push(flags | AVP_FLAG_VENDOR);
    buf.push(((avp_len >> 16) & 0xff) as u8);
    buf.push(((avp_len >> 8) & 0xff) as u8);
    buf.push((avp_len & 0xff) as u8);
    buf.extend_from_slice(&vendor_id.to_be_bytes());
    buf.extend_from_slice(data);

    while buf.len() < padded_len {
        buf.push(0);
    }
    buf
}

// ── Typed AVP helpers ──────────────────────────────────────────────────────

/// Encode a UTF8String/DiameterIdentity AVP (no vendor).
pub fn encode_avp_utf8(code: u32, value: &str) -> Vec<u8> {
    encode_avp(code, AVP_FLAG_MANDATORY, value.as_bytes())
}

/// Encode a Unsigned32 AVP (no vendor).
pub fn encode_avp_u32(code: u32, value: u32) -> Vec<u8> {
    encode_avp(code, AVP_FLAG_MANDATORY, &value.to_be_bytes())
}

/// Encode a UTF8String/DiameterIdentity AVP with 3GPP vendor.
pub fn encode_avp_utf8_3gpp(code: u32, value: &str) -> Vec<u8> {
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, value.as_bytes())
}

/// Encode a Unsigned32 AVP with 3GPP vendor.
pub fn encode_avp_u32_3gpp(code: u32, value: u32) -> Vec<u8> {
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, &value.to_be_bytes())
}

/// Encode an OctetString AVP with 3GPP vendor.
pub fn encode_avp_octet_3gpp(code: u32, data: &[u8]) -> Vec<u8> {
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, data)
}

/// Encode a Grouped AVP with 3GPP vendor (data = concatenated child AVPs).
pub fn encode_avp_grouped_3gpp(code: u32, children: &[u8]) -> Vec<u8> {
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, children)
}

/// Encode an OctetString AVP (base vendor, no vendor flag).
pub fn encode_avp_octet(code: u32, data: &[u8]) -> Vec<u8> {
    encode_avp(code, AVP_FLAG_MANDATORY, data)
}

/// Encode a Grouped AVP (base vendor, no vendor flag).
pub fn encode_avp_grouped(code: u32, children: &[u8]) -> Vec<u8> {
    encode_avp(code, AVP_FLAG_MANDATORY, children)
}

/// Encode an Unsigned64 AVP (base vendor, no vendor flag).
pub fn encode_avp_u64(code: u32, value: u64) -> Vec<u8> {
    encode_avp(code, AVP_FLAG_MANDATORY, &value.to_be_bytes())
}

/// Encode a signed Integer32 AVP with 3GPP vendor.
pub fn encode_avp_i32_3gpp(code: u32, value: i32) -> Vec<u8> {
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, &value.to_be_bytes())
}

/// Offset between the NTP epoch (1900-01-01 00:00:00 UTC) and the Unix
/// epoch (1970-01-01 00:00:00 UTC) in seconds — exactly 70 years.
pub const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;

/// Convert a `SystemTime` to a Diameter Time AVP value (RFC 6733 §4.3.1):
/// 32-bit unsigned NTP-style seconds since 1900-01-01 UTC.  Returns 0 for
/// pre-1970 timestamps.
pub fn system_time_to_diameter_time(time: std::time::SystemTime) -> u32 {
    let unix_secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (unix_secs.wrapping_add(NTP_UNIX_EPOCH_OFFSET) & 0xFFFF_FFFF) as u32
}

/// Encode a Time AVP (no vendor).
pub fn encode_avp_time(code: u32, time: std::time::SystemTime) -> Vec<u8> {
    let secs = system_time_to_diameter_time(time);
    encode_avp(code, AVP_FLAG_MANDATORY, &secs.to_be_bytes())
}

/// Encode a Time AVP with 3GPP vendor.
pub fn encode_avp_time_3gpp(code: u32, time: std::time::SystemTime) -> Vec<u8> {
    let secs = system_time_to_diameter_time(time);
    encode_avp_vendor(
        code,
        AVP_FLAG_MANDATORY,
        dictionary::VENDOR_3GPP,
        &secs.to_be_bytes(),
    )
}

/// Encode an Address AVP (IPv4).
pub fn encode_avp_address_ipv4(code: u32, ip: std::net::Ipv4Addr) -> Vec<u8> {
    let mut data = Vec::with_capacity(6);
    data.extend_from_slice(&1u16.to_be_bytes()); // Address family: IPv4
    data.extend_from_slice(&ip.octets());
    encode_avp(code, AVP_FLAG_MANDATORY, &data)
}

/// Encode an Address AVP (IPv4 or IPv6) with 3GPP vendor.  Used by the
/// SMS-Information block for SCCP / Client / MTC-IWF addresses
/// (TS 32.299 §7.2.79).
pub fn encode_avp_address_3gpp(code: u32, ip: std::net::IpAddr) -> Vec<u8> {
    let mut data = Vec::with_capacity(18);
    match ip {
        std::net::IpAddr::V4(v4) => {
            data.extend_from_slice(&1u16.to_be_bytes()); // Address family: IPv4
            data.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            data.extend_from_slice(&2u16.to_be_bytes()); // Address family: IPv6
            data.extend_from_slice(&v6.octets());
        }
    }
    encode_avp_vendor(code, AVP_FLAG_MANDATORY, dictionary::VENDOR_3GPP, &data)
}

/// Encode a Vendor-Specific-Application-Id grouped AVP.
pub fn encode_vendor_specific_app_id(vendor_id: u32, auth_app_id: u32) -> Vec<u8> {
    let mut children = Vec::new();
    children.extend_from_slice(&encode_avp_u32(dictionary::avp::VENDOR_ID, vendor_id));
    children.extend_from_slice(&encode_avp_u32(dictionary::avp::AUTH_APPLICATION_ID, auth_app_id));
    encode_avp(dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID, AVP_FLAG_MANDATORY, &children)
}

// ── Full message encoding ──────────────────────────────────────────────────

/// Build a generic Diameter answer carrying the standard mandatory AVPs
/// (Session-Id, Origin-Host, Origin-Realm, Auth-Session-State,
/// Vendor-Specific-Application-Id when applicable, Result-Code).
///
/// Used by the dispatcher's `@diameter.on_command(...)` fallback to
/// auto-ack incoming requests with a 2001-Success once the script
/// handler returns. Per-app typed answers stay in their own modules
/// (`cx::build_uaa_*`, `s6c::build_ala_*`, etc.) — this builder is only
/// for the open-extension path.
#[allow(clippy::too_many_arguments)]
pub fn encode_generic_answer(
    origin_host: &str,
    origin_realm: &str,
    session_id: &str,
    command_code: u32,
    application_id: u32,
    result_code: u32,
    hop_by_hop: u32,
    end_to_end: u32,
) -> Vec<u8> {
    let mut avp_buf = Vec::with_capacity(160);
    avp_buf.extend_from_slice(&encode_avp_utf8(dictionary::avp::SESSION_ID, session_id));
    avp_buf.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_HOST, origin_host));
    avp_buf.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_REALM, origin_realm));
    avp_buf.extend_from_slice(&encode_avp_u32(dictionary::avp::AUTH_SESSION_STATE, 1));
    // Apps with a 3GPP-vendor application-id (Cx, Sh, Rx, S6c, SGd) need
    // Vendor-Specific-Application-Id; base apps (Ro, Rf) don't. Match
    // dictionary::app_name_by_id to detect the vendor side.
    if let Some(name) = dictionary::app_name_by_id(application_id) {
        if let Some((vendor, _)) = dictionary::app_id_by_name(name) {
            if vendor != 0 {
                avp_buf
                    .extend_from_slice(&encode_vendor_specific_app_id(vendor, application_id));
            }
        }
    }
    avp_buf.extend_from_slice(&encode_avp_u32(dictionary::avp::RESULT_CODE, result_code));

    encode_diameter_message(
        FLAG_PROXIABLE,
        command_code,
        application_id,
        hop_by_hop,
        end_to_end,
        &avp_buf,
    )
}

/// Encode a complete Diameter message.
pub fn encode_diameter_message(
    flags: u8,
    command_code: u32,
    application_id: u32,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: &[u8],
) -> Vec<u8> {
    let msg_len = 20 + avps.len();
    let mut buf = Vec::with_capacity(msg_len);

    // Version
    buf.push(1);
    // Message length (24-bit)
    buf.push(((msg_len >> 16) & 0xff) as u8);
    buf.push(((msg_len >> 8) & 0xff) as u8);
    buf.push((msg_len & 0xff) as u8);
    // Flags
    buf.push(flags);
    // Command-Code (24-bit)
    buf.push(((command_code >> 16) & 0xff) as u8);
    buf.push(((command_code >> 8) & 0xff) as u8);
    buf.push((command_code & 0xff) as u8);
    // Application-Id
    buf.extend_from_slice(&application_id.to_be_bytes());
    // Hop-by-Hop
    buf.extend_from_slice(&hop_by_hop.to_be_bytes());
    // End-to-End
    buf.extend_from_slice(&end_to_end.to_be_bytes());
    // AVPs
    buf.extend_from_slice(avps);

    buf
}

// ── Command name mapping ───────────────────────────────────────────────────

pub fn command_name(code: u32, is_request: bool) -> &'static str {
    match (code, is_request) {
        // Base
        (257, true) => "CER", (257, false) => "CEA",
        (258, true) => "RAR", (258, false) => "RAA",
        (265, true) => "AAR", (265, false) => "AAA",
        (271, true) => "ACR", (271, false) => "ACA",
        (272, true) => "CCR", (272, false) => "CCA",
        (274, true) => "ASR", (274, false) => "ASA",
        (275, true) => "STR", (275, false) => "STA",
        (280, true) => "DWR", (280, false) => "DWA",
        (282, true) => "DPR", (282, false) => "DPA",
        // Cx
        (300, true) => "UAR", (300, false) => "UAA",
        (301, true) => "SAR", (301, false) => "SAA",
        (302, true) => "LIR", (302, false) => "LIA",
        (303, true) => "MAR", (303, false) => "MAA",
        (304, true) => "RTR", (304, false) => "RTA",
        (305, true) => "PPR", (305, false) => "PPA",
        // Sh
        (306, true) => "UDR", (306, false) => "UDA",
        (307, true) => "PUR", (307, false) => "PUA",
        (308, true) => "SNR", (308, false) => "SNA",
        (309, true) => "PNR", (309, false) => "PNA",
        // S6a
        (316, true) => "ULR", (316, false) => "ULA",
        (317, true) => "CLR", (317, false) => "CLA",
        (318, true) => "AIR", (318, false) => "AIA",
        (319, true) => "IDR", (319, false) => "IDA",
        (320, true) => "DSR", (320, false) => "DSA",
        (321, true) => "PUR-S6a", (321, false) => "PUA-S6a",
        (323, true) => "NOR", (323, false) => "NOA",
        (324, true) => "ECR", (324, false) => "ECA",
        _ => "Unknown",
    }
}

/// Extract IMSI from decoded AVPs.
pub fn extract_imsi(avps: &Value) -> Option<String> {
    avps.get("User-Name").and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Extract a u32 AVP value by name from decoded AVPs.
pub fn extract_u32_avp(avps: &Value, avp_code: u32) -> Option<u32> {
    let name = super::dictionary::avp_name(avp_code)?;
    avps.get(name).and_then(|v| v.as_u64()).map(|v| v as u32)
}

/// Extract a grouped AVP value by name — returns the inner JSON object.
pub fn extract_grouped_avp(avps: &Value, avp_code: u32) -> Option<Value> {
    let name = super::dictionary::avp_name(avp_code)?;
    avps.get(name).cloned()
}

/// Extract an OctetString AVP value (hex-encoded) by name, decoded to bytes.
pub fn extract_octet_avp(avps: &Value, avp_code: u32) -> Option<Vec<u8>> {
    let name = super::dictionary::avp_name(avp_code)?;
    let hex_str = avps.get(name).and_then(|v| v.as_str())?;
    hex::decode(hex_str)
}

// ── Hex encoding helper ────────────────────────────────────────────────────

pub mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for &b in data {
            s.push(HEX_CHARS[(b >> 4) as usize] as char);
            s.push(HEX_CHARS[(b & 0x0f) as usize] as char);
        }
        s
    }

    pub fn decode(hex_str: &str) -> Option<Vec<u8>> {
        if hex_str.len() % 2 != 0 {
            return None;
        }
        let mut bytes = Vec::with_capacity(hex_str.len() / 2);
        for chunk in hex_str.as_bytes().chunks(2) {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            bytes.push((hi << 4) | lo);
        }
        Some(bytes)
    }

    fn hex_digit(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

// ── MSISDN encoding (TBCD) ────────────────────────────────────────────────

/// Encode MSISDN as TBCD (Telephony Binary Coded Decimal) for Diameter.
/// E.g. "33612345678" → [0x33, 0x16, 0x32, 0x54, 0x76, 0xf8]
pub fn encode_msisdn_tbcd(msisdn: &str) -> Vec<u8> {
    let digits: Vec<u8> = msisdn.bytes().filter_map(|b| {
        if b.is_ascii_digit() { Some(b - b'0') } else { None }
    }).collect();

    let mut result = Vec::with_capacity(digits.len().div_ceil(2));
    for chunk in digits.chunks(2) {
        let lo = chunk[0];
        let hi = if chunk.len() > 1 { chunk[1] } else { 0x0f };
        result.push((hi << 4) | lo);
    }
    result
}

/// Decode TBCD-encoded MSISDN back to string.
pub fn decode_msisdn_tbcd(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        let lo = byte & 0x0f;
        let hi = (byte >> 4) & 0x0f;
        if lo <= 9 { s.push((b'0' + lo) as char); }
        if hi <= 9 { s.push((b'0' + hi) as char); }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_avp_utf8() {
        let avp = encode_avp_utf8(dictionary::avp::ORIGIN_HOST, "ip-sm-gw.ims.example.com");
        let decoded = decode_avps(&avp);
        assert_eq!(
            decoded.get("Origin-Host").and_then(|v| v.as_str()),
            Some("ip-sm-gw.ims.example.com")
        );
    }

    #[test]
    fn encode_decode_avp_u32() {
        let avp = encode_avp_u32(dictionary::avp::RESULT_CODE, 2001);
        let decoded = decode_avps(&avp);
        assert_eq!(
            decoded.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
    }

    #[test]
    fn encode_decode_avp_3gpp() {
        let msisdn = encode_msisdn_tbcd("33612345678");
        let avp = encode_avp_octet_3gpp(dictionary::avp::MSISDN, &msisdn);
        let decoded = decode_avps(&avp);
        assert!(decoded.get("MSISDN").is_some());
    }

    #[test]
    fn encode_decode_full_message() {
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::SESSION_ID, "test;session;1"));
        avps.extend_from_slice(&encode_avp_u32(dictionary::avp::RESULT_CODE, 2001));
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_HOST, "hss.example.com"));
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_REALM, "example.com"));

        let msg = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            0x12345678,
            0xAABBCCDD,
            &avps,
        );

        let decoded = decode_diameter(&msg).unwrap();
        assert!(decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_MULTIMEDIA_AUTH);
        assert_eq!(decoded.application_id, dictionary::CX_APP_ID);
        assert_eq!(decoded.hop_by_hop, 0x12345678);
        assert_eq!(decoded.end_to_end, 0xAABBCCDD);
        assert_eq!(command_name(decoded.command_code, decoded.is_request), "MAR");

        assert_eq!(
            decoded.avps.get("Session-Id").and_then(|v| v.as_str()),
            Some("test;session;1")
        );
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
    }

    #[test]
    fn avp_padding() {
        let avp = encode_avp(1, AVP_FLAG_MANDATORY, b"abc");
        assert_eq!(avp.len(), 12);
        assert_eq!(avp[11], 0);
    }

    #[test]
    fn vendor_avp_encoding() {
        let avp = encode_avp_vendor(3300, AVP_FLAG_MANDATORY, 10415, b"\x91\x33\x16");
        assert_eq!(avp.len(), 16);
        assert_ne!(avp[4] & AVP_FLAG_VENDOR, 0);
    }

    #[test]
    fn msisdn_tbcd_roundtrip() {
        let original = "33612345678";
        let encoded = encode_msisdn_tbcd(original);
        let decoded = decode_msisdn_tbcd(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn msisdn_tbcd_odd_length() {
        let original = "3361234567";
        let encoded = encode_msisdn_tbcd(original);
        let decoded = decode_msisdn_tbcd(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_roundtrip() {
        let data = b"\x01\x02\x03\xff";
        let encoded = hex::encode(data);
        assert_eq!(encoded, "010203ff");
        let decoded = hex::decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn generic_answer_3gpp_app_carries_vendor_specific_app_id() {
        let wire = encode_generic_answer(
            "siphon.example.com",
            "example.com",
            "test;1;1",
            dictionary::CMD_ALERT_SERVICE_CENTRE,
            dictionary::S6C_APP_ID,
            dictionary::DIAMETER_SUCCESS,
            10,
            20,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(!decoded.is_request);
        assert_eq!(decoded.command_code, dictionary::CMD_ALERT_SERVICE_CENTRE);
        assert_eq!(decoded.application_id, dictionary::S6C_APP_ID);
        assert_eq!(
            decoded.avps.get("Result-Code").and_then(|v| v.as_u64()),
            Some(2001)
        );
        // 3GPP-vendor app must carry Vendor-Specific-Application-Id.
        assert!(decoded.avps.get("Vendor-Specific-Application-Id").is_some());
    }

    #[test]
    fn generic_answer_base_app_omits_vendor_specific_app_id() {
        // Rf is a base (vendor 0) application — VSA is unnecessary.
        let wire = encode_generic_answer(
            "siphon.example.com",
            "example.com",
            "test;1;1",
            dictionary::CMD_ACCOUNTING,
            dictionary::RF_APP_ID,
            dictionary::DIAMETER_SUCCESS,
            5,
            6,
        );
        let decoded = decode_diameter(&wire).unwrap();
        assert!(decoded.avps.get("Vendor-Specific-Application-Id").is_none());
        assert_eq!(decoded.application_id, dictionary::RF_APP_ID);
    }
}
