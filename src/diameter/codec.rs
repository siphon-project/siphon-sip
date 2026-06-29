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
    /// Original wire bytes. Carried so the Diameter server relay path can reconstruct the
    /// lossless AVP tree from an answer (the JSON `avps` view is lossy). Empty
    /// only for messages not produced by `decode_diameter`.
    pub raw: Vec<u8>,
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
        raw: msg.to_vec(),
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

// ── Lossless AVP tree (Diameter server relay path) ──────────────────────────────────────
//
// The `serde_json::Value` decode path above is LOSSY (drops AVP flags, folds
// vendor-id away, hex-encodes OctetStrings ambiguously, collapses duplicate
// AVPs into arrays losing order). That is fine for the typed app modules that
// read named fields, but a Diameter server must relay a message —
// including AVPs it does not understand — byte-faithfully, append a
// Route-Record, and re-serialize. This tree preserves every AVP's code,
// vendor, flags, and raw value bytes in order, so `from_wire → to_wire`
// reproduces a structurally identical message (padding normalized to zero).
//
// It is ADDITIVE: the JSON path is untouched and every existing caller keeps
// working. Typed interpretation happens lazily (`Avp::as_str` / `as_u32`),
// only at the boundary that needs it.

/// Error decoding a Diameter message into the lossless AVP tree.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("message too short: {0} bytes (need >= 20)")]
    HeaderTooShort(usize),
    #[error("unsupported Diameter version: {0}")]
    UnsupportedVersion(u8),
    #[error("declared message length {declared} out of range for {actual}-byte buffer")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("AVP truncated: need {need} bytes at offset {offset}, have {have}")]
    Truncated {
        offset: usize,
        need: usize,
        have: usize,
    },
    #[error("invalid AVP length {length} at offset {offset} (header is {header} bytes)")]
    InvalidAvpLength {
        offset: usize,
        length: usize,
        header: usize,
    },
}

/// An AVP's value: either opaque bytes or a parsed list of child AVPs.
///
/// Whether an AVP is treated as `Grouped` is decided by the dictionary
/// (`AvpType::Grouped`); unknown AVPs are always `Raw`, which keeps the tree
/// lossless without requiring a dictionary entry for every relayed AVP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvpData {
    Raw(Vec<u8>),
    Grouped(Vec<Avp>),
}

/// A single AVP in the lossless tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Avp {
    pub code: u32,
    pub vendor: u32,
    /// Wire flags byte (V/M/P) — preserved verbatim on re-encode. Never
    /// re-derived: relaying a peer's message must not silently flip the
    /// M-bit, unlike the typed `encode_avp_*` helpers which force Mandatory.
    pub flags: u8,
    pub value: AvpData,
}

impl Avp {
    /// Build a UTF8String / DiameterIdentity AVP, setting the Mandatory bit
    /// (and the Vendor bit when `vendor != 0`).
    pub fn utf8(code: u32, vendor: u32, value: &str) -> Avp {
        Avp::raw(code, vendor, value.as_bytes().to_vec())
    }

    /// Build an Unsigned32 AVP.
    pub fn u32(code: u32, vendor: u32, value: u32) -> Avp {
        Avp::raw(code, vendor, value.to_be_bytes().to_vec())
    }

    /// Build a Raw-valued AVP with the Mandatory bit (and Vendor bit when
    /// `vendor != 0`) set — the common case for AVPs siphon constructs.
    pub fn raw(code: u32, vendor: u32, value: Vec<u8>) -> Avp {
        let mut flags = AVP_FLAG_MANDATORY;
        if vendor != 0 {
            flags |= AVP_FLAG_VENDOR;
        }
        Avp {
            code,
            vendor,
            flags,
            value: AvpData::Raw(value),
        }
    }

    /// Raw value bytes, if this AVP is not grouped.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        match &self.value {
            AvpData::Raw(bytes) => Some(bytes),
            AvpData::Grouped(_) => None,
        }
    }

    /// Interpret the value as a UTF-8 string (lossy), if not grouped.
    pub fn as_str(&self) -> Option<String> {
        self.raw_bytes()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }

    /// Interpret the value as a big-endian Unsigned32, if not grouped.
    pub fn as_u32(&self) -> Option<u32> {
        match self.raw_bytes() {
            Some(bytes) if bytes.len() >= 4 => {
                Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            }
            _ => None,
        }
    }
}

/// Parse a sequence of AVPs from the AVP region of a message (or the value of
/// a Grouped AVP). Returns an error on a malformed length so the caller can
/// answer with `DIAMETER_INVALID_AVP_LENGTH` rather than silently truncating.
pub fn parse_avps(data: &[u8]) -> Result<Vec<Avp>, DecodeError> {
    let mut avps = Vec::new();
    let mut pos = 0;

    // Loop while a full AVP header (8 bytes minimum) remains. Trailing bytes
    // shorter than a header are padding remnants and ignored.
    while pos + 8 <= data.len() {
        let code = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let flags = data[pos + 4];
        let length = ((data[pos + 5] as usize) << 16)
            | ((data[pos + 6] as usize) << 8)
            | (data[pos + 7] as usize);

        let has_vendor = (flags & AVP_FLAG_VENDOR) != 0;
        let header_size = if has_vendor { 12 } else { 8 };

        if length < header_size {
            return Err(DecodeError::InvalidAvpLength {
                offset: pos,
                length,
                header: header_size,
            });
        }
        if pos + length > data.len() {
            return Err(DecodeError::Truncated {
                offset: pos,
                need: length,
                have: data.len() - pos,
            });
        }

        let vendor = if has_vendor {
            u32::from_be_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
        } else {
            0
        };

        let value_bytes = &data[pos + header_size..pos + length];
        let value = match dictionary::lookup_avp(code, vendor) {
            Some(def) if def.data_type == AvpType::Grouped => {
                AvpData::Grouped(parse_avps(value_bytes)?)
            }
            _ => AvpData::Raw(value_bytes.to_vec()),
        };

        avps.push(Avp {
            code,
            vendor,
            flags,
            value,
        });

        // Advance past the 4-byte-padded AVP. A peer may omit the final AVP's
        // padding inside a Grouped value; clamping keeps us from looping.
        pos += (length + 3) & !3;
    }

    Ok(avps)
}

/// Encode a sequence of AVPs back to wire bytes, each padded to a 4-byte
/// boundary with zero bytes.
pub fn encode_avps(avps: &[Avp]) -> Vec<u8> {
    let mut out = Vec::new();
    for avp in avps {
        encode_one_avp(avp, &mut out);
    }
    out
}

fn encode_one_avp(avp: &Avp, out: &mut Vec<u8>) {
    let owned_group;
    let value: &[u8] = match &avp.value {
        AvpData::Raw(bytes) => bytes,
        AvpData::Grouped(children) => {
            owned_group = encode_avps(children);
            &owned_group
        }
    };

    let has_vendor = (avp.flags & AVP_FLAG_VENDOR) != 0;
    let header_size = if has_vendor { 12 } else { 8 };
    let length = header_size + value.len();
    let padded = (length + 3) & !3;

    let start = out.len();
    out.extend_from_slice(&avp.code.to_be_bytes());
    out.push(avp.flags);
    out.push(((length >> 16) & 0xff) as u8);
    out.push(((length >> 8) & 0xff) as u8);
    out.push((length & 0xff) as u8);
    if has_vendor {
        out.extend_from_slice(&avp.vendor.to_be_bytes());
    }
    out.extend_from_slice(value);
    while out.len() - start < padded {
        out.push(0);
    }
}

/// A Diameter message decoded into the lossless AVP tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterMsg {
    pub flags: u8,
    pub command_code: u32,
    pub application_id: u32,
    pub hop_by_hop: u32,
    pub end_to_end: u32,
    pub avps: Vec<Avp>,
}

impl DiameterMsg {
    /// Decode a complete message (header + AVPs) into the tree.
    pub fn from_wire(msg: &[u8]) -> Result<Self, DecodeError> {
        if msg.len() < 20 {
            return Err(DecodeError::HeaderTooShort(msg.len()));
        }
        let version = msg[0];
        if version != 1 {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        let declared = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        if declared < 20 || declared > msg.len() {
            return Err(DecodeError::LengthMismatch {
                declared,
                actual: msg.len(),
            });
        }
        let flags = msg[4];
        let command_code = ((msg[5] as u32) << 16) | ((msg[6] as u32) << 8) | (msg[7] as u32);
        let application_id = u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let hop_by_hop = u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]);
        let end_to_end = u32::from_be_bytes([msg[16], msg[17], msg[18], msg[19]]);
        let avps = parse_avps(&msg[20..declared])?;

        Ok(DiameterMsg {
            flags,
            command_code,
            application_id,
            hop_by_hop,
            end_to_end,
            avps,
        })
    }

    /// Serialize the tree back to wire bytes, recomputing the message length.
    pub fn to_wire(&self) -> Vec<u8> {
        let avp_bytes = encode_avps(&self.avps);
        encode_diameter_message(
            self.flags,
            self.command_code,
            self.application_id,
            self.hop_by_hop,
            self.end_to_end,
            &avp_bytes,
        )
    }

    pub fn is_request(&self) -> bool {
        (self.flags & FLAG_REQUEST) != 0
    }

    pub fn is_proxiable(&self) -> bool {
        (self.flags & FLAG_PROXIABLE) != 0
    }

    pub fn is_error(&self) -> bool {
        (self.flags & FLAG_ERROR) != 0
    }

    /// First top-level AVP matching (code, vendor).
    pub fn find(&self, code: u32, vendor: u32) -> Option<&Avp> {
        self.avps
            .iter()
            .find(|avp| avp.code == code && avp.vendor == vendor)
    }

    /// All top-level AVPs matching (code, vendor), in order.
    pub fn find_all<'a>(&'a self, code: u32, vendor: u32) -> impl Iterator<Item = &'a Avp> + 'a {
        self.avps
            .iter()
            .filter(move |avp| avp.code == code && avp.vendor == vendor)
    }

    /// Convenience: a base (vendor 0) AVP's value as a UTF-8 string.
    pub fn get_str(&self, code: u32) -> Option<String> {
        self.find(code, 0).and_then(|avp| avp.as_str())
    }

    /// Remove every top-level AVP matching (code, vendor); returns how many
    /// were removed.
    pub fn remove(&mut self, code: u32, vendor: u32) -> usize {
        let before = self.avps.len();
        self.avps
            .retain(|avp| !(avp.code == code && avp.vendor == vendor));
        before - self.avps.len()
    }
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

// ── TBCD / ISDN-AddressString encoding (3GPP TS 29.002 §17.7.8 + TS 23.003 §3.1) ──

/// ISDN-AddressString ToN/NPI byte for "International, E.164" — the only
/// value emitted by the SMSC / IMS core for MT-SMS routing AVPs today.
/// Bit 7 (extension) = 1, ToN = 001 (international), NPI = 0001 (E.164).
pub const TON_NPI_INTERNATIONAL_E164: u8 = 0x91;

/// Encode a digit string as TBCD-STRING per 3GPP TS 29.002 §17.7.8 /
/// TS 23.003 §3.1 — each octet holds two digits packed low-nibble first,
/// odd-length strings padded with 0xF in the final high nibble.
///
/// E.g. `"31"` → `[0x13]`, `"3197010267609"` →
/// `[0x13, 0x79, 0x10, 0x20, 0x76, 0x06, 0xF9]`.
pub fn encode_tbcd_digits(digits: &str) -> Vec<u8> {
    let parsed: Vec<u8> = digits
        .bytes()
        .filter_map(|b| if b.is_ascii_digit() { Some(b - b'0') } else { None })
        .collect();

    let mut result = Vec::with_capacity(parsed.len().div_ceil(2));
    for chunk in parsed.chunks(2) {
        let lo = chunk[0];
        let hi = if chunk.len() > 1 { chunk[1] } else { 0x0f };
        result.push((hi << 4) | lo);
    }
    result
}

/// Decode TBCD-STRING bytes back to a digit string. Stops at the first
/// 0xF filler nibble (TS 23.003 §3.1: F is the only valid filler in the
/// trailing high nibble of an odd-length string).
pub fn decode_tbcd_digits(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for &byte in data {
        let lo = byte & 0x0f;
        let hi = (byte >> 4) & 0x0f;
        if lo <= 9 {
            s.push((b'0' + lo) as char);
        }
        if hi <= 9 {
            s.push((b'0' + hi) as char);
        }
    }
    s
}

/// Encode an E.164 number as an ISDN-AddressString per 3GPP TS 29.002
/// §17.7.8 — one ToN/NPI octet followed by the TBCD digit string.
///
/// Used for MSISDN (701, TS 29.336 §6.4.5), SC-Address (3300, TS 29.336
/// §6.4.6 / TS 29.338 §6.3.2.3), SGSN-Number (1489, TS 29.272 §7.3.102),
/// and MME-Number-for-MT-SMS (1645, TS 29.272 §7.3.146). A leading `+`
/// on the input is stripped — international form is signalled via the
/// ToN/NPI byte, not the literal character.
pub fn encode_isdn_address_string(digits: &str, ton_npi: u8) -> Vec<u8> {
    let tbcd = encode_tbcd_digits(digits);
    let mut result = Vec::with_capacity(1 + tbcd.len());
    result.push(ton_npi);
    result.extend_from_slice(&tbcd);
    result
}

/// Decode an ISDN-AddressString back to a plain digit string. The leading
/// ToN/NPI octet is consumed but not surfaced (callers route on the digit
/// part — siphon does not distinguish international vs national today).
///
/// Be lenient on the receive side: some non-conformant peers omit the
/// ToN/NPI byte and ship raw TBCD. Detection rule — the first byte of an
/// ISDN-AddressString always has bit 7 set (RFC: extension bit), while a
/// TBCD digit-pair byte never does (digits are 0x0-0x9). If bit 7 is
/// clear, treat the whole buffer as TBCD-only.
pub fn decode_isdn_address_string(data: &[u8]) -> String {
    match data.first() {
        Some(&first) if first & 0x80 != 0 => decode_tbcd_digits(&data[1..]),
        _ => decode_tbcd_digits(data),
    }
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
        let msisdn = encode_tbcd_digits("33612345678");
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
    fn tbcd_roundtrip_even_length() {
        let original = "33612345678";
        let encoded = encode_tbcd_digits(original);
        let decoded = decode_tbcd_digits(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn tbcd_roundtrip_odd_length() {
        let original = "3361234567";
        let encoded = encode_tbcd_digits(original);
        let decoded = decode_tbcd_digits(&encoded);
        assert_eq!(decoded, original);
    }

    /// Anchor the exact wire bytes for the bug-report trace's MSISDN.
    /// `"3197010267609"` (13 digits) → TBCD `[0x13, 0x79, 0x10, 0x20,
    /// 0x76, 0x06, 0xF9]` (7 octets); ISDN-AddressString `[0x91, …]`
    /// (8 octets). Compare against pre-fix behaviour where siphon shipped
    /// 13 raw ASCII bytes (`0x33 0x31 0x39 …`).
    #[test]
    fn isdn_address_string_matches_ts_29002_wire_format() {
        let tbcd = encode_tbcd_digits("3197010267609");
        assert_eq!(
            tbcd,
            vec![0x13, 0x79, 0x10, 0x20, 0x76, 0x06, 0xF9],
            "TBCD-encoded MSISDN must nibble-swap each digit pair and \
             pad odd length with 0xF (TS 23.003 §3.1)"
        );

        let isdn = encode_isdn_address_string("3197010267609", TON_NPI_INTERNATIONAL_E164);
        assert_eq!(
            isdn,
            vec![0x91, 0x13, 0x79, 0x10, 0x20, 0x76, 0x06, 0xF9],
            "ISDN-AddressString prepends ToN/NPI 0x91 to the TBCD digits \
             (TS 29.002 §17.7.8)"
        );

        // Leading '+' is conveyed via ToN/NPI, not the literal character.
        let plus = encode_isdn_address_string("+3197010267609", TON_NPI_INTERNATIONAL_E164);
        assert_eq!(plus, isdn);
    }

    #[test]
    fn isdn_address_string_roundtrip() {
        for raw in [
            "31612345678",
            "3197010267609",
            "1",
            "12345",
            "316000000000000",
        ] {
            let encoded = encode_isdn_address_string(raw, TON_NPI_INTERNATIONAL_E164);
            assert_eq!(decode_isdn_address_string(&encoded), raw);
        }
    }

    #[test]
    fn decode_isdn_address_string_tolerates_missing_ton_npi() {
        // Some implementations ship raw TBCD without the ToN/NPI byte.
        // First byte 0x13 has bit 7 clear → treat as TBCD-only.
        let raw_tbcd = vec![0x13, 0x79, 0x10, 0x20, 0x76, 0x06, 0xF9];
        assert_eq!(decode_isdn_address_string(&raw_tbcd), "3197010267609");
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

// ── Lossless AVP tree tests (Phase 0 — Diameter server relay) ───────────────────────────

#[cfg(test)]
mod avp_tree_tests {
    use super::*;

    #[test]
    fn single_avp_no_vendor_roundtrip() {
        let avp = Avp::utf8(dictionary::avp::ORIGIN_HOST, 0, "diam.epc.example.org");
        let wire = encode_avps(std::slice::from_ref(&avp));
        let parsed = parse_avps(&wire).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], avp);
        assert_eq!(parsed[0].as_str().as_deref(), Some("diam.epc.example.org"));
        // No vendor field on the wire (8-byte header).
        assert_eq!(parsed[0].flags & AVP_FLAG_VENDOR, 0);
    }

    #[test]
    fn single_avp_vendor_roundtrip() {
        // 999_001 is outside the dictionary, so it stays Raw (not Grouped).
        let avp = Avp::u32(999_001, dictionary::VENDOR_3GPP, 0xDEAD_BEEF);
        let wire = encode_avps(std::slice::from_ref(&avp));
        let parsed = parse_avps(&wire).unwrap();
        assert_eq!(parsed[0], avp);
        assert_eq!(parsed[0].vendor, dictionary::VENDOR_3GPP);
        assert_ne!(parsed[0].flags & AVP_FLAG_VENDOR, 0);
        assert_eq!(parsed[0].as_u32(), Some(0xDEAD_BEEF));
    }

    #[test]
    fn flags_preserved_verbatim_not_rederived() {
        // An AVP arriving WITHOUT the Mandatory bit must re-encode without it —
        // relaying must never flip the M-bit (unlike encode_avp_* helpers).
        let avp = Avp {
            code: dictionary::avp::ORIGIN_HOST,
            vendor: 0,
            flags: 0, // neither M nor V
            value: AvpData::Raw(b"peer.example.org".to_vec()),
        };
        let wire = encode_avps(std::slice::from_ref(&avp));
        assert_eq!(wire[4], 0, "flags byte must be written verbatim");
        let parsed = parse_avps(&wire).unwrap();
        assert_eq!(parsed[0].flags, 0);
    }

    #[test]
    fn three_byte_value_padded_to_four() {
        let avp = Avp::raw(1, 0, vec![0xAA, 0xBB, 0xCC]);
        let wire = encode_avps(std::slice::from_ref(&avp));
        // 8-byte header + 3-byte value = 11, padded to 12.
        assert_eq!(wire.len(), 12);
        assert_eq!(&wire[11..12], &[0u8], "pad byte must be zero");
        // Declared length is the UNPADDED length (11), per RFC 6733.
        let declared = ((wire[5] as usize) << 16) | ((wire[6] as usize) << 8) | (wire[7] as usize);
        assert_eq!(declared, 11);
        let parsed = parse_avps(&wire).unwrap();
        assert_eq!(parsed[0].raw_bytes(), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn nested_grouped_three_levels_roundtrip() {
        // Vendor-Specific-Application-Id (260) is Grouped in the dictionary;
        // nest it inside two more grouped layers using known grouped codes.
        // Use SIP-Auth-Data-Item (612, 3GPP, Grouped) and Subscription-Id-style
        // nesting via Vendor-Specific-Application-Id children.
        let inner = Avp {
            code: dictionary::avp::VENDOR_SPECIFIC_APPLICATION_ID,
            vendor: 0,
            flags: AVP_FLAG_MANDATORY,
            value: AvpData::Grouped(vec![
                Avp::u32(dictionary::avp::VENDOR_ID, 0, dictionary::VENDOR_3GPP),
                Avp::u32(dictionary::avp::AUTH_APPLICATION_ID, 0, dictionary::CX_APP_ID),
            ]),
        };
        let wire = encode_avps(std::slice::from_ref(&inner));
        let parsed = parse_avps(&wire).unwrap();
        assert_eq!(parsed.len(), 1);
        match &parsed[0].value {
            AvpData::Grouped(children) => {
                assert_eq!(children.len(), 2);
                assert_eq!(children[0].as_u32(), Some(dictionary::VENDOR_3GPP));
                assert_eq!(children[1].as_u32(), Some(dictionary::CX_APP_ID));
            }
            other => panic!("expected grouped, got {other:?}"),
        }
        assert_eq!(parsed[0], inner);
    }

    #[test]
    fn malformed_avp_length_errors() {
        // AVP code (4) + flags (0) + length = 4 (< 8-byte header) → InvalidAvpLength.
        let bad = [0u8, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0];
        let err = parse_avps(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidAvpLength { .. }));
    }

    #[test]
    fn truncated_avp_errors() {
        // Header claims length 100 but only 12 bytes present → Truncated.
        let mut bad = vec![0u8, 0, 0, 1, 0];
        bad.extend_from_slice(&[0, 0, 100]); // length = 100
        bad.extend_from_slice(&[0, 0, 0, 0]);
        let err = parse_avps(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Truncated { .. }));
    }

    #[test]
    fn full_message_from_wire_to_wire() {
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::SESSION_ID, "diam;1;1"));
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_HOST, "mme.example.org"));
        avps.extend_from_slice(&encode_avp_u32(dictionary::avp::RESULT_CODE, 2001));
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_CAPABILITIES_EXCHANGE,
            0,
            0x1122_3344,
            0x5566_7788,
            &avps,
        );

        let msg = DiameterMsg::from_wire(&wire).unwrap();
        assert!(msg.is_request());
        assert!(msg.is_proxiable());
        assert_eq!(msg.hop_by_hop, 0x1122_3344);
        assert_eq!(msg.end_to_end, 0x5566_7788);
        assert_eq!(msg.get_str(dictionary::avp::SESSION_ID).as_deref(), Some("diam;1;1"));

        // Byte-exact round-trip for this well-formed (zero-padded) message.
        assert_eq!(msg.to_wire(), wire);
    }

    #[test]
    fn from_wire_rejects_bad_version_and_length() {
        let mut wire = encode_diameter_message(0, 257, 0, 1, 1, &[]);
        wire[0] = 2; // bad version
        assert!(matches!(
            DiameterMsg::from_wire(&wire),
            Err(DecodeError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            DiameterMsg::from_wire(&[1, 0, 0, 5]),
            Err(DecodeError::HeaderTooShort(4))
        ));
    }

    #[test]
    fn remove_and_find() {
        let mut msg = DiameterMsg {
            flags: FLAG_REQUEST,
            command_code: 257,
            application_id: 0,
            hop_by_hop: 1,
            end_to_end: 1,
            avps: vec![
                Avp::utf8(dictionary::avp::ORIGIN_HOST, 0, "a"),
                Avp::utf8(dictionary::avp::ROUTE_RECORD, 0, "hop1"),
                Avp::utf8(dictionary::avp::ROUTE_RECORD, 0, "hop2"),
            ],
        };
        assert_eq!(msg.find_all(dictionary::avp::ROUTE_RECORD, 0).count(), 2);
        assert_eq!(msg.remove(dictionary::avp::ROUTE_RECORD, 0), 2);
        assert_eq!(msg.find_all(dictionary::avp::ROUTE_RECORD, 0).count(), 0);
        assert!(msg.find(dictionary::avp::ORIGIN_HOST, 0).is_some());
    }

    #[test]
    fn corpus_real_message_structural_roundtrip() {
        // Feed a realistically-shaped message (mixed vendor + grouped) through
        // from_wire → to_wire → from_wire and assert structural stability.
        let mut avps = Vec::new();
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::SESSION_ID, "scscf;42;7"));
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_HOST, "scscf.ims.example.org"));
        avps.extend_from_slice(&encode_avp_utf8(dictionary::avp::ORIGIN_REALM, "ims.example.org"));
        avps.extend_from_slice(&encode_vendor_specific_app_id(
            dictionary::VENDOR_3GPP,
            dictionary::CX_APP_ID,
        ));
        avps.extend_from_slice(&encode_avp_utf8_3gpp(dictionary::avp::PUBLIC_IDENTITY, "sip:alice@ims.example.org"));
        let wire = encode_diameter_message(
            FLAG_REQUEST | FLAG_PROXIABLE,
            dictionary::CMD_MULTIMEDIA_AUTH,
            dictionary::CX_APP_ID,
            7,
            8,
            &avps,
        );

        let first = DiameterMsg::from_wire(&wire).unwrap();
        let second = DiameterMsg::from_wire(&first.to_wire()).unwrap();
        assert_eq!(first, second);
    }
}

#[cfg(test)]
mod avp_tree_proptests {
    use super::*;
    use proptest::prelude::*;

    // Generate an arbitrary leaf AVP (Raw value). Codes avoid the dictionary's
    // Grouped entries so the parser keeps them Raw (matching how they were
    // built), keeping the structural-equality invariant clean.
    fn arb_leaf_avp() -> impl Strategy<Value = Avp> {
        (
            900_000u32..900_100, // codes well outside the dictionary
            prop::option::of(Just(dictionary::VENDOR_3GPP)),
            prop::collection::vec(any::<u8>(), 0..40),
        )
            .prop_map(|(code, vendor, bytes)| {
                let vendor = vendor.unwrap_or(0);
                Avp::raw(code, vendor, bytes)
            })
    }

    fn arb_message() -> impl Strategy<Value = DiameterMsg> {
        (
            any::<u8>(),
            0u32..0x00FF_FFFF,
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            prop::collection::vec(arb_leaf_avp(), 0..12),
        )
            .prop_map(
                |(flags, command_code, application_id, hop_by_hop, end_to_end, avps)| DiameterMsg {
                    flags,
                    command_code,
                    application_id,
                    hop_by_hop,
                    end_to_end,
                    avps,
                },
            )
    }

    proptest! {
        #[test]
        fn structural_roundtrip(msg in arb_message()) {
            let wire = msg.to_wire();
            let reparsed = DiameterMsg::from_wire(&wire).unwrap();
            prop_assert_eq!(reparsed, msg);
        }

        #[test]
        fn output_padding_is_zero(avps in prop::collection::vec(arb_leaf_avp(), 0..12)) {
            // Re-encode and verify every pad byte is zero by re-walking the
            // encoded buffer: each AVP's declared length, padded, must land on
            // a 4-byte boundary with zero fill.
            let wire = encode_avps(&avps);
            let mut pos = 0;
            while pos + 8 <= wire.len() {
                let flags = wire[pos + 4];
                let length = ((wire[pos + 5] as usize) << 16)
                    | ((wire[pos + 6] as usize) << 8)
                    | (wire[pos + 7] as usize);
                let _ = flags;
                let padded = (length + 3) & !3;
                for pad_byte in &wire[pos + length..pos + padded] {
                    prop_assert_eq!(*pad_byte, 0u8);
                }
                pos += padded;
            }
        }
    }
}
