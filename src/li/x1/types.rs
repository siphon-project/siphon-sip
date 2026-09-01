//! The X1 data dictionary as Rust types.
//!
//! Every type here mirrors a simple or complex type from ETSI TS 103 221-1
//! v1.23.1 or the TS 103 280 v2.19.1 dictionary, and every one of them refuses
//! to exist in an invalid state: the constructors enforce the schema's pattern,
//! enumeration and range facets, so a value that reached a struct field is a
//! value the schema accepts.
//!
//! This is deliberately belt-and-braces with the schema validation in
//! [`super::schema`]. The two cover different things:
//!
//! * The validator catches structure — cardinality, ordering, unknown
//!   elements, unknown `xsi:type` — which types cannot express.
//! * The types catch the facets the validator is known to miss. `uppsala`
//!   does not inherit pattern facets through an empty
//!   `<xs:restriction base="…"/>`, which is exactly how TS 103 221-1 derives
//!   [`XId`], [`DId`] and [`X1TransactionId`] from the dictionary's `UUID`.
//!   Those are the primary keys of the entire provisioning model, so they are
//!   parsed into real [`Uuid`]s here.
//!
//! # The IPv6 rule
//!
//! TS 103 280 constrains `IPv6Address` to `([0-9a-f]{4}:){7}([0-9a-f]{4})`:
//! eight groups of exactly four lowercase hex digits, with no `::` compression
//! and no omitted leading zeros. Rust's [`Ipv6Addr`] `Display` produces the
//! *compressed* form, so `to_string()` is wrong here and would fail an ADMF's
//! validator on the first dual-stack destination. Always go through
//! [`format_ipv6`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use uuid::Uuid;

use super::error::{ErrorCode, X1Error};

/// XML namespace of the X1 schema (TS 103 221-1). Unchanged since 2017 and
/// across every published version, so it is a constant rather than config.
pub const NS_X1: &str = "http://uri.etsi.org/03221/X1/2017/10";

/// XML namespace of the TS 103 280 common dictionary.
pub const NS_COMMON: &str = "http://uri.etsi.org/03280/common/2017/07";

/// XML Schema instance namespace, for the `xsi:type` message discriminator.
pub const NS_XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// The schema version this build implements, as it appears on the wire.
///
/// Every X1 message carries `<version>`, so this is not merely a build-time
/// choice — the peer may check it. Overridable via `lawful_intercept.x1.version`
/// so a mediation partner that pins an older version can be accommodated
/// without a code change; the message set is identical across the published
/// v1.x range, so only the declared string differs.
pub const DEFAULT_VERSION: &str = "v1.23.1";

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Parse a TS 103 280 `UUID`: 8-4-4-4-12 lowercase hex.
///
/// Stricter than [`Uuid::parse_str`], which also accepts uppercase, braces and
/// the `urn:uuid:` form. The dictionary's pattern permits none of those, and a
/// value we accepted loosely would be echoed back in a `GetTaskDetails`
/// response and rejected by the ADMF's own validator.
fn parse_dictionary_uuid(value: &str, field: &str) -> Result<Uuid, X1Error> {
    let shaped = value.len() == 36
        && value.as_bytes().iter().enumerate().all(|(index, byte)| {
            match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
            }
        });
    if !shaped {
        return Err(X1Error::syntax(format!(
            "{field} {value:?} is not a TS 103 280 UUID \
             (expected 8-4-4-4-12 lowercase hex)"
        )));
    }
    Uuid::parse_str(value)
        .map_err(|error| X1Error::syntax(format!("{field} {value:?} is not a UUID: {error}")))
}

/// Declare a UUID-shaped newtype (`XId`, `DId`, `X1TransactionId`).
macro_rules! uuid_newtype {
    ($name:ident, $field:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            /// Parse from the wire form, enforcing the dictionary's pattern.
            pub fn parse(value: &str) -> Result<Self, X1Error> {
                parse_dictionary_uuid(value, $field).map(Self)
            }

            /// Wrap an already-known UUID.
            pub fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Mint a fresh random identifier.
            pub fn generate() -> Self {
                Self(Uuid::new_v4())
            }

            /// The underlying UUID.
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }

            /// The 16 raw bytes, as carried in an X2/X3 PDU header.
            pub fn as_bytes(&self) -> [u8; 16] {
                *self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                // `hyphenated` renders lowercase, which is what the pattern wants.
                write!(formatter, "{}", self.0.hyphenated())
            }
        }
    };
}

uuid_newtype!(
    XId,
    "xId",
    "A task identifier (TS 103 221-1 clause 5.1).\n\n\
     This is the identity of a provisioned intercept and the value that goes\n\
     into the 16-byte XID field of every X2 and X3 PDU delivered for it."
);
uuid_newtype!(
    DId,
    "dId",
    "A destination identifier (TS 103 221-1 clause 5.1).\n\n\
     Names a provisioned delivery sink. A task delivers only to the DIDs it\n\
     lists in `listOfDIDs`."
);
uuid_newtype!(
    X1TransactionId,
    "x1TransactionId",
    "Correlates one request message with its response (clause 5.2).\n\n\
     Echoed verbatim on the response, including on an `ErrorResponse`."
);

/// The `admfIdentifier` / `neIdentifier` envelope fields (`xs:token`).
///
/// `xs:token` forbids leading/trailing whitespace, line feeds, tabs and
/// runs of internal spaces. Enforced rather than assumed, because these are
/// compared against certificate details.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Token(String);

impl Token {
    /// Parse, enforcing `xs:token` lexical rules.
    pub fn parse(value: &str, field: &str) -> Result<Self, X1Error> {
        if value.is_empty() {
            return Err(X1Error::syntax(format!("{field} must not be empty")));
        }
        if value.contains(['\n', '\r', '\t'])
            || value.starts_with(' ')
            || value.ends_with(' ')
            || value.contains("  ")
        {
            return Err(X1Error::syntax(format!(
                "{field} {value:?} is not a valid xs:token"
            )));
        }
        Ok(Self(value.to_string()))
    }

    /// A fixed, known-valid token used where a value is structurally required
    /// but none was readable.
    ///
    /// The one caller is the placeholder envelope the decoder builds when a
    /// request message's own envelope could not be parsed: the response
    /// container must still hold a slot for that message, and the slot needs
    /// an envelope. `"unknown"` is a single ASCII word, so it satisfies
    /// `xs:token` by construction and needs no fallible parse.
    pub fn unknown() -> Self {
        Self("unknown".to_string())
    }

    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The `version` envelope field — pattern `v1\.\d+\.\d+`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version(String);

impl Version {
    /// Parse, enforcing the schema's pattern.
    pub fn parse(value: &str) -> Result<Self, X1Error> {
        let Some(rest) = value.strip_prefix("v1.") else {
            return Err(X1Error::new(
                ErrorCode::UnsupportedVersion,
                format!("version {value:?} does not match the pattern v1.<minor>.<patch>"),
            ));
        };
        let mut parts = rest.split('.');
        let valid = match (parts.next(), parts.next(), parts.next()) {
            (Some(minor), Some(patch), None) => {
                !minor.is_empty()
                    && !patch.is_empty()
                    && minor.bytes().all(|b| b.is_ascii_digit())
                    && patch.bytes().all(|b| b.is_ascii_digit())
            }
            _ => false,
        };
        if !valid {
            return Err(X1Error::new(
                ErrorCode::UnsupportedVersion,
                format!("version {value:?} does not match the pattern v1.<minor>.<patch>"),
            ));
        }
        Ok(Self(value.to_string()))
    }

    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Version {
    fn default() -> Self {
        Self(DEFAULT_VERSION.to_string())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A TS 103 280 `LIID` — the handover identifier the mediation function keys on.
///
/// Pattern `([!-~]{1,25})|([0-9a-f]{26,50})`: either 1-25 printable ASCII
/// characters, or 26-50 lowercase hex digits.
///
/// Note this is *not* the task identity. In TS 103 221-1 the LIID lives inside
/// `TaskDetails/listOfMediationDetails/mediationDetails/LIID`; the task's own
/// identity is its [`XId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Liid(String);

impl Liid {
    /// Parse, enforcing the dictionary's pattern.
    pub fn parse(value: &str) -> Result<Self, X1Error> {
        let bytes = value.as_bytes();
        let printable_form =
            (1..=25).contains(&bytes.len()) && bytes.iter().all(|b| (0x21..=0x7e).contains(b));
        let hex_form = (26..=50).contains(&bytes.len())
            && bytes
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
        if !printable_form && !hex_form {
            return Err(X1Error::syntax(format!(
                "LIID {value:?} does not match the TS 103 280 pattern \
                 (1-25 printable ASCII, or 26-50 lowercase hex digits)"
            )));
        }
        Ok(Self(value.to_string()))
    }

    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Liid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// A TS 103 280 `QualifiedMicrosecondDateTime`.
///
/// Pattern requires exactly six fractional digits and an explicit zone. We
/// always emit UTC (`Z`); we accept any explicit offset on the way in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp(String);

impl Timestamp {
    /// The current time, rendered in the schema's form.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// Render a [`SystemTime`] in the schema's form.
    pub fn from_system_time(time: SystemTime) -> Self {
        use chrono::TimeZone;

        // `chrono` is pulled in with default-features off (no `clock`), so
        // there is no `From<SystemTime>` — go through the epoch the same way
        // `asn1::system_time_to_generalized` does.
        let duration = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let datetime = chrono::Utc
            .timestamp_opt(duration.as_secs() as i64, duration.subsec_nanos())
            .single()
            .unwrap_or(chrono::DateTime::UNIX_EPOCH);
        // %.6f is exactly six fractional digits — the pattern accepts no other
        // width, so this format string is load-bearing.
        Self(datetime.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
    }

    /// Parse from the wire.
    ///
    /// Strict on the shape, deliberately lenient on the width of the fractional
    /// second: the dictionary's pattern requires exactly six digits, but real
    /// peers emit milliseconds. sipgate's `li-lib` renders a Java
    /// `XMLGregorianCalendar`, which gives three, and refusing it would mean no
    /// warrant could be provisioned at all — a far worse outcome on a lawful
    /// intercept interface than accepting a timestamp that is merely written
    /// differently while carrying the same instant.
    ///
    /// So: one to nine fractional digits are accepted and **normalised to six**,
    /// which keeps everything siphon subsequently emits conformant even when
    /// its input was not. A deviation is logged rather than absorbed silently,
    /// because it is the operator's to raise with the peer's vendor.
    ///
    /// The strict form is still available as
    /// [`matches_qualified_microsecond`], and what siphon *emits* is always
    /// exactly six digits — see [`Self::from_system_time`].
    pub fn parse(value: &str) -> Result<Self, X1Error> {
        if matches_qualified_microsecond(value) {
            return Ok(Self(value.to_string()));
        }
        if let Some(normalised) = normalise_fractional_seconds(value) {
            tracing::warn!(
                received = %value,
                normalised = %normalised,
                "X1 peer sent a messageTimestamp that is not a TS 103 280 \
                 QualifiedMicrosecondDateTime (the pattern requires exactly six fractional \
                 digits); accepting it and normalising, but the peer is emitting a \
                 schema-invalid timestamp"
            );
            return Ok(Self(normalised));
        }
        Err(X1Error::syntax(format!(
            "messageTimestamp {value:?} is not a QualifiedMicrosecondDateTime \
             (expected YYYY-MM-DDThh:mm:ss.ffffff followed by Z or ±hh:mm)"
        )))
    }

    /// Borrow as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Rewrite a date-time whose fractional second is not six digits into one that
/// is, or `None` when the rest of the shape is wrong.
///
/// Pads a short fraction with zeros and truncates a long one; truncation is
/// safe because sub-microsecond precision is below what the field can carry.
pub(crate) fn normalise_fractional_seconds(value: &str) -> Option<String> {
    let (seconds, rest) = value.split_once('.')?;

    // The part before the fraction must already be `YYYY-MM-DDThh:mm:ss`.
    let bytes = seconds.as_bytes();
    if bytes.len() != 19 {
        return None;
    }
    let digits_at = |positions: &[usize]| positions.iter().all(|i| bytes[*i].is_ascii_digit());
    if !digits_at(&[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]) {
        return None;
    }
    if !(bytes[4] == b'-' && bytes[7] == b'-' && bytes[10] == b'T' && bytes[13] == b':' && bytes[16] == b':')
    {
        return None;
    }

    // Split the fraction from the zone designator that follows it.
    let split = rest.find(['Z', '+', '-']).unwrap_or(rest.len());
    let (fraction, zone) = rest.split_at(split);
    if fraction.is_empty() || fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let zone_ok = match zone.as_bytes() {
        b"Z" => true,
        zone if zone.len() == 6 => {
            (zone[0] == b'+' || zone[0] == b'-')
                && zone[1].is_ascii_digit()
                && zone[2].is_ascii_digit()
                && zone[3] == b':'
                && zone[4].is_ascii_digit()
                && zone[5].is_ascii_digit()
        }
        _ => false,
    };
    if !zone_ok {
        return None;
    }

    let mut micros = fraction.to_string();
    micros.truncate(6);
    while micros.len() < 6 {
        micros.push('0');
    }
    Some(format!("{seconds}.{micros}{zone}"))
}

/// Check the `QualifiedMicrosecondDateTime` pattern:
/// `[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}(Z|[+-][0-9]{2}:[0-9]{2})`
fn matches_qualified_microsecond(value: &str) -> bool {
    let bytes = value.as_bytes();
    // The fixed part up to and including the six fractional digits is 26 bytes.
    if bytes.len() < 27 {
        return false;
    }
    let digits_at = |positions: &[usize]| positions.iter().all(|i| bytes[*i].is_ascii_digit());
    let literal_at = |position: usize, expected: u8| bytes[position] == expected;

    if !digits_at(&[0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25]) {
        return false;
    }
    if !(literal_at(4, b'-')
        && literal_at(7, b'-')
        && literal_at(10, b'T')
        && literal_at(13, b':')
        && literal_at(16, b':')
        && literal_at(19, b'.'))
    {
        return false;
    }
    match &bytes[26..] {
        b"Z" => true,
        zone if zone.len() == 6 => {
            (zone[0] == b'+' || zone[0] == b'-')
                && zone[1].is_ascii_digit()
                && zone[2].is_ascii_digit()
                && zone[3] == b':'
                && zone[4].is_ascii_digit()
                && zone[5].is_ascii_digit()
        }
        _ => false,
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Addresses — where the IPv6 rule bites
// ---------------------------------------------------------------------------

/// Render an IPv6 address in the TS 103 280 form: eight groups of exactly four
/// lowercase hex digits, no compression.
///
/// [`Ipv6Addr`]'s own `Display` produces the RFC 5952 compressed form
/// (`2001:db8::1`), which the dictionary's pattern rejects. Every IPv6 value
/// leaving siphon on X1 goes through here.
pub fn format_ipv6(address: Ipv6Addr) -> String {
    let segments = address.segments();
    let mut out = String::with_capacity(39);
    for (index, segment) in segments.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        // {:04x} is the "exactly four lowercase hex digits" the pattern wants.
        out.push_str(&format!("{segment:04x}"));
    }
    out
}

/// Parse an IPv6 address in the dictionary's fully expanded form.
///
/// Deliberately refuses the compressed and uppercase forms even though
/// [`Ipv6Addr`]'s parser accepts them: an ADMF that sent us a compressed
/// address sent something its own schema rejects, and quietly accepting it
/// would hide the defect until the value came back out of a
/// `GetDestinationDetails`.
pub fn parse_expanded_ipv6(value: &str) -> Result<Ipv6Addr, X1Error> {
    let groups: Vec<&str> = value.split(':').collect();
    let well_formed = groups.len() == 8
        && groups.iter().all(|group| {
            group.len() == 4
                && group
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    if !well_formed {
        return Err(X1Error::syntax(format!(
            "IPv6Address {value:?} is not in the TS 103 280 form — it requires eight \
             groups of exactly four lowercase hex digits with no '::' compression \
             (for example 2001:0db8:0000:0000:0000:0000:0000:0001)"
        )));
    }
    value
        .parse::<Ipv6Addr>()
        .map_err(|error| X1Error::syntax(format!("IPv6Address {value:?} is not valid: {error}")))
}

/// Parse an IPv4 address in the dictionary's dotted-quad form.
pub fn parse_ipv4(value: &str) -> Result<Ipv4Addr, X1Error> {
    value
        .parse::<Ipv4Addr>()
        .map_err(|error| X1Error::syntax(format!("IPv4Address {value:?} is not valid: {error}")))
}

/// A TS 103 280 `Port` — a choice of TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Port {
    /// `TCPPort`.
    Tcp(u16),
    /// `UDPPort`.
    Udp(u16),
}

impl Port {
    /// The port number, whichever transport it names.
    pub fn number(self) -> u16 {
        match self {
            Self::Tcp(port) | Self::Udp(port) => port,
        }
    }

    /// The element name this variant serialises as.
    pub fn element_name(self) -> &'static str {
        match self {
            Self::Tcp(_) => "TCPPort",
            Self::Udp(_) => "UDPPort",
        }
    }
}

/// A TS 103 280 `IPAddressPort` — the delivery address form we use for X2/X3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpAddressPort {
    /// The collector's address.
    pub address: IpAddr,
    /// The collector's port, carrying its transport.
    pub port: Port,
}

impl IpAddressPort {
    /// As a [`std::net::SocketAddr`], for handing to a delivery path.
    pub fn socket_addr(&self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.address, self.port.number())
    }

    /// The address rendered as the schema requires (expanded for IPv6).
    pub fn address_text(&self) -> String {
        match self.address {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format_ipv6(v6),
        }
    }

    /// The element name the address serialises as.
    pub fn address_element_name(&self) -> &'static str {
        match self.address {
            IpAddr::V4(_) => "IPv4Address",
            IpAddr::V6(_) => "IPv6Address",
        }
    }
}

/// A `DeliveryAddress` (TS 103 221-1 clause 6.3.1.2) — a choice of four forms.
///
/// Only [`Self::IpAddressAndPort`] can carry X2/X3 product. The other three are
/// modelled so they round-trip through `GetDestinationDetails` rather than
/// being silently dropped, but a task pointed at one is refused with
/// [`ErrorCode::UnsupportedDeliveryAddressType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryAddress {
    /// `ipAddressAndPort` — the only form siphon can deliver to.
    IpAddressAndPort(IpAddressPort),
    /// `e164Number`.
    E164Number(String),
    /// `uri`.
    Uri(String),
    /// `emailAddress`.
    EmailAddress(String),
}

impl DeliveryAddress {
    /// The socket to deliver to, or `None` for a form siphon cannot deliver to.
    pub fn socket_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            Self::IpAddressAndPort(address) => Some(address.socket_addr()),
            _ => None,
        }
    }

    /// The schema element name of this variant, for error messages.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::IpAddressAndPort(_) => "ipAddressAndPort",
            Self::E164Number(_) => "e164Number",
            Self::Uri(_) => "uri",
            Self::EmailAddress(_) => "emailAddress",
        }
    }
}

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Declare an enum whose variants map 1:1 to an XSD enumeration's values.
macro_rules! xsd_enum {
    ($(#[$meta:meta])* $name:ident, $field:literal, { $($variant:ident => $text:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                #[doc = concat!("`", $text, "`")]
                $variant
            ),+
        }

        impl $name {
            /// The value as it appears in the XML.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $text),+
                }
            }

            /// Parse from the wire, rejecting anything outside the enumeration.
            pub fn parse(value: &str) -> Result<Self, X1Error> {
                match value {
                    $($text => Ok(Self::$variant),)+
                    other => Err(X1Error::syntax(format!(
                        concat!($field, " {:?} is not one of: ", $(" ", $text),+),
                        other
                    ))),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

xsd_enum!(
    /// What a task or destination delivers (TS 103 221-1 clause 6.2.1.2).
    ///
    /// Replaces the two-valued `IriOnly`/`IriAndCc` this module used before,
    /// which had no way to express an X3-only warrant.
    DeliveryType, "deliveryType", {
        X2Only => "X2Only",
        X3Only => "X3Only",
        X2AndX3 => "X2andX3",
    }
);

impl DeliveryType {
    /// Whether this delivery type requires X2 (IRI) delivery.
    pub fn includes_iri(self) -> bool {
        matches!(self, Self::X2Only | Self::X2AndX3)
    }

    /// Whether this delivery type requires X3 (content) delivery.
    ///
    /// The gate on whether a task can be honoured at all: content framing
    /// lives in the media engine, so a node whose media backend cannot emit
    /// X3 must refuse such a task rather than accept it and deliver nothing.
    pub fn includes_content(self) -> bool {
        matches!(self, Self::X3Only | Self::X2AndX3)
    }
}

xsd_enum!(
    /// Mediation-layer delivery type (`MediationDetails/deliveryType`).
    MediationDeliveryType, "deliveryType", {
        Hi2Only => "HI2Only",
        Hi3Only => "HI3Only",
        Hi2AndHi3 => "HI2andHI3",
    }
);

xsd_enum!(
    /// Service scoping (`ServiceType`).
    ServiceType, "serviceType", {
        Voice => "voice",
        Data => "data",
        Messaging => "messaging",
        PushToTalk => "pushToTalk",
        Lals => "LALS",
        Rcs => "RCS",
    }
);

xsd_enum!(
    /// Acknowledgement value on a success response.
    ///
    /// siphon provisions synchronously, so it always answers
    /// `AcknowledgedAndCompleted`; `Acknowledged` exists for the inbound
    /// direction, where the ADMF may answer our reports either way.
    OkValue, "oK", {
        AcknowledgedAndCompleted => "AcknowledgedAndCompleted",
        Acknowledged => "Acknowledged",
    }
);

xsd_enum!(
    /// Provisioning state of a task (`TaskStatus/provisioningStatus`).
    ProvisioningStatus, "provisioningStatus", {
        AwaitingProvisioning => "awaitingProvisioning",
        Failed => "failed",
        Complete => "complete",
    }
);

xsd_enum!(
    /// Delivery state of a destination (`DestinationStatus`).
    DestinationDeliveryStatus, "destinationDeliveryStatus", {
        ActiveAndWorking => "activeAndWorking",
        DeliveryFault => "deliveryFault",
    }
);

xsd_enum!(
    /// Overall NE health (`NeStatusDetails/neStatus`).
    NeStatus, "neStatus", {
        Ok => "OK",
        Faults => "Faults",
    }
);

xsd_enum!(
    /// Why a `ReportTaskIssue` / `ReportDestinationIssue` is being sent.
    TaskReportType, "taskReportType", {
        AllClear => "AllClear",
        Warning => "Warning",
        NonTerminatingFault => "NonTerminatingFault",
        TerminatingFault => "TerminatingFault",
        ImplicitDeactivation => "ImplicitDeactivation",
        FullyActionedAndSuccessful => "FullyActionedAndSuccessful",
        FullyActionedAndUnsuccessful => "FullyActionedAndUnsuccessful",
    }
);

xsd_enum!(
    /// Why a `ReportNEIssue` is being sent.
    TypeOfNeIssueMessage, "typeOfNeIssueMessage", {
        Warning => "Warning",
        FaultCleared => "FaultCleared",
        FaultReport => "FaultReport",
        Alert => "Alert",
    }
);

// ---------------------------------------------------------------------------
// Target identifiers
// ---------------------------------------------------------------------------

/// A target identifier from `TargetIdentifier`'s choice (clause 6.2.1.2).
///
/// The schema offers forty alternatives; siphon intercepts SIP, so it
/// implements the ones an IMS actually keys on, plus the two IP forms. An
/// alternative outside that set decodes to [`Self::Unsupported`] and the task
/// is refused with [`ErrorCode::UnsupportedTargetIdentifierType`] — named, not
/// silently ignored, because an ignored identifier is an intercept that
/// quietly matches nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetIdentifier {
    /// `sipUri` — a SIP or SIPS URI.
    SipUri(String),
    /// `telUri` — a `tel:` URI.
    TelUri(String),
    /// `e164Number` — up to 15 digits, no `+`.
    E164Number(String),
    /// `impu` — IMS Public User Identity.
    Impu(String),
    /// `impi` — IMS Private User Identity.
    Impi(String),
    /// `imsi`.
    Imsi(String),
    /// `imei`.
    Imei(String),
    /// `ipv4Address`.
    Ipv4Address(Ipv4Addr),
    /// `ipv6Address`, held expanded per the dictionary.
    Ipv6Address(Ipv6Addr),
    /// An alternative from the schema that siphon cannot intercept on.
    ///
    /// Carries the element name so the `ErrorResponse` can say which one.
    Unsupported(String),
}

impl TargetIdentifier {
    /// The schema element name this identifier serialises as.
    pub fn element_name(&self) -> &str {
        match self {
            Self::SipUri(_) => "sipUri",
            Self::TelUri(_) => "telUri",
            Self::E164Number(_) => "e164Number",
            Self::Impu(_) => "impu",
            Self::Impi(_) => "impi",
            Self::Imsi(_) => "imsi",
            Self::Imei(_) => "imei",
            Self::Ipv4Address(_) => "ipv4Address",
            Self::Ipv6Address(_) => "ipv6Address",
            Self::Unsupported(name) => name,
        }
    }

    /// The identifier's value rendered as the schema requires.
    pub fn value_text(&self) -> String {
        match self {
            Self::SipUri(value)
            | Self::TelUri(value)
            | Self::E164Number(value)
            | Self::Impu(value)
            | Self::Impi(value)
            | Self::Imsi(value)
            | Self::Imei(value) => value.clone(),
            Self::Ipv4Address(address) => address.to_string(),
            Self::Ipv6Address(address) => format_ipv6(*address),
            Self::Unsupported(_) => String::new(),
        }
    }

    /// Whether siphon can match SIP traffic against this identifier.
    pub fn is_supported(&self) -> bool {
        !matches!(self, Self::Unsupported(_))
    }

    /// Build from a schema element name and its text content.
    ///
    /// Validates the dictionary's pattern for the forms siphon implements.
    /// Any other element name from the choice yields [`Self::Unsupported`];
    /// that is not an error here, because a container holding an unsupported
    /// identifier still has to be answered per-message rather than rejected
    /// wholesale.
    pub fn from_element(name: &str, value: &str) -> Result<Self, X1Error> {
        match name {
            "sipUri" => {
                if !(value.starts_with("sip:") || value.starts_with("sips:")) {
                    return Err(X1Error::syntax(format!(
                        "sipUri {value:?} must begin with sip: or sips:"
                    )));
                }
                Ok(Self::SipUri(value.to_string()))
            }
            "telUri" => {
                if !value.starts_with("tel:") {
                    return Err(X1Error::syntax(format!(
                        "telUri {value:?} must begin with tel:"
                    )));
                }
                Ok(Self::TelUri(value.to_string()))
            }
            "e164Number" => {
                // InternationalE164 is [0-9]{1,15} — digits only, no leading '+'.
                if value.is_empty()
                    || value.len() > 15
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return Err(X1Error::syntax(format!(
                        "e164Number {value:?} must be 1 to 15 digits with no leading '+'"
                    )));
                }
                Ok(Self::E164Number(value.to_string()))
            }
            "impu" => Ok(Self::Impu(value.to_string())),
            "impi" => Ok(Self::Impi(value.to_string())),
            "imsi" => {
                if !(6..=15).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(X1Error::syntax(format!(
                        "imsi {value:?} must be 6 to 15 digits"
                    )));
                }
                Ok(Self::Imsi(value.to_string()))
            }
            "imei" => {
                if value.len() != 14 || !value.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(X1Error::syntax(format!(
                        "imei {value:?} must be exactly 14 digits"
                    )));
                }
                Ok(Self::Imei(value.to_string()))
            }
            "ipv4Address" => parse_ipv4(value).map(Self::Ipv4Address),
            "ipv6Address" => parse_expanded_ipv6(value).map(Self::Ipv6Address),
            other => Ok(Self::Unsupported(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- identifiers ----------------------------------------------------

    #[test]
    fn xid_accepts_the_dictionary_form() {
        let id = XId::parse("11111111-2222-3333-4444-555555555555").unwrap();
        assert_eq!(id.to_string(), "11111111-2222-3333-4444-555555555555");
    }

    #[test]
    fn xid_rejects_what_the_schema_validator_misses() {
        // These are exactly the values `uppsala` lets through, because
        // TS 103 221-1 derives XId via an empty <xs:restriction base="UUID"/>
        // and uppsala does not inherit the pattern facet. The typed layer is
        // the guard for this class.
        assert!(XId::parse("not-a-uuid").is_err());
        assert!(XId::parse("11111111-2222-3333-4444-55555555555").is_err()); // short
        assert!(XId::parse("11111111222233334444555555555555").is_err()); // no hyphens
        assert!(XId::parse("{11111111-2222-3333-4444-555555555555}").is_err()); // braces
        assert!(XId::parse("urn:uuid:11111111-2222-3333-4444-555555555555").is_err());
    }

    #[test]
    fn xid_rejects_uppercase_hex() {
        // The dictionary pattern is lowercase-only. `Uuid::parse_str` would
        // accept this, which is why we pattern-check before parsing.
        assert!(XId::parse("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE").is_err());
        assert!(XId::parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").is_ok());
    }

    #[test]
    fn generated_xid_round_trips_through_its_own_parser() {
        for _ in 0..64 {
            let id = XId::generate();
            let parsed = XId::parse(&id.to_string()).expect("generated XID must be dictionary-valid");
            assert_eq!(id, parsed);
        }
    }

    #[test]
    fn xid_bytes_are_the_x2_x3_pdu_field() {
        let id = XId::parse("000102030405060708090a0b0c0d0e0f".to_string().as_str());
        assert!(id.is_err(), "unhyphenated form must be rejected");
        let id = XId::parse("00010203-0405-0607-0809-0a0b0c0d0e0f").unwrap();
        assert_eq!(
            id.as_bytes(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn token_enforces_xs_token_rules() {
        assert!(Token::parse("admf-id", "admfIdentifier").is_ok());
        assert!(Token::parse("", "admfIdentifier").is_err());
        assert!(Token::parse(" leading", "admfIdentifier").is_err());
        assert!(Token::parse("trailing ", "admfIdentifier").is_err());
        assert!(Token::parse("two  spaces", "admfIdentifier").is_err());
        assert!(Token::parse("with\ttab", "admfIdentifier").is_err());
        assert!(Token::parse("with\nnewline", "admfIdentifier").is_err());
    }

    #[test]
    fn version_enforces_the_pattern() {
        assert_eq!(Version::parse("v1.23.1").unwrap().as_str(), "v1.23.1");
        assert!(Version::parse("v1.15.1").is_ok());
        assert!(Version::parse("1.23.1").is_err()); // no leading v
        assert!(Version::parse("v2.0.0").is_err()); // schema pins v1
        assert!(Version::parse("v1.23").is_err()); // too few parts
        assert!(Version::parse("v1.23.1.0").is_err()); // too many parts
        assert!(Version::parse("v1.x.1").is_err()); // non-digit
    }

    #[test]
    fn default_version_is_itself_valid() {
        assert!(Version::parse(DEFAULT_VERSION).is_ok());
        assert_eq!(Version::default().as_str(), DEFAULT_VERSION);
    }

    #[test]
    fn liid_accepts_both_dictionary_forms() {
        assert!(Liid::parse("LI-2026-0001").is_ok()); // printable ASCII
        assert!(Liid::parse(&"a".repeat(25)).is_ok()); // 25 printable
        assert!(Liid::parse(&"0123456789abcdef".repeat(2)).is_ok()); // 32 hex
        // 26 'a's is over the printable form's 25-char limit but 'a' is a hex
        // digit, so it matches the second alternative. The two branches of the
        // pattern genuinely overlap like this.
        assert!(Liid::parse(&"a".repeat(26)).is_ok());
        assert!(Liid::parse(&"0123456789abcdef".repeat(3)).is_ok()); // 48 hex
        assert!(Liid::parse("").is_err());
        assert!(Liid::parse("has space").is_err()); // space is not in [!-~]
    }

    #[test]
    fn liid_rejects_lengths_between_the_two_alternatives() {
        // 26-50 characters that are printable but not all hex digits satisfy
        // neither branch: too long for [!-~]{1,25}, not hex for [0-9a-f]{26,50}.
        assert!(Liid::parse(&"z".repeat(26)).is_err());
        assert!(Liid::parse(&"z".repeat(50)).is_err());
        assert!(Liid::parse("LI-2026-0001-THIS-IS-FAR-TOO-LONG").is_err());
        // Over 50 hex digits is over both.
        assert!(Liid::parse(&"a".repeat(51)).is_err());
        assert!(Liid::parse(&"0123456789abcdef".repeat(4)).is_err()); // 64 hex
        // Uppercase hex is not in [0-9a-f], so a 26-char uppercase run fails.
        assert!(Liid::parse(&"A".repeat(26)).is_err());
    }

    // -- timestamps -----------------------------------------------------

    #[test]
    fn timestamp_now_matches_the_schema_pattern() {
        let stamp = Timestamp::now();
        assert!(
            matches_qualified_microsecond(stamp.as_str()),
            "generated timestamp {stamp} does not match the schema pattern"
        );
        assert!(Timestamp::parse(stamp.as_str()).is_ok());
    }

    #[test]
    fn timestamp_accepts_the_schema_form_unchanged() {
        let stamp = Timestamp::parse("2026-08-31T09:00:00.123456Z").unwrap();
        assert_eq!(stamp.as_str(), "2026-08-31T09:00:00.123456Z");
    }

    #[test]
    fn timestamp_normalises_a_peer_that_sends_milliseconds() {
        // The real case: sipgate's li-lib renders a Java XMLGregorianCalendar,
        // which gives three fractional digits. The dictionary's pattern wants
        // six. Refusing it would mean no warrant could ever be provisioned, so
        // it is accepted and normalised — and what siphon emits stays exactly
        // six digits.
        let stamp = Timestamp::parse("2026-08-31T16:53:33.632Z").unwrap();
        assert_eq!(stamp.as_str(), "2026-08-31T16:53:33.632000Z");
        assert!(matches_qualified_microsecond(stamp.as_str()));
    }

    #[test]
    fn timestamp_normalises_other_fraction_widths() {
        for (input, want) in [
            ("2026-08-31T09:00:00.1Z", "2026-08-31T09:00:00.100000Z"),
            ("2026-08-31T09:00:00.12Z", "2026-08-31T09:00:00.120000Z"),
            ("2026-08-31T09:00:00.1234567Z", "2026-08-31T09:00:00.123456Z"),
            ("2026-08-31T09:00:00.123456789Z", "2026-08-31T09:00:00.123456Z"),
            ("2026-08-31T09:00:00.632+02:00", "2026-08-31T09:00:00.632000+02:00"),
        ] {
            let stamp = Timestamp::parse(input)
                .unwrap_or_else(|error| panic!("{input} should normalise: {error}"));
            assert_eq!(stamp.as_str(), want, "{input}");
            assert!(matches_qualified_microsecond(stamp.as_str()), "{input}");
        }
    }

    #[test]
    fn timestamp_still_refuses_a_wrong_shape() {
        // Leniency is about the width of the fraction, not about the shape.
        assert!(Timestamp::parse("2026-08-31T09:00:00Z").is_err()); // no fraction at all
        assert!(Timestamp::parse("2026-08-31T09:00:00.").is_err()); // no fraction, no zone
        assert!(Timestamp::parse("2026-08-31 09:00:00.000000Z").is_err()); // space, not T
        assert!(Timestamp::parse("31-08-2026T09:00:00.000000Z").is_err()); // wrong order
        assert!(Timestamp::parse("2026-08-31T09:00:00.abcdefZ").is_err()); // not digits
        assert!(Timestamp::parse("2026-08-31T09:00:00.0000000000Z").is_err()); // ten digits
        assert!(Timestamp::parse("").is_err());
    }

    #[test]
    fn timestamp_requires_an_explicit_zone() {
        assert!(Timestamp::parse("2026-08-31T09:00:00.000000").is_err());
        assert!(Timestamp::parse("2026-08-31T09:00:00.000000+02:00").is_ok());
        assert!(Timestamp::parse("2026-08-31T09:00:00.000000-05:00").is_ok());
        assert!(Timestamp::parse("2026-08-31T09:00:00.000000+0200").is_err());
    }

    #[test]
    fn what_siphon_emits_is_always_the_strict_form() {
        // Leniency is inbound only. Anything siphon puts on the wire must
        // satisfy the pattern exactly, or a conformant peer would reject it.
        for _ in 0..64 {
            let stamp = Timestamp::now();
            assert!(
                matches_qualified_microsecond(stamp.as_str()),
                "emitted {stamp} is not schema-valid"
            );
        }
    }

    #[test]
    fn timestamp_renders_a_known_instant() {
        let epoch = Timestamp::from_system_time(SystemTime::UNIX_EPOCH);
        assert_eq!(epoch.as_str(), "1970-01-01T00:00:00.000000Z");
    }

    // -- the IPv6 rule --------------------------------------------------

    #[test]
    fn format_ipv6_expands_what_display_would_compress() {
        let address: Ipv6Addr = "2001:db8::1".parse().unwrap();
        // What Rust would give us, and what the schema demands.
        assert_eq!(address.to_string(), "2001:db8::1");
        assert_eq!(
            format_ipv6(address),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn format_ipv6_handles_the_all_zero_and_all_ones_edges() {
        assert_eq!(
            format_ipv6(Ipv6Addr::UNSPECIFIED),
            "0000:0000:0000:0000:0000:0000:0000:0000"
        );
        assert_eq!(
            format_ipv6(Ipv6Addr::LOCALHOST),
            "0000:0000:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(
            format_ipv6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        );
    }

    #[test]
    fn format_ipv6_output_always_satisfies_the_dictionary_pattern() {
        // Property: whatever address we are handed, what we emit parses back
        // through the strict reader. This is the guard that keeps a
        // dual-stack node from failing an ADMF's validator.
        let cases = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            "2001:db8::1".parse().unwrap(),
            "fe80::1%0".parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::LOCALHOST),
            "::ffff:192.0.2.1".parse().unwrap(),
            "2001:db8:1c18:6b8c::1".parse().unwrap(),
        ];
        for address in cases {
            let text = format_ipv6(address);
            let reparsed = parse_expanded_ipv6(&text)
                .unwrap_or_else(|error| panic!("emitted {text:?} is not schema-valid: {error}"));
            assert_eq!(reparsed, address);
        }
    }

    #[test]
    fn parse_expanded_ipv6_refuses_the_compressed_form() {
        // TS 103 280 constrains IPv6Address to eight four-digit groups, so the
        // compressed form is invalid however readable it is. Accepting it here
        // would hide a peer's defect rather than surface it.
        assert!(parse_expanded_ipv6("2001:db8::1").is_err());
        assert!(parse_expanded_ipv6("::1").is_err());
        assert!(parse_expanded_ipv6("2001:db8:1c18:6b8c::1").is_err());
    }

    #[test]
    fn parse_expanded_ipv6_refuses_uppercase_and_short_groups() {
        assert!(parse_expanded_ipv6("2001:0DB8:0000:0000:0000:0000:0000:0001").is_err());
        assert!(parse_expanded_ipv6("2001:db8:0:0:0:0:0:1").is_err());
        assert!(parse_expanded_ipv6("2001:0db8:0000:0000:0000:0000:0001").is_err()); // 7 groups
        assert!(parse_expanded_ipv6("2001:0db8:0000:0000:0000:0000:0000:0000:0001").is_err());
    }

    #[test]
    fn parse_expanded_ipv6_accepts_the_expanded_form() {
        let address = parse_expanded_ipv6("2001:0db8:1c18:6b8c:0000:0000:0000:0001").unwrap();
        assert_eq!(
            address,
            "2001:db8:1c18:6b8c::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn ip_address_port_renders_v6_expanded() {
        let endpoint = IpAddressPort {
            address: IpAddr::V6("2001:db8::1".parse().unwrap()),
            port: Port::Tcp(42069),
        };
        assert_eq!(
            endpoint.address_text(),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
        assert_eq!(endpoint.address_element_name(), "IPv6Address");
        assert_eq!(endpoint.socket_addr().port(), 42069);
    }

    #[test]
    fn ip_address_port_renders_v4_plainly() {
        let endpoint = IpAddressPort {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            port: Port::Udp(6544),
        };
        assert_eq!(endpoint.address_text(), "192.0.2.10");
        assert_eq!(endpoint.address_element_name(), "IPv4Address");
        assert_eq!(endpoint.port.element_name(), "UDPPort");
    }

    // -- enumerations ---------------------------------------------------

    #[test]
    fn delivery_type_matches_the_schema_values_exactly() {
        // Note the lowercase 'a' in X2andX3 — a natural-looking "X2AndX3" on
        // the wire would be rejected by the ADMF.
        assert_eq!(DeliveryType::X2Only.as_str(), "X2Only");
        assert_eq!(DeliveryType::X3Only.as_str(), "X3Only");
        assert_eq!(DeliveryType::X2AndX3.as_str(), "X2andX3");
        assert_eq!(DeliveryType::parse("X2andX3").unwrap(), DeliveryType::X2AndX3);
        assert!(DeliveryType::parse("X2AndX3").is_err());
        assert!(DeliveryType::parse("iri_only").is_err());
    }

    #[test]
    fn delivery_type_splits_iri_from_content() {
        assert!(DeliveryType::X2Only.includes_iri());
        assert!(!DeliveryType::X2Only.includes_content());

        assert!(!DeliveryType::X3Only.includes_iri());
        assert!(DeliveryType::X3Only.includes_content());

        assert!(DeliveryType::X2AndX3.includes_iri());
        assert!(DeliveryType::X2AndX3.includes_content());
    }

    #[test]
    fn enum_round_trips() {
        for value in [
            DeliveryType::X2Only,
            DeliveryType::X3Only,
            DeliveryType::X2AndX3,
        ] {
            assert_eq!(DeliveryType::parse(value.as_str()).unwrap(), value);
        }
        for value in [
            TaskReportType::AllClear,
            TaskReportType::Warning,
            TaskReportType::NonTerminatingFault,
            TaskReportType::TerminatingFault,
            TaskReportType::ImplicitDeactivation,
            TaskReportType::FullyActionedAndSuccessful,
            TaskReportType::FullyActionedAndUnsuccessful,
        ] {
            assert_eq!(TaskReportType::parse(value.as_str()).unwrap(), value);
        }
        for value in [
            TypeOfNeIssueMessage::Warning,
            TypeOfNeIssueMessage::FaultCleared,
            TypeOfNeIssueMessage::FaultReport,
            TypeOfNeIssueMessage::Alert,
        ] {
            assert_eq!(TypeOfNeIssueMessage::parse(value.as_str()).unwrap(), value);
        }
    }

    #[test]
    fn ne_status_and_ok_values_match_the_schema_casing() {
        assert_eq!(NeStatus::Ok.as_str(), "OK");
        assert_eq!(NeStatus::Faults.as_str(), "Faults");
        assert_eq!(
            OkValue::AcknowledgedAndCompleted.as_str(),
            "AcknowledgedAndCompleted"
        );
    }

    // -- target identifiers ---------------------------------------------

    #[test]
    fn target_identifier_parses_the_ims_set() {
        assert_eq!(
            TargetIdentifier::from_element("sipUri", "sip:alice@example.com").unwrap(),
            TargetIdentifier::SipUri("sip:alice@example.com".into())
        );
        assert_eq!(
            TargetIdentifier::from_element("telUri", "tel:+15551234567").unwrap(),
            TargetIdentifier::TelUri("tel:+15551234567".into())
        );
        assert_eq!(
            TargetIdentifier::from_element("e164Number", "15551234567").unwrap(),
            TargetIdentifier::E164Number("15551234567".into())
        );
        assert!(TargetIdentifier::from_element("impu", "sip:alice@ims.example").is_ok());
        assert!(TargetIdentifier::from_element("impi", "alice@ims.example").is_ok());
        assert!(TargetIdentifier::from_element("imsi", "001010000000001").is_ok());
        assert!(TargetIdentifier::from_element("imei", "01234567890123").is_ok());
    }

    #[test]
    fn target_identifier_enforces_dictionary_patterns() {
        assert!(TargetIdentifier::from_element("sipUri", "alice@example.com").is_err());
        assert!(TargetIdentifier::from_element("telUri", "+15551234567").is_err());
        // InternationalE164 is digits only — a leading '+' is not in the pattern.
        assert!(TargetIdentifier::from_element("e164Number", "+15551234567").is_err());
        assert!(TargetIdentifier::from_element("e164Number", "1234567890123456").is_err());
        assert!(TargetIdentifier::from_element("imsi", "12345").is_err()); // too short
        assert!(TargetIdentifier::from_element("imei", "0123456789012").is_err()); // 13 digits
    }

    #[test]
    fn target_identifier_ipv6_must_be_expanded() {
        assert!(TargetIdentifier::from_element("ipv6Address", "2001:db8::1").is_err());
        let target = TargetIdentifier::from_element(
            "ipv6Address",
            "2001:0db8:0000:0000:0000:0000:0000:0001",
        )
        .unwrap();
        // And it renders back out expanded.
        assert_eq!(
            target.value_text(),
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        );
    }

    #[test]
    fn unknown_choice_alternative_is_named_not_dropped() {
        // An identifier type siphon cannot intercept on must be visible as
        // such, so ActivateTask can refuse with 3010 naming it, rather than
        // provisioning a task that silently matches nothing.
        let target = TargetIdentifier::from_element("gtpuTunnelId", "42").unwrap();
        assert!(!target.is_supported());
        assert_eq!(target.element_name(), "gtpuTunnelId");
        match target {
            TargetIdentifier::Unsupported(name) => assert_eq!(name, "gtpuTunnelId"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn supported_identifiers_report_themselves_supported() {
        assert!(TargetIdentifier::from_element("sipUri", "sip:a@b.com")
            .unwrap()
            .is_supported());
        assert!(TargetIdentifier::from_element("imsi", "001010000000001")
            .unwrap()
            .is_supported());
    }

    #[test]
    fn delivery_address_reports_its_kind_and_socket() {
        let deliverable = DeliveryAddress::IpAddressAndPort(IpAddressPort {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
            port: Port::Tcp(42069),
        });
        assert_eq!(deliverable.kind(), "ipAddressAndPort");
        assert_eq!(
            deliverable.socket_addr().map(|s| s.to_string()),
            Some("192.0.2.50:42069".to_string())
        );

        let undeliverable = DeliveryAddress::EmailAddress("mdf@example.com".into());
        assert_eq!(undeliverable.kind(), "emailAddress");
        assert!(undeliverable.socket_addr().is_none());
    }
}
