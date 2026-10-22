//! Diameter AVP dictionary for SIPhon.
//!
//! Static lookup table of AVP definitions covering:
//!   - Base Diameter (RFC 6733)
//!   - Credit-Control / Gy (RFC 4006)
//!   - 3GPP Cx/Dx (TS 29.228/229) and Sh (TS 29.329) — IMS
//!   - 3GPP Gx (TS 29.212) and Rx (TS 29.214) — Policy
//!   - 3GPP Ro/Rf (TS 32.299) — IMS Online/Offline Charging

/// How an AVP value is encoded on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvpType {
    OctetString,
    UTF8String,
    Unsigned32,
    Unsigned64,
    Integer32,
    Enumerated,
    Grouped,
    Address,
    Time,
    DiameterIdentity,
    /// An E.164 number as a bare TBCD-string, with no nature-of-address
    /// octet before the digits, which is how the 3GPP specifications define
    /// MSISDN, SC-Address, SGSN-Number, MME-Number-for-MT-SMS and MSC-Number.
    /// Surfaces to scripts as a digit string. See `codec::decode_tbcd_digits`.
    TbcdString,
}

impl AvpType {
    /// Whether this type contains nested AVPs.
    pub fn is_container(&self) -> bool {
        matches!(self, AvpType::Grouped)
    }

    /// Whether this type is text-representable (UTF8String or DiameterIdentity).
    pub fn is_text(&self) -> bool {
        matches!(self, AvpType::UTF8String | AvpType::DiameterIdentity)
    }
}

/// A single AVP definition: code + vendor + human name + wire type.
#[derive(Debug, Clone, Copy)]
pub struct AvpDef {
    pub code: u32,
    pub vendor_id: u32,
    pub name: &'static str,
    pub data_type: AvpType,
}

impl AvpDef {
    /// Whether this AVP is vendor-specific (vendor_id != 0).
    pub fn is_vendor_specific(&self) -> bool {
        self.vendor_id != 0
    }
}

/// 3GPP vendor identifier (IANA enterprise number 10415).
const TGPP: u32 = 10415;

/// Sorted by (vendor_id, code) for binary search.
static AVP_TABLE: &[AvpDef] = &[
    // ── Base Diameter (RFC 6733), vendor_id = 0 ─────────────────────────────
    AvpDef {
        code: 1,
        vendor_id: 0,
        name: "User-Name",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 8,
        vendor_id: 0,
        name: "Framed-IP-Address",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 11,
        vendor_id: 0,
        name: "Filter-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 25,
        vendor_id: 0,
        name: "Class",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 27,
        vendor_id: 0,
        name: "Session-Timeout",
        data_type: AvpType::Unsigned32,
    },
    // The APN of a Gx session (TS 29.212 clause 4.5.1, RFC 7155 clause 4.2.2).
    AvpDef {
        code: 30,
        vendor_id: 0,
        name: "Called-Station-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 33,
        vendor_id: 0,
        name: "Proxy-State",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 44,
        vendor_id: 0,
        name: "Acct-Session-Id",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 50,
        vendor_id: 0,
        name: "Acct-Multi-Session-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 55,
        vendor_id: 0,
        name: "Event-Timestamp",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 85,
        vendor_id: 0,
        name: "Acct-Interim-Interval",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 97,
        vendor_id: 0,
        name: "Framed-IPv6-Prefix",
        data_type: AvpType::OctetString,
    },
    // The digest attributes of RFC 5090, which obsoletes RFC 4590: RADIUS
    // attribute codes, so no vendor. TS 29.229 table 6.3.0.1 reuses them
    // inside SIP-Digest-Authenticate.
    AvpDef {
        code: 104,
        vendor_id: 0,
        name: "Digest-Realm",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 110,
        vendor_id: 0,
        name: "Digest-QoP",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 111,
        vendor_id: 0,
        name: "Digest-Algorithm",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 121,
        vendor_id: 0,
        name: "Digest-HA1",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 257,
        vendor_id: 0,
        name: "Host-IP-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 258,
        vendor_id: 0,
        name: "Auth-Application-Id",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 259,
        vendor_id: 0,
        name: "Acct-Application-Id",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 260,
        vendor_id: 0,
        name: "Vendor-Specific-Application-Id",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 263,
        vendor_id: 0,
        name: "Session-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 264,
        vendor_id: 0,
        name: "Origin-Host",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 265,
        vendor_id: 0,
        name: "Supported-Vendor-Id",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 266,
        vendor_id: 0,
        name: "Vendor-Id",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 267,
        vendor_id: 0,
        name: "Firmware-Revision",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 268,
        vendor_id: 0,
        name: "Result-Code",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 269,
        vendor_id: 0,
        name: "Product-Name",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 270,
        vendor_id: 0,
        name: "Session-Binding",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 274,
        vendor_id: 0,
        name: "Auth-Grace-Period",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 277,
        vendor_id: 0,
        name: "Auth-Session-State",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 278,
        vendor_id: 0,
        name: "Origin-State-Id",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 279,
        vendor_id: 0,
        name: "Failed-AVP",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 281,
        vendor_id: 0,
        name: "Error-Message",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 282,
        vendor_id: 0,
        name: "Route-Record",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 283,
        vendor_id: 0,
        name: "Destination-Realm",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 284,
        vendor_id: 0,
        name: "Proxy-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 285,
        vendor_id: 0,
        name: "Re-Auth-Request-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 291,
        vendor_id: 0,
        name: "Authorization-Lifetime",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 293,
        vendor_id: 0,
        name: "Destination-Host",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 295,
        vendor_id: 0,
        name: "Termination-Cause",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 296,
        vendor_id: 0,
        name: "Origin-Realm",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 297,
        vendor_id: 0,
        name: "Experimental-Result",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 298,
        vendor_id: 0,
        name: "Experimental-Result-Code",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 299,
        vendor_id: 0,
        name: "Inband-Security-Id",
        data_type: AvpType::Unsigned32,
    },
    // ── RFC 8506 (obsoletes RFC 4006) Credit-Control / Gy, vendor_id = 0 ───
    // Codes per the IANA aaa-parameters registry (RFC 8506 §12). The prior
    // table used a self-consistent but non-standard numbering that a real OCS
    // (CGRateS, go-diameter) rejects — every code below is the on-the-wire
    // value.
    AvpDef {
        code: 412,
        vendor_id: 0,
        name: "CC-Input-Octets",
        data_type: AvpType::Unsigned64,
    },
    AvpDef {
        code: 413,
        vendor_id: 0,
        name: "CC-Money",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 414,
        vendor_id: 0,
        name: "CC-Output-Octets",
        data_type: AvpType::Unsigned64,
    },
    AvpDef {
        code: 415,
        vendor_id: 0,
        name: "CC-Request-Number",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 416,
        vendor_id: 0,
        name: "CC-Request-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 417,
        vendor_id: 0,
        name: "CC-Service-Specific-Units",
        data_type: AvpType::Unsigned64,
    },
    AvpDef {
        code: 418,
        vendor_id: 0,
        name: "CC-Session-Failover",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 419,
        vendor_id: 0,
        name: "CC-Sub-Session-Id",
        data_type: AvpType::Unsigned64,
    },
    AvpDef {
        code: 420,
        vendor_id: 0,
        name: "CC-Time",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 421,
        vendor_id: 0,
        name: "CC-Total-Octets",
        data_type: AvpType::Unsigned64,
    },
    AvpDef {
        code: 426,
        vendor_id: 0,
        name: "Credit-Control",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 427,
        vendor_id: 0,
        name: "Credit-Control-Failure-Handling",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 428,
        vendor_id: 0,
        name: "Direct-Debiting-Failure-Handling",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 430,
        vendor_id: 0,
        name: "Final-Unit-Indication",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 431,
        vendor_id: 0,
        name: "Granted-Service-Unit",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 432,
        vendor_id: 0,
        name: "Rating-Group",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 433,
        vendor_id: 0,
        name: "Redirect-Address-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 434,
        vendor_id: 0,
        name: "Redirect-Server",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 435,
        vendor_id: 0,
        name: "Redirect-Server-Address",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 436,
        vendor_id: 0,
        name: "Requested-Action",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 437,
        vendor_id: 0,
        name: "Requested-Service-Unit",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 438,
        vendor_id: 0,
        name: "Restriction-Filter-Rule",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 439,
        vendor_id: 0,
        name: "Service-Identifier",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 443,
        vendor_id: 0,
        name: "Subscription-Id",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 444,
        vendor_id: 0,
        name: "Subscription-Id-Data",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 446,
        vendor_id: 0,
        name: "Used-Service-Unit",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 448,
        vendor_id: 0,
        name: "Validity-Time",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 449,
        vendor_id: 0,
        name: "Final-Unit-Action",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 450,
        vendor_id: 0,
        name: "Subscription-Id-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 451,
        vendor_id: 0,
        name: "Tariff-Time-Change",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 452,
        vendor_id: 0,
        name: "Tariff-Change-Usage",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 453,
        vendor_id: 0,
        name: "G-S-U-Pool-Identifier",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 455,
        vendor_id: 0,
        name: "Multiple-Services-Indicator",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 456,
        vendor_id: 0,
        name: "Multiple-Services-Credit-Control",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 457,
        vendor_id: 0,
        name: "G-S-U-Pool-Reference",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 458,
        vendor_id: 0,
        name: "User-Equipment-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 459,
        vendor_id: 0,
        name: "User-Equipment-Info-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 460,
        vendor_id: 0,
        name: "User-Equipment-Info-Value",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 461,
        vendor_id: 0,
        name: "Service-Context-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 480,
        vendor_id: 0,
        name: "Accounting-Record-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 485,
        vendor_id: 0,
        name: "Accounting-Record-Number",
        data_type: AvpType::Unsigned32,
    },
    // ── 3GPP AVPs, vendor_id = 10415 (sorted by code) ─────────────────────

    // GBA: Zh and Zn (TS 29.109 Table 6.1)
    AvpDef {
        code: 400,
        vendor_id: TGPP,
        name: "GBA-UserSecSettings",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 401,
        vendor_id: TGPP,
        name: "Transaction-Identifier",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 402,
        vendor_id: TGPP,
        name: "NAF-Id",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 403,
        vendor_id: TGPP,
        name: "GAA-Service-Identifier",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 404,
        vendor_id: TGPP,
        name: "Key-ExpiryTime",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 405,
        vendor_id: TGPP,
        name: "ME-Key-Material",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 406,
        vendor_id: TGPP,
        name: "UICC-Key-Material",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 407,
        vendor_id: TGPP,
        name: "GBA_U-Awareness-Indicator",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 408,
        vendor_id: TGPP,
        name: "BootstrapInfoCreationTime",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 409,
        vendor_id: TGPP,
        name: "GUSS-Timestamp",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 410,
        vendor_id: TGPP,
        name: "GBA-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 421,
        vendor_id: TGPP,
        name: "SHA-256-Indication",
        data_type: AvpType::Enumerated,
    },
    // Cx/Dx (TS 29.228/229)
    AvpDef {
        code: 600,
        vendor_id: TGPP,
        name: "Visited-Network-Identifier",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 601,
        vendor_id: TGPP,
        name: "Public-Identity",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 602,
        vendor_id: TGPP,
        name: "Server-Name",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 603,
        vendor_id: TGPP,
        name: "Server-Capabilities",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 604,
        vendor_id: TGPP,
        name: "Mandatory-Capability",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 605,
        vendor_id: TGPP,
        name: "Optional-Capability",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 606,
        vendor_id: TGPP,
        name: "User-Data",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 607,
        vendor_id: TGPP,
        name: "SIP-Number-Auth-Items",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 608,
        vendor_id: TGPP,
        name: "SIP-Authentication-Scheme",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 609,
        vendor_id: TGPP,
        name: "SIP-Authenticate",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 610,
        vendor_id: TGPP,
        name: "SIP-Authorization",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 611,
        vendor_id: TGPP,
        name: "SIP-Authentication-Context",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 612,
        vendor_id: TGPP,
        name: "SIP-Auth-Data-Item",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 613,
        vendor_id: TGPP,
        name: "SIP-Item-Number",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 614,
        vendor_id: TGPP,
        name: "Server-Assignment-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 615,
        vendor_id: TGPP,
        name: "Deregistration-Reason",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 616,
        vendor_id: TGPP,
        name: "Reason-Code",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 617,
        vendor_id: TGPP,
        name: "Reason-Info",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 618,
        vendor_id: TGPP,
        name: "Charging-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 619,
        vendor_id: TGPP,
        name: "Primary-Event-Charging-Function-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 620,
        vendor_id: TGPP,
        name: "Secondary-Event-Charging-Function-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 621,
        vendor_id: TGPP,
        name: "Primary-Charging-Collection-Function-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 622,
        vendor_id: TGPP,
        name: "Secondary-Charging-Collection-Function-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 623,
        vendor_id: TGPP,
        name: "User-Authorization-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 624,
        vendor_id: TGPP,
        name: "User-Data-Already-Available",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 625,
        vendor_id: TGPP,
        name: "Confidentiality-Key",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 626,
        vendor_id: TGPP,
        name: "Integrity-Key",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 628,
        vendor_id: TGPP,
        name: "Supported-Features",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 629,
        vendor_id: TGPP,
        name: "Feature-List-ID",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 630,
        vendor_id: TGPP,
        name: "Feature-List",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 631,
        vendor_id: TGPP,
        name: "Supported-Applications",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 632,
        vendor_id: TGPP,
        name: "Associated-Identities",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 633,
        vendor_id: TGPP,
        name: "Originating-Request",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 635,
        vendor_id: TGPP,
        name: "SIP-Digest-Authenticate",
        data_type: AvpType::Grouped,
    },
    // IMS restoration (TS 23.380; TS 29.229 table 6.3.1 and clauses
    // 6.3.46 to 6.3.52, 6.3.62, 6.3.63, 6.3.70, 6.3.71, 6.3.74 to 6.3.76).
    AvpDef {
        code: 639,
        vendor_id: TGPP,
        name: "SCSCF-Restoration-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 640,
        vendor_id: TGPP,
        name: "Path",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 641,
        vendor_id: TGPP,
        name: "Contact",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 642,
        vendor_id: TGPP,
        name: "Subscription-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 643,
        vendor_id: TGPP,
        name: "Call-ID-SIP-Header",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 644,
        vendor_id: TGPP,
        name: "From-SIP-Header",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 645,
        vendor_id: TGPP,
        name: "To-SIP-Header",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 646,
        vendor_id: TGPP,
        name: "Record-Route",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 647,
        vendor_id: TGPP,
        name: "Associated-Registered-Identities",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 648,
        vendor_id: TGPP,
        name: "Multiple-Registration-Indication",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 649,
        vendor_id: TGPP,
        name: "Restoration-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 654,
        vendor_id: TGPP,
        name: "Initial-CSeq-Sequence-Number",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 655,
        vendor_id: TGPP,
        name: "SAR-Flags",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 660,
        vendor_id: TGPP,
        name: "P-CSCF-Subscription-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 661,
        vendor_id: TGPP,
        name: "Registration-Time-Out",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 662,
        vendor_id: TGPP,
        name: "Alternate-Digest-Algorithm",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 663,
        vendor_id: TGPP,
        name: "Alternate-Digest-HA1",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 664,
        vendor_id: TGPP,
        name: "Failed-PCSCF",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 665,
        vendor_id: TGPP,
        name: "PCSCF-FQDN",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 666,
        vendor_id: TGPP,
        name: "PCSCF-IP-Address",
        data_type: AvpType::Address,
    },
    // Sh (TS 29.329)
    AvpDef {
        code: 700,
        vendor_id: TGPP,
        name: "User-Identity",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 701,
        vendor_id: TGPP,
        name: "MSISDN",
        data_type: AvpType::TbcdString,
    },
    AvpDef {
        code: 702,
        vendor_id: TGPP,
        name: "User-Data-Sh",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 703,
        vendor_id: TGPP,
        name: "Data-Reference",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 704,
        vendor_id: TGPP,
        name: "Service-Indication",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 705,
        vendor_id: TGPP,
        name: "Subs-Req-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 706,
        vendor_id: TGPP,
        name: "Requested-Domain",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 707,
        vendor_id: TGPP,
        name: "Current-Location",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 708,
        vendor_id: TGPP,
        name: "Identity-Set",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 709,
        vendor_id: TGPP,
        name: "Expiry-Time",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 710,
        vendor_id: TGPP,
        name: "Send-Data-Indication",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 711,
        vendor_id: TGPP,
        name: "DSAI-Tag",
        data_type: AvpType::OctetString,
    },
    // Ro/Rf Charging (TS 32.299)
    AvpDef {
        code: 823,
        vendor_id: TGPP,
        name: "Event-Type",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 824,
        vendor_id: TGPP,
        name: "SIP-Method",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 825,
        vendor_id: TGPP,
        name: "Event",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 829,
        vendor_id: TGPP,
        name: "Role-of-Node",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 830,
        vendor_id: TGPP,
        name: "User-Session-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 831,
        vendor_id: TGPP,
        name: "Calling-Party-Address",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 832,
        vendor_id: TGPP,
        name: "Called-Party-Address",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 833,
        vendor_id: TGPP,
        name: "Time-Stamps",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 834,
        vendor_id: TGPP,
        name: "SIP-Request-Timestamp",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 835,
        vendor_id: TGPP,
        name: "SIP-Response-Timestamp",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 836,
        vendor_id: TGPP,
        name: "Application-Server",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 837,
        vendor_id: TGPP,
        name: "Application-Provided-Called-Party-Address",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 838,
        vendor_id: TGPP,
        name: "Inter-Operator-Identifier",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 839,
        vendor_id: TGPP,
        name: "Originating-IOI",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 840,
        vendor_id: TGPP,
        name: "Terminating-IOI",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 841,
        vendor_id: TGPP,
        name: "IMS-Charging-Identifier",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 848,
        vendor_id: TGPP,
        name: "Served-Party-IP-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 850,
        vendor_id: TGPP,
        name: "Application-Server-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 851,
        vendor_id: TGPP,
        name: "Trunk-Group-Id",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 852,
        vendor_id: TGPP,
        name: "Incoming-Trunk-Group-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 853,
        vendor_id: TGPP,
        name: "Outgoing-Trunk-Group-Id",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 854,
        vendor_id: TGPP,
        name: "Bearer-Service",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 861,
        vendor_id: TGPP,
        name: "Cause-Code",
        data_type: AvpType::Integer32,
    },
    AvpDef {
        code: 862,
        vendor_id: TGPP,
        name: "Node-Functionality",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 866,
        vendor_id: TGPP,
        name: "PS-Free-Format-Data",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 868,
        vendor_id: TGPP,
        name: "Time-Quota-Threshold",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 873,
        vendor_id: TGPP,
        name: "Service-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 874,
        vendor_id: TGPP,
        name: "PS-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 876,
        vendor_id: TGPP,
        name: "IMS-Information",
        data_type: AvpType::Grouped,
    },
    // Address Address-Type / Address-Data envelope (TS 32.299 §7.2.8/§7.2.9)
    AvpDef {
        code: 886,
        vendor_id: TGPP,
        name: "Originator-Address",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 897,
        vendor_id: TGPP,
        name: "Address-Data",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 899,
        vendor_id: TGPP,
        name: "Address-Type",
        data_type: AvpType::Enumerated,
    },
    // SMS-Information envelope: Recipient-Address (TS 32.299 §7.2.155)
    AvpDef {
        code: 1201,
        vendor_id: TGPP,
        name: "Recipient-Address",
        data_type: AvpType::Grouped,
    },
    // Charging: Access-Network-Information (TS 32.299), one access-net-spec
    // of the SIP P-Access-Network-Info header, a member of IMS-Information
    AvpDef {
        code: 1263,
        vendor_id: TGPP,
        name: "Access-Network-Information",
        data_type: AvpType::OctetString,
    },
    // S6a / S6d (TS 29.272) — MME/SGSN ↔ HSS for LTE attach + auth vectors
    AvpDef {
        code: 1400,
        vendor_id: TGPP,
        name: "Subscription-Data",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 1401,
        vendor_id: TGPP,
        name: "Terminal-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 1402,
        vendor_id: TGPP,
        name: "IMEI",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 1403,
        vendor_id: TGPP,
        name: "Software-Version",
        data_type: AvpType::UTF8String,
    },
    AvpDef {
        code: 1405,
        vendor_id: TGPP,
        name: "ULR-Flags",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 1406,
        vendor_id: TGPP,
        name: "ULA-Flags",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 1407,
        vendor_id: TGPP,
        name: "Visited-PLMN-Id",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 1408,
        vendor_id: TGPP,
        name: "Requested-EUTRAN-Authentication-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 1410,
        vendor_id: TGPP,
        name: "Number-Of-Requested-Vectors",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 1411,
        vendor_id: TGPP,
        name: "Re-Synchronization-Info",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 1412,
        vendor_id: TGPP,
        name: "Immediate-Response-Preferred",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 1413,
        vendor_id: TGPP,
        name: "Authentication-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 1414,
        vendor_id: TGPP,
        name: "E-UTRAN-Vector",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 1420,
        vendor_id: TGPP,
        name: "Cancellation-Type",
        data_type: AvpType::Enumerated,
    },
    // S13 (TS 29.272 clause 7.3.51), EIR to MME/SGSN
    AvpDef {
        code: 1445,
        vendor_id: TGPP,
        name: "Equipment-Status",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 1447,
        vendor_id: TGPP,
        name: "RAND",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 1448,
        vendor_id: TGPP,
        name: "XRES",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 1449,
        vendor_id: TGPP,
        name: "AUTN",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 1450,
        vendor_id: TGPP,
        name: "KASME",
        data_type: AvpType::OctetString,
    },
    // Terminal-Information member of a 3GPP2 terminal (TS 29.272 clause 7.3.6)
    AvpDef {
        code: 1471,
        vendor_id: TGPP,
        name: "3GPP2-MEID",
        data_type: AvpType::OctetString,
    },
    // S6c served-node identifiers (TS 29.336 / 29.272)
    AvpDef {
        code: 1489,
        vendor_id: TGPP,
        name: "SGSN-Number",
        data_type: AvpType::TbcdString,
    },
    AvpDef {
        code: 1635,
        vendor_id: TGPP,
        name: "PUR-Flags",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 1645,
        vendor_id: TGPP,
        name: "MME-Number-for-MT-SMS",
        data_type: AvpType::TbcdString,
    },
    // SMS-Information block (TS 32.299 §7.2.79 / §7.2.158 / §7.2.171)
    AvpDef {
        code: 2000,
        vendor_id: TGPP,
        name: "SMS-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2001,
        vendor_id: TGPP,
        name: "Data-Coding-Scheme",
        data_type: AvpType::Integer32,
    },
    // Note: Multiple-Services-Credit-Control is base RFC 8506 code 456
    // (vendor 0), listed above — NOT a 3GPP vendor AVP. The prior (2006,10415)
    // entry collided with the real 3GPP Interface-Type and has been removed.
    AvpDef {
        code: 2007,
        vendor_id: TGPP,
        name: "SM-Message-Type",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 2008,
        vendor_id: TGPP,
        name: "Originator-SCCP-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 2009,
        vendor_id: TGPP,
        name: "Originator-Interface",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2010,
        vendor_id: TGPP,
        name: "Recipient-SCCP-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 2011,
        vendor_id: TGPP,
        name: "Reply-Path-Requested",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 2012,
        vendor_id: TGPP,
        name: "SM-Discharge-Time",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 2013,
        vendor_id: TGPP,
        name: "SM-Protocol-ID",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 2014,
        vendor_id: TGPP,
        name: "SM-Status",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 2015,
        vendor_id: TGPP,
        name: "SM-User-Data-Header",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 2016,
        vendor_id: TGPP,
        name: "SMS-Node",
        data_type: AvpType::Enumerated,
    },
    // TS 32.299 §7.2.171: code 2017 is SMSC-Address (the prior "Interface-Id"
    // label was wrong — Interface-Id is 2003 — and was never emitted). The old
    // (2024 Interface-Text / 2025 Interface-Type) rows were likewise mislabeled
    // and unused, so removed rather than left to poison the generic decoder.
    AvpDef {
        code: 2017,
        vendor_id: TGPP,
        name: "SMSC-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 2018,
        vendor_id: TGPP,
        name: "Client-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 2019,
        vendor_id: TGPP,
        name: "Number-of-Messages-Sent",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 2026,
        vendor_id: TGPP,
        name: "Recipient-Info",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2027,
        vendor_id: TGPP,
        name: "Originator-Received-Address",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2028,
        vendor_id: TGPP,
        name: "Recipient-Received-Address",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2029,
        vendor_id: TGPP,
        name: "SM-Service-Type",
        data_type: AvpType::Enumerated,
    },
    // Serving-Node (TS 29.272 §7.3.109) — the grouped AVP an S6c SRA carries the located node in.
    // Without these the SRA reads as "no serving node" and every MT-SMS falls through to the
    // off-net trunk, which is exactly what it looked like before: the SGd path silently unused.
    // Codes cross-checked against Wireshark's own 3GPP Diameter dissector, not just our table.
    AvpDef {
        code: 2041,
        vendor_id: TGPP,
        name: "Start-Time",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 2042,
        vendor_id: TGPP,
        name: "Stop-Time",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 2401,
        vendor_id: TGPP,
        name: "Serving-Node",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 2402,
        vendor_id: TGPP,
        name: "MME-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 2403,
        vendor_id: TGPP,
        name: "MSC-Number",
        data_type: AvpType::TbcdString,
    },
    AvpDef {
        code: 2408,
        vendor_id: TGPP,
        name: "MME-Realm",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 2409,
        vendor_id: TGPP,
        name: "SGSN-Name",
        data_type: AvpType::DiameterIdentity,
    },
    AvpDef {
        code: 2410,
        vendor_id: TGPP,
        name: "SGSN-Realm",
        data_type: AvpType::DiameterIdentity,
    },
    // Charging — Visited Network Identifier (TS 32.299 §7.2.74)
    AvpDef {
        code: 2713,
        vendor_id: TGPP,
        name: "IMS-Visited-Network-Identifier",
        data_type: AvpType::UTF8String,
    },
    // SMS-Information extras (TS 32.299 §7.2.79) interleaved with S6c codes by code order
    AvpDef {
        code: 3010,
        vendor_id: TGPP,
        name: "Application-Port-Identifier",
        data_type: AvpType::Unsigned32,
    },
    // User-Identifier (TS 29.336 §6.3.3) — the grouped AVP naming the subscriber an
    // MO-Forward-Short-Message came from. Its MSISDN child (701) is the only thing in an OFR that
    // says who sent the message; without it a receiving SMSC has nothing but the IMSI, and the
    // recipient cannot reply. The RP-layer names for these addresses (sm-RP-DA / sm-RP-OA) are
    // MAP IEs from TS 29.002 and have no Diameter code point — the RP layer terminates at the
    // serving node.
    AvpDef {
        code: 3102,
        vendor_id: TGPP,
        name: "User-Identifier",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3111,
        vendor_id: TGPP,
        name: "External-Identifier",
        data_type: AvpType::UTF8String,
    },
    // S6c (TS 29.336) and SGd (TS 29.338) — SMS over Diameter
    AvpDef {
        code: 3300,
        vendor_id: TGPP,
        name: "SC-Address",
        data_type: AvpType::TbcdString,
    },
    AvpDef {
        code: 3301,
        vendor_id: TGPP,
        name: "SM-RP-UI",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3308,
        vendor_id: TGPP,
        name: "SM-RP-MTI",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 3316,
        vendor_id: TGPP,
        name: "SM-Delivery-Outcome",
        data_type: AvpType::Grouped,
    },
    // TS 29.338 clauses 5.3.3.15 to 5.3.3.20: the per-node outcomes inside
    // SM-Delivery-Outcome, and the cause and absence diagnostic each carries.
    AvpDef {
        code: 3317,
        vendor_id: TGPP,
        name: "MME-SM-Delivery-Outcome",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3318,
        vendor_id: TGPP,
        name: "MSC-SM-Delivery-Outcome",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3319,
        vendor_id: TGPP,
        name: "SGSN-SM-Delivery-Outcome",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3320,
        vendor_id: TGPP,
        name: "IP-SM-GW-SM-Delivery-Outcome",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3321,
        vendor_id: TGPP,
        name: "SM-Delivery-Cause",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 3322,
        vendor_id: TGPP,
        name: "Absent-User-Diagnostic-SM",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 3324,
        vendor_id: TGPP,
        name: "SMSMI-Correlation-ID",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3332,
        vendor_id: TGPP,
        name: "SMS-GMSC-Address",
        data_type: AvpType::Address,
    },
    // SMS-Information device-trigger / result extras (TS 32.299 §7.2.79).
    // MTC-IWF-Address is 3406 and SMS-Result is 3409 (verified against the
    // go-diameter tgpp_ro_rf dictionary). The prior 3413/3408 codes were wrong
    // — 3408 is SM-Sequence-Number and 3413 is Teleservice — and were emitted
    // on the Rf wire, so a CDF would misparse the SMS record.
    AvpDef {
        code: 3405,
        vendor_id: TGPP,
        name: "SM-Device-Trigger-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3406,
        vendor_id: TGPP,
        name: "MTC-IWF-Address",
        data_type: AvpType::Address,
    },
    AvpDef {
        code: 3407,
        vendor_id: TGPP,
        name: "SM-Device-Trigger-Indicator",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 3409,
        vendor_id: TGPP,
        name: "SMS-Result",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 3410,
        vendor_id: TGPP,
        name: "VCS-Information",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3411,
        vendor_id: TGPP,
        name: "Basic-Service-Code",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3412,
        vendor_id: TGPP,
        name: "Bearer-Capability",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3413,
        vendor_id: TGPP,
        name: "Teleservice",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3414,
        vendor_id: TGPP,
        name: "ISUP-Location-Number",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3415,
        vendor_id: TGPP,
        name: "Forwarding-Pending",
        data_type: AvpType::Enumerated,
    },
    AvpDef {
        code: 3416,
        vendor_id: TGPP,
        name: "ISUP-Cause",
        data_type: AvpType::Grouped,
    },
    AvpDef {
        code: 3417,
        vendor_id: TGPP,
        name: "MSC-Address",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3418,
        vendor_id: TGPP,
        name: "Network-Call-Reference-Number",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3419,
        vendor_id: TGPP,
        name: "Start-of-Charging",
        data_type: AvpType::Time,
    },
    AvpDef {
        code: 3420,
        vendor_id: TGPP,
        name: "VLR-Number",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3422,
        vendor_id: TGPP,
        name: "ISUP-Cause-Diagnostics",
        data_type: AvpType::OctetString,
    },
    AvpDef {
        code: 3423,
        vendor_id: TGPP,
        name: "ISUP-Cause-Location",
        data_type: AvpType::Unsigned32,
    },
    AvpDef {
        code: 3424,
        vendor_id: TGPP,
        name: "ISUP-Cause-Value",
        data_type: AvpType::Unsigned32,
    },
];

/// Look up an AVP definition by (code, vendor_id).
///
/// Uses binary search on the static table (sorted by vendor_id, then code).
pub fn lookup_avp(code: u32, vendor_id: u32) -> Option<&'static AvpDef> {
    if vendor_id == VENDOR_3GPP {
        if let Some(entry) = policy::lookup(code) {
            return Some(&entry.definition);
        }
    }
    AVP_TABLE
        .binary_search_by(|entry| entry.vendor_id.cmp(&vendor_id).then(entry.code.cmp(&code)))
        .ok()
        .map(|idx| &AVP_TABLE[idx])
}

/// Every definition: the main table, then the policy and charging control
/// AVPs of TS 29.212 and TS 29.214 ([`policy`]).
fn all_definitions() -> impl Iterator<Item = &'static AvpDef> {
    AVP_TABLE
        .iter()
        .chain(policy::POLICY_AVPS.iter().map(|entry| &entry.definition))
}

/// Look up an AVP definition by name (linear scan — use sparingly).
pub fn lookup_by_name(name: &str) -> Option<&'static AvpDef> {
    all_definitions().find(|entry| entry.name == name)
}

/// Look up an AVP definition by a Python-style kwarg name. Translates
/// snake_case to kebab-Case (preserving the dictionary's exact casing
/// of acronyms like `MSISDN` or `SM-RP-UI`) and matches
/// case-insensitively. Used by the generic `diameter.send_request`
/// kwarg encoder.
///
/// Examples:
///   "msisdn"                → "MSISDN"
///   "sc_address"            → "SC-Address"
///   "sm_rp_ui"              → "SM-RP-UI"
///   "user_name"             → "User-Name"
pub fn lookup_avp_by_python_name(name: &str) -> Option<&'static AvpDef> {
    // An underscore in the kwarg stands for a hyphen, or for the underscore a
    // few AVP names hold themselves (`GBA_U-Awareness-Indicator`).
    let same = |left: u8, right: u8| {
        let fold = |byte: u8| if byte == b'_' { b'-' } else { byte };
        fold(left).eq_ignore_ascii_case(&fold(right))
    };
    all_definitions().find(|entry| {
        entry.name.len() == name.len()
            && entry
                .name
                .bytes()
                .zip(name.bytes())
                .all(|(left, right)| same(left, right))
    })
}

/// Whether an AVP goes out with the M bit. Every AVP this node builds does,
/// except the few whose specification forbids it: GUSS-Timestamp, which
/// TS 29.109 Table 6.1 lists with "V" under Must and "M" under Must not, and
/// the four base AVPs RFC 6733 section 4.5 lists with M under "MUST NOT":
/// Firmware-Revision (267), Product-Name (269), Error-Message (281) and
/// Error-Reporting-Host (294). The AVPs of IMS restoration, which TS 29.229
/// Table 6.3.1 lists with "V" under Must and "M" under Must not, go without
/// it too. A Gx or Rx AVP goes with the bit its table gives it ([`policy`]).
pub fn avp_is_mandatory(code: u32, vendor_id: u32) -> bool {
    const ERROR_REPORTING_HOST: u32 = 294;
    if vendor_id == VENDOR_3GPP {
        if let Some(entry) = policy::lookup(code) {
            return entry.mandatory;
        }
    }
    match vendor_id {
        VENDOR_3GPP => !matches!(
            code,
            avp::GUSS_TIMESTAMP
                | avp::FEATURE_LIST_ID
                | avp::FEATURE_LIST
                | avp::SCSCF_RESTORATION_INFO..=avp::RESTORATION_INFO
                | avp::INITIAL_CSEQ_SEQUENCE_NUMBER
                | avp::SAR_FLAGS
                | avp::PCSCF_SUBSCRIPTION_INFO
                | avp::REGISTRATION_TIME_OUT
                | avp::FAILED_PCSCF..=avp::PCSCF_IP_ADDRESS
        ),
        0 => !matches!(
            code,
            avp::FIRMWARE_REVISION | avp::PRODUCT_NAME | avp::ERROR_MESSAGE | ERROR_REPORTING_HOST
        ),
        _ => true,
    }
}

/// Look up an AVP name by code (tries vendor=0, then vendor=10415).
pub fn avp_name(code: u32) -> Option<&'static str> {
    lookup_avp(code, 0)
        .or_else(|| lookup_avp(code, VENDOR_3GPP))
        .map(|def| def.name)
}

/// Total number of AVP definitions in the dictionary.
pub fn avp_count() -> usize {
    AVP_TABLE.len() + policy::POLICY_AVPS.len()
}

// ── Application IDs ──────────────────────────────────────────────────────

/// Cx Application-Id (TS 29.228/29.229) — IMS registration/auth
pub const CX_APP_ID: u32 = 16777216;
/// Sh Application-Id (TS 29.328/29.329) — IMS user data
pub const SH_APP_ID: u32 = 16777217;
/// Gx Application-Id (TS 29.212) — Policy and Charging Control
pub const GX_APP_ID: u32 = 16777238;
/// Rx Application-Id (TS 29.214) — QoS/policy (P-CSCF ↔ PCRF/PCF)
pub const RX_APP_ID: u32 = 16777236;
/// Ro Application-Id (RFC 4006 / TS 32.299) — Online Charging
pub const RO_APP_ID: u32 = 4;
/// Rf Application-Id (TS 32.299) — Offline Charging (base accounting)
pub const RF_APP_ID: u32 = 3;
/// S6c Application-Id (TS 29.336) — SMS-over-Diameter, SMSC ↔ HSS
pub const S6C_APP_ID: u32 = 16777312;
/// SGd Application-Id (TS 29.338) — SMS-over-Diameter, SMSC ↔ MME/SGSN
pub const SGD_APP_ID: u32 = 16777313;
/// S6a Application-Id (TS 29.272) — MME ↔ HSS for LTE attach/auth
pub const S6A_APP_ID: u32 = 16777251;
/// S13 Application-Id (TS 29.272 clause 7.1.8): MME or SGSN to EIR for the
/// ME identity check
pub const S13_APP_ID: u32 = 16777252;
/// 3GPP Zh application, BSF to HSS (TS 29.109 clause 6.0)
pub const ZH_APP_ID: u32 = 16777221;
/// 3GPP Zn application, NAF to BSF (TS 29.109 clause 6.0)
pub const ZN_APP_ID: u32 = 16777220;
/// Relay Application-Id (RFC 6733 §2.4): advertised by a relay or redirect
/// agent, and common with every application a peer advertises (§5.3)
pub const RELAY_APP_ID: u32 = 0xffff_ffff;
/// 3GPP Vendor-Id
pub const VENDOR_3GPP: u32 = 10415;

/// Resolve an application name (case-insensitive) to its
/// `(vendor_id, app_id)` tuple. Accepts the canonical short form
/// (`"Cx"`, `"Sh"`, `"Gx"`, `"Rx"`, `"Ro"`, `"Rf"`, `"S6c"`, `"SGd"`, `"S6a"`,
/// `"S13"`, `"Zh"`, `"Zn"`).
pub fn app_id_by_name(name: &str) -> Option<(u32, u32)> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "cx" => Some((VENDOR_3GPP, CX_APP_ID)),
        "sh" => Some((VENDOR_3GPP, SH_APP_ID)),
        "gx" => Some((VENDOR_3GPP, GX_APP_ID)),
        "rx" => Some((VENDOR_3GPP, RX_APP_ID)),
        "ro" => Some((0, RO_APP_ID)),
        "rf" => Some((0, RF_APP_ID)),
        "s6c" => Some((VENDOR_3GPP, S6C_APP_ID)),
        "sgd" => Some((VENDOR_3GPP, SGD_APP_ID)),
        "s6a" => Some((VENDOR_3GPP, S6A_APP_ID)),
        "s13" => Some((VENDOR_3GPP, S13_APP_ID)),
        "zh" => Some((VENDOR_3GPP, ZH_APP_ID)),
        "zn" => Some((VENDOR_3GPP, ZN_APP_ID)),
        _ => None,
    }
}

/// Whether an application-id is a Diameter *accounting* application, which is
/// advertised in the CER/CEA via `Acct-Application-Id (259)` rather than
/// `Auth-Application-Id (258)` (RFC 6733 §2.4 / §6.9). Today only base
/// accounting — Rf (id 3) — is an accounting application; every other app
/// SIPhon speaks (Cx/Sh/Gx/Rx/Ro/S6a/S13/S6c/SGd/Zh/Zn) is an auth application. Advertising
/// an accounting app as an auth app makes strict peers (freeDiameter,
/// go-diameter/CGRateS) answer `DIAMETER_NO_COMMON_APPLICATION`.
pub fn is_accounting_application(app_id: u32) -> bool {
    app_id == RF_APP_ID
}

/// Reverse of [`app_id_by_name`] — returns the canonical short name
/// for an `app_id`. Used when building the dispatch key for inbound
/// `@diameter.on_command(name, application=...)` handlers.
pub fn app_name_by_id(app_id: u32) -> Option<&'static str> {
    match app_id {
        CX_APP_ID => Some("Cx"),
        SH_APP_ID => Some("Sh"),
        GX_APP_ID => Some("Gx"),
        RX_APP_ID => Some("Rx"),
        RO_APP_ID => Some("Ro"),
        RF_APP_ID => Some("Rf"),
        S6C_APP_ID => Some("S6c"),
        SGD_APP_ID => Some("SGd"),
        S6A_APP_ID => Some("S6a"),
        S13_APP_ID => Some("S13"),
        ZH_APP_ID => Some("Zh"),
        ZN_APP_ID => Some("Zn"),
        _ => None,
    }
}

/// Resolve a Diameter command name (case-insensitive, with or without
/// the `-Request` suffix) to its command code. Examples:
///   "Send-Routing-Info-for-SM-Request"   → 8388647
///   "Send-Routing-Info-for-SM"           → 8388647
///   "send-routing-info-for-sm-request"   → 8388647
///   "Multimedia-Auth-Request"            → 303
///   "MAR"                                → 303 (3-letter acronym alias)
pub fn command_code_by_name(name: &str) -> Option<u32> {
    let lower = name.to_ascii_lowercase();
    let stripped = lower
        .strip_suffix("-request")
        .or_else(|| lower.strip_suffix("-answer"))
        .unwrap_or(lower.as_str());
    match stripped {
        // Cx
        "user-authorization" | "uar" | "uaa" => Some(CMD_USER_AUTHORIZATION),
        "server-assignment" | "sar" | "saa" => Some(CMD_SERVER_ASSIGNMENT),
        "location-info" | "lir" | "lia" => Some(CMD_LOCATION_INFO),
        "multimedia-auth" | "mar" | "maa" => Some(CMD_MULTIMEDIA_AUTH),
        "registration-termination" | "rtr" | "rta" => Some(CMD_REGISTRATION_TERMINATION),
        "push-profile" | "ppr" | "ppa" => Some(CMD_PUSH_PROFILE),
        // Sh
        "user-data" | "udr" | "uda" => Some(CMD_SH_USER_DATA),
        "profile-update" | "pur" | "pua" => Some(CMD_SH_PROFILE_UPDATE),
        "subscribe-notifications" | "snr" | "sna" => Some(CMD_SH_SUBSCRIBE_NOTIFICATIONS),
        "push-notification" | "pnr" | "pna" => Some(CMD_SH_PUSH_NOTIFICATION),
        // Gx / Rx / charging
        "credit-control" | "ccr" | "cca" => Some(CMD_CREDIT_CONTROL),
        "re-auth" | "rar" | "raa" => Some(CMD_RE_AUTH),
        "abort-session" | "asr" | "asa" => Some(CMD_ABORT_SESSION),
        "aa" | "aar" | "aaa" => Some(CMD_AA),
        "session-termination" | "str" | "sta" => Some(CMD_SESSION_TERMINATION),
        "accounting" | "acr" | "aca" => Some(CMD_ACCOUNTING),
        // S6c
        "send-routing-info-for-sm" | "srr" | "sra" => Some(CMD_SEND_ROUTING_INFO_FOR_SM),
        "alert-service-centre" | "alert-sc" | "alr" | "ala" => Some(CMD_ALERT_SERVICE_CENTRE),
        "report-sm-delivery-status" | "rsr" | "rsa" => Some(CMD_REPORT_SM_DELIVERY_STATUS),
        // SGd
        "mo-forward-short-message" | "ofr" | "ofa" => Some(CMD_MO_FORWARD_SHORT_MESSAGE),
        "mt-forward-short-message" | "tfr" | "tfa" => Some(CMD_MT_FORWARD_SHORT_MESSAGE),
        // S6a (TS 29.272). Note: "pur" stays mapped to Sh Profile-Update above;
        // S6a Purge-UE is reached via "purge-ue" to avoid the acronym clash.
        "update-location" | "ulr" | "ula" => Some(CMD_UPDATE_LOCATION),
        "cancel-location" | "clr" | "cla" => Some(CMD_CANCEL_LOCATION),
        "authentication-information" | "air" | "aia" => Some(CMD_AUTHENTICATION_INFORMATION),
        "insert-subscriber-data" | "idr" | "ida" => Some(CMD_INSERT_SUBSCRIBER_DATA),
        "delete-subscriber-data" | "dsr" | "dsa" => Some(CMD_DELETE_SUBSCRIBER_DATA),
        "purge-ue" | "pua-s6a" => Some(CMD_PURGE_UE),
        "notify" | "nor" | "noa" => Some(CMD_NOTIFY),
        // S13 (TS 29.272 clause 5.2.4)
        "me-identity-check" | "ecr" | "eca" => Some(CMD_ME_IDENTITY_CHECK),
        // Zn (TS 29.109). Zh has no command of its own: it is "mar" above.
        "bootstrapping-info" | "bir" | "bia" => Some(CMD_BOOTSTRAPPING_INFO),
        // Base
        "capabilities-exchange" | "cer" | "cea" => Some(CMD_CAPABILITIES_EXCHANGE),
        "device-watchdog" | "dwr" | "dwa" => Some(CMD_DEVICE_WATCHDOG),
        "disconnect-peer" | "dpr" | "dpa" => Some(CMD_DISCONNECT_PEER),
        _ => None,
    }
}

/// Reverse of [`command_code_by_name`] — returns the canonical
/// long-form name (without suffix) for a command code. Used when
/// building the dispatch key for inbound `@diameter.on_command`.
pub fn command_name_by_code(code: u32) -> Option<&'static str> {
    Some(match code {
        CMD_USER_AUTHORIZATION => "User-Authorization",
        CMD_SERVER_ASSIGNMENT => "Server-Assignment",
        CMD_LOCATION_INFO => "Location-Info",
        CMD_MULTIMEDIA_AUTH => "Multimedia-Auth",
        CMD_REGISTRATION_TERMINATION => "Registration-Termination",
        CMD_PUSH_PROFILE => "Push-Profile",
        CMD_SH_USER_DATA => "User-Data",
        CMD_SH_PROFILE_UPDATE => "Profile-Update",
        CMD_SH_SUBSCRIBE_NOTIFICATIONS => "Subscribe-Notifications",
        CMD_SH_PUSH_NOTIFICATION => "Push-Notification",
        CMD_CREDIT_CONTROL => "Credit-Control",
        CMD_RE_AUTH => "Re-Auth",
        CMD_ABORT_SESSION => "Abort-Session",
        CMD_AA => "AA",
        CMD_SESSION_TERMINATION => "Session-Termination",
        CMD_ACCOUNTING => "Accounting",
        CMD_SEND_ROUTING_INFO_FOR_SM => "Send-Routing-Info-for-SM",
        CMD_ALERT_SERVICE_CENTRE => "Alert-Service-Centre",
        CMD_REPORT_SM_DELIVERY_STATUS => "Report-SM-Delivery-Status",
        CMD_MO_FORWARD_SHORT_MESSAGE => "MO-Forward-Short-Message",
        CMD_MT_FORWARD_SHORT_MESSAGE => "MT-Forward-Short-Message",
        CMD_BOOTSTRAPPING_INFO => "Bootstrapping-Info",
        CMD_ME_IDENTITY_CHECK => "ME-Identity-Check",
        CMD_CAPABILITIES_EXCHANGE => "Capabilities-Exchange",
        CMD_DEVICE_WATCHDOG => "Device-Watchdog",
        CMD_DISCONNECT_PEER => "Disconnect-Peer",
        _ => return None,
    })
}

// ── Cx/Dx Command Codes (TS 29.228) ────────────────────────────────────

/// User-Authorization-Request/Answer
pub const CMD_USER_AUTHORIZATION: u32 = 300;
/// Server-Assignment-Request/Answer
pub const CMD_SERVER_ASSIGNMENT: u32 = 301;
/// Location-Info-Request/Answer
pub const CMD_LOCATION_INFO: u32 = 302;
/// Multimedia-Auth-Request/Answer
pub const CMD_MULTIMEDIA_AUTH: u32 = 303;
/// Registration-Termination-Request/Answer
pub const CMD_REGISTRATION_TERMINATION: u32 = 304;
/// Push-Profile-Request/Answer
pub const CMD_PUSH_PROFILE: u32 = 305;

// ── Zn Command Code (TS 29.109 clause 6.1) ─────────────────────────────

/// Bootstrapping-Info-Request/Answer
pub const CMD_BOOTSTRAPPING_INFO: u32 = 310;

// ── Sh Command Codes (TS 29.329) ────────────────────────────────────────

/// User-Data-Request/Answer (Sh)
pub const CMD_SH_USER_DATA: u32 = 306;
/// Profile-Update-Request/Answer (Sh)
pub const CMD_SH_PROFILE_UPDATE: u32 = 307;
/// Subscribe-Notifications-Request/Answer (Sh)
pub const CMD_SH_SUBSCRIBE_NOTIFICATIONS: u32 = 308;
/// Push-Notification-Request/Answer (Sh)
pub const CMD_SH_PUSH_NOTIFICATION: u32 = 309;

// ── Gx Command Codes (TS 29.212) ────────────────────────────────────────

/// Credit-Control-Request/Answer (Gx uses 272, same as Gy)
pub const CMD_CREDIT_CONTROL: u32 = 272;
/// Re-Auth-Request/Answer (Gx RAR: PCRF → PGW)
pub const CMD_RE_AUTH: u32 = 258;
/// Abort-Session-Request/Answer
pub const CMD_ABORT_SESSION: u32 = 274;

// ── Rx Command Codes (TS 29.214) ────────────────────────────────────────

/// AA-Request/Answer (Rx: P-CSCF → PCRF)
pub const CMD_AA: u32 = 265;
/// Session-Termination-Request/Answer (Rx)
pub const CMD_SESSION_TERMINATION: u32 = 275;

// ── Ro/Rf Command Codes (TS 32.299) ──────────────────────────────────

/// Accounting-Request/Answer (Rf offline charging)
pub const CMD_ACCOUNTING: u32 = 271;

// ── SGd Command Codes (TS 29.338) ────────────────────────────────────────

/// MO-Forward-Short-Message-Request/Answer (OFR/OFA) — MME → SMSC.
pub const CMD_MO_FORWARD_SHORT_MESSAGE: u32 = 8388645;
/// MT-Forward-Short-Message-Request/Answer (TFR/TFA) — SMSC → MME.
pub const CMD_MT_FORWARD_SHORT_MESSAGE: u32 = 8388646;

// ── S6c Command Codes (TS 29.336) ────────────────────────────────────────

/// Send-Routing-Info-for-SM-Request/Answer (SRR/SRA) — SMSC → HSS.
pub const CMD_SEND_ROUTING_INFO_FOR_SM: u32 = 8388647;
/// Alert-Service-Centre-Request/Answer (ALR/ALA) — HSS → SMSC.
pub const CMD_ALERT_SERVICE_CENTRE: u32 = 8388648;
/// Report-SM-Delivery-Status-Request/Answer (RSR/RSA) — SMSC → HSS.
pub const CMD_REPORT_SM_DELIVERY_STATUS: u32 = 8388649;

// ── S6a Command Codes (TS 29.272) ────────────────────────────────────────

/// Update-Location-Request/Answer (ULR/ULA) — MME → HSS.
pub const CMD_UPDATE_LOCATION: u32 = 316;
/// Cancel-Location-Request/Answer (CLR/CLA) — HSS → MME.
pub const CMD_CANCEL_LOCATION: u32 = 317;
/// Authentication-Information-Request/Answer (AIR/AIA) — MME → HSS.
pub const CMD_AUTHENTICATION_INFORMATION: u32 = 318;
/// Insert-Subscriber-Data-Request/Answer (IDR/IDA) — HSS → MME.
pub const CMD_INSERT_SUBSCRIBER_DATA: u32 = 319;
/// Delete-Subscriber-Data-Request/Answer (DSR/DSA) — HSS → MME.
pub const CMD_DELETE_SUBSCRIBER_DATA: u32 = 320;
/// Purge-UE-Request/Answer (PUR/PUA) — MME → HSS.
pub const CMD_PURGE_UE: u32 = 321;
/// Notify-Request/Answer (NOR/NOA) — MME → HSS.
pub const CMD_NOTIFY: u32 = 323;

// ── S13 Command Code (TS 29.272 clause 7.2.2) ───────────────────────────

/// ME-Identity-Check-Request/Answer (ECR/ECA) — MME or SGSN → EIR.
pub const CMD_ME_IDENTITY_CHECK: u32 = 324;

// ── Equipment-Status values (TS 29.272 clause 7.3.51) ───────────────────

/// The mobile equipment is permitted to be used.
pub const EQUIPMENT_STATUS_PERMITTEDLISTED: u32 = 0;
/// The mobile equipment is prohibited from use.
pub const EQUIPMENT_STATUS_PROHIBITEDLISTED: u32 = 1;
/// The mobile equipment is to be tracked.
pub const EQUIPMENT_STATUS_TRACKINGLISTED: u32 = 2;

// ── Base Diameter Command Codes ──────────────────────────────────────────

pub const CMD_CAPABILITIES_EXCHANGE: u32 = 257;
pub const CMD_DEVICE_WATCHDOG: u32 = 280;
pub const CMD_DISCONNECT_PEER: u32 = 282;

// ── Result Codes ─────────────────────────────────────────────────────────

pub const DIAMETER_SUCCESS: u32 = 2001;
pub const DIAMETER_LIMITED_SUCCESS: u32 = 2002;
pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
pub const DIAMETER_TOO_BUSY: u32 = 3004;
pub const DIAMETER_LOOP_DETECTED: u32 = 3005;
/// CER from a peer whose asserted Origin-Host fails validation (RFC 6733
/// §5.2 / §7.1.3.4) — answered in the CEA, then the connection is closed.
pub const DIAMETER_UNKNOWN_PEER: u32 = 3010;
/// CER from a peer that has no application in common with this node (RFC
/// 6733 §5.3 / §7.1.5). Answered in the CEA, then the connection is closed.
pub const DIAMETER_NO_COMMON_APPLICATION: u32 = 5010;
pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
/// RFC 6733 §7.1.5: a request for a session the receiver does not hold.
pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
/// RFC 6733 section 7.1.5: an AVP with the M bit the receiver does not
/// support. The same number as DIAMETER_ERROR_USER_UNKNOWN, which TS 29.229
/// sends as an Experimental-Result-Code.
pub const DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
/// Malformed AVP length on an inbound message (RFC 6733 §7.1.5).
pub const DIAMETER_INVALID_AVP_LENGTH: u32 = 5014;
pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
pub const DIAMETER_ERROR_ABSENT_USER: u32 = 4201;

// ── 3GPP Experimental Result Codes ──────────────────────────────────────

/// Cx: first registration
pub const DIAMETER_FIRST_REGISTRATION: u32 = 2001;
/// Cx: subsequent registration
pub const DIAMETER_SUBSEQUENT_REGISTRATION: u32 = 2002;
/// Cx: server name not stored
pub const DIAMETER_SERVER_NAME_NOT_STORED: u32 = 2003;
/// Cx: identity not registered
pub const DIAMETER_ERROR_IDENTITY_NOT_REGISTERED: u32 = 5003;
/// Zh: the IMPI or IMPU is unknown to the HSS (TS 29.109 clause 6.2.2.1)
pub const DIAMETER_ERROR_IDENTITY_UNKNOWN: u32 = 5401;
/// Zn: the BSF cannot authorize the request (TS 29.109 clause 6.2.2.2)
pub const DIAMETER_ERROR_NOT_AUTHORIZED: u32 = 5402;
/// Zn: the B-TID is unknown or expired (TS 29.109 clause 6.2.2.3)
pub const DIAMETER_ERROR_TRANSACTION_IDENTIFIER_INVALID: u32 = 5403;
/// S13: the EIR does not know the mobile equipment (TS 29.272 clause 7.4.3.5)
pub const DIAMETER_ERROR_EQUIPMENT_UNKNOWN: u32 = 5422;

// ── Result-Code metric labels ────────────────────────────────────────────

/// Base Result-Codes (RFC 6733 §7.1, RFC 4006 §9) that get a label of their own.
///
/// Deliberately a fixed table rather than `code.to_string()`: the value arrives
/// on the wire from a peer, and one Prometheus series per distinct integer a
/// broken or hostile peer chooses to emit is a cardinality attack on the scrape
/// endpoint. Anything outside this table buckets to its class, so an unlisted
/// code degrades to `5xxx_other` — still useful, never unbounded.
///
/// An incomplete table is therefore safe by construction; extend it when a code
/// turns out to be worth watching on its own.
const KNOWN_RESULT_CODES: &[(u32, &str)] = &[
    (1001, "1001"), // MULTI_ROUND_AUTH
    (2001, "2001"), // SUCCESS
    (2002, "2002"), // LIMITED_SUCCESS
    (3001, "3001"), // COMMAND_UNSUPPORTED
    (3002, "3002"), // UNABLE_TO_DELIVER
    (3003, "3003"), // REALM_NOT_SERVED
    (3004, "3004"), // TOO_BUSY
    (3005, "3005"), // LOOP_DETECTED
    (3007, "3007"), // APPLICATION_UNSUPPORTED
    (3010, "3010"), // UNKNOWN_PEER
    (4001, "4001"), // AUTHENTICATION_REJECTED
    (4002, "4002"), // OUT_OF_SPACE
    (4010, "4010"), // END_USER_SERVICE_DENIED
    (4011, "4011"), // CREDIT_CONTROL_NOT_APPLICABLE
    (4012, "4012"), // CREDIT_LIMIT_REACHED
    (4181, "4181"), // AUTHENTICATION_DATA_UNAVAILABLE (3GPP)
    (4201, "4201"), // ERROR_ABSENT_USER (3GPP)
    (5001, "5001"), // AVP_UNSUPPORTED
    (5002, "5002"), // UNKNOWN_SESSION_ID
    (5003, "5003"), // AUTHORIZATION_REJECTED
    (5004, "5004"), // INVALID_AVP_VALUE
    (5005, "5005"), // MISSING_AVP
    (5009, "5009"), // AVP_OCCURS_TOO_MANY_TIMES
    (5011, "5011"), // UNSUPPORTED_VERSION
    (5012, "5012"), // UNABLE_TO_COMPLY
    (5014, "5014"), // INVALID_AVP_LENGTH
    (5030, "5030"), // USER_UNKNOWN
    (5031, "5031"), // RATING_FAILED
];

/// 3GPP Experimental-Result-Codes worth a label of their own (TS 29.229 Cx,
/// TS 29.329 Sh, TS 29.214 Rx). Labelled `exp:*` so a vendor 5001 is never
/// conflated with base 5001 — they are different failures in different
/// namespaces, and reading one as the other sends you to the wrong subsystem.
const KNOWN_EXPERIMENTAL_RESULT_CODES: &[(u32, &str)] = &[
    (2001, "exp:2001"), // FIRST_REGISTRATION
    (2002, "exp:2002"), // SUBSEQUENT_REGISTRATION
    (2003, "exp:2003"), // UNREGISTERED_SERVICE
    (2004, "exp:2004"), // SUCCESS_SERVER_NAME_NOT_STORED
    (5001, "exp:5001"), // ERROR_USER_UNKNOWN
    (5002, "exp:5002"), // ERROR_IDENTITIES_DONT_MATCH
    (5003, "exp:5003"), // ERROR_IDENTITY_NOT_REGISTERED
    (5004, "exp:5004"), // ERROR_ROAMING_NOT_ALLOWED
    (5005, "exp:5005"), // ERROR_IDENTITY_ALREADY_REGISTERED
    (5006, "exp:5006"), // ERROR_AUTH_SCHEME_NOT_SUPPORTED
    (5007, "exp:5007"), // ERROR_IN_ASSIGNMENT_TYPE
    (5008, "exp:5008"), // ERROR_TOO_MUCH_DATA
    (5061, "exp:5061"), // INVALID_SERVICE_INFORMATION (Rx)
    (5063, "exp:5063"), // REQUESTED_SERVICE_NOT_AUTHORIZED (Rx)
    (5401, "exp:5401"), // ERROR_IDENTITY_UNKNOWN (Zh)
    (5402, "exp:5402"), // ERROR_NOT_AUTHORIZED (Zn)
    (5403, "exp:5403"), // ERROR_TRANSACTION_IDENTIFIER_INVALID (Zn)
    (5422, "exp:5422"), // ERROR_EQUIPMENT_UNKNOWN (S13)
];

/// The class bucket an unlisted Result-Code falls into (RFC 6733 §7.1:
/// 1xxx informational, 2xxx success, 3xxx protocol error, 4xxx transient
/// failure, 5xxx permanent failure).
fn result_code_class(code: u32) -> &'static str {
    match code / 1000 {
        1 => "1xxx_other",
        2 => "2xxx_other",
        3 => "3xxx_other",
        4 => "4xxx_other",
        5 => "5xxx_other",
        _ => "other",
    }
}

/// Bounded metric label for a Result-Code seen on an answer.
///
/// `experimental` selects the 3GPP Experimental-Result-Code namespace, which is
/// labelled `exp:*` and bucketed separately.
///
/// Returns `&'static str`, so labelling an answer allocates nothing and the
/// series set is bounded by these tables at compile time rather than by what a
/// peer chooses to send.
pub fn result_code_label(code: u32, experimental: bool) -> &'static str {
    let table = if experimental {
        KNOWN_EXPERIMENTAL_RESULT_CODES
    } else {
        KNOWN_RESULT_CODES
    };
    if let Some((_, label)) = table.iter().find(|(known, _)| *known == code) {
        return label;
    }
    if experimental {
        // Keep the namespaces distinct in the bucket too, for the same reason
        // the known codes carry the prefix.
        return match code / 1000 {
            1 => "exp:1xxx_other",
            2 => "exp:2xxx_other",
            3 => "exp:3xxx_other",
            4 => "exp:4xxx_other",
            5 => "exp:5xxx_other",
            _ => "exp:other",
        };
    }
    result_code_class(code)
}

/// The Result-Code precedence rule for an answer, as one function.
///
/// An answer carries the base `Result-Code` **or** the 3GPP
/// `Experimental-Result-Code`, not both (TS 29.229 §6.2) — Cx, Sh and Rx report
/// their interface-specific outcomes through the experimental namespace, so for
/// those it is the only code present. When a peer sends both anyway, the base
/// code wins, so one answer is never counted twice or under the wrong namespace.
///
/// Both directions share this: the client side extracts the two values from the
/// decoded JSON view of a received answer, the server side from the lossless
/// tree of an answer it is about to emit. Two extractors, one rule — the two
/// must not be able to disagree about what an answer said.
pub fn answer_result_label(base: Option<u32>, experimental: Option<u32>) -> &'static str {
    match (base, experimental) {
        (Some(code), _) => result_code_label(code, false),
        (None, Some(code)) => result_code_label(code, true),
        // A peer answering with no Result-Code at all is itself worth seeing.
        (None, None) => "none",
    }
}

/// Whether a Result-Code denotes success (RFC 6733 §7.1.2 — the 2xxx class).
pub fn result_code_is_success(code: u32) -> bool {
    (2000..3000).contains(&code)
}

// ── AVP Codes (for encoding) ─────────────────────────────────────────────

pub mod avp;
mod policy;

#[cfg(test)]
mod tests {
    use super::*;

    /// The Gx and Rx AVPs that TS 29.212 table 5.3.1 and TS 29.214 table
    /// 5.3.1 (Rel-18) list with M under "Must not" go without it; their
    /// neighbours in the same tables, listed "M,V", keep it. A reusing
    /// application that overrides the rule (TS 29.272 table 7.3.1/2 "Must
    /// set" for RAT-Type on S6a) sets the bit in its own encoder.
    #[test]
    fn gx_and_rx_avps_the_tables_forbid_the_m_bit_go_without_it() {
        for code in [
            avp::RX_REQUEST_TYPE,
            avp::RAT_TYPE,
            avp::ALLOCATION_RETENTION_PRIORITY,
            avp::APN_AGGREGATE_MAX_BITRATE_DL,
            avp::APN_AGGREGATE_MAX_BITRATE_UL,
            avp::PRIORITY_LEVEL,
            avp::PRE_EMPTION_CAPABILITY,
            avp::PRE_EMPTION_VULNERABILITY,
            avp::DEFAULT_EPS_BEARER_QOS,
            avp::AN_GW_ADDRESS,
            avp::FLOW_INFORMATION,
            avp::FLOW_DIRECTION,
        ] {
            assert!(!avp_is_mandatory(code, VENDOR_3GPP), "AVP {code}");
        }
        for code in [
            avp::CHARGING_RULE_INSTALL,
            avp::CHARGING_RULE_DEFINITION,
            avp::CHARGING_RULE_NAME,
            avp::EVENT_TRIGGER,
            avp::PRECEDENCE,
            avp::QOS_INFORMATION,
            avp::QOS_CLASS_IDENTIFIER,
            avp::IP_CAN_TYPE,
        ] {
            assert!(avp_is_mandatory(code, VENDOR_3GPP), "AVP {code}");
        }
    }

    /// The AVPs a PCRF used to write as raw octets, and the 3GPP-* ones the
    /// Gx and Rx re-used tables take over, each with the code, type and M bit
    /// of its Rel-18 table: TS 29.212 and TS 29.214 table 5.3.0.1, TS 29.061
    /// table 9a.
    #[test]
    fn policy_avps_have_the_code_type_and_m_bit_of_their_table() {
        for (name, code, data_type, mandatory) in [
            ("Revalidation-Time", 1042, AvpType::Time, true),
            ("Rule-Activation-Time", 1043, AvpType::Time, true),
            ("Rule-Deactivation-Time", 1044, AvpType::Time, true),
            ("3GPP-PS-Data-Off-Status", 2847, AvpType::Enumerated, false),
            (
                "Usage-Monitoring-Information",
                1067,
                AvpType::Grouped,
                false,
            ),
            ("Monitoring-Key", 1066, AvpType::OctetString, false),
            ("Packet-Filter-Information", 1061, AvpType::Grouped, false),
            ("RR-Bandwidth", 521, AvpType::Unsigned32, true),
            ("RS-Bandwidth", 522, AvpType::Unsigned32, true),
            ("SIP-Forking-Indication", 523, AvpType::Enumerated, true),
            ("Acceptable-Service-Info", 526, AvpType::Grouped, true),
            (
                "Min-Requested-Bandwidth-DL",
                534,
                AvpType::Unsigned32,
                false,
            ),
            (
                "Min-Requested-Bandwidth-UL",
                535,
                AvpType::Unsigned32,
                false,
            ),
            ("AF-Signalling-Protocol", 529, AvpType::Enumerated, false),
            (
                "Access-Network-Charging-Identifier-Value",
                503,
                AvpType::OctetString,
                true,
            ),
            ("Content-Version", 552, AvpType::Unsigned64, false),
            ("3GPP-SGSN-MCC-MNC", 18, AvpType::UTF8String, false),
            ("3GPP-User-Location-Info", 22, AvpType::OctetString, false),
            ("3GPP-MS-TimeZone", 23, AvpType::OctetString, false),
        ] {
            let definition = lookup_by_name(name).unwrap_or_else(|| panic!("{name} is defined"));
            assert_eq!(
                (definition.code, definition.vendor_id),
                (code, VENDOR_3GPP),
                "{name}"
            );
            assert_eq!(definition.data_type, data_type, "{name}");
            assert_eq!(
                lookup_avp(code, VENDOR_3GPP).map(|found| found.name),
                Some(name)
            );
            assert_eq!(avp_is_mandatory(code, VENDOR_3GPP), mandatory, "{name}");
        }
        assert_eq!(
            lookup_avp_by_python_name("revalidation_time").map(|found| found.code),
            Some(1042)
        );
    }

    #[test]
    fn the_policy_table_is_sorted_and_shares_no_code_with_the_main_table() {
        for pair in policy::POLICY_AVPS.windows(2) {
            assert!(
                pair[0].definition.code < pair[1].definition.code,
                "policy table not sorted at {}",
                pair[1].definition.name
            );
        }
        for entry in policy::POLICY_AVPS {
            let code = entry.definition.code;
            assert!(
                !AVP_TABLE
                    .iter()
                    .any(|main| main.vendor_id == VENDOR_3GPP && main.code == code),
                "{} is defined twice",
                entry.definition.name
            );
        }
    }

    #[test]
    fn known_result_codes_label_as_themselves() {
        assert_eq!(result_code_label(2001, false), "2001");
        assert_eq!(result_code_label(4012, false), "4012");
        assert_eq!(result_code_label(5012, false), "5012");
    }

    #[test]
    fn unknown_result_codes_bucket_to_their_class() {
        // The cardinality bound: a code siphon does not know must never mint a
        // series of its own, because the value comes off the wire from a peer.
        assert_eq!(result_code_label(4999, false), "4xxx_other");
        assert_eq!(result_code_label(5099, false), "5xxx_other");
        assert_eq!(result_code_label(3999, false), "3xxx_other");
        assert_eq!(result_code_label(2999, false), "2xxx_other");
        assert_eq!(result_code_label(1999, false), "1xxx_other");
        // Outside every defined class — still one fixed label, not a new series.
        assert_eq!(result_code_label(9999, false), "other");
        assert_eq!(result_code_label(0, false), "other");
    }

    #[test]
    fn experimental_codes_keep_their_own_namespace() {
        // A 3GPP Experimental-Result-Code 5001 (ERROR_USER_UNKNOWN) and a base
        // Result-Code 5001 (AVP_UNSUPPORTED) are different failures in
        // different subsystems. Sharing a series would send an operator to the
        // wrong one.
        assert_eq!(result_code_label(5001, true), "exp:5001");
        assert_eq!(result_code_label(5001, false), "5001");
        assert_ne!(
            result_code_label(5001, true),
            result_code_label(5001, false)
        );

        assert_eq!(result_code_label(2001, true), "exp:2001");
        assert_eq!(result_code_label(5099, true), "exp:5xxx_other");
        assert_eq!(result_code_label(9999, true), "exp:other");
    }

    #[test]
    fn every_label_is_bounded_across_the_whole_u32_range() {
        // The property that actually protects the scrape endpoint: whatever a
        // peer sends, the label set stays finite. Sampled rather than
        // exhaustive over 2^32, but dense across the ranges peers use.
        use std::collections::HashSet;
        let mut labels = HashSet::new();
        for code in (0..70_000).chain(4_294_967_000..=u32::MAX) {
            labels.insert(result_code_label(code, false));
            labels.insert(result_code_label(code, true));
        }
        let ceiling = KNOWN_RESULT_CODES.len() + KNOWN_EXPERIMENTAL_RESULT_CODES.len() + 12;
        assert!(
            labels.len() <= ceiling,
            "result-code labels are unbounded: {} distinct labels from a range \
             a peer controls (ceiling {ceiling})",
            labels.len()
        );
    }

    #[test]
    fn success_is_the_2xxx_class() {
        assert!(result_code_is_success(2001));
        assert!(result_code_is_success(2002));
        assert!(!result_code_is_success(1001));
        assert!(!result_code_is_success(3002));
        assert!(!result_code_is_success(4012));
        assert!(!result_code_is_success(5012));
    }

    #[test]
    fn table_ordering_is_valid() {
        for pair in AVP_TABLE.windows(2) {
            let left = (pair[0].vendor_id, pair[0].code);
            let right = (pair[1].vendor_id, pair[1].code);
            assert!(
                left < right,
                "table not sorted at {} (v={}) vs {} (v={})",
                pair[0].name,
                pair[0].vendor_id,
                pair[1].name,
                pair[1].vendor_id,
            );
        }
    }

    #[test]
    fn base_diameter_session_id() {
        let entry = lookup_avp(263, 0).unwrap();
        assert_eq!(entry.name, "Session-Id");
        assert!(entry.data_type.is_text());
        assert!(!entry.is_vendor_specific());
    }

    #[test]
    fn base_diameter_result_code() {
        let entry = lookup_avp(268, 0).unwrap();
        assert_eq!(entry.name, "Result-Code");
        assert_eq!(entry.data_type, AvpType::Unsigned32);
    }

    #[test]
    fn vendor_specific_cx_server_name() {
        let entry = lookup_avp(602, TGPP).unwrap();
        assert_eq!(entry.name, "Server-Name");
        assert!(entry.is_vendor_specific());
        assert!(entry.data_type.is_text());
    }

    #[test]
    fn grouped_avps_are_containers() {
        let auth_data = lookup_avp(612, TGPP).unwrap();
        assert_eq!(auth_data.name, "SIP-Auth-Data-Item");
        assert!(auth_data.data_type.is_container());
    }

    /// TS 29.229 table 6.3.0.1 and clause 6.3.36: SIP-Digest-Authenticate is
    /// 635 of the 3GPP vendor and groups Digest-Realm (104), Digest-QoP (110),
    /// Digest-Algorithm (111) and Digest-HA1 (121), the codes RFC 5090
    /// assigns as RADIUS attributes and so without a vendor, and the
    /// 3GPP pair Alternate-Digest-Algorithm (662) and Alternate-Digest-HA1
    /// (663). All but the group are UTF8String.
    #[test]
    fn sip_digest_avps_have_the_codes_of_ts_29_229() {
        for (code, vendor, name) in [
            (104, 0, "Digest-Realm"),
            (110, 0, "Digest-QoP"),
            (111, 0, "Digest-Algorithm"),
            (121, 0, "Digest-HA1"),
            (662, TGPP, "Alternate-Digest-Algorithm"),
            (663, TGPP, "Alternate-Digest-HA1"),
        ] {
            let definition = lookup_avp(code, vendor).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(definition.name, name);
            assert_eq!(definition.data_type, AvpType::UTF8String, "{name}");
            let by_name = lookup_avp_by_python_name(name).unwrap();
            assert_eq!((by_name.code, by_name.vendor_id), (code, vendor), "{name}");
        }
        let group = lookup_avp(635, TGPP).unwrap();
        assert_eq!(group.name, "SIP-Digest-Authenticate");
        assert!(group.data_type.is_container());
    }

    #[test]
    fn unknown_code_returns_none() {
        assert!(lookup_avp(65535, 0).is_none());
        assert!(lookup_avp(1, 99999).is_none());
    }

    #[test]
    fn lookup_by_name_finds_entries() {
        let entry = lookup_by_name("Origin-Host").unwrap();
        assert_eq!(entry.code, 264);
        assert_eq!(entry.vendor_id, 0);

        let entry = lookup_by_name("Public-Identity").unwrap();
        assert_eq!(entry.code, 601);
        assert_eq!(entry.vendor_id, TGPP);

        assert!(lookup_by_name("Nonexistent-AVP").is_none());
    }

    #[test]
    fn avp_count_is_substantial() {
        assert!(
            avp_count() > 100,
            "dictionary should have > 100 AVP entries"
        );
    }

    #[test]
    fn credit_control_avp_codes_match_rfc8506() {
        // Spec oracle (NOT a round-trip): AVP name -> (code, vendor). Base
        // Credit-Control codes are from the IANA aaa-parameters registry
        // (RFC 8506 §12); the vendor-10415 charging AVPs are from 3GPP
        // TS 32.299. This fails if the dictionary drifts from the on-the-wire
        // values a real OCS/CDF (CGRateS, go-diameter) expects — the class of
        // bug that made the prior self-consistent-but-wrong table pass its own
        // encode/decode round-trips while being rejected on the wire.
        let reference: &[(&str, u32, u32)] = &[
            // RFC 8506 Credit-Control (vendor 0)
            ("CC-Input-Octets", 412, 0),
            ("CC-Money", 413, 0),
            ("CC-Output-Octets", 414, 0),
            ("CC-Request-Number", 415, 0),
            ("CC-Request-Type", 416, 0),
            ("CC-Service-Specific-Units", 417, 0),
            ("CC-Session-Failover", 418, 0),
            ("CC-Sub-Session-Id", 419, 0),
            ("CC-Time", 420, 0),
            ("CC-Total-Octets", 421, 0),
            ("Credit-Control-Failure-Handling", 427, 0),
            ("Final-Unit-Indication", 430, 0),
            ("Granted-Service-Unit", 431, 0),
            ("Rating-Group", 432, 0),
            ("Redirect-Address-Type", 433, 0),
            ("Redirect-Server", 434, 0),
            ("Redirect-Server-Address", 435, 0),
            ("Requested-Action", 436, 0),
            ("Requested-Service-Unit", 437, 0),
            ("Service-Identifier", 439, 0),
            ("Subscription-Id", 443, 0),
            ("Subscription-Id-Data", 444, 0),
            ("Used-Service-Unit", 446, 0),
            ("Validity-Time", 448, 0),
            ("Final-Unit-Action", 449, 0),
            ("Subscription-Id-Type", 450, 0),
            ("Tariff-Time-Change", 451, 0),
            ("G-S-U-Pool-Identifier", 453, 0),
            ("Multiple-Services-Indicator", 455, 0),
            ("Multiple-Services-Credit-Control", 456, 0),
            ("G-S-U-Pool-Reference", 457, 0),
            ("User-Equipment-Info", 458, 0),
            ("User-Equipment-Info-Type", 459, 0),
            ("User-Equipment-Info-Value", 460, 0),
            ("Service-Context-Id", 461, 0),
            // 3GPP charging AVPs emitted on the Rf/Ro wire (vendor 10415)
            ("Service-Information", 873, TGPP),
            ("IMS-Information", 876, TGPP),
            ("SMS-Information", 2000, TGPP),
            ("Node-Functionality", 862, TGPP),
            ("Role-of-Node", 829, TGPP),
            ("Time-Quota-Threshold", 868, TGPP),
            // VCS-Information and members (TS 32.299, TS 32.276), as in
            // Wireshark's diameter/dictionary.xml.
            ("VCS-Information", 3410, TGPP),
            ("Basic-Service-Code", 3411, TGPP),
            ("Bearer-Capability", 3412, TGPP),
            ("Teleservice", 3413, TGPP),
            ("ISUP-Location-Number", 3414, TGPP),
            ("Forwarding-Pending", 3415, TGPP),
            ("ISUP-Cause", 3416, TGPP),
            ("MSC-Address", 3417, TGPP),
            ("Network-Call-Reference-Number", 3418, TGPP),
            ("Start-of-Charging", 3419, TGPP),
            ("VLR-Number", 3420, TGPP),
            ("ISUP-Cause-Diagnostics", 3422, TGPP),
            ("ISUP-Cause-Location", 3423, TGPP),
            ("ISUP-Cause-Value", 3424, TGPP),
            ("Bearer-Service", 854, TGPP),
            ("PS-Free-Format-Data", 866, TGPP),
            ("Start-Time", 2041, TGPP),
            ("Stop-Time", 2042, TGPP),
            ("SMSC-Address", 2017, TGPP),
            ("MTC-IWF-Address", 3406, TGPP),
            ("SMS-Result", 3409, TGPP),
        ];
        for &(name, code, vendor) in reference {
            let entry =
                lookup_by_name(name).unwrap_or_else(|| panic!("dictionary missing AVP {name}"));
            assert_eq!(entry.code, code, "{name} code");
            assert_eq!(entry.vendor_id, vendor, "{name} vendor");
            // Reverse lookup by (code, vendor) must round-trip to the same name.
            let by_code = lookup_avp(code, vendor)
                .unwrap_or_else(|| panic!("no AVP at ({code}, {vendor}) for {name}"));
            assert_eq!(by_code.name, name, "reverse lookup for ({code},{vendor})");
        }
    }

    #[test]
    fn old_miscoded_credit_control_codes_are_gone() {
        // Regression guard for the pre-fix numbering: these codes previously
        // named the wrong AVP. After the fix 426 is Credit-Control (was
        // Granted-Service-Unit), 456 is MSCC (was CC-Total-Octets), and the
        // bogus 3GPP-vendor MSCC at (2006, 10415) is removed entirely.
        assert_ne!(lookup_by_name("Granted-Service-Unit").unwrap().code, 426);
        assert_ne!(lookup_by_name("CC-Time").unwrap().code, 454);
        assert_ne!(lookup_by_name("Final-Unit-Indication").unwrap().code, 431);
        assert!(
            lookup_avp(2006, TGPP).is_none(),
            "stale 3GPP MSCC still present"
        );
        assert_eq!(lookup_avp(426, 0).unwrap().name, "Credit-Control");
        assert_eq!(
            lookup_avp(456, 0).unwrap().name,
            "Multiple-Services-Credit-Control"
        );
    }

    #[test]
    fn avp_type_classification() {
        assert!(AvpType::Grouped.is_container());
        assert!(!AvpType::Unsigned32.is_container());
        assert!(AvpType::UTF8String.is_text());
        assert!(AvpType::DiameterIdentity.is_text());
        assert!(!AvpType::OctetString.is_text());
    }

    // -----------------------------------------------------------------
    // Generic-API resolution helpers
    // -----------------------------------------------------------------

    #[test]
    fn lookup_avp_by_python_name_handles_acronyms() {
        // Python kwargs in snake_case translate to the dictionary's
        // Title-Kebab convention with case-insensitive match — covers
        // acronym-heavy AVP names that don't title-case cleanly.
        assert_eq!(lookup_avp_by_python_name("msisdn").unwrap().code, 701);
        assert_eq!(lookup_avp_by_python_name("sc_address").unwrap().code, 3300);
        assert_eq!(lookup_avp_by_python_name("sm_rp_ui").unwrap().code, 3301);
        assert_eq!(lookup_avp_by_python_name("user_name").unwrap().code, 1);
        assert_eq!(
            lookup_avp_by_python_name("visited_network_identifier")
                .unwrap()
                .code,
            600
        );
        assert!(lookup_avp_by_python_name("not_a_real_avp").is_none());
    }

    #[test]
    fn app_id_by_name_round_trips() {
        for app in &["Cx", "Sh", "Gx", "Rx", "Ro", "Rf", "S6c", "SGd"] {
            let (vendor, app_id) = app_id_by_name(app).expect("app must resolve");
            let _ = vendor;
            let resolved = app_name_by_id(app_id).expect("app id must resolve");
            // Case-insensitive comparison — `S6c` vs `s6c` both round-trip.
            assert!(resolved.eq_ignore_ascii_case(app));
        }
    }

    #[test]
    fn app_id_by_name_is_case_insensitive() {
        assert_eq!(app_id_by_name("s6c"), app_id_by_name("S6c"));
        assert_eq!(app_id_by_name("SGD"), app_id_by_name("sgd"));
        assert!(app_id_by_name("not-an-app").is_none());
    }

    #[test]
    fn gx_resolves_to_the_3gpp_application_id() {
        // TS 29.212 §5.1: Gx is vendor-specific to 3GPP (10415) with
        // application id 16777238.
        for name in ["Gx", "gx", "GX", "gX"] {
            assert_eq!(app_id_by_name(name), Some((10415, 16_777_238)), "{name}");
        }
        assert_eq!(app_name_by_id(16_777_238), Some("Gx"));
        // The neighbouring ids belong to other applications and must not be
        // mistaken for Gx (Rx is 16777236).
        assert_eq!(app_name_by_id(16_777_236), Some("Rx"));
        assert_eq!(app_name_by_id(16_777_237), None);
    }

    #[test]
    fn s13_resolves_to_its_3gpp_application_id() {
        // TS 29.272 clause 7.1.8: S13/S13' is a vendor-specific Diameter
        // application of 3GPP (10415) with application identifier 16777252.
        for name in ["S13", "s13"] {
            assert_eq!(app_id_by_name(name), Some((10415, 16_777_252)), "{name}");
        }
        assert_eq!(app_name_by_id(16_777_252), Some("S13"));
        assert!(!is_accounting_application(16_777_252));
        // S6a is the id before it, and stays S6a.
        assert_eq!(app_name_by_id(16_777_251), Some("S6a"));
        assert_eq!(app_name_by_id(16_777_253), None);
    }

    #[test]
    fn me_identity_check_is_command_324() {
        // TS 29.272 clause 7.2.2, Table 7.2.2/1: ME-Identity-Check-Request
        // ECR 324 and ME-Identity-Check-Answer ECA 324.
        for name in [
            "ME-Identity-Check-Request",
            "ME-Identity-Check-Answer",
            "ME-Identity-Check",
            "me-identity-check-request",
            "ECR",
            "eca",
        ] {
            assert_eq!(command_code_by_name(name), Some(324), "{name}");
        }
        assert_eq!(command_name_by_code(324), Some("ME-Identity-Check"));
        assert_eq!(super::super::codec::command_name(324, true), "ECR");
        assert_eq!(super::super::codec::command_name(324, false), "ECA");
    }

    #[test]
    fn s13_avps_are_defined_as_ts_29_272_gives_them() {
        // Code and value type from TS 29.272 Table 7.3.1/1 and clauses
        // 7.3.3 (Terminal-Information), 7.3.4 (IMEI), 7.3.5 (Software-
        // Version), 7.3.6 (3GPP2-MEID) and 7.3.51 (Equipment-Status). Every
        // one of them is vendor 3GPP and goes out with M and V.
        let table = [
            (1401, "Terminal-Information", AvpType::Grouped),
            (1402, "IMEI", AvpType::UTF8String),
            (1403, "Software-Version", AvpType::UTF8String),
            (1445, "Equipment-Status", AvpType::Enumerated),
            (1471, "3GPP2-MEID", AvpType::OctetString),
        ];
        for (code, name, data_type) in table {
            let def = lookup_avp(code, 10415)
                .unwrap_or_else(|| panic!("{name} ({code}) is not in the dictionary"));
            assert_eq!(def.name, name);
            assert_eq!(def.data_type, data_type, "{name}");
            assert_eq!(lookup_by_name(name).map(|def| def.code), Some(code));
            assert!(avp_is_mandatory(code, 10415), "{name} carries M");
        }
        for (python_name, code) in [
            ("terminal_information", 1401),
            ("imei", 1402),
            ("software_version", 1403),
            ("equipment_status", 1445),
        ] {
            assert_eq!(
                lookup_avp_by_python_name(python_name).map(|def| (def.vendor_id, def.code)),
                Some((10415, code)),
                "{python_name}"
            );
        }
    }

    #[test]
    fn equipment_status_values_are_those_of_ts_29_272_clause_7_3_51() {
        // PERMITTEDLISTED (0), PROHIBITEDLISTED (1), TRACKINGLISTED (2).
        assert_eq!(EQUIPMENT_STATUS_PERMITTEDLISTED, 0);
        assert_eq!(EQUIPMENT_STATUS_PROHIBITEDLISTED, 1);
        assert_eq!(EQUIPMENT_STATUS_TRACKINGLISTED, 2);
    }

    #[test]
    fn equipment_unknown_is_experimental_result_5422() {
        // TS 29.272 clause 7.4.3.5: DIAMETER_ERROR_EQUIPMENT_UNKNOWN (5422),
        // sent by the EIR for a mobile equipment it does not know.
        assert_eq!(DIAMETER_ERROR_EQUIPMENT_UNKNOWN, 5422);
        assert_eq!(answer_result_label(None, Some(5422)), "exp:5422");
    }

    #[test]
    fn zh_and_zn_resolve_to_their_3gpp_application_ids() {
        // TS 29.109 clause 6.0: "The Diameter application identifier assigned
        // to the Zh interface application is 16777221", and "to the Zn and
        // Zpn interface application are 16777220 and 16777268 respectively".
        // The vendor is 3GPP (10415).
        for name in ["Zh", "zh", "ZH"] {
            assert_eq!(app_id_by_name(name), Some((10415, 16_777_221)), "{name}");
        }
        for name in ["Zn", "zn", "ZN"] {
            assert_eq!(app_id_by_name(name), Some((10415, 16_777_220)), "{name}");
        }
        assert_eq!(app_name_by_id(16_777_221), Some("Zh"));
        assert_eq!(app_name_by_id(16_777_220), Some("Zn"));
        // Both are advertised as Auth-Application-Id.
        assert!(!is_accounting_application(16_777_221));
        assert!(!is_accounting_application(16_777_220));
        // The ids on either side belong to other applications.
        assert_eq!(app_name_by_id(16_777_219), None);
        assert_eq!(app_name_by_id(16_777_222), None);
        assert_eq!(app_name_by_id(16_777_216), Some("Cx"));
    }

    #[test]
    fn bootstrapping_info_is_command_310() {
        // TS 29.109 clause 6.1: "The Zn and Zpn interfaces assign new
        // Command-Codes 310 and 312."
        for name in [
            "Bootstrapping-Info-Request",
            "Bootstrapping-Info-Answer",
            "Bootstrapping-Info",
            "bootstrapping-info-request",
            "BIR",
            "bia",
        ] {
            assert_eq!(command_code_by_name(name), Some(310), "{name}");
        }
        assert_eq!(command_name_by_code(310), Some("Bootstrapping-Info"));
        // Zh reuses the Cx command: "The messages in Zh interface use the
        // same Command-Code value 303".
        assert_eq!(command_code_by_name("MAR"), Some(303));
    }

    #[test]
    fn gba_avps_are_defined_as_ts_29_109_table_6_1_gives_them() {
        // Code, name and value type from TS 29.109 Table 6.1; "The Vendor-Id
        // header of all AVPs defined in this specification shall be set to
        // 3GPP (10415)".
        let table = [
            (400, "GBA-UserSecSettings", AvpType::OctetString),
            (401, "Transaction-Identifier", AvpType::OctetString),
            (402, "NAF-Id", AvpType::OctetString),
            (403, "GAA-Service-Identifier", AvpType::OctetString),
            (404, "Key-ExpiryTime", AvpType::Time),
            (405, "ME-Key-Material", AvpType::OctetString),
            (406, "UICC-Key-Material", AvpType::OctetString),
            (407, "GBA_U-Awareness-Indicator", AvpType::Enumerated),
            (408, "BootstrapInfoCreationTime", AvpType::Time),
            (409, "GUSS-Timestamp", AvpType::Time),
            (410, "GBA-Type", AvpType::Enumerated),
            (421, "SHA-256-Indication", AvpType::Enumerated),
        ];
        for (code, name, data_type) in table {
            let def = lookup_avp(code, 10415)
                .unwrap_or_else(|| panic!("{name} ({code}) is not in the dictionary"));
            assert_eq!(def.name, name);
            assert_eq!(def.data_type, data_type, "{name}");
            assert_eq!(lookup_by_name(name).map(|def| def.code), Some(code));
        }
    }

    #[test]
    fn python_names_reach_the_gba_avps() {
        for (python_name, code) in [
            ("gba_usersecsettings", 400),
            ("transaction_identifier", 401),
            ("naf_id", 402),
            ("gaa_service_identifier", 403),
            ("key_expirytime", 404),
            ("me_key_material", 405),
            ("uicc_key_material", 406),
            // The AVP name itself holds an underscore.
            ("gba_u_awareness_indicator", 407),
            ("bootstrapinfocreationtime", 408),
            ("guss_timestamp", 409),
            ("gba_type", 410),
        ] {
            assert_eq!(
                lookup_avp_by_python_name(python_name).map(|def| (def.vendor_id, def.code)),
                Some((10415, code)),
                "{python_name}"
            );
        }
        // Names without an underscore of their own are found as before.
        assert_eq!(
            lookup_avp_by_python_name("sm_rp_ui").map(|def| def.name),
            Some("SM-RP-UI")
        );
    }

    #[test]
    fn gx_is_an_auth_application() {
        // Gx credit control runs over the RFC 4006 command set, but the
        // application itself is advertised as Auth-Application-Id.
        assert!(!is_accounting_application(GX_APP_ID));
        assert!(is_accounting_application(RF_APP_ID));
    }

    #[test]
    fn command_code_by_name_handles_long_form_with_request_suffix() {
        assert_eq!(
            command_code_by_name("Send-Routing-Info-for-SM-Request"),
            Some(CMD_SEND_ROUTING_INFO_FOR_SM)
        );
        assert_eq!(
            command_code_by_name("Send-Routing-Info-for-SM"),
            Some(CMD_SEND_ROUTING_INFO_FOR_SM)
        );
        assert_eq!(
            command_code_by_name("Alert-Service-Centre-Request"),
            Some(CMD_ALERT_SERVICE_CENTRE)
        );
        assert_eq!(
            command_code_by_name("MT-Forward-Short-Message-Request"),
            Some(CMD_MT_FORWARD_SHORT_MESSAGE)
        );
        assert_eq!(
            command_code_by_name("Multimedia-Auth-Request"),
            Some(CMD_MULTIMEDIA_AUTH)
        );
    }

    #[test]
    fn command_code_by_name_handles_acronym_aliases() {
        assert_eq!(
            command_code_by_name("SRR"),
            Some(CMD_SEND_ROUTING_INFO_FOR_SM)
        );
        assert_eq!(command_code_by_name("ALR"), Some(CMD_ALERT_SERVICE_CENTRE));
        assert_eq!(
            command_code_by_name("TFR"),
            Some(CMD_MT_FORWARD_SHORT_MESSAGE)
        );
        assert_eq!(
            command_code_by_name("OFR"),
            Some(CMD_MO_FORWARD_SHORT_MESSAGE)
        );
        assert_eq!(command_code_by_name("MAR"), Some(CMD_MULTIMEDIA_AUTH));
    }

    #[test]
    fn command_name_by_code_round_trip_for_known_apps() {
        for code in [
            CMD_SEND_ROUTING_INFO_FOR_SM,
            CMD_ALERT_SERVICE_CENTRE,
            CMD_MT_FORWARD_SHORT_MESSAGE,
            CMD_MO_FORWARD_SHORT_MESSAGE,
            CMD_USER_AUTHORIZATION,
        ] {
            let name = command_name_by_code(code).expect("code must resolve");
            let resolved = command_code_by_name(name).expect("name must resolve");
            assert_eq!(resolved, code);
        }
    }

    #[test]
    fn command_code_by_name_is_case_insensitive() {
        assert_eq!(
            command_code_by_name("send-routing-info-for-sm-request"),
            command_code_by_name("Send-Routing-Info-for-SM-Request")
        );
        assert_eq!(command_code_by_name("alr"), command_code_by_name("ALR"),);
    }

    #[test]
    fn command_code_by_name_returns_none_for_unknown() {
        assert!(command_code_by_name("Bogus-Request").is_none());
    }
}
