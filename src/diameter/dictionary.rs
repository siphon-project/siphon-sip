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
    /// ISDN-AddressString (3GPP TS 29.002 §17.7.8): one ToN/NPI octet
    /// followed by the TBCD-packed E.164 digit string. Surfaces to scripts
    /// as a plain digit string, not raw bytes — see
    /// [`crate::diameter::codec::decode_isdn_address_string`].
    ISDNAddressString,
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
    AvpDef { code: 1,   vendor_id: 0, name: "User-Name",                    data_type: AvpType::UTF8String },
    AvpDef { code: 8,   vendor_id: 0, name: "Framed-IP-Address",            data_type: AvpType::OctetString },
    AvpDef { code: 11,  vendor_id: 0, name: "Filter-Id",                    data_type: AvpType::UTF8String },
    AvpDef { code: 25,  vendor_id: 0, name: "Class",                        data_type: AvpType::OctetString },
    AvpDef { code: 27,  vendor_id: 0, name: "Session-Timeout",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 33,  vendor_id: 0, name: "Proxy-State",                  data_type: AvpType::OctetString },
    AvpDef { code: 44,  vendor_id: 0, name: "Acct-Session-Id",              data_type: AvpType::OctetString },
    AvpDef { code: 50,  vendor_id: 0, name: "Acct-Multi-Session-Id",        data_type: AvpType::UTF8String },
    AvpDef { code: 55,  vendor_id: 0, name: "Event-Timestamp",              data_type: AvpType::Time },
    AvpDef { code: 85,  vendor_id: 0, name: "Acct-Interim-Interval",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 97,  vendor_id: 0, name: "Framed-IPv6-Prefix",           data_type: AvpType::OctetString },
    AvpDef { code: 257, vendor_id: 0, name: "Host-IP-Address",              data_type: AvpType::Address },
    AvpDef { code: 258, vendor_id: 0, name: "Auth-Application-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 259, vendor_id: 0, name: "Acct-Application-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 260, vendor_id: 0, name: "Vendor-Specific-Application-Id", data_type: AvpType::Grouped },
    AvpDef { code: 263, vendor_id: 0, name: "Session-Id",                   data_type: AvpType::UTF8String },
    AvpDef { code: 264, vendor_id: 0, name: "Origin-Host",                  data_type: AvpType::DiameterIdentity },
    AvpDef { code: 265, vendor_id: 0, name: "Supported-Vendor-Id",          data_type: AvpType::Unsigned32 },
    AvpDef { code: 266, vendor_id: 0, name: "Vendor-Id",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 267, vendor_id: 0, name: "Firmware-Revision",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 268, vendor_id: 0, name: "Result-Code",                  data_type: AvpType::Unsigned32 },
    AvpDef { code: 269, vendor_id: 0, name: "Product-Name",                 data_type: AvpType::UTF8String },
    AvpDef { code: 270, vendor_id: 0, name: "Session-Binding",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 274, vendor_id: 0, name: "Auth-Grace-Period",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 277, vendor_id: 0, name: "Auth-Session-State",           data_type: AvpType::Enumerated },
    AvpDef { code: 278, vendor_id: 0, name: "Origin-State-Id",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 279, vendor_id: 0, name: "Failed-AVP",                   data_type: AvpType::Grouped },
    AvpDef { code: 281, vendor_id: 0, name: "Error-Message",                data_type: AvpType::UTF8String },
    AvpDef { code: 282, vendor_id: 0, name: "Route-Record",                 data_type: AvpType::DiameterIdentity },
    AvpDef { code: 283, vendor_id: 0, name: "Destination-Realm",            data_type: AvpType::DiameterIdentity },
    AvpDef { code: 284, vendor_id: 0, name: "Proxy-Info",                   data_type: AvpType::Grouped },
    AvpDef { code: 285, vendor_id: 0, name: "Re-Auth-Request-Type",         data_type: AvpType::Enumerated },
    AvpDef { code: 291, vendor_id: 0, name: "Authorization-Lifetime",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 293, vendor_id: 0, name: "Destination-Host",             data_type: AvpType::DiameterIdentity },
    AvpDef { code: 295, vendor_id: 0, name: "Termination-Cause",            data_type: AvpType::Enumerated },
    AvpDef { code: 296, vendor_id: 0, name: "Origin-Realm",                 data_type: AvpType::DiameterIdentity },
    AvpDef { code: 297, vendor_id: 0, name: "Experimental-Result",          data_type: AvpType::Grouped },
    AvpDef { code: 298, vendor_id: 0, name: "Experimental-Result-Code",     data_type: AvpType::Unsigned32 },
    AvpDef { code: 299, vendor_id: 0, name: "Inband-Security-Id",           data_type: AvpType::Unsigned32 },

    // ── RFC 8506 (obsoletes RFC 4006) Credit-Control / Gy, vendor_id = 0 ───
    // Codes per the IANA aaa-parameters registry (RFC 8506 §12). The prior
    // table used a self-consistent but non-standard numbering that a real OCS
    // (CGRateS, go-diameter) rejects — every code below is the on-the-wire
    // value.
    AvpDef { code: 412, vendor_id: 0, name: "CC-Input-Octets",              data_type: AvpType::Unsigned64 },
    AvpDef { code: 413, vendor_id: 0, name: "CC-Money",                     data_type: AvpType::Grouped },
    AvpDef { code: 414, vendor_id: 0, name: "CC-Output-Octets",             data_type: AvpType::Unsigned64 },
    AvpDef { code: 415, vendor_id: 0, name: "CC-Request-Number",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 416, vendor_id: 0, name: "CC-Request-Type",              data_type: AvpType::Enumerated },
    AvpDef { code: 417, vendor_id: 0, name: "CC-Service-Specific-Units",    data_type: AvpType::Unsigned64 },
    AvpDef { code: 418, vendor_id: 0, name: "CC-Session-Failover",          data_type: AvpType::Enumerated },
    AvpDef { code: 419, vendor_id: 0, name: "CC-Sub-Session-Id",            data_type: AvpType::Unsigned64 },
    AvpDef { code: 420, vendor_id: 0, name: "CC-Time",                      data_type: AvpType::Unsigned32 },
    AvpDef { code: 421, vendor_id: 0, name: "CC-Total-Octets",              data_type: AvpType::Unsigned64 },
    AvpDef { code: 426, vendor_id: 0, name: "Credit-Control",               data_type: AvpType::Enumerated },
    AvpDef { code: 427, vendor_id: 0, name: "Credit-Control-Failure-Handling", data_type: AvpType::Enumerated },
    AvpDef { code: 428, vendor_id: 0, name: "Direct-Debiting-Failure-Handling", data_type: AvpType::Enumerated },
    AvpDef { code: 430, vendor_id: 0, name: "Final-Unit-Indication",        data_type: AvpType::Grouped },
    AvpDef { code: 431, vendor_id: 0, name: "Granted-Service-Unit",         data_type: AvpType::Grouped },
    AvpDef { code: 432, vendor_id: 0, name: "Rating-Group",                 data_type: AvpType::Unsigned32 },
    AvpDef { code: 433, vendor_id: 0, name: "Redirect-Address-Type",        data_type: AvpType::Enumerated },
    AvpDef { code: 434, vendor_id: 0, name: "Redirect-Server",              data_type: AvpType::Grouped },
    AvpDef { code: 435, vendor_id: 0, name: "Redirect-Server-Address",      data_type: AvpType::UTF8String },
    AvpDef { code: 436, vendor_id: 0, name: "Requested-Action",             data_type: AvpType::Enumerated },
    AvpDef { code: 437, vendor_id: 0, name: "Requested-Service-Unit",       data_type: AvpType::Grouped },
    AvpDef { code: 438, vendor_id: 0, name: "Restriction-Filter-Rule",      data_type: AvpType::OctetString },
    AvpDef { code: 439, vendor_id: 0, name: "Service-Identifier",           data_type: AvpType::Unsigned32 },
    AvpDef { code: 443, vendor_id: 0, name: "Subscription-Id",              data_type: AvpType::Grouped },
    AvpDef { code: 444, vendor_id: 0, name: "Subscription-Id-Data",         data_type: AvpType::UTF8String },
    AvpDef { code: 446, vendor_id: 0, name: "Used-Service-Unit",            data_type: AvpType::Grouped },
    AvpDef { code: 448, vendor_id: 0, name: "Validity-Time",                data_type: AvpType::Unsigned32 },
    AvpDef { code: 449, vendor_id: 0, name: "Final-Unit-Action",            data_type: AvpType::Enumerated },
    AvpDef { code: 450, vendor_id: 0, name: "Subscription-Id-Type",         data_type: AvpType::Enumerated },
    AvpDef { code: 452, vendor_id: 0, name: "Tariff-Change-Usage",          data_type: AvpType::Enumerated },
    AvpDef { code: 453, vendor_id: 0, name: "G-S-U-Pool-Identifier",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 455, vendor_id: 0, name: "Multiple-Services-Indicator",  data_type: AvpType::Enumerated },
    AvpDef { code: 456, vendor_id: 0, name: "Multiple-Services-Credit-Control", data_type: AvpType::Grouped },
    AvpDef { code: 457, vendor_id: 0, name: "G-S-U-Pool-Reference",         data_type: AvpType::Grouped },
    AvpDef { code: 458, vendor_id: 0, name: "User-Equipment-Info",          data_type: AvpType::Grouped },
    AvpDef { code: 459, vendor_id: 0, name: "User-Equipment-Info-Type",     data_type: AvpType::Enumerated },
    AvpDef { code: 460, vendor_id: 0, name: "User-Equipment-Info-Value",    data_type: AvpType::OctetString },
    AvpDef { code: 461, vendor_id: 0, name: "Service-Context-Id",           data_type: AvpType::UTF8String },
    AvpDef { code: 480, vendor_id: 0, name: "Accounting-Record-Type",       data_type: AvpType::Enumerated },
    AvpDef { code: 485, vendor_id: 0, name: "Accounting-Record-Number",     data_type: AvpType::Unsigned32 },

    // ── 3GPP AVPs, vendor_id = 10415 (sorted by code) ─────────────────────

    // Rx (TS 29.214)
    AvpDef { code: 500,  vendor_id: TGPP, name: "Abort-Cause",                        data_type: AvpType::Enumerated },
    AvpDef { code: 501,  vendor_id: TGPP, name: "Access-Network-Charging-Address",    data_type: AvpType::Address },
    AvpDef { code: 502,  vendor_id: TGPP, name: "Access-Network-Charging-Identifier", data_type: AvpType::Grouped },
    AvpDef { code: 504,  vendor_id: TGPP, name: "AF-Application-Identifier",          data_type: AvpType::OctetString },
    AvpDef { code: 505,  vendor_id: TGPP, name: "AF-Charging-Identifier",             data_type: AvpType::OctetString },
    AvpDef { code: 507,  vendor_id: TGPP, name: "Flow-Description",                   data_type: AvpType::OctetString },
    AvpDef { code: 508,  vendor_id: TGPP, name: "Flow-Grouping",                      data_type: AvpType::Grouped },
    AvpDef { code: 509,  vendor_id: TGPP, name: "Flow-Number",                        data_type: AvpType::Unsigned32 },
    AvpDef { code: 510,  vendor_id: TGPP, name: "Flows",                              data_type: AvpType::Grouped },
    AvpDef { code: 511,  vendor_id: TGPP, name: "Flow-Status",                        data_type: AvpType::Enumerated },
    AvpDef { code: 512,  vendor_id: TGPP, name: "Flow-Usage",                         data_type: AvpType::Enumerated },
    AvpDef { code: 513,  vendor_id: TGPP, name: "Specific-Action",                    data_type: AvpType::Enumerated },
    AvpDef { code: 515,  vendor_id: TGPP, name: "Max-Requested-Bandwidth-DL",         data_type: AvpType::Unsigned32 },
    AvpDef { code: 516,  vendor_id: TGPP, name: "Max-Requested-Bandwidth-UL",         data_type: AvpType::Unsigned32 },
    AvpDef { code: 517,  vendor_id: TGPP, name: "Media-Component-Description",        data_type: AvpType::Grouped },
    AvpDef { code: 518,  vendor_id: TGPP, name: "Media-Component-Number",             data_type: AvpType::Unsigned32 },
    AvpDef { code: 519,  vendor_id: TGPP, name: "Media-Sub-Component",                data_type: AvpType::Grouped },
    AvpDef { code: 520,  vendor_id: TGPP, name: "Media-Type",                         data_type: AvpType::Enumerated },
    AvpDef { code: 524,  vendor_id: TGPP, name: "Codec-Data",                         data_type: AvpType::OctetString },
    AvpDef { code: 527,  vendor_id: TGPP, name: "Service-Info-Status",                data_type: AvpType::Enumerated },
    AvpDef { code: 533,  vendor_id: TGPP, name: "Rx-Request-Type",                    data_type: AvpType::Enumerated },
    // Cx/Dx (TS 29.228/229)
    AvpDef { code: 600,  vendor_id: TGPP, name: "Visited-Network-Identifier",         data_type: AvpType::OctetString },
    AvpDef { code: 601,  vendor_id: TGPP, name: "Public-Identity",                    data_type: AvpType::UTF8String },
    AvpDef { code: 602,  vendor_id: TGPP, name: "Server-Name",                        data_type: AvpType::UTF8String },
    AvpDef { code: 603,  vendor_id: TGPP, name: "Server-Capabilities",                data_type: AvpType::Grouped },
    AvpDef { code: 604,  vendor_id: TGPP, name: "Mandatory-Capability",               data_type: AvpType::Unsigned32 },
    AvpDef { code: 605,  vendor_id: TGPP, name: "Optional-Capability",                data_type: AvpType::Unsigned32 },
    AvpDef { code: 606,  vendor_id: TGPP, name: "User-Data",                          data_type: AvpType::OctetString },
    AvpDef { code: 607,  vendor_id: TGPP, name: "SIP-Number-Auth-Items",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 608,  vendor_id: TGPP, name: "SIP-Authentication-Scheme",          data_type: AvpType::UTF8String },
    AvpDef { code: 609,  vendor_id: TGPP, name: "SIP-Authenticate",                   data_type: AvpType::OctetString },
    AvpDef { code: 610,  vendor_id: TGPP, name: "SIP-Authorization",                  data_type: AvpType::OctetString },
    AvpDef { code: 611,  vendor_id: TGPP, name: "SIP-Authentication-Context",         data_type: AvpType::OctetString },
    AvpDef { code: 612,  vendor_id: TGPP, name: "SIP-Auth-Data-Item",                 data_type: AvpType::Grouped },
    AvpDef { code: 613,  vendor_id: TGPP, name: "SIP-Item-Number",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 614,  vendor_id: TGPP, name: "Server-Assignment-Type",             data_type: AvpType::Enumerated },
    AvpDef { code: 615,  vendor_id: TGPP, name: "Deregistration-Reason",              data_type: AvpType::Grouped },
    AvpDef { code: 616,  vendor_id: TGPP, name: "Reason-Code",                        data_type: AvpType::Enumerated },
    AvpDef { code: 617,  vendor_id: TGPP, name: "Reason-Info",                        data_type: AvpType::UTF8String },
    AvpDef { code: 618,  vendor_id: TGPP, name: "Charging-Information",               data_type: AvpType::Grouped },
    AvpDef { code: 619,  vendor_id: TGPP, name: "Primary-Event-Charging-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 620,  vendor_id: TGPP, name: "Secondary-Event-Charging-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 621,  vendor_id: TGPP, name: "Primary-Charging-Collection-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 622,  vendor_id: TGPP, name: "Secondary-Charging-Collection-Function-Name", data_type: AvpType::DiameterIdentity },
    AvpDef { code: 623,  vendor_id: TGPP, name: "User-Authorization-Type",            data_type: AvpType::Enumerated },
    AvpDef { code: 624,  vendor_id: TGPP, name: "User-Data-Already-Available",        data_type: AvpType::Enumerated },
    AvpDef { code: 625,  vendor_id: TGPP, name: "Confidentiality-Key",                data_type: AvpType::OctetString },
    AvpDef { code: 626,  vendor_id: TGPP, name: "Integrity-Key",                      data_type: AvpType::OctetString },
    AvpDef { code: 628,  vendor_id: TGPP, name: "Supported-Features",                 data_type: AvpType::Grouped },
    AvpDef { code: 629,  vendor_id: TGPP, name: "Feature-List-ID",                    data_type: AvpType::Unsigned32 },
    AvpDef { code: 630,  vendor_id: TGPP, name: "Feature-List",                       data_type: AvpType::Unsigned32 },
    AvpDef { code: 631,  vendor_id: TGPP, name: "Supported-Applications",             data_type: AvpType::Grouped },
    AvpDef { code: 632,  vendor_id: TGPP, name: "Associated-Identities",              data_type: AvpType::Grouped },
    AvpDef { code: 633,  vendor_id: TGPP, name: "Originating-Request",                data_type: AvpType::Enumerated },
    // Sh (TS 29.329)
    AvpDef { code: 700,  vendor_id: TGPP, name: "User-Identity",                      data_type: AvpType::Grouped },
    AvpDef { code: 701,  vendor_id: TGPP, name: "MSISDN",                             data_type: AvpType::ISDNAddressString },
    AvpDef { code: 702,  vendor_id: TGPP, name: "User-Data-Sh",                       data_type: AvpType::OctetString },
    AvpDef { code: 703,  vendor_id: TGPP, name: "Data-Reference",                     data_type: AvpType::Enumerated },
    AvpDef { code: 704,  vendor_id: TGPP, name: "Service-Indication",                 data_type: AvpType::OctetString },
    AvpDef { code: 705,  vendor_id: TGPP, name: "Subs-Req-Type",                      data_type: AvpType::Enumerated },
    AvpDef { code: 706,  vendor_id: TGPP, name: "Requested-Domain",                   data_type: AvpType::Enumerated },
    AvpDef { code: 707,  vendor_id: TGPP, name: "Current-Location",                   data_type: AvpType::Enumerated },
    AvpDef { code: 708,  vendor_id: TGPP, name: "Identity-Set",                       data_type: AvpType::Enumerated },
    AvpDef { code: 709,  vendor_id: TGPP, name: "Expiry-Time",                        data_type: AvpType::Time },
    AvpDef { code: 710,  vendor_id: TGPP, name: "Send-Data-Indication",               data_type: AvpType::Enumerated },
    AvpDef { code: 711,  vendor_id: TGPP, name: "DSAI-Tag",                           data_type: AvpType::OctetString },
    // Ro/Rf Charging (TS 32.299)
    AvpDef { code: 823,  vendor_id: TGPP, name: "Event-Type",                         data_type: AvpType::Grouped },
    AvpDef { code: 824,  vendor_id: TGPP, name: "SIP-Method",                         data_type: AvpType::UTF8String },
    AvpDef { code: 825,  vendor_id: TGPP, name: "Event",                              data_type: AvpType::UTF8String },
    AvpDef { code: 829,  vendor_id: TGPP, name: "Role-of-Node",                       data_type: AvpType::Enumerated },
    AvpDef { code: 830,  vendor_id: TGPP, name: "User-Session-Id",                    data_type: AvpType::UTF8String },
    AvpDef { code: 831,  vendor_id: TGPP, name: "Calling-Party-Address",              data_type: AvpType::UTF8String },
    AvpDef { code: 832,  vendor_id: TGPP, name: "Called-Party-Address",               data_type: AvpType::UTF8String },
    AvpDef { code: 833,  vendor_id: TGPP, name: "Time-Stamps",                        data_type: AvpType::Grouped },
    AvpDef { code: 834,  vendor_id: TGPP, name: "SIP-Request-Timestamp",              data_type: AvpType::Time },
    AvpDef { code: 835,  vendor_id: TGPP, name: "SIP-Response-Timestamp",             data_type: AvpType::Time },
    AvpDef { code: 836,  vendor_id: TGPP, name: "Application-Server",                 data_type: AvpType::UTF8String },
    AvpDef { code: 837,  vendor_id: TGPP, name: "Application-Provided-Called-Party-Address", data_type: AvpType::UTF8String },
    AvpDef { code: 838,  vendor_id: TGPP, name: "Inter-Operator-Identifier",          data_type: AvpType::Grouped },
    AvpDef { code: 839,  vendor_id: TGPP, name: "Originating-IOI",                    data_type: AvpType::UTF8String },
    AvpDef { code: 840,  vendor_id: TGPP, name: "Terminating-IOI",                    data_type: AvpType::UTF8String },
    AvpDef { code: 841,  vendor_id: TGPP, name: "IMS-Charging-Identifier",            data_type: AvpType::UTF8String },
    AvpDef { code: 848,  vendor_id: TGPP, name: "Served-Party-IP-Address",            data_type: AvpType::Address },
    AvpDef { code: 850,  vendor_id: TGPP, name: "Application-Server-Information",     data_type: AvpType::Grouped },
    AvpDef { code: 851,  vendor_id: TGPP, name: "Trunk-Group-Id",                     data_type: AvpType::Grouped },
    AvpDef { code: 852,  vendor_id: TGPP, name: "Incoming-Trunk-Group-Id",            data_type: AvpType::UTF8String },
    AvpDef { code: 853,  vendor_id: TGPP, name: "Outgoing-Trunk-Group-Id",            data_type: AvpType::UTF8String },
    AvpDef { code: 861,  vendor_id: TGPP, name: "Cause-Code",                         data_type: AvpType::Integer32 },
    AvpDef { code: 862,  vendor_id: TGPP, name: "Node-Functionality",                 data_type: AvpType::Enumerated },
    AvpDef { code: 873,  vendor_id: TGPP, name: "Service-Information",                data_type: AvpType::Grouped },
    AvpDef { code: 874,  vendor_id: TGPP, name: "PS-Information",                     data_type: AvpType::Grouped },
    AvpDef { code: 876,  vendor_id: TGPP, name: "IMS-Information",                    data_type: AvpType::Grouped },
    // Address Address-Type / Address-Data envelope (TS 32.299 §7.2.8/§7.2.9)
    AvpDef { code: 886,  vendor_id: TGPP, name: "Originator-Address",                 data_type: AvpType::Grouped },
    AvpDef { code: 897,  vendor_id: TGPP, name: "Address-Data",                       data_type: AvpType::UTF8String },
    AvpDef { code: 899,  vendor_id: TGPP, name: "Address-Type",                       data_type: AvpType::Enumerated },
    // Gx (TS 29.212) — codes per 3GPP / HSS crate reference
    AvpDef { code: 1000, vendor_id: TGPP, name: "Bearer-Usage",                       data_type: AvpType::Enumerated },
    AvpDef { code: 1001, vendor_id: TGPP, name: "Charging-Rule-Install",              data_type: AvpType::Grouped },
    AvpDef { code: 1002, vendor_id: TGPP, name: "Charging-Rule-Remove",               data_type: AvpType::Grouped },
    AvpDef { code: 1003, vendor_id: TGPP, name: "Charging-Rule-Definition",           data_type: AvpType::Grouped },
    AvpDef { code: 1004, vendor_id: TGPP, name: "Charging-Rule-Base-Name",            data_type: AvpType::UTF8String },
    AvpDef { code: 1005, vendor_id: TGPP, name: "Charging-Rule-Name",                 data_type: AvpType::OctetString },
    AvpDef { code: 1006, vendor_id: TGPP, name: "Event-Trigger",                      data_type: AvpType::Enumerated },
    AvpDef { code: 1007, vendor_id: TGPP, name: "Metering-Method",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1008, vendor_id: TGPP, name: "Offline",                            data_type: AvpType::Enumerated },
    AvpDef { code: 1009, vendor_id: TGPP, name: "Online",                             data_type: AvpType::Enumerated },
    AvpDef { code: 1010, vendor_id: TGPP, name: "Precedence",                         data_type: AvpType::Unsigned32 },
    AvpDef { code: 1011, vendor_id: TGPP, name: "Reporting-Level",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1013, vendor_id: TGPP, name: "TFT-Packet-Filter-Information",      data_type: AvpType::Grouped },
    AvpDef { code: 1014, vendor_id: TGPP, name: "ToS-Traffic-Class",                  data_type: AvpType::OctetString },
    AvpDef { code: 1016, vendor_id: TGPP, name: "QoS-Information",                    data_type: AvpType::Grouped },
    AvpDef { code: 1018, vendor_id: TGPP, name: "Charging-Rule-Report",               data_type: AvpType::Grouped },
    AvpDef { code: 1019, vendor_id: TGPP, name: "PCC-Rule-Status",                    data_type: AvpType::Enumerated },
    AvpDef { code: 1020, vendor_id: TGPP, name: "Bearer-Identifier",                  data_type: AvpType::OctetString },
    AvpDef { code: 1021, vendor_id: TGPP, name: "Bearer-Operation",                   data_type: AvpType::Enumerated },
    AvpDef { code: 1022, vendor_id: TGPP, name: "Access-Network-Charging-Identifier-Gx", data_type: AvpType::Grouped },
    AvpDef { code: 1023, vendor_id: TGPP, name: "Bearer-Control-Mode",                data_type: AvpType::Enumerated },
    AvpDef { code: 1024, vendor_id: TGPP, name: "Network-Request-Support",            data_type: AvpType::Enumerated },
    AvpDef { code: 1025, vendor_id: TGPP, name: "Guaranteed-Bitrate-DL",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 1026, vendor_id: TGPP, name: "Guaranteed-Bitrate-UL",              data_type: AvpType::Unsigned32 },
    AvpDef { code: 1027, vendor_id: TGPP, name: "IP-CAN-Type",                        data_type: AvpType::Enumerated },
    AvpDef { code: 1028, vendor_id: TGPP, name: "QoS-Class-Identifier",               data_type: AvpType::Enumerated },
    AvpDef { code: 1031, vendor_id: TGPP, name: "Rule-Failure-Code",                  data_type: AvpType::Enumerated },
    AvpDef { code: 1032, vendor_id: TGPP, name: "RAT-Type",                           data_type: AvpType::Enumerated },
    AvpDef { code: 1034, vendor_id: TGPP, name: "Allocation-Retention-Priority",      data_type: AvpType::Grouped },
    AvpDef { code: 1040, vendor_id: TGPP, name: "APN-Aggregate-Max-Bitrate-DL",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 1041, vendor_id: TGPP, name: "APN-Aggregate-Max-Bitrate-UL",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 1045, vendor_id: TGPP, name: "Session-Release-Cause",              data_type: AvpType::Enumerated },
    AvpDef { code: 1046, vendor_id: TGPP, name: "Priority-Level",                     data_type: AvpType::Unsigned32 },
    AvpDef { code: 1047, vendor_id: TGPP, name: "Pre-emption-Capability",             data_type: AvpType::Enumerated },
    AvpDef { code: 1048, vendor_id: TGPP, name: "Pre-emption-Vulnerability",          data_type: AvpType::Enumerated },
    AvpDef { code: 1049, vendor_id: TGPP, name: "Default-EPS-Bearer-QoS",             data_type: AvpType::Grouped },
    AvpDef { code: 1050, vendor_id: TGPP, name: "AN-GW-Address",                      data_type: AvpType::Address },
    // SMS-Information envelope: Recipient-Address (TS 32.299 §7.2.155)
    AvpDef { code: 1201, vendor_id: TGPP, name: "Recipient-Address",                  data_type: AvpType::Grouped },
    // S6a / S6d (TS 29.272) — MME/SGSN ↔ HSS for LTE attach + auth vectors
    AvpDef { code: 1400, vendor_id: TGPP, name: "Subscription-Data",                  data_type: AvpType::Grouped },
    AvpDef { code: 1401, vendor_id: TGPP, name: "Terminal-Information",               data_type: AvpType::Grouped },
    AvpDef { code: 1402, vendor_id: TGPP, name: "IMEI",                               data_type: AvpType::UTF8String },
    AvpDef { code: 1403, vendor_id: TGPP, name: "Software-Version",                   data_type: AvpType::UTF8String },
    AvpDef { code: 1405, vendor_id: TGPP, name: "ULR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1406, vendor_id: TGPP, name: "ULA-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1407, vendor_id: TGPP, name: "Visited-PLMN-Id",                    data_type: AvpType::OctetString },
    AvpDef { code: 1408, vendor_id: TGPP, name: "Requested-EUTRAN-Authentication-Info", data_type: AvpType::Grouped },
    AvpDef { code: 1410, vendor_id: TGPP, name: "Number-Of-Requested-Vectors",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 1411, vendor_id: TGPP, name: "Re-Synchronization-Info",            data_type: AvpType::OctetString },
    AvpDef { code: 1412, vendor_id: TGPP, name: "Immediate-Response-Preferred",       data_type: AvpType::Unsigned32 },
    AvpDef { code: 1413, vendor_id: TGPP, name: "Authentication-Info",                data_type: AvpType::Grouped },
    AvpDef { code: 1414, vendor_id: TGPP, name: "E-UTRAN-Vector",                     data_type: AvpType::Grouped },
    AvpDef { code: 1420, vendor_id: TGPP, name: "Cancellation-Type",                  data_type: AvpType::Enumerated },
    AvpDef { code: 1447, vendor_id: TGPP, name: "RAND",                               data_type: AvpType::OctetString },
    AvpDef { code: 1448, vendor_id: TGPP, name: "XRES",                               data_type: AvpType::OctetString },
    AvpDef { code: 1449, vendor_id: TGPP, name: "AUTN",                               data_type: AvpType::OctetString },
    AvpDef { code: 1450, vendor_id: TGPP, name: "KASME",                              data_type: AvpType::OctetString },
    // S6c served-node identifiers (TS 29.336 / 29.272)
    AvpDef { code: 1489, vendor_id: TGPP, name: "SGSN-Number",                        data_type: AvpType::ISDNAddressString },
    AvpDef { code: 1635, vendor_id: TGPP, name: "PUR-Flags",                          data_type: AvpType::Unsigned32 },
    AvpDef { code: 1645, vendor_id: TGPP, name: "MME-Number-for-MT-SMS",              data_type: AvpType::ISDNAddressString },
    // SMS-Information block (TS 32.299 §7.2.79 / §7.2.158 / §7.2.171)
    AvpDef { code: 2000, vendor_id: TGPP, name: "SMS-Information",                    data_type: AvpType::Grouped },
    AvpDef { code: 2001, vendor_id: TGPP, name: "Data-Coding-Scheme",                 data_type: AvpType::Integer32 },
    // Note: Multiple-Services-Credit-Control is base RFC 8506 code 456
    // (vendor 0), listed above — NOT a 3GPP vendor AVP. The prior (2006,10415)
    // entry collided with the real 3GPP Interface-Type and has been removed.
    AvpDef { code: 2007, vendor_id: TGPP, name: "SM-Message-Type",                    data_type: AvpType::Enumerated },
    AvpDef { code: 2008, vendor_id: TGPP, name: "Originator-SCCP-Address",            data_type: AvpType::Address },
    AvpDef { code: 2009, vendor_id: TGPP, name: "Originator-Interface",               data_type: AvpType::Grouped },
    AvpDef { code: 2010, vendor_id: TGPP, name: "Recipient-SCCP-Address",             data_type: AvpType::Address },
    AvpDef { code: 2011, vendor_id: TGPP, name: "Reply-Path-Requested",               data_type: AvpType::Enumerated },
    AvpDef { code: 2012, vendor_id: TGPP, name: "SM-Discharge-Time",                  data_type: AvpType::Time },
    AvpDef { code: 2013, vendor_id: TGPP, name: "SM-Protocol-ID",                     data_type: AvpType::OctetString },
    AvpDef { code: 2014, vendor_id: TGPP, name: "SM-Status",                          data_type: AvpType::OctetString },
    AvpDef { code: 2015, vendor_id: TGPP, name: "SM-User-Data-Header",                data_type: AvpType::OctetString },
    AvpDef { code: 2016, vendor_id: TGPP, name: "SMS-Node",                           data_type: AvpType::Enumerated },
    // TS 32.299 §7.2.171: code 2017 is SMSC-Address (the prior "Interface-Id"
    // label was wrong — Interface-Id is 2003 — and was never emitted). The old
    // (2024 Interface-Text / 2025 Interface-Type) rows were likewise mislabeled
    // and unused, so removed rather than left to poison the generic decoder.
    AvpDef { code: 2017, vendor_id: TGPP, name: "SMSC-Address",                       data_type: AvpType::Address },
    AvpDef { code: 2018, vendor_id: TGPP, name: "Client-Address",                     data_type: AvpType::Address },
    AvpDef { code: 2019, vendor_id: TGPP, name: "Number-of-Messages-Sent",            data_type: AvpType::Unsigned32 },
    AvpDef { code: 2026, vendor_id: TGPP, name: "Recipient-Info",                     data_type: AvpType::Grouped },
    AvpDef { code: 2027, vendor_id: TGPP, name: "Originator-Received-Address",        data_type: AvpType::Grouped },
    AvpDef { code: 2028, vendor_id: TGPP, name: "Recipient-Received-Address",         data_type: AvpType::Grouped },
    AvpDef { code: 2029, vendor_id: TGPP, name: "SM-Service-Type",                    data_type: AvpType::Enumerated },
    // Charging — Visited Network Identifier (TS 32.299 §7.2.74)
    AvpDef { code: 2713, vendor_id: TGPP, name: "IMS-Visited-Network-Identifier",     data_type: AvpType::UTF8String },
    // SMS-Information extras (TS 32.299 §7.2.79) interleaved with S6c codes by code order
    AvpDef { code: 3010, vendor_id: TGPP, name: "Application-Port-Identifier",        data_type: AvpType::Unsigned32 },
    AvpDef { code: 3111, vendor_id: TGPP, name: "External-Identifier",                data_type: AvpType::UTF8String },
    // S6c (TS 29.336) and SGd (TS 29.338) — SMS over Diameter
    AvpDef { code: 3300, vendor_id: TGPP, name: "SC-Address",                         data_type: AvpType::ISDNAddressString },
    AvpDef { code: 3301, vendor_id: TGPP, name: "SM-RP-UI",                           data_type: AvpType::OctetString },
    AvpDef { code: 3308, vendor_id: TGPP, name: "SM-RP-MTI",                          data_type: AvpType::Enumerated },
    AvpDef { code: 3316, vendor_id: TGPP, name: "SM-Delivery-Outcome",                data_type: AvpType::Grouped },
    AvpDef { code: 3324, vendor_id: TGPP, name: "SMSMI-Correlation-ID",               data_type: AvpType::Grouped },
    AvpDef { code: 3332, vendor_id: TGPP, name: "SMS-GMSC-Address",                   data_type: AvpType::Address },
    // SMS-Information device-trigger / result extras (TS 32.299 §7.2.79).
    // MTC-IWF-Address is 3406 and SMS-Result is 3409 (verified against the
    // go-diameter tgpp_ro_rf dictionary). The prior 3413/3408 codes were wrong
    // — 3408 is SM-Sequence-Number and 3413 is Teleservice — and were emitted
    // on the Rf wire, so a CDF would misparse the SMS record.
    AvpDef { code: 3405, vendor_id: TGPP, name: "SM-Device-Trigger-Information",      data_type: AvpType::Grouped },
    AvpDef { code: 3406, vendor_id: TGPP, name: "MTC-IWF-Address",                    data_type: AvpType::Address },
    AvpDef { code: 3407, vendor_id: TGPP, name: "SM-Device-Trigger-Indicator",        data_type: AvpType::Enumerated },
    AvpDef { code: 3409, vendor_id: TGPP, name: "SMS-Result",                         data_type: AvpType::Unsigned32 },
];

/// Look up an AVP definition by (code, vendor_id).
///
/// Uses binary search on the static table (sorted by vendor_id, then code).
pub fn lookup_avp(code: u32, vendor_id: u32) -> Option<&'static AvpDef> {
    AVP_TABLE
        .binary_search_by(|entry| {
            entry.vendor_id.cmp(&vendor_id).then(entry.code.cmp(&code))
        })
        .ok()
        .map(|idx| &AVP_TABLE[idx])
}

/// Look up an AVP definition by name (linear scan — use sparingly).
pub fn lookup_by_name(name: &str) -> Option<&'static AvpDef> {
    AVP_TABLE.iter().find(|entry| entry.name == name)
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
    let kebab = name.replace('_', "-");
    AVP_TABLE
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(&kebab))
}

/// Look up an AVP name by code (tries vendor=0, then vendor=10415).
pub fn avp_name(code: u32) -> Option<&'static str> {
    lookup_avp(code, 0)
        .or_else(|| lookup_avp(code, VENDOR_3GPP))
        .map(|def| def.name)
}

/// Total number of AVP definitions in the dictionary.
pub fn avp_count() -> usize {
    AVP_TABLE.len()
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
/// 3GPP Vendor-Id
pub const VENDOR_3GPP: u32 = 10415;

/// Resolve an application name (case-insensitive) to its
/// `(vendor_id, app_id)` tuple. Accepts the canonical short form
/// (`"Cx"`, `"Sh"`, `"Rx"`, `"Ro"`, `"Rf"`, `"S6c"`, `"SGd"`).
pub fn app_id_by_name(name: &str) -> Option<(u32, u32)> {
    let lower = name.to_ascii_lowercase();
    match lower.as_str() {
        "cx" => Some((VENDOR_3GPP, CX_APP_ID)),
        "sh" => Some((VENDOR_3GPP, SH_APP_ID)),
        "rx" => Some((VENDOR_3GPP, RX_APP_ID)),
        "ro" => Some((0, RO_APP_ID)),
        "rf" => Some((0, RF_APP_ID)),
        "s6c" => Some((VENDOR_3GPP, S6C_APP_ID)),
        "sgd" => Some((VENDOR_3GPP, SGD_APP_ID)),
        "s6a" => Some((VENDOR_3GPP, S6A_APP_ID)),
        _ => None,
    }
}

/// Whether an application-id is a Diameter *accounting* application, which is
/// advertised in the CER/CEA via `Acct-Application-Id (259)` rather than
/// `Auth-Application-Id (258)` (RFC 6733 §2.4 / §6.9). Today only base
/// accounting — Rf (id 3) — is an accounting application; every other app
/// SIPhon speaks (Cx/Sh/Rx/Ro/S6a/S6c/SGd) is an auth application. Advertising
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
        RX_APP_ID => Some("Rx"),
        RO_APP_ID => Some("Ro"),
        RF_APP_ID => Some("Rf"),
        S6C_APP_ID => Some("S6c"),
        SGD_APP_ID => Some("SGd"),
        S6A_APP_ID => Some("S6a"),
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
        "report-sm-delivery-status" | "rsr" | "rsa" => {
            Some(CMD_REPORT_SM_DELIVERY_STATUS)
        }
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
pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
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

// ── AVP Codes (for encoding) ─────────────────────────────────────────────

pub mod avp {
    // Base Diameter
    pub const USER_NAME: u32 = 1;
    pub const HOST_IP_ADDRESS: u32 = 257;
    pub const AUTH_APPLICATION_ID: u32 = 258;
    pub const VENDOR_SPECIFIC_APPLICATION_ID: u32 = 260;
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const SUPPORTED_VENDOR_ID: u32 = 265;
    pub const VENDOR_ID: u32 = 266;
    pub const FIRMWARE_REVISION: u32 = 267;
    pub const RESULT_CODE: u32 = 268;
    pub const PRODUCT_NAME: u32 = 269;
    pub const DISCONNECT_CAUSE: u32 = 273;
    pub const AUTH_SESSION_STATE: u32 = 277;
    pub const ORIGIN_STATE_ID: u32 = 278;
    pub const ERROR_MESSAGE: u32 = 281;
    pub const ROUTE_RECORD: u32 = 282;
    pub const DESTINATION_REALM: u32 = 283;
    pub const DESTINATION_HOST: u32 = 293;
    pub const TERMINATION_CAUSE: u32 = 295;
    pub const ORIGIN_REALM: u32 = 296;
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;

    // RFC 6733 §8.21 Event-Timestamp / §8.19 Acct-Interim-Interval
    pub const EVENT_TIMESTAMP: u32 = 55;
    pub const ACCT_INTERIM_INTERVAL: u32 = 85;

    // Base RADIUS/Diameter
    pub const FRAMED_IP_ADDRESS: u32 = 8;
    pub const FRAMED_IPV6_PREFIX: u32 = 97;
    pub const ACCT_APPLICATION_ID: u32 = 259;

    // Accounting (RFC 6733)
    pub const ACCOUNTING_RECORD_TYPE: u32 = 480;
    pub const ACCOUNTING_RECORD_NUMBER: u32 = 485;

    // RFC 8506 (obsoletes RFC 4006) Credit-Control / Gy — vendor 0.
    // Codes per the IANA aaa-parameters registry; see the AVP_TABLE note.
    pub const FILTER_ID: u32 = 11;
    pub const CC_INPUT_OCTETS: u32 = 412;
    pub const CC_MONEY: u32 = 413;
    pub const CC_OUTPUT_OCTETS: u32 = 414;
    pub const CC_REQUEST_NUMBER: u32 = 415;
    pub const CC_REQUEST_TYPE: u32 = 416;
    pub const CC_SERVICE_SPECIFIC_UNITS: u32 = 417;
    pub const CC_SESSION_FAILOVER: u32 = 418;
    pub const CC_SUB_SESSION_ID: u32 = 419;
    pub const CC_TIME: u32 = 420;
    pub const CC_TOTAL_OCTETS: u32 = 421;
    pub const CREDIT_CONTROL_FAILURE_HANDLING: u32 = 427;
    pub const FINAL_UNIT_INDICATION: u32 = 430;
    pub const GRANTED_SERVICE_UNIT: u32 = 431;
    pub const RATING_GROUP: u32 = 432;
    pub const REDIRECT_ADDRESS_TYPE: u32 = 433;
    pub const REDIRECT_SERVER: u32 = 434;
    pub const REDIRECT_SERVER_ADDRESS: u32 = 435;
    pub const REQUESTED_ACTION: u32 = 436;
    pub const REQUESTED_SERVICE_UNIT: u32 = 437;
    pub const RESTRICTION_FILTER_RULE: u32 = 438;
    pub const SERVICE_IDENTIFIER: u32 = 439;
    pub const SUBSCRIPTION_ID: u32 = 443;
    pub const SUBSCRIPTION_ID_DATA: u32 = 444;
    pub const USED_SERVICE_UNIT: u32 = 446;
    pub const VALIDITY_TIME: u32 = 448;
    pub const FINAL_UNIT_ACTION: u32 = 449;
    pub const SUBSCRIPTION_ID_TYPE: u32 = 450;
    pub const G_S_U_POOL_IDENTIFIER: u32 = 453;
    pub const MULTIPLE_SERVICES_INDICATOR: u32 = 455;
    pub const MULTIPLE_SERVICES_CREDIT_CONTROL: u32 = 456;
    pub const G_S_U_POOL_REFERENCE: u32 = 457;
    pub const USER_EQUIPMENT_INFO: u32 = 458;
    pub const USER_EQUIPMENT_INFO_TYPE: u32 = 459;
    pub const USER_EQUIPMENT_INFO_VALUE: u32 = 460;
    pub const SERVICE_CONTEXT_ID: u32 = 461;

    // 3GPP Cx (TS 29.228)
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
    pub const PUBLIC_IDENTITY: u32 = 601;
    pub const SERVER_NAME: u32 = 602;
    pub const SERVER_CAPABILITIES: u32 = 603;
    pub const MANDATORY_CAPABILITY: u32 = 604;
    pub const OPTIONAL_CAPABILITY: u32 = 605;
    pub const USER_DATA_CX: u32 = 606;
    pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
    pub const SIP_AUTHENTICATION_SCHEME: u32 = 608;
    pub const SIP_AUTHENTICATE: u32 = 609;
    pub const SIP_AUTHORIZATION: u32 = 610;
    pub const SIP_AUTH_DATA_ITEM: u32 = 612;
    pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
    pub const DEREGISTRATION_REASON: u32 = 615;
    pub const REASON_CODE: u32 = 616;
    pub const REASON_INFO: u32 = 617;
    pub const CHARGING_INFORMATION: u32 = 618;
    pub const USER_AUTHORIZATION_TYPE: u32 = 623;
    pub const USER_DATA_ALREADY_AVAILABLE: u32 = 624;
    pub const CONFIDENTIALITY_KEY: u32 = 625;
    pub const INTEGRITY_KEY: u32 = 626;
    pub const SUPPORTED_FEATURES: u32 = 628;
    pub const FEATURE_LIST_ID: u32 = 629;
    pub const FEATURE_LIST: u32 = 630;

    // 3GPP Sh (TS 29.329)
    pub const MSISDN: u32 = 701;
    pub const USER_IDENTITY: u32 = 700;
    pub const USER_DATA_SH: u32 = 702;
    pub const DATA_REFERENCE: u32 = 703;
    pub const SERVICE_INDICATION: u32 = 704;
    pub const SUBS_REQ_TYPE: u32 = 705;

    // 3GPP Gx (TS 29.212)
    pub const CHARGING_RULE_INSTALL: u32 = 1001;
    pub const CHARGING_RULE_REMOVE: u32 = 1002;
    pub const CHARGING_RULE_DEFINITION: u32 = 1003;
    pub const CHARGING_RULE_BASE_NAME: u32 = 1004;
    pub const CHARGING_RULE_NAME: u32 = 1005;
    pub const EVENT_TRIGGER: u32 = 1006;
    pub const METERING_METHOD: u32 = 1007;
    pub const OFFLINE: u32 = 1008;
    pub const ONLINE: u32 = 1009;
    pub const PRECEDENCE: u32 = 1010;
    pub const QOS_INFORMATION: u32 = 1016;
    pub const BEARER_IDENTIFIER: u32 = 1020;
    pub const GUARANTEED_BITRATE_DL: u32 = 1025;
    pub const GUARANTEED_BITRATE_UL: u32 = 1026;
    pub const IP_CAN_TYPE: u32 = 1027;
    pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
    pub const PRIORITY_LEVEL: u32 = 1046;
    pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
    pub const DEFAULT_EPS_BEARER_QOS: u32 = 1049;

    // 3GPP Rx (TS 29.214)
    pub const ABORT_CAUSE: u32 = 500;
    pub const ACCESS_NETWORK_CHARGING_ADDRESS: u32 = 501;
    pub const ACCESS_NETWORK_CHARGING_IDENTIFIER: u32 = 502;
    pub const AF_APPLICATION_IDENTIFIER: u32 = 504;
    pub const AF_CHARGING_IDENTIFIER: u32 = 505;
    pub const FLOW_DESCRIPTION: u32 = 507;
    pub const FLOW_NUMBER: u32 = 509;
    pub const FLOWS: u32 = 510;
    pub const FLOW_STATUS: u32 = 511;
    pub const FLOW_USAGE: u32 = 512;
    pub const SPECIFIC_ACTION: u32 = 513;
    pub const MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
    pub const MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
    pub const MEDIA_COMPONENT_DESCRIPTION: u32 = 517;
    pub const MEDIA_COMPONENT_NUMBER: u32 = 518;
    pub const MEDIA_SUB_COMPONENT: u32 = 519;
    pub const MEDIA_TYPE: u32 = 520;
    pub const CODEC_DATA: u32 = 524;
    pub const SERVICE_INFO_STATUS: u32 = 527;
    pub const RX_REQUEST_TYPE: u32 = 533;

    // 3GPP Ro/Rf Charging (TS 32.299)
    pub const EVENT_TYPE: u32 = 823;
    pub const SIP_METHOD_CHARGING: u32 = 824;
    pub const EVENT: u32 = 825;
    pub const ROLE_OF_NODE: u32 = 829;
    pub const USER_SESSION_ID: u32 = 830;
    pub const CALLING_PARTY_ADDRESS: u32 = 831;
    pub const CALLED_PARTY_ADDRESS: u32 = 832;
    pub const TIME_STAMPS: u32 = 833;
    pub const SIP_REQUEST_TIMESTAMP: u32 = 834;
    pub const SIP_RESPONSE_TIMESTAMP: u32 = 835;
    pub const APPLICATION_SERVER: u32 = 836;
    pub const APPLICATION_PROVIDED_CALLED_PARTY_ADDRESS: u32 = 837;
    pub const INTER_OPERATOR_IDENTIFIER: u32 = 838;
    pub const ORIGINATING_IOI: u32 = 839;
    pub const TERMINATING_IOI: u32 = 840;
    pub const IMS_CHARGING_IDENTIFIER: u32 = 841;
    pub const SERVED_PARTY_IP_ADDRESS: u32 = 848;
    pub const APPLICATION_SERVER_INFORMATION: u32 = 850;
    pub const TRUNK_GROUP_ID: u32 = 851;
    pub const INCOMING_TRUNK_GROUP_ID: u32 = 852;
    pub const OUTGOING_TRUNK_GROUP_ID: u32 = 853;
    pub const CAUSE_CODE: u32 = 861;
    pub const NODE_FUNCTIONALITY: u32 = 862;
    pub const SERVICE_INFORMATION: u32 = 873;
    pub const IMS_INFORMATION: u32 = 876;
    pub const IMS_VISITED_NETWORK_IDENTIFIER: u32 = 2713;


    // 3GPP S6c served-node identifiers
    pub const SGSN_NUMBER: u32 = 1489;
    pub const MME_NUMBER_FOR_MT_SMS: u32 = 1645;

    // 3GPP S6c (TS 29.336) and SGd (TS 29.338) — SMS over Diameter
    pub const SC_ADDRESS: u32 = 3300;
    pub const SM_RP_UI: u32 = 3301;
    pub const SM_RP_MTI: u32 = 3308;
    pub const SM_DELIVERY_OUTCOME: u32 = 3316;
    pub const SMSMI_CORRELATION_ID: u32 = 3324;
    pub const SMS_GMSC_ADDRESS: u32 = 3332;

    // 3GPP SMS-Information (TS 32.299 §7.2.79) — IMS SMS offline charging
    pub const ORIGINATOR_ADDRESS: u32 = 886;
    pub const ADDRESS_DATA: u32 = 897;
    pub const ADDRESS_TYPE: u32 = 899;
    pub const RECIPIENT_ADDRESS: u32 = 1201;
    pub const SMS_INFORMATION: u32 = 2000;
    pub const DATA_CODING_SCHEME: u32 = 2001;
    pub const SM_MESSAGE_TYPE: u32 = 2007;
    pub const ORIGINATOR_SCCP_ADDRESS: u32 = 2008;
    pub const ORIGINATOR_INTERFACE: u32 = 2009;
    pub const RECIPIENT_SCCP_ADDRESS: u32 = 2010;
    pub const REPLY_PATH_REQUESTED: u32 = 2011;
    pub const SM_DISCHARGE_TIME: u32 = 2012;
    pub const SM_PROTOCOL_ID: u32 = 2013;
    pub const SM_STATUS: u32 = 2014;
    pub const SM_USER_DATA_HEADER: u32 = 2015;
    pub const SMS_NODE: u32 = 2016;
    pub const SMSC_ADDRESS: u32 = 2017;
    pub const CLIENT_ADDRESS: u32 = 2018;
    pub const NUMBER_OF_MESSAGES_SENT: u32 = 2019;
    pub const RECIPIENT_INFO: u32 = 2026;
    pub const ORIGINATOR_RECEIVED_ADDRESS: u32 = 2027;
    pub const RECIPIENT_RECEIVED_ADDRESS: u32 = 2028;
    pub const SM_SERVICE_TYPE: u32 = 2029;
    pub const APPLICATION_PORT_IDENTIFIER: u32 = 3010;
    pub const EXTERNAL_IDENTIFIER: u32 = 3111;
    pub const SM_DEVICE_TRIGGER_INFORMATION: u32 = 3405;
    pub const MTC_IWF_ADDRESS: u32 = 3406;
    pub const SM_DEVICE_TRIGGER_INDICATOR: u32 = 3407;
    pub const SMS_RESULT: u32 = 3409;

    // ── S6a / S6d (TS 29.272) ────────────────────────────────────────────
    pub const RAT_TYPE: u32 = 1032;
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    pub const TERMINAL_INFORMATION: u32 = 1401;
    pub const IMEI: u32 = 1402;
    pub const SOFTWARE_VERSION: u32 = 1403;
    pub const ULR_FLAGS: u32 = 1405;
    pub const ULA_FLAGS: u32 = 1406;
    pub const VISITED_PLMN_ID: u32 = 1407;
    pub const REQUESTED_EUTRAN_AUTHENTICATION_INFO: u32 = 1408;
    pub const NUMBER_OF_REQUESTED_VECTORS: u32 = 1410;
    pub const RE_SYNCHRONIZATION_INFO: u32 = 1411;
    pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
    pub const AUTHENTICATION_INFO: u32 = 1413;
    pub const E_UTRAN_VECTOR: u32 = 1414;
    pub const CANCELLATION_TYPE: u32 = 1420;
    pub const RAND: u32 = 1447;
    pub const XRES: u32 = 1448;
    pub const AUTN: u32 = 1449;
    pub const KASME: u32 = 1450;
    pub const PUR_FLAGS: u32 = 1635;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_ordering_is_valid() {
        for pair in AVP_TABLE.windows(2) {
            let left = (pair[0].vendor_id, pair[0].code);
            let right = (pair[1].vendor_id, pair[1].code);
            assert!(
                left < right,
                "table not sorted at {} (v={}) vs {} (v={})",
                pair[0].name, pair[0].vendor_id,
                pair[1].name, pair[1].vendor_id,
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
        assert!(avp_count() > 100, "dictionary should have > 100 AVP entries");
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
            ("SMSC-Address", 2017, TGPP),
            ("MTC-IWF-Address", 3406, TGPP),
            ("SMS-Result", 3409, TGPP),
        ];
        for &(name, code, vendor) in reference {
            let entry = lookup_by_name(name)
                .unwrap_or_else(|| panic!("dictionary missing AVP {name}"));
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
        assert!(lookup_avp(2006, TGPP).is_none(), "stale 3GPP MSCC still present");
        assert_eq!(lookup_avp(426, 0).unwrap().name, "Credit-Control");
        assert_eq!(lookup_avp(456, 0).unwrap().name, "Multiple-Services-Credit-Control");
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
            lookup_avp_by_python_name("visited_network_identifier").unwrap().code,
            600
        );
        assert!(lookup_avp_by_python_name("not_a_real_avp").is_none());
    }

    #[test]
    fn app_id_by_name_round_trips() {
        for app in &["Cx", "Sh", "Rx", "Ro", "Rf", "S6c", "SGd"] {
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
        assert_eq!(command_code_by_name("SRR"), Some(CMD_SEND_ROUTING_INFO_FOR_SM));
        assert_eq!(command_code_by_name("ALR"), Some(CMD_ALERT_SERVICE_CENTRE));
        assert_eq!(command_code_by_name("TFR"), Some(CMD_MT_FORWARD_SHORT_MESSAGE));
        assert_eq!(command_code_by_name("OFR"), Some(CMD_MO_FORWARD_SHORT_MESSAGE));
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
        assert_eq!(
            command_code_by_name("alr"),
            command_code_by_name("ALR"),
        );
    }

    #[test]
    fn command_code_by_name_returns_none_for_unknown() {
        assert!(command_code_by_name("Bogus-Request").is_none());
    }
}
