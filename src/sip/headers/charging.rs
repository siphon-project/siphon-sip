//! IMS charging header parsers (3GPP / IETF).
//!
//! - `P-Charging-Vector` (RFC 7315 §5.6) — `icid-value`, `orig-ioi`, `term-ioi`,
//!   `icid-generated-at`. Mandatory in IMS dialogs; ICID is the unique
//!   correlator that ties together every ACR (S-CSCF, P-CSCF, AS, …) for
//!   the same session per TS 32.299 §7.2.73.
//! - `P-Served-User` (RFC 5502) — explicit served-user identity used by
//!   S-CSCF to disambiguate originating vs terminating role per
//!   TS 24.229 §5.4.3.2.
//! - `P-Visited-Network-ID` (RFC 7315 §5.5) — visited network identifier
//!   for roaming users; copied into the `IMS-Visited-Network-Identifier`
//!   AVP per TS 32.299 §7.2.74.

/// Parsed `P-Charging-Vector` header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChargingVector {
    /// IMS Charging Identifier — unique per session, unquoted.
    pub icid: Option<String>,
    /// Host that generated the ICID (RFC 7315 `icid-generated-at`).
    pub icid_generated_at: Option<String>,
    /// Originating Inter-Operator Identifier.
    pub orig_ioi: Option<String>,
    /// Terminating Inter-Operator Identifier.
    pub term_ioi: Option<String>,
}

/// Parsed `P-Served-User` header (RFC 5502).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedUser {
    /// SIP/SIPS/TEL URI — unwrapped from `<...>` if present.
    pub uri: String,
    /// Session case: `"orig"` or `"term"`.
    pub sescase: Option<String>,
    /// Registration state: `"reg"` or `"unreg"`.
    pub regstate: Option<String>,
}

impl ChargingVector {
    /// Parse a `P-Charging-Vector` header value per RFC 7315 §5.6.
    ///
    /// Accepts both quoted (`icid-value="..."`) and unquoted forms; siphon
    /// itself emits unquoted (TS 24.229-compatible) but real-world traffic
    /// includes both.
    pub fn parse(value: &str) -> Self {
        let mut out = ChargingVector::default();
        for raw in value.split(';') {
            let part = raw.trim();
            if part.is_empty() {
                continue;
            }
            let (key, val) = match part.split_once('=') {
                Some((k, v)) => (k.trim(), strip_quotes(v.trim())),
                None => continue,
            };
            match key.to_ascii_lowercase().as_str() {
                "icid-value" => out.icid = Some(val.to_string()),
                "icid-generated-at" => out.icid_generated_at = Some(val.to_string()),
                "orig-ioi" => out.orig_ioi = Some(val.to_string()),
                "term-ioi" => out.term_ioi = Some(val.to_string()),
                _ => {}
            }
        }
        out
    }

    /// True if no fields were extracted.
    pub fn is_empty(&self) -> bool {
        self.icid.is_none()
            && self.icid_generated_at.is_none()
            && self.orig_ioi.is_none()
            && self.term_ioi.is_none()
    }
}

impl ServedUser {
    /// Parse a `P-Served-User` header value per RFC 5502 §3.2.
    ///
    /// Returns `None` if no URI can be extracted.
    pub fn parse(value: &str) -> Option<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return None;
        }

        let (uri_part, params_part) = split_uri_and_params(trimmed);
        let uri = unwrap_uri(uri_part).to_string();
        if uri.is_empty() {
            return None;
        }

        let mut sescase = None;
        let mut regstate = None;
        for raw in params_part.split(';') {
            let part = raw.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((key, val)) = part.split_once('=') {
                let lower = key.trim().to_ascii_lowercase();
                let v = strip_quotes(val.trim()).to_ascii_lowercase();
                match lower.as_str() {
                    "sescase" if v == "orig" || v == "term" => sescase = Some(v),
                    "regstate" if v == "reg" || v == "unreg" => regstate = Some(v),
                    _ => {}
                }
            }
        }

        Some(ServedUser {
            uri,
            sescase,
            regstate,
        })
    }
}

/// Parse the first `vnetwork-spec` from a `P-Visited-Network-ID` header
/// value per RFC 7315 §5.5. Multiple values are comma-separated; we return
/// the first one with surrounding quotes stripped. Returns `None` for an
/// empty value.
pub fn parse_visited_network_id(value: &str) -> Option<String> {
    let first = value.split(',').next()?.trim();
    let first = match first.split_once(';') {
        Some((spec, _params)) => spec.trim(),
        None => first,
    };
    let unquoted = strip_quotes(first);
    if unquoted.is_empty() {
        None
    } else {
        Some(unquoted.to_string())
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

fn strip_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 && bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"' {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Split a name-addr/addr-spec from its `;`-prefixed parameter section.
///
/// Handles `<sip:user@host>;sescase=orig` (split at the first `;` after
/// `>`) as well as bare `sip:user@host;param=value` (split at first `;`).
fn split_uri_and_params(input: &str) -> (&str, &str) {
    if let Some(start) = input.find('<') {
        if let Some(rel_end) = input[start..].find('>') {
            let end = start + rel_end + 1;
            let head = &input[..end];
            let tail = input[end..].trim_start();
            let tail = tail.strip_prefix(';').unwrap_or(tail);
            return (head, tail);
        }
    }
    match input.split_once(';') {
        Some((head, tail)) => (head, tail),
        None => (input, ""),
    }
}

fn unwrap_uri(input: &str) -> &str {
    let trimmed = input.trim();
    if let (Some(open), Some(close)) = (trimmed.find('<'), trimmed.rfind('>')) {
        if open < close {
            return trimmed[open + 1..close].trim();
        }
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── P-Charging-Vector ───────────────────────────────────────────────

    #[test]
    fn charging_vector_full() {
        let cv = ChargingVector::parse(
            "icid-value=AyretyU0dm+6O2IrT5tAFrbHLso=023551024;\
             icid-generated-at=192.0.6.8;\
             orig-ioi=home1.net;term-ioi=home2.net",
        );
        assert_eq!(
            cv.icid.as_deref(),
            Some("AyretyU0dm+6O2IrT5tAFrbHLso=023551024")
        );
        assert_eq!(cv.icid_generated_at.as_deref(), Some("192.0.6.8"));
        assert_eq!(cv.orig_ioi.as_deref(), Some("home1.net"));
        assert_eq!(cv.term_ioi.as_deref(), Some("home2.net"));
    }

    #[test]
    fn charging_vector_quoted_icid() {
        // Real-world IMS traffic frequently quotes the ICID
        let cv = ChargingVector::parse(
            "icid-value=\"AyretyU0dm+6O2IrT5tAFrbHLso=023551024\";orig-ioi=home1.net",
        );
        assert_eq!(
            cv.icid.as_deref(),
            Some("AyretyU0dm+6O2IrT5tAFrbHLso=023551024")
        );
        assert_eq!(cv.orig_ioi.as_deref(), Some("home1.net"));
        assert!(cv.term_ioi.is_none());
    }

    #[test]
    fn charging_vector_only_icid() {
        let cv = ChargingVector::parse("icid-value=icid-rf-test-001");
        assert_eq!(cv.icid.as_deref(), Some("icid-rf-test-001"));
        assert!(cv.icid_generated_at.is_none());
        assert!(cv.orig_ioi.is_none());
        assert!(cv.term_ioi.is_none());
    }

    #[test]
    fn charging_vector_unknown_params_ignored() {
        let cv = ChargingVector::parse("icid-value=icid-1;ggsn=gw.example.com;auth-token=opaque");
        assert_eq!(cv.icid.as_deref(), Some("icid-1"));
        assert!(cv.icid_generated_at.is_none());
    }

    #[test]
    fn charging_vector_empty() {
        let cv = ChargingVector::parse("");
        assert!(cv.is_empty());
    }

    #[test]
    fn charging_vector_whitespace_tolerant() {
        let cv = ChargingVector::parse(" icid-value = icid-1 ; orig-ioi = home1.net ");
        assert_eq!(cv.icid.as_deref(), Some("icid-1"));
        assert_eq!(cv.orig_ioi.as_deref(), Some("home1.net"));
    }

    #[test]
    fn charging_vector_case_insensitive_keys() {
        let cv = ChargingVector::parse("ICID-Value=icid-1;Orig-IOI=home1.net");
        assert_eq!(cv.icid.as_deref(), Some("icid-1"));
        assert_eq!(cv.orig_ioi.as_deref(), Some("home1.net"));
    }

    // ── P-Served-User ───────────────────────────────────────────────────

    #[test]
    fn served_user_orig() {
        let su = ServedUser::parse("<sip:user1@example.com>;sescase=orig;regstate=reg").unwrap();
        assert_eq!(su.uri, "sip:user1@example.com");
        assert_eq!(su.sescase.as_deref(), Some("orig"));
        assert_eq!(su.regstate.as_deref(), Some("reg"));
    }

    #[test]
    fn served_user_term_unreg() {
        let su = ServedUser::parse("<sip:user2@example.com>;sescase=term;regstate=unreg").unwrap();
        assert_eq!(su.sescase.as_deref(), Some("term"));
        assert_eq!(su.regstate.as_deref(), Some("unreg"));
    }

    #[test]
    fn served_user_bare_addr_spec() {
        // RFC 5502 allows addr-spec without angle brackets when there are no
        // parameters that would require disambiguation
        let su = ServedUser::parse("sip:user@example.com").unwrap();
        assert_eq!(su.uri, "sip:user@example.com");
        assert!(su.sescase.is_none());
        assert!(su.regstate.is_none());
    }

    #[test]
    fn served_user_invalid_sescase_dropped() {
        let su = ServedUser::parse("<sip:u@h>;sescase=bogus").unwrap();
        assert_eq!(su.uri, "sip:u@h");
        assert!(su.sescase.is_none());
    }

    #[test]
    fn served_user_empty_returns_none() {
        assert!(ServedUser::parse("").is_none());
        assert!(ServedUser::parse("   ").is_none());
    }

    #[test]
    fn served_user_tel_uri() {
        let su = ServedUser::parse("<tel:+15551234>;sescase=orig").unwrap();
        assert_eq!(su.uri, "tel:+15551234");
        assert_eq!(su.sescase.as_deref(), Some("orig"));
    }

    // ── P-Visited-Network-ID ────────────────────────────────────────────

    #[test]
    fn visited_network_unquoted() {
        assert_eq!(
            parse_visited_network_id("other.net"),
            Some("other.net".into())
        );
    }

    #[test]
    fn visited_network_quoted_with_spaces() {
        assert_eq!(
            parse_visited_network_id("\"Visited Network 1\""),
            Some("Visited Network 1".into())
        );
    }

    #[test]
    fn visited_network_first_of_many() {
        // RFC 7315 allows comma-separated lists; we take the first value
        assert_eq!(
            parse_visited_network_id("home.example.com, \"Visited 2\""),
            Some("home.example.com".into())
        );
    }

    #[test]
    fn visited_network_strips_params() {
        assert_eq!(
            parse_visited_network_id("other.net;tag=1"),
            Some("other.net".into())
        );
    }

    #[test]
    fn visited_network_empty() {
        assert_eq!(parse_visited_network_id(""), None);
        assert_eq!(parse_visited_network_id("\"\""), None);
    }
}
