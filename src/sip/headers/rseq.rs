//! RFC 3262 RSeq / RAck header parsing for reliable provisional responses.
//!
//! Format:
//!   RSeq: <response-number>
//!   RAck: <response-number> <cseq-number> <method>

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::OnceLock;

/// Allocate the next RSeq value for a reliable provisional response.
///
/// RFC 3262 §3 requires the initial RSeq to be chosen randomly in the range
/// [1, 2^31 - 1] and to increase monotonically per response within a dialog.
/// A process-wide atomic counter satisfies both — random first value, then
/// monotonic across all dialogs (each dialog only ever sees a strictly
/// increasing subsequence, which is what the spec actually mandates).
pub fn next_rseq() -> u32 {
    static COUNTER: OnceLock<AtomicU32> = OnceLock::new();
    let counter = COUNTER.get_or_init(|| {
        let mut buf = [0u8; 4];
        let _ = getrandom::fill(&mut buf);
        // Mask to 31 bits (RFC 3262 ceiling) and ensure non-zero (RSeq MUST > 0).
        let init = u32::from_le_bytes(buf) & 0x7FFF_FFFF;
        AtomicU32::new(init.max(1))
    });
    let value = counter.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF;
    if value == 0 {
        counter.fetch_add(1, Ordering::Relaxed) & 0x7FFF_FFFF
    } else {
        value
    }
}

/// Parsed `RSeq` header — sequence number for a reliable provisional response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSeq {
    pub response_number: u32,
}

/// Parsed `RAck` header — acknowledges a reliable provisional response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    /// The RSeq number being acknowledged.
    pub response_number: u32,
    /// The CSeq number of the original INVITE.
    pub cseq_number: u32,
    /// The method of the original request (always "INVITE" in practice).
    pub method: String,
}

impl RSeq {
    /// Parse an `RSeq` header value.
    ///
    /// Example: "1" → RSeq { response_number: 1 }
    pub fn parse(value: &str) -> Option<Self> {
        let response_number = value.trim().parse::<u32>().ok()?;
        if response_number == 0 {
            return None; // RFC 3262 §7.1: RSeq MUST be > 0
        }
        Some(RSeq { response_number })
    }

    /// Format as a SIP header value.
    pub fn to_header_value(&self) -> String {
        self.response_number.to_string()
    }
}

impl RAck {
    /// Parse a `RAck` header value.
    ///
    /// Example: "776656 1 INVITE" → RAck { response_number: 776656, cseq_number: 1, method: "INVITE" }
    pub fn parse(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return None;
        }

        let response_number = parts[0].parse::<u32>().ok()?;
        let cseq_number = parts[1].parse::<u32>().ok()?;
        let method = parts[2].to_string();

        if response_number == 0 {
            return None;
        }

        Some(RAck {
            response_number,
            cseq_number,
            method,
        })
    }

    /// Format as a SIP header value.
    pub fn to_header_value(&self) -> String {
        format!(
            "{} {} {}",
            self.response_number, self.cseq_number, self.method
        )
    }
}

/// Check if a SIP message requires reliable provisional response handling.
/// Returns true if `Require` or `Supported` contains `100rel`.
pub fn supports_100rel(headers: &super::SipHeaders) -> bool {
    for header_name in &["Require", "Supported"] {
        if let Some(values) = headers.get_all(header_name) {
            for value in values {
                for token in value.split(',') {
                    if token.trim().eq_ignore_ascii_case("100rel") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check if `100rel` is in the `Require` header (mandatory, not just supported).
pub fn requires_100rel(headers: &super::SipHeaders) -> bool {
    if let Some(values) = headers.get_all("Require") {
        for value in values {
            for token in value.split(',') {
                if token.trim().eq_ignore_ascii_case("100rel") {
                    return true;
                }
            }
        }
    }
    false
}

/// Strip the `100rel` reliability contract from a response being forwarded
/// toward a peer that never advertised `100rel`.
///
/// Removes the `RSeq` header and the `100rel` option-tag from `Require`
/// (dropping `Require` entirely when no other option-tags remain). Returns
/// `true` when anything changed.
///
/// No-op when `peer_supports_100rel` is true — the reliable provisional then
/// flows end-to-end (RFC 3262 §3) — or when the response carries no
/// reliability markers, so it is safe to call on every forwarded response,
/// including 2xx/non-2xx that never carry `RSeq`.
///
/// A B2BUA that PRACKs a B-leg's reliable provisional locally must not present
/// the same contract to an A-leg that can't honour it: a plain SIP trunk that
/// never offered `100rel` will CANCEL a `183` carrying `Require: 100rel` rather
/// than PRACK it.
pub fn strip_100rel_for_unsupported_peer(
    headers: &mut super::SipHeaders,
    peer_supports_100rel: bool,
) -> bool {
    if peer_supports_100rel {
        return false;
    }
    let mut changed = false;
    if headers.has("RSeq") {
        headers.remove("RSeq");
        changed = true;
    }
    // Remove the `100rel` option-tag from any `Require` value, preserving the
    // others (e.g. `precondition`). Drop the header when nothing remains.
    if let Some(values) = headers.get_all("Require").cloned() {
        let mut kept: Vec<String> = Vec::new();
        let mut removed_any = false;
        for value in &values {
            let remaining: Vec<&str> = value
                .split(',')
                .map(|token| token.trim())
                .filter(|token| {
                    if token.eq_ignore_ascii_case("100rel") {
                        removed_any = true;
                        false
                    } else {
                        !token.is_empty()
                    }
                })
                .collect();
            if !remaining.is_empty() {
                kept.push(remaining.join(", "));
            }
        }
        if removed_any {
            changed = true;
            if kept.is_empty() {
                headers.remove("Require");
            } else {
                headers.set_all("Require", kept);
            }
        }
    }
    changed
}

/// Extract `RSeq` from SIP headers.
pub fn parse_rseq(headers: &super::SipHeaders) -> Option<RSeq> {
    headers.get("RSeq").and_then(|v| RSeq::parse(v))
}

/// Extract `RAck` from SIP headers.
pub fn parse_rack(headers: &super::SipHeaders) -> Option<RAck> {
    headers.get("RAck").and_then(|v| RAck::parse(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- RSeq parsing ---

    #[test]
    fn parse_rseq_simple() {
        let result = RSeq::parse("1").unwrap();
        assert_eq!(result.response_number, 1);
    }

    #[test]
    fn parse_rseq_large_number() {
        let result = RSeq::parse("776656").unwrap();
        assert_eq!(result.response_number, 776656);
    }

    #[test]
    fn parse_rseq_with_whitespace() {
        let result = RSeq::parse("  42  ").unwrap();
        assert_eq!(result.response_number, 42);
    }

    #[test]
    fn parse_rseq_zero_rejected() {
        assert!(RSeq::parse("0").is_none());
    }

    #[test]
    fn parse_rseq_invalid() {
        assert!(RSeq::parse("abc").is_none());
        assert!(RSeq::parse("").is_none());
    }

    #[test]
    fn rseq_to_header_value() {
        let rseq = RSeq {
            response_number: 42,
        };
        assert_eq!(rseq.to_header_value(), "42");
    }

    // --- RAck parsing ---

    #[test]
    fn parse_rack_standard() {
        let result = RAck::parse("776656 1 INVITE").unwrap();
        assert_eq!(result.response_number, 776656);
        assert_eq!(result.cseq_number, 1);
        assert_eq!(result.method, "INVITE");
    }

    #[test]
    fn parse_rack_with_whitespace() {
        let result = RAck::parse("  100  5  INVITE  ").unwrap();
        assert_eq!(result.response_number, 100);
        assert_eq!(result.cseq_number, 5);
        assert_eq!(result.method, "INVITE");
    }

    #[test]
    fn parse_rack_zero_response_number_rejected() {
        assert!(RAck::parse("0 1 INVITE").is_none());
    }

    #[test]
    fn parse_rack_missing_parts() {
        assert!(RAck::parse("776656 1").is_none());
        assert!(RAck::parse("776656").is_none());
        assert!(RAck::parse("").is_none());
    }

    #[test]
    fn parse_rack_too_many_parts() {
        assert!(RAck::parse("776656 1 INVITE extra").is_none());
    }

    #[test]
    fn parse_rack_invalid_numbers() {
        assert!(RAck::parse("abc 1 INVITE").is_none());
        assert!(RAck::parse("776656 abc INVITE").is_none());
    }

    #[test]
    fn rack_to_header_value() {
        let rack = RAck {
            response_number: 776656,
            cseq_number: 1,
            method: "INVITE".to_string(),
        };
        assert_eq!(rack.to_header_value(), "776656 1 INVITE");
    }

    // --- 100rel detection ---

    #[test]
    fn supports_100rel_in_supported() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Supported", "timer, 100rel, replaces".to_string());
        assert!(supports_100rel(&headers));
    }

    #[test]
    fn supports_100rel_in_require() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100rel".to_string());
        assert!(supports_100rel(&headers));
    }

    #[test]
    fn supports_100rel_case_insensitive() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Supported", "100REL".to_string());
        assert!(supports_100rel(&headers));
    }

    #[test]
    fn supports_100rel_not_present() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Supported", "timer, replaces".to_string());
        assert!(!supports_100rel(&headers));
    }

    #[test]
    fn requires_100rel_true() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100rel".to_string());
        assert!(requires_100rel(&headers));
    }

    #[test]
    fn requires_100rel_false_when_only_supported() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Supported", "100rel".to_string());
        assert!(!requires_100rel(&headers));
    }

    // --- Header extraction ---

    #[test]
    fn extract_rseq_from_headers() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("RSeq", "42".to_string());
        let rseq = parse_rseq(&headers).unwrap();
        assert_eq!(rseq.response_number, 42);
    }

    #[test]
    fn extract_rack_from_headers() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("RAck", "42 1 INVITE".to_string());
        let rack = parse_rack(&headers).unwrap();
        assert_eq!(rack.response_number, 42);
        assert_eq!(rack.cseq_number, 1);
        assert_eq!(rack.method, "INVITE");
    }

    #[test]
    fn extract_missing_headers() {
        let headers = super::super::SipHeaders::new();
        assert!(parse_rseq(&headers).is_none());
        assert!(parse_rack(&headers).is_none());
    }

    #[test]
    fn next_rseq_is_monotonic_and_nonzero() {
        let a = next_rseq();
        let b = next_rseq();
        let c = next_rseq();
        assert_ne!(a, 0);
        assert_ne!(b, 0);
        assert_ne!(c, 0);
        assert!(b > a || (a == 0x7FFF_FFFF && b == 1));
        assert!(c > b || (b == 0x7FFF_FFFF && c == 1));
        // 31-bit ceiling
        assert!(a <= 0x7FFF_FFFF);
        assert!(c <= 0x7FFF_FFFF);
    }

    // --- 100rel strip for an unsupported peer ---

    #[test]
    fn strip_100rel_removes_rseq_and_require_when_peer_unsupported() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100rel".to_string());
        headers.set("RSeq", "1".to_string());
        let changed = strip_100rel_for_unsupported_peer(&mut headers, false);
        assert!(changed);
        assert!(!headers.has("RSeq"));
        assert!(!headers.has("Require"));
    }

    #[test]
    fn strip_100rel_preserves_other_require_tags() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100rel, precondition".to_string());
        headers.set("RSeq", "7".to_string());
        let changed = strip_100rel_for_unsupported_peer(&mut headers, false);
        assert!(changed);
        assert!(!headers.has("RSeq"));
        assert_eq!(headers.get("Require"), Some(&"precondition".to_string()));
    }

    #[test]
    fn strip_100rel_noop_when_peer_supports() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100rel".to_string());
        headers.set("RSeq", "1".to_string());
        let changed = strip_100rel_for_unsupported_peer(&mut headers, true);
        assert!(!changed);
        assert!(headers.has("RSeq"));
        assert_eq!(headers.get("Require"), Some(&"100rel".to_string()));
    }

    #[test]
    fn strip_100rel_noop_without_markers() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "precondition".to_string());
        let changed = strip_100rel_for_unsupported_peer(&mut headers, false);
        assert!(!changed);
        assert!(!headers.has("RSeq"));
        assert_eq!(headers.get("Require"), Some(&"precondition".to_string()));
    }

    #[test]
    fn strip_100rel_case_insensitive() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Require", "100REL".to_string());
        headers.set("RSeq", "1".to_string());
        let changed = strip_100rel_for_unsupported_peer(&mut headers, false);
        assert!(changed);
        assert!(!headers.has("RSeq"));
        assert!(!headers.has("Require"));
    }
}
