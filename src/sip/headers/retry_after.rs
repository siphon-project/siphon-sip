//! RFC 3261 §20.33 `Retry-After` header parsing.
//!
//! Wire format:
//!   Retry-After = delta-seconds [ comment ] *( SEMI retry-param )
//!
//! e.g. `Retry-After: 18`, `Retry-After: 120 (I'm in a meeting)`,
//! `Retry-After: 30;duration=600`.
//!
//! Only the leading `delta-seconds` integer is meaningful for backoff /
//! failover decisions, so we parse that and ignore any trailing comment and
//! parameters. Unlike HTTP (RFC 7231 §7.1.3), SIP `Retry-After` is never an
//! HTTP-date, so an `HTTP-date`-shaped value (`Mon, 01 Jan 2035 ...`) simply
//! has no leading digits and yields `None`.

use std::time::Duration;

/// Parse a `Retry-After` header value into a cooldown `Duration`.
///
/// Reads the leading `delta-seconds` integer (RFC 3261 §20.33) and returns it
/// as a `Duration`; any trailing comment `(...)` and `;param`s are ignored.
/// Returns `None` when the value has no leading integer (absent header,
/// garbage, or an HTTP-date form) or overflows `u64` seconds.
///
/// Examples:
///   "18"                -> Some(18s)
///   "120 (I'm busy)"    -> Some(120s)
///   "30;duration=600"   -> Some(30s)
///   "Mon, 01 Jan ..."   -> None
///   "garbage"           -> None
pub fn parse(value: &str) -> Option<Duration> {
    let digits: String = value
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    // Overflow (an absurdly long digit run) parses to None rather than panicking.
    digits.parse::<u64>().ok().map(Duration::from_secs)
}

/// Extract and parse the `Retry-After` header from a message's headers.
pub fn parse_retry_after(headers: &super::SipHeaders) -> Option<Duration> {
    headers.get("Retry-After").and_then(|value| parse(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_seconds() {
        assert_eq!(parse("18"), Some(Duration::from_secs(18)));
    }

    #[test]
    fn parse_zero() {
        assert_eq!(parse("0"), Some(Duration::from_secs(0)));
    }

    #[test]
    fn parse_with_comment() {
        assert_eq!(parse("120 (I'm busy)"), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_with_comment_no_space() {
        assert_eq!(parse("30(back soon)"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_with_param() {
        assert_eq!(parse("30;duration=600"), Some(Duration::from_secs(30)));
    }

    #[test]
    fn parse_with_comment_and_param() {
        assert_eq!(
            parse("300 (maintenance);duration=3600"),
            Some(Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_leading_whitespace() {
        assert_eq!(parse("   45"), Some(Duration::from_secs(45)));
    }

    #[test]
    fn parse_large_value() {
        assert_eq!(parse("86400"), Some(Duration::from_secs(86400)));
    }

    #[test]
    fn reject_http_date_form() {
        // SIP Retry-After is never an HTTP-date; it has no leading digits.
        assert_eq!(parse("Mon, 01 Jan 2035 12:00:00 GMT"), None);
    }

    #[test]
    fn reject_garbage() {
        assert_eq!(parse("garbage"), None);
    }

    #[test]
    fn reject_empty() {
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
    }

    #[test]
    fn reject_leading_sign() {
        // A signed value has no leading ASCII digit.
        assert_eq!(parse("-5"), None);
    }

    #[test]
    fn overflow_yields_none() {
        // Too many digits to fit u64 seconds — graceful None, no panic.
        assert_eq!(parse("999999999999999999999999999999"), None);
    }

    #[test]
    fn extract_from_headers() {
        let mut headers = super::super::SipHeaders::new();
        headers.set("Retry-After", "30;duration=600".to_string());
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(30)));
    }

    #[test]
    fn extract_absent_header() {
        let headers = super::super::SipHeaders::new();
        assert_eq!(parse_retry_after(&headers), None);
    }
}
