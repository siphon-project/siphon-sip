//! RFC 3261 message validation.
//!
//! The parser's job is to turn octets into a [`SipMessage`]; it fails only when
//! it cannot do that unambiguously. A message can be perfectly parseable and
//! still be invalid — an unsupported version, a CSeq that disagrees with the
//! Request-Line, an unbalanced quoted string in a display name. RFC 3261
//! requires the element to *answer* those with a specific status, which is only
//! possible if the message parsed in the first place. That is the split: the
//! parser accepts them, this module names the rejection and the status, and the
//! dispatcher sends it.
//!
//! Every check here is one RFC 4475 §3.1.2 case. Checks that the RFC marks as
//! discretionary ("an element could choose to be liberal") are still applied,
//! but deliberately kept narrow so ordinary traffic cannot trip them — the
//! scalar check, for instance, only rejects on CSeq, because RFC 4475 §3.1.2.4
//! attributes the 400 to the CSeq error and explicitly permits an element to
//! process a request whose Max-Forwards alone is out of range.

use crate::sip::message::{SipMessage, StartLine};

/// Header fields whose value is a name-addr / addr-spec, and which therefore
/// have to satisfy the display-name and angle-bracket rules of RFC 3261 §20.
const ADDRESS_HEADERS: &[&str] = &[
    "To",
    "From",
    "Contact",
    "Route",
    "Record-Route",
    "Reply-To",
    "Referred-By",
    "Refer-To",
    "P-Asserted-Identity",
    "P-Preferred-Identity",
];

/// RFC 3261 §8.1.1.5: a CSeq sequence number "MUST be expressible as a 32-bit
/// unsigned integer and MUST be less than 2**31".
const MAX_CSEQ: u64 = 1 << 31;

/// A parseable message that must still be refused, with the status RFC 3261
/// requires the element to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// Status code to send (requests) — responses are discarded instead.
    pub status: u16,
    /// Reason phrase paired with `status`.
    pub reason: &'static str,
    /// What was wrong, for the log.
    pub detail: String,
}

impl Rejection {
    fn bad_request(detail: impl Into<String>) -> Self {
        Self {
            status: 400,
            reason: "Bad Request",
            detail: detail.into(),
        }
    }
}

/// Validate a parsed message against RFC 3261.
///
/// `Ok(())` means the message may proceed to routing. `Err` carries the status
/// the element owes the peer; a response that fails validation is discarded
/// rather than answered, since there is nothing to answer.
pub fn validate_message(message: &SipMessage) -> Result<(), Rejection> {
    validate_version(message)?;
    validate_cseq(message)?;
    validate_date(message)?;
    validate_request_uri(message)?;
    validate_address_headers(message)?;
    validate_parameters(message)?;
    Ok(())
}

/// RFC 3261 §8.1.3.5 / §27.4: a version other than 2.0 gets 505. RFC 4475
/// §3.1.2.16.
fn validate_version(message: &SipMessage) -> Result<(), Rejection> {
    let version = match &message.start_line {
        StartLine::Request(request) => &request.version,
        StartLine::Response(response) => &response.version,
    };

    if version.major != 2 || version.minor != 0 {
        return Err(Rejection {
            status: 505,
            reason: "Version Not Supported",
            detail: format!(
                "SIP/{}.{} is not supported (RFC 3261 §27.4)",
                version.major, version.minor
            ),
        });
    }
    Ok(())
}

/// RFC 3261 §8.1.1.5: the CSeq method is case-sensitive and MUST match the
/// Request-Line method, and the sequence number MUST be under 2**31.
/// RFC 4475 §3.1.2.4, §3.1.2.5, §3.1.2.17 and §3.1.2.18.
fn validate_cseq(message: &SipMessage) -> Result<(), Rejection> {
    // A missing CSeq is a §3.3.1 application-layer concern, not this check's.
    let Some(cseq) = message.headers.get("CSeq") else {
        return Ok(());
    };

    let cseq = cseq.trim();
    let mut parts = cseq.split_whitespace();
    let Some(sequence) = parts.next() else {
        return Err(Rejection::bad_request("empty CSeq"));
    };

    match sequence.parse::<u64>() {
        Ok(sequence) if sequence < MAX_CSEQ => {}
        _ => {
            return Err(Rejection::bad_request(format!(
                "CSeq sequence number {sequence:?} is not below 2**31 (RFC 3261 §8.1.1.5)"
            )));
        }
    }

    // The method half only exists to be compared with the Request-Line, so it
    // is checked on requests alone.
    if let StartLine::Request(request) = &message.start_line {
        if let Some(cseq_method) = parts.next() {
            let method = request.method.as_str();
            if cseq_method != method {
                return Err(Rejection::bad_request(format!(
                    "CSeq method {cseq_method:?} does not match Request-Line method \
                     {method:?} (RFC 3261 §8.1.1.5)"
                )));
            }
        }
    }

    Ok(())
}

/// RFC 3261 §20.17: the SIP-Date time zone MUST be "GMT". RFC 4475 §3.1.2.12
/// notes that "UT", "UTC" and "UCT" are all invalid too.
fn validate_date(message: &SipMessage) -> Result<(), Rejection> {
    let Some(date) = message.headers.get("Date") else {
        return Ok(());
    };

    let date = date.trim();
    if !date.ends_with("GMT") {
        let zone = date.rsplit(' ').next().unwrap_or(date);
        return Err(Rejection::bad_request(format!(
            "Date time zone {zone:?} is not GMT (RFC 3261 §20.17)"
        )));
    }
    Ok(())
}

/// RFC 4475 §3.1.2.11: a Request-URI carrying escaped headers is malformed, and
/// rejecting it with 400 is explicitly sanctioned. Forwarding it is not — the
/// escaped headers must never reach the Request-URI of a forwarded request, nor
/// be promoted into real headers.
fn validate_request_uri(message: &SipMessage) -> Result<(), Rejection> {
    let StartLine::Request(request) = &message.start_line else {
        return Ok(());
    };

    if !request.request_uri.headers.is_empty() {
        return Err(Rejection::bad_request(
            "Request-URI carries escaped headers (RFC 4475 §3.1.2.11)",
        ));
    }
    Ok(())
}

/// Display-name and angle-bracket rules for address headers (RFC 3261 §20):
///
/// * a quoted display name has to be closed — RFC 4475 §3.1.2.6;
/// * `LAQUOT = SWS "<"` and `RAQUOT = ">" SWS`, so whitespace may precede `<`
///   and follow `>`, but never sits inside the brackets — §3.1.2.14;
/// * "if the URI ... contains a comma, question mark or semicolon, the URI MUST
///   be enclosed in angle brackets" — §3.1.2.13.
fn validate_address_headers(message: &SipMessage) -> Result<(), Rejection> {
    for name in ADDRESS_HEADERS {
        let Some(values) = message.headers.get_all(name) else {
            continue;
        };

        for value in values {
            if has_unbalanced_quote(value) {
                return Err(Rejection::bad_request(format!(
                    "{name} has an unterminated quoted string (RFC 3261 §25.1)"
                )));
            }

            if let Some(inner) = angle_bracketed(value) {
                if inner.starts_with([' ', '\t']) || inner.ends_with([' ', '\t']) {
                    return Err(Rejection::bad_request(format!(
                        "{name} has whitespace inside <> (RFC 3261 §25.1 LAQUOT/RAQUOT)"
                    )));
                }
            } else if value.contains('?') {
                // A bare addr-spec cannot carry a `?`: everything after it would
                // be read as a header parameter of the field, not of the URI.
                return Err(Rejection::bad_request(format!(
                    "{name} is a bare addr-spec containing '?' and is not enclosed \
                     in <> (RFC 3261 §20)"
                )));
            }
        }
    }
    Ok(())
}

/// RFC 4475 §3.1.2.1: header field parameter lists with extraneous separators
/// (`;;,;,,`) are malformed — a parameter has to have a name.
fn validate_parameters(message: &SipMessage) -> Result<(), Rejection> {
    for name in ["Via", "Contact", "Route", "Record-Route"] {
        let Some(values) = message.headers.get_all(name) else {
            continue;
        };

        for value in values {
            // Only inspect the parameter region, so a display name or a URI
            // containing these characters is never mistaken for a separator.
            let params = match angle_bracketed_end(value) {
                Some(end) => &value[end..],
                None => value.as_str(),
            };

            if params
                .split([';', ','])
                .skip(1)
                .any(|param| param.trim().is_empty())
            {
                return Err(Rejection::bad_request(format!(
                    "{name} has an empty header field parameter (RFC 4475 §3.1.2.1)"
                )));
            }
        }
    }
    Ok(())
}

/// True when `value` contains an odd number of unescaped `"` characters.
fn has_unbalanced_quote(value: &str) -> bool {
    let mut escaped = false;
    let mut open = false;
    for character in value.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if open => escaped = true,
            '"' => open = !open,
            _ => {}
        }
    }
    open
}

/// The text between the first `<` and the matching `>`, if the value is a
/// name-addr.
fn angle_bracketed(value: &str) -> Option<&str> {
    let open = value.find('<')?;
    let close = value[open + 1..].find('>')? + open + 1;
    Some(&value[open + 1..close])
}

/// Index just past the `>` of a name-addr, i.e. where its parameters begin.
fn angle_bracketed_end(value: &str) -> Option<usize> {
    let open = value.find('<')?;
    let close = value[open + 1..].find('>')? + open + 1;
    Some(close + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::parser::parse_sip_message_bytes;

    fn validate(raw: &str) -> Result<(), Rejection> {
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("fixture should parse");
        validate_message(&message)
    }

    const WELL_FORMED: &str = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:caller@example.net>;tag=1\r\n",
        "Max-Forwards: 70\r\n",
        "Call-ID: ok@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK1\r\n",
        "Date: Fri, 01 Jan 2010 16:00:00 GMT\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    #[test]
    fn well_formed_request_passes() {
        assert_eq!(validate(WELL_FORMED), Ok(()));
    }

    #[test]
    fn unsupported_version_is_505() {
        let raw = WELL_FORMED.replace("SIP/2.0\r\nTo:", "SIP/7.0\r\nTo:");
        let rejection = validate(&raw).expect_err("SIP/7.0 must be refused");
        assert_eq!(rejection.status, 505);
    }

    #[test]
    fn cseq_method_must_match_the_request_line() {
        let raw = WELL_FORMED.replace("CSeq: 1 INVITE", "CSeq: 1 OPTIONS");
        let rejection = validate(&raw).expect_err("CSeq method mismatch must be refused");
        assert_eq!(rejection.status, 400);
    }

    #[test]
    fn cseq_sequence_number_must_be_below_2_pow_31() {
        let raw = WELL_FORMED.replace("CSeq: 1 INVITE", "CSeq: 36893488147419103232 INVITE");
        let rejection = validate(&raw).expect_err("overlarge CSeq must be refused");
        assert_eq!(rejection.status, 400);

        // The boundary itself is legal.
        let raw = WELL_FORMED.replace("CSeq: 1 INVITE", "CSeq: 2147483647 INVITE");
        assert_eq!(validate(&raw), Ok(()));
    }

    #[test]
    fn date_time_zone_must_be_gmt() {
        for zone in ["EST", "UT", "UTC", "UCT"] {
            let raw = WELL_FORMED.replace("16:00:00 GMT", &format!("16:00:00 {zone}"));
            let rejection = validate(&raw).expect_err("non-GMT Date must be refused");
            assert_eq!(rejection.status, 400, "{zone} should be refused");
        }
    }

    #[test]
    fn unterminated_quoted_display_name_is_refused() {
        let raw = WELL_FORMED.replace(
            "To: <sip:user@example.com>",
            "To: \"Mr. J. User <sip:j.user@example.com>",
        );
        assert_eq!(
            validate(&raw).expect_err("unbalanced quote must be refused").status,
            400
        );
    }

    #[test]
    fn whitespace_inside_angle_brackets_is_refused() {
        let raw = WELL_FORMED.replace(
            "To: <sip:user@example.com>",
            "To: \"Watson, Thomas\" < sip:t.watson@example.org >",
        );
        assert_eq!(
            validate(&raw).expect_err("spaces within addr-spec must be refused").status,
            400
        );
    }

    #[test]
    fn bare_addr_spec_with_a_question_mark_is_refused() {
        let raw = WELL_FORMED.replace(
            "To: <sip:user@example.com>",
            "To: sip:user@example.com?Route=%3Csip:sip.example.com%3E",
        );
        assert_eq!(
            validate(&raw).expect_err("bare addr-spec with '?' must be refused").status,
            400
        );
    }

    #[test]
    fn empty_header_field_parameters_are_refused() {
        let raw = WELL_FORMED.replace(
            "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK1",
            "Via: SIP/2.0/UDP 192.0.2.15;;,;,,",
        );
        assert_eq!(
            validate(&raw).expect_err("extraneous separators must be refused").status,
            400
        );
    }

    #[test]
    fn escaped_headers_in_the_request_uri_are_refused() {
        let raw = WELL_FORMED.replace(
            "INVITE sip:user@example.com SIP/2.0",
            "INVITE sip:user@example.com?Route=%3Csip:example.com%3E SIP/2.0",
        );
        assert_eq!(
            validate(&raw).expect_err("escaped headers in R-URI must be refused").status,
            400
        );
    }

    #[test]
    fn a_quoted_display_name_containing_an_escaped_quote_is_balanced() {
        assert!(!has_unbalanced_quote("\"J Rosenberg \\\"\" <sip:jdrosen@example.com>"));
        assert!(has_unbalanced_quote("\"Mr. J. User <sip:j.user@example.com>"));
    }

    #[test]
    fn ordinary_parameters_are_not_mistaken_for_empty_ones() {
        for value in [
            "SIP/2.0/UDP host.example.com;branch=z9hG4bK1",
            "<sip:user@example.com>;expires=3600;q=0.5",
            "SIP/2.0/UDP host.example.com;branch=z9hG4bK1;received=192.0.2.1",
        ] {
            let raw = WELL_FORMED.replace(
                "Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK1",
                &format!("Via: {value}"),
            );
            assert_eq!(validate(&raw), Ok(()), "{value} should be accepted");
        }
    }
}
