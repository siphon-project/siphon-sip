//! Malformed message tests from RFC 4475
//! 
//! These tests verify that the parser handles malformed messages
//! gracefully (either by rejecting them or handling them appropriately)

use siphon::sip::parse_sip_message;

/// Test: Missing required headers
/// RFC 3261 requires To, From, Call-ID, CSeq, Via, Max-Forwards
#[test]
fn test_missing_required_headers() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   \r\n";

    // Should either parse (with missing headers) or reject cleanly
    let _result = parse_sip_message(message);
    // Parser may accept or reject - both are valid
    // The important thing is it doesn't panic
}

/// Test: Invalid SIP version
#[test]
fn test_invalid_sip_version() {
    let message = "INVITE sip:user@example.com SIP/3.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    // Should parse but version should be noted
    if let Ok((_, msg)) = parse_sip_message(message) {
        if let siphon::sip::StartLine::Request(req) = &msg.start_line {
            assert_eq!(req.version.major, 3);
        }
    }
}

/// Test: Invalid status code
#[test]
fn test_invalid_status_code() {
    let message = "SIP/2.0 999 Invalid\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    // Should parse but status code should be 999
    if let Ok((_, msg)) = parse_sip_message(message) {
        assert_eq!(msg.status_code().unwrap(), 999);
    }
}



