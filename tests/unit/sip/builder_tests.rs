use siphon::sip::{Method, SipMessageBuilder, SipUri};

/// Test building an INVITE request (RFC 3261 Section 7.1)
#[test]
fn test_build_invite_request() {
    let request = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("example.com".to_string()).with_user("user".to_string()),
        )
        .via("SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds".to_string())
        .to("<sip:user@example.com>".to_string())
        .from("<sip:caller@example.com>;tag=1928301774".to_string())
        .call_id("a84b4c76e66710@host.example.com".to_string())
        .cseq("1 INVITE".to_string())
        .max_forwards(70)
        .build()
        .unwrap();

    assert!(request.is_request());
    assert_eq!(request.method().unwrap().as_str(), "INVITE");
    assert_eq!(request.request_uri().unwrap().host, "example.com");
    assert_eq!(request.headers.max_forwards(), Some(70));
}

/// Test building a 200 OK response (RFC 3261 Section 7.2)
#[test]
fn test_build_200_ok_response() {
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds".to_string())
        .to("<sip:user@example.com>;tag=1928301774".to_string())
        .from("<sip:caller@example.com>;tag=1928301774".to_string())
        .call_id("a84b4c76e66710@host.example.com".to_string())
        .cseq("1 INVITE".to_string())
        .build()
        .unwrap();

    assert!(response.is_response());
    assert_eq!(response.status_code().unwrap(), 200);
}

/// Test round-trip: build -> parse -> verify
#[test]
fn test_round_trip() {
    let original = SipMessageBuilder::new()
        .request(Method::Invite, SipUri::new("example.com".to_string()))
        .call_id("test@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .build()
        .unwrap();

    let bytes = original.to_bytes();
    let message_str = String::from_utf8_lossy(&bytes);

    let parsed = siphon::sip::parse_sip_message(&message_str).unwrap().1;

    assert_eq!(
        original.method().unwrap().as_str(),
        parsed.method().unwrap().as_str()
    );
    assert_eq!(
        original.request_uri().unwrap().host,
        parsed.request_uri().unwrap().host
    );
}

/// Test body handling
#[test]
fn test_body_handling() {
    let body = "v=0\r\no=user 123456 123456 IN IP4 192.0.2.1\r\n";

    let request = SipMessageBuilder::new()
        .request(Method::Invite, SipUri::new("example.com".to_string()))
        .call_id("test@example.com".to_string())
        .cseq("1 INVITE".to_string())
        .content_type("application/sdp".to_string())
        .body_str(body)
        .build()
        .unwrap();

    assert_eq!(request.headers.content_length(), Some(body.len()));
    assert_eq!(String::from_utf8_lossy(&request.body), body);
}
