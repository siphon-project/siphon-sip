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

/// A parsed message goes back out in canonical header order, whatever order it
/// arrived in: the proxy-processing headers first (RFC 3261 §7.3.1), then the
/// dialog-identifying ones, then the `Content-*` group with `Content-Length`
/// last. The input below is deliberately scrambled.
#[test]
fn serializes_headers_in_canonical_order() {
    let raw = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Content-Length: 0\r\n",
        "Allow: INVITE, ACK, BYE\r\n",
        "Content-Type: application/sdp\r\n",
        "CSeq: 1 INVITE\r\n",
        "Call-ID: a84b4c76e66710@192.0.2.10\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Max-Forwards: 70\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n",
        "\r\n",
    );

    let message = siphon::sip::parse_sip_message(raw).unwrap().1;
    let wire = String::from_utf8(message.to_bytes()).unwrap();
    let names: Vec<&str> = wire
        .lines()
        .skip(1)
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect();

    assert_eq!(
        names,
        vec![
            "Via",
            "Max-Forwards",
            "From",
            "To",
            "Call-ID",
            "CSeq",
            "Allow",
            "Content-Type",
            "Content-Length",
        ]
    );
}

/// Re-parsing siphon's own output and serialising it again must produce the
/// same bytes — the ordering has to be a fixed point, or a message relayed
/// through two siphons would keep being rewritten.
#[test]
fn serialization_order_is_a_fixed_point() {
    let raw = concat!(
        "SIP/2.0 200 OK\r\n",
        "Content-Length: 0\r\n",
        "Supported: timer,replaces\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK776asdhds\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "To: <sip:user@example.com>;tag=sb-f7d98a826abb\r\n",
        "Call-ID: a84b4c76e66710@192.0.2.10\r\n",
        "CSeq: 1 INVITE\r\n",
        "\r\n",
    );

    let once = siphon::sip::parse_sip_message(raw).unwrap().1.to_bytes();
    let once_str = String::from_utf8(once.clone()).unwrap();
    let twice = siphon::sip::parse_sip_message(&once_str)
        .unwrap()
        .1
        .to_bytes();

    assert_eq!(once, twice);
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
