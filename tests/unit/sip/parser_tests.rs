use siphon::sip::parse_sip_message;

/// Test basic INVITE request parsing (RFC 3261 Section 7.1)
#[test]
fn test_parse_invite_request() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Call-ID: a84b4c76e66710@host.example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:caller@host.example.com>\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Failed to parse INVITE request");

    let (remaining, msg) = result.unwrap();
    assert_eq!(remaining, "", "Should consume entire message");

    assert!(msg.is_request(), "Should be a request");
    assert_eq!(msg.method().unwrap().as_str(), "INVITE");
    assert_eq!(msg.request_uri().unwrap().host, "example.com");
    assert_eq!(msg.request_uri().unwrap().user.as_ref().unwrap(), "user");
}

/// Test 200 OK response parsing (RFC 3261 Section 7.2)
#[test]
fn test_parse_200_ok_response() {
    let message = concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds\r\n",
        "To: <sip:user@example.com>;tag=1928301774\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Call-ID: a84b4c76e66710@host.example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Contact: <sip:user@host.example.com>\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok(), "Failed to parse 200 OK response");

    let (remaining, msg) = result.unwrap();
    assert_eq!(remaining, "", "Should consume entire message");

    assert!(msg.is_response(), "Should be a response");
    assert_eq!(msg.status_code().unwrap(), 200);
}

/// Test header folding (RFC 3261 Section 7.3.1)
#[test]
fn test_header_folding() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776asdhds;\r\n",
        " received=192.0.2.1\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:caller@example.com>;tag=1928301774\r\n",
        "Call-ID: a84b4c76e66710@host.example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    match &result {
        Ok((_remaining, msg)) => {
            if let Some(via) = msg.headers.via() {
                assert!(via.contains("received=192.0.2.1"), "Folded header should be parsed correctly. Via: {:?}", via);
            } else {
                panic!("Via header not found. Headers: {:?}", msg.headers.names());
            }
        }
        Err(e) => {
            panic!("Failed to parse folded header: {:?}. Message length: {}", e, message.len());
        }
    }
}

/// Test all standard SIP methods (RFC 3261 Section 7.1)
#[test]
fn test_all_sip_methods() {
    let methods = vec!["INVITE", "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER"];

    for method in methods {
        let message = format!(
            concat!(
                "{} sip:user@example.com SIP/2.0\r\n",
                "Call-ID: test@example.com\r\n",
                "CSeq: 1 {}\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            method, method,
        );

        let result = parse_sip_message(&message);
        assert!(result.is_ok(), "Failed to parse {} request", method);

        let (_, msg) = result.unwrap();
        assert_eq!(msg.method().unwrap().as_str(), method);
    }
}

/// Test extension SIP methods: SUBSCRIBE, NOTIFY, MESSAGE, PUBLISH, INFO, UPDATE, REFER, PRACK
#[test]
fn test_extension_sip_methods() {
    let methods = vec![
        "SUBSCRIBE", "NOTIFY", "MESSAGE", "PUBLISH",
        "INFO", "UPDATE", "REFER", "PRACK",
    ];

    for method in methods {
        let message = format!(
            concat!(
                "{} sip:user@example.com SIP/2.0\r\n",
                "Call-ID: test@example.com\r\n",
                "CSeq: 1 {}\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            method, method,
        );

        let result = parse_sip_message(&message);
        assert!(result.is_ok(), "Failed to parse {} request", method);

        let (_, msg) = result.unwrap();
        assert_eq!(msg.method().unwrap().as_str(), method);
    }
}

/// Test SUBSCRIBE request with Event header (RFC 3265)
#[test]
fn test_parse_subscribe_with_event_header() {
    let message = concat!(
        "SUBSCRIBE sip:user@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bK776\r\n",
        "To: <sip:user@example.com>\r\n",
        "From: <sip:watcher@example.com>;tag=12345\r\n",
        "Call-ID: subscribe-test@example.com\r\n",
        "CSeq: 1 SUBSCRIBE\r\n",
        "Event: presence\r\n",
        "Expires: 3600\r\n",
        "Accept: application/pidf+xml\r\n",
        "Contact: <sip:watcher@host.example.com>\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let (remaining, msg) = parse_sip_message(message).unwrap();
    assert_eq!(remaining, "");
    assert!(msg.is_request());
    assert_eq!(msg.method().unwrap().as_str(), "SUBSCRIBE");
    assert_eq!(msg.headers.get("Event").unwrap(), "presence");
    assert_eq!(msg.headers.get("Expires").unwrap(), "3600");
    assert_eq!(msg.headers.get("Accept").unwrap(), "application/pidf+xml");
}

/// Test NOTIFY request with subscription state (RFC 3265)
#[test]
fn test_parse_notify_with_body() {
    let pidf_body = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"\r\n",
        " entity=\"sip:user@example.com\">\r\n",
        " <tuple id=\"t1\">\r\n",
        "  <status><basic>open</basic></status>\r\n",
        " </tuple>\r\n",
        "</presence>\r\n",
    );

    let message = format!(
        concat!(
            "NOTIFY sip:watcher@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP server.example.com:5060;branch=z9hG4bKnotify1\r\n",
            "To: <sip:watcher@example.com>;tag=12345\r\n",
            "From: <sip:user@example.com>;tag=67890\r\n",
            "Call-ID: subscribe-test@example.com\r\n",
            "CSeq: 1 NOTIFY\r\n",
            "Event: presence\r\n",
            "Subscription-State: active;expires=3599\r\n",
            "Content-Type: application/pidf+xml\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        pidf_body.len(),
        pidf_body,
    );

    let (remaining, msg) = parse_sip_message(&message).unwrap();
    assert_eq!(remaining, "");
    assert_eq!(msg.method().unwrap().as_str(), "NOTIFY");
    assert_eq!(msg.headers.get("Event").unwrap(), "presence");
    assert_eq!(
        msg.headers.get("Subscription-State").unwrap(),
        "active;expires=3599",
    );
    assert_eq!(msg.body.len(), pidf_body.len());
}

/// Test PUBLISH request with SIP-ETag (RFC 3903)
#[test]
fn test_parse_publish_with_etag() {
    let pidf_body = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n",
        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\"\r\n",
        " entity=\"sip:user@example.com\">\r\n",
        " <tuple id=\"t1\">\r\n",
        "  <status><basic>open</basic></status>\r\n",
        " </tuple>\r\n",
        "</presence>\r\n",
    );

    let message = format!(
        concat!(
            "PUBLISH sip:user@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bKpub1\r\n",
            "To: <sip:user@example.com>\r\n",
            "From: <sip:user@example.com>;tag=pub001\r\n",
            "Call-ID: publish-test@example.com\r\n",
            "CSeq: 1 PUBLISH\r\n",
            "Event: presence\r\n",
            "SIP-If-Match: dx200xyz\r\n",
            "Content-Type: application/pidf+xml\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        pidf_body.len(),
        pidf_body,
    );

    let (remaining, msg) = parse_sip_message(&message).unwrap();
    assert_eq!(remaining, "");
    assert_eq!(msg.method().unwrap().as_str(), "PUBLISH");
    assert_eq!(msg.headers.get("SIP-If-Match").unwrap(), "dx200xyz");
    assert_eq!(msg.headers.get("Event").unwrap(), "presence");
    assert_eq!(msg.body.len(), pidf_body.len());
}

/// Test MESSAGE request with text body (RFC 3428)
#[test]
fn test_parse_message_with_text_body() {
    let text_body = "Hello, this is a test instant message.";

    let message = format!(
        concat!(
            "MESSAGE sip:user@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP host.example.com:5060;branch=z9hG4bKmsg1\r\n",
            "To: <sip:user@example.com>\r\n",
            "From: <sip:sender@example.com>;tag=msg001\r\n",
            "Call-ID: message-test@example.com\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Type: text/plain\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        text_body.len(),
        text_body,
    );

    let (remaining, msg) = parse_sip_message(&message).unwrap();
    assert_eq!(remaining, "");
    assert_eq!(msg.method().unwrap().as_str(), "MESSAGE");
    assert_eq!(
        msg.headers.get("Content-Type").unwrap(),
        "text/plain",
    );
    assert_eq!(String::from_utf8_lossy(&msg.body), text_body);
}

/// Test URI parsing with parameters (RFC 3261 Section 19.1.1)
#[test]
fn test_uri_with_parameters() {
    let message = concat!(
        "INVITE sip:user@example.com;transport=udp;lr SIP/2.0\r\n",
        "Call-ID: test@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok());

    let (_, msg) = result.unwrap();
    let uri = msg.request_uri().unwrap();
    assert_eq!(uri.get_param("transport"), Some("udp"));
    assert_eq!(uri.get_param("lr"), Some(""));
}

/// Test Content-Length header handling (RFC 3261 Section 20.14)
#[test]
fn test_content_length() {
    let body = "v=0\r\no=user 123456 123456 IN IP4 192.0.2.1\r\n";
    let message = format!(
        concat!(
            "INVITE sip:user@example.com SIP/2.0\r\n",
            "Call-ID: test@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {}\r\n",
            "\r\n",
            "{}",
        ),
        body.len(), body,
    );

    let result = parse_sip_message(&message);
    assert!(result.is_ok());

    let (_, msg) = result.unwrap();
    assert_eq!(msg.body.len(), body.len());
    assert_eq!(String::from_utf8_lossy(&msg.body), body);
}

/// Test Max-Forwards header (RFC 3261 Section 20.22)
#[test]
fn test_max_forwards() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Max-Forwards: 70\r\n",
        "Call-ID: test@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok());

    let (_, msg) = result.unwrap();
    assert_eq!(msg.headers.max_forwards(), Some(70));
}

/// Test multiple Via headers (RFC 3261 Section 20.42)
#[test]
fn test_multiple_via_headers() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP proxy1.example.com:5060;branch=z9hG4bK1\r\n",
        "Via: SIP/2.0/UDP proxy2.example.com:5060;branch=z9hG4bK2\r\n",
        "Call-ID: test@example.com\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok());

    let (_, msg) = result.unwrap();
    let via_headers = msg.headers.get_all("Via").unwrap();
    assert_eq!(via_headers.len(), 2);
}

/// Test case-insensitive header names (RFC 3261 Section 7.3)
#[test]
fn test_case_insensitive_headers() {
    let message = concat!(
        "INVITE sip:user@example.com SIP/2.0\r\n",
        "call-id: test@example.com\r\n",
        "cseq: 1 INVITE\r\n",
        "content-length: 0\r\n",
        "\r\n",
    );

    let result = parse_sip_message(message);
    assert!(result.is_ok());

    let (_, msg) = result.unwrap();
    assert!(msg.headers.call_id().is_some());
    assert!(msg.headers.cseq().is_some());
    assert!(msg.headers.content_length().is_some());
}
