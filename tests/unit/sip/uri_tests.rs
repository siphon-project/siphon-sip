use siphon::sip::uri::SipUri;
use siphon::sip::parse_sip_message;

/// Test basic SIP URI parsing
#[test]
fn test_basic_uri() {
    let uri = SipUri::new("example.com".to_string());
    assert_eq!(uri.scheme, "sip");
    assert_eq!(uri.host, "example.com");
    assert_eq!(uri.user, None);
    assert_eq!(uri.port, None);
}

/// Test URI with user
#[test]
fn test_uri_with_user() {
    let uri = SipUri::new("example.com".to_string())
        .with_user("user".to_string());
    assert_eq!(uri.user.as_ref().unwrap(), "user");
}

/// Test URI with port
#[test]
fn test_uri_with_port() {
    let uri = SipUri::new("example.com".to_string())
        .with_port(5060);
    assert_eq!(uri.port, Some(5060));
}

/// Test URI with parameters
#[test]
fn test_uri_with_params() {
    let uri = SipUri::new("example.com".to_string())
        .with_param("transport".to_string(), Some("udp".to_string()))
        .with_param("lr".to_string(), None);
    
    assert_eq!(uri.get_param("transport"), Some("udp"));
    assert_eq!(uri.get_param("lr"), Some(""));
}

/// Test URI parsing from message
#[test]
fn test_parse_uri_from_message() {
    let message = "INVITE sip:user@example.com:5060;transport=udp SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let result = parse_sip_message(message);
    assert!(result.is_ok());
    
    let (_, msg) = result.unwrap();
    let uri = msg.request_uri().unwrap();
    assert_eq!(uri.user.as_ref().unwrap(), "user");
    assert_eq!(uri.host, "example.com");
    assert_eq!(uri.port, Some(5060));
    assert_eq!(uri.get_param("transport"), Some("udp"));
}

// ---------------------------------------------------------------------------
// IPv6 tests
// ---------------------------------------------------------------------------

#[test]
fn parse_ipv6_uri_from_message() {
    let message = concat!(
        "INVITE sip:bob@[2001:db8::1]:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP [2001:db8::2]:5060;branch=z9hG4bK-v6\r\n",
        "Call-ID: ipv6@test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let (_, msg) = parse_sip_message(message).unwrap();
    let uri = msg.request_uri().unwrap();
    assert_eq!(uri.user.as_ref().unwrap(), "bob");
    assert_eq!(uri.host, "[2001:db8::1]");
    assert_eq!(uri.port, Some(5060));
}

#[test]
fn ipv6_uri_roundtrip() {
    let message = concat!(
        "INVITE sip:bob@[2001:db8::1]:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP [2001:db8::2]:5060;branch=z9hG4bK-v6\r\n",
        "Call-ID: ipv6@test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );

    let (_, msg) = parse_sip_message(message).unwrap();
    let serialized = String::from_utf8(msg.to_bytes()).unwrap();

    // Reparse
    let (_, msg2) = parse_sip_message(&serialized).unwrap();
    let uri = msg2.request_uri().unwrap();
    assert_eq!(uri.host, "[2001:db8::1]");
    assert_eq!(uri.port, Some(5060));
    assert_eq!(uri.to_string(), "sip:bob@[2001:db8::1]:5060");
}

#[test]
fn sip_uri_ipv6_constructed_bare() {
    // Simulates constructing a URI from SocketAddr::ip().to_string()
    let uri = SipUri::new("::1".to_string()).with_port(5060);
    let s = uri.to_string();
    assert_eq!(s, "sip:[::1]:5060");
}

#[test]
fn sip_uri_ipv6_display() {
    let uri = SipUri::new("2001:db8::1".to_string())
        .with_user("alice".to_string())
        .with_port(5060)
        .with_param("transport".to_string(), Some("tcp".to_string()));
    assert_eq!(
        format!("{uri}"),
        "sip:alice@[2001:db8::1]:5060;transport=tcp"
    );
}
