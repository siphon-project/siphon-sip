use siphon::sip::{parse_sip_message, Method};

#[test]
fn test_method_from_str_extension_methods() {
    // First-class variants (not Extension)
    assert_eq!(Method::from_str("SUBSCRIBE"), Method::Subscribe);
    assert_eq!(Method::from_str("NOTIFY"), Method::Notify);
    assert_eq!(Method::from_str("MESSAGE"), Method::Message);
    assert_eq!(Method::from_str("PUBLISH"), Method::Publish);
    assert_eq!(Method::from_str("INFO"), Method::Info);
    assert_eq!(Method::from_str("UPDATE"), Method::Update);
    assert_eq!(Method::from_str("REFER"), Method::Refer);
    assert_eq!(Method::from_str("PRACK"), Method::Prack);

    // Case-insensitive
    assert_eq!(Method::from_str("subscribe"), Method::Subscribe);
    assert_eq!(Method::from_str("Publish"), Method::Publish);
    assert_eq!(Method::from_str("notify"), Method::Notify);
}

#[test]
fn test_method_as_str_roundtrip() {
    let methods = vec![
        Method::Invite,
        Method::Ack,
        Method::Bye,
        Method::Cancel,
        Method::Options,
        Method::Register,
        Method::Info,
        Method::Update,
        Method::Prack,
        Method::Subscribe,
        Method::Notify,
        Method::Refer,
        Method::Message,
        Method::Publish,
    ];

    for method in methods {
        let string = method.as_str();
        let parsed = Method::from_str(string);
        assert_eq!(parsed, method, "Roundtrip failed for {}", string);
    }
}

#[test]
fn test_unknown_method_is_extension() {
    let method = Method::from_str("FOOBAR");
    assert_eq!(method, Method::Extension("FOOBAR".to_string()));
    assert_eq!(method.as_str(), "FOOBAR");
}

#[test]
fn test_is_request() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let (_, msg) = parse_sip_message(message).unwrap();
    assert!(msg.is_request());
    assert!(!msg.is_response());
}

#[test]
fn test_is_response() {
    let message = "SIP/2.0 200 OK\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let (_, msg) = parse_sip_message(message).unwrap();
    assert!(msg.is_response());
    assert!(!msg.is_request());
}

#[test]
fn test_method_accessor() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let (_, msg) = parse_sip_message(message).unwrap();
    assert_eq!(msg.method().unwrap().as_str(), "INVITE");
}

#[test]
fn test_status_code_accessor() {
    let message = "SIP/2.0 200 OK\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let (_, msg) = parse_sip_message(message).unwrap();
    assert_eq!(msg.status_code().unwrap(), 200);
}

#[test]
fn test_request_uri_accessor() {
    let message = "INVITE sip:user@example.com SIP/2.0\r\n\
                   Call-ID: test@example.com\r\n\
                   CSeq: 1 INVITE\r\n\
                   Content-Length: 0\r\n\
                   \r\n";

    let (_, msg) = parse_sip_message(message).unwrap();
    let uri = msg.request_uri().unwrap();
    assert_eq!(uri.host, "example.com");
}
