//! Proptest roundtrip tests for the SIP parser.
//!
//! Property: `parse(serialize(message)) == message` for generated SIP messages.

use proptest::prelude::*;
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::message::Method;
use siphon::sip::parse_sip_message;
use siphon::sip::uri::SipUri;

/// Generate a valid SIP method.
fn method_strategy() -> impl Strategy<Value = Method> {
    prop_oneof![
        Just(Method::Invite),
        Just(Method::Ack),
        Just(Method::Bye),
        Just(Method::Cancel),
        Just(Method::Options),
        Just(Method::Register),
        Just(Method::Subscribe),
        Just(Method::Notify),
        Just(Method::Message),
        Just(Method::Publish),
        Just(Method::Info),
        Just(Method::Update),
        Just(Method::Refer),
        Just(Method::Prack),
    ]
}

/// Generate a valid SIP URI host (IPv4 or simple domain).
fn host_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // IPv4 addresses
        (1u8..=254, 0u8..=254, 0u8..=254, 1u8..=254)
            .prop_map(|(a, b, c, d)| { format!("{a}.{b}.{c}.{d}") }),
        // Simple domain names
        "[a-z][a-z0-9]{1,8}\\.[a-z]{2,4}".prop_map(|s| s),
    ]
}

/// Generate a valid SIP URI user part (optional).
fn user_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        3 => Just(None),
        7 => "[a-zA-Z][a-zA-Z0-9_.]{0,12}".prop_map(Some),
    ]
}

/// Generate a SIP URI.
fn sip_uri_strategy() -> impl Strategy<Value = SipUri> {
    (
        user_strategy(),
        host_strategy(),
        prop::option::of(1024u16..65535),
    )
        .prop_map(|(user, host, port)| {
            let mut uri = SipUri::new(host);
            if let Some(user) = user {
                uri = uri.with_user(user);
            }
            if let Some(port) = port {
                uri.port = Some(port);
            }
            uri
        })
}

/// Generate a valid Via header value.
fn via_strategy() -> impl Strategy<Value = String> {
    (
        prop_oneof![Just("UDP"), Just("TCP"), Just("TLS")],
        host_strategy(),
        prop::option::of(1024u16..65535),
    )
        .prop_map(|(transport, host, port)| {
            let port_str = port.map(|p| format!(":{p}")).unwrap_or_default();
            format!(
                "SIP/2.0/{transport} {host}{port_str};branch=z9hG4bK{:08x}",
                rand_branch()
            )
        })
}

fn rand_branch() -> u32 {
    // Deterministic enough for prop testing — proptest controls randomness
    42
}

/// Generate a valid Call-ID.
fn call_id_strategy() -> impl Strategy<Value = String> {
    "[a-f0-9]{8,16}@[a-z]{3,8}\\.[a-z]{2,3}".prop_map(|s| s)
}

/// Generate a valid From/To tag.
fn tag_strategy() -> impl Strategy<Value = String> {
    "[a-f0-9]{4,12}".prop_map(|s| s)
}

/// Generate a SIP request message via the builder, then test roundtrip.
fn sip_request_strategy() -> impl Strategy<Value = siphon::sip::message::SipMessage> {
    (
        method_strategy(),
        sip_uri_strategy(),
        via_strategy(),
        call_id_strategy(),
        tag_strategy(),
        tag_strategy(),
        1u32..999999,
        prop::option::of("[a-zA-Z0-9 .,!?]{1,50}"),
    )
        .prop_map(
            |(method, uri, via, call_id, from_tag, to_tag, cseq_num, body)| {
                let method_str = method.as_str().to_string();
                let from = format!("<sip:user@example.com>;tag={from_tag}");
                let to = format!("<{uri}>;tag={to_tag}");
                let cseq = format!("{cseq_num} {method_str}");

                let mut builder = SipMessageBuilder::new()
                    .request(method, uri)
                    .via(via)
                    .from(from)
                    .to(to)
                    .call_id(call_id)
                    .cseq(cseq)
                    .max_forwards(70);

                if let Some(ref body_text) = body {
                    builder = builder
                        .content_type("text/plain".to_string())
                        .body(body_text.as_bytes().to_vec());
                } else {
                    builder = builder.content_length(0);
                }

                builder
                    .build()
                    .expect("builder should produce valid message")
            },
        )
}

/// Generate a SIP response message via the builder, then test roundtrip.
fn sip_response_strategy() -> impl Strategy<Value = siphon::sip::message::SipMessage> {
    (
        prop_oneof![
            Just((100u16, "Trying")),
            Just((180, "Ringing")),
            Just((200, "OK")),
            Just((302, "Moved Temporarily")),
            Just((400, "Bad Request")),
            Just((404, "Not Found")),
            Just((486, "Busy Here")),
            Just((500, "Server Internal Error")),
            Just((603, "Decline")),
        ],
        via_strategy(),
        call_id_strategy(),
        tag_strategy(),
        tag_strategy(),
        1u32..999999,
        method_strategy(),
    )
        .prop_map(
            |((status_code, reason), via, call_id, from_tag, to_tag, cseq_num, method)| {
                let method_str = method.as_str().to_string();
                let from = format!("<sip:user@example.com>;tag={from_tag}");
                let to = format!("<sip:dest@example.com>;tag={to_tag}");
                let cseq = format!("{cseq_num} {method_str}");

                SipMessageBuilder::new()
                    .response(status_code, reason.to_string())
                    .via(via)
                    .from(from)
                    .to(to)
                    .call_id(call_id)
                    .cseq(cseq)
                    .content_length(0)
                    .build()
                    .expect("builder should produce valid response")
            },
        )
}

/// Generate a valid SDP body.
fn sdp_body_strategy() -> impl Strategy<Value = String> {
    (
        // Session ID and version
        1000000u64..9999999,
        1u64..99,
        // Connection IP (IPv4)
        (1u8..=254, 0u8..=254, 0u8..=254, 1u8..=254),
        // Audio port
        1024u16..65000,
        // Codec set
        prop_oneof![
            Just("0"),       // PCMU only
            Just("0 8"),     // PCMU + PCMA
            Just("0 8 101"), // PCMU + PCMA + telephone-event
        ],
    )
        .prop_map(|(session_id, version, (a, b, c, d), port, codecs)| {
            let ip = format!("{a}.{b}.{c}.{d}");
            let mut sdp = format!(
                "v=0\r\n\
                 o=- {session_id} {version} IN IP4 {ip}\r\n\
                 s=-\r\n\
                 c=IN IP4 {ip}\r\n\
                 t=0 0\r\n\
                 m=audio {port} RTP/AVP {codecs}\r\n\
                 a=rtpmap:0 PCMU/8000\r\n"
            );
            if codecs.contains("8") {
                sdp.push_str("a=rtpmap:8 PCMA/8000\r\n");
            }
            if codecs.contains("101") {
                sdp.push_str("a=rtpmap:101 telephone-event/8000\r\n");
            }
            sdp
        })
}

/// Generate a SIP INVITE with SDP body.
fn sip_invite_with_sdp_strategy() -> impl Strategy<Value = siphon::sip::message::SipMessage> {
    (
        sip_uri_strategy(),
        via_strategy(),
        call_id_strategy(),
        tag_strategy(),
        tag_strategy(),
        1u32..999999,
        sdp_body_strategy(),
    )
        .prop_map(|(uri, via, call_id, from_tag, to_tag, cseq_num, sdp)| {
            let from = format!("<sip:user@example.com>;tag={from_tag}");
            let to = format!("<{uri}>;tag={to_tag}");
            let cseq = format!("{cseq_num} INVITE");

            SipMessageBuilder::new()
                .request(Method::Invite, uri)
                .via(via)
                .from(from)
                .to(to)
                .call_id(call_id)
                .cseq(cseq)
                .max_forwards(70)
                .content_type("application/sdp".to_string())
                .body(sdp.as_bytes().to_vec())
                .build()
                .expect("builder should produce valid INVITE with SDP")
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn roundtrip_request(message in sip_request_strategy()) {
        let wire = message.to_bytes();
        let wire_str = String::from_utf8(wire).expect("message should be valid UTF-8");
        let (remaining, reparsed) = parse_sip_message(&wire_str)
            .map_err(|e| format!("parse failed: {e}\nInput:\n{wire_str}"))
            .unwrap();

        prop_assert_eq!(remaining, "", "parser should consume entire message");
        prop_assert!(reparsed.is_request(), "should still be a request");
        prop_assert_eq!(
            reparsed.method().unwrap().as_str(),
            message.method().unwrap().as_str(),
            "method should roundtrip"
        );
        prop_assert_eq!(
            &reparsed.request_uri().unwrap().host,
            &message.request_uri().unwrap().host,
            "host should roundtrip"
        );
        prop_assert_eq!(
            reparsed.request_uri().unwrap().user.as_deref(),
            message.request_uri().unwrap().user.as_deref(),
            "user should roundtrip"
        );
        prop_assert_eq!(
            reparsed.request_uri().unwrap().port,
            message.request_uri().unwrap().port,
            "port should roundtrip"
        );
        let reparsed_call_id = reparsed.headers.call_id();
        let original_call_id = message.headers.call_id();
        prop_assert_eq!(reparsed_call_id, original_call_id, "Call-ID should roundtrip");
        prop_assert_eq!(reparsed.body.len(), message.body.len(), "body length should roundtrip");
        prop_assert_eq!(&reparsed.body, &message.body, "body should roundtrip");
    }

    #[test]
    fn roundtrip_response(message in sip_response_strategy()) {
        let wire = message.to_bytes();
        let wire_str = String::from_utf8(wire).expect("message should be valid UTF-8");
        let (remaining, reparsed) = parse_sip_message(&wire_str)
            .map_err(|e| format!("parse failed: {e}\nInput:\n{wire_str}"))
            .unwrap();

        prop_assert_eq!(remaining, "", "parser should consume entire message");
        prop_assert!(reparsed.is_response(), "should still be a response");
        prop_assert_eq!(
            reparsed.status_code().unwrap(),
            message.status_code().unwrap(),
            "status code should roundtrip"
        );
        let reparsed_call_id = reparsed.headers.call_id();
        let original_call_id = message.headers.call_id();
        prop_assert_eq!(reparsed_call_id, original_call_id, "Call-ID should roundtrip");
    }

    #[test]
    fn roundtrip_invite_with_sdp(message in sip_invite_with_sdp_strategy()) {
        let wire = message.to_bytes();
        let wire_str = String::from_utf8(wire).expect("message should be valid UTF-8");
        let (remaining, reparsed) = parse_sip_message(&wire_str)
            .map_err(|e| format!("parse failed: {e}\nInput:\n{wire_str}"))
            .unwrap();

        prop_assert_eq!(remaining, "", "parser should consume entire message");
        prop_assert!(reparsed.is_request(), "should still be a request");
        prop_assert_eq!(
            reparsed.method().unwrap().as_str(),
            "INVITE",
            "method should be INVITE"
        );
        // Content-Length must match body
        let content_length = reparsed.headers.content_length();
        prop_assert_eq!(
            content_length,
            Some(reparsed.body.len()),
            "Content-Length should match body length"
        );
        // Body should roundtrip exactly
        prop_assert_eq!(&reparsed.body, &message.body, "SDP body should roundtrip");
        // Content-Type should roundtrip
        prop_assert_eq!(
            reparsed.headers.content_type().unwrap(),
            "application/sdp",
            "Content-Type should roundtrip"
        );
        // Body should start with "v=0"
        let body_str = String::from_utf8_lossy(&reparsed.body);
        prop_assert!(body_str.starts_with("v=0"), "SDP should start with v=0");
    }

    #[test]
    fn roundtrip_uri(user in user_strategy(), host in host_strategy(), port in prop::option::of(1024u16..65535u16)) {
        let mut uri = SipUri::new(host.clone());
        if let Some(ref user) = user {
            uri = uri.with_user(user.clone());
        }
        if let Some(port) = port {
            uri.port = Some(port);
        }

        let serialized = uri.to_string();
        let reparsed = siphon::sip::parser::parse_uri_standalone(&serialized)
            .map_err(|e| format!("URI parse failed: {e}\nInput: {serialized}"))
            .unwrap();

        prop_assert_eq!(&reparsed.host, &host, "host should roundtrip");
        prop_assert_eq!(reparsed.user, user.map(|s| s.to_string()), "user should roundtrip");
        prop_assert_eq!(reparsed.port, port, "port should roundtrip");
    }
}
