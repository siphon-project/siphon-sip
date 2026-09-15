use super::*;

fn params(media: OriginateMedia) -> OriginateParams {
    OriginateParams {
        to: "sip:+14035551212@carrier.example".to_string(),
        to_display: None,
        from: None,
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
        privacy: None,
        headers: Vec::new(),
        timeout_secs: 30,
        media,
        session_timer: None,
    }
}

fn identity<'a>() -> OriginateIdentity<'a> {
    OriginateIdentity {
        sip_call_id: "b2b-originate-1",
        from_tag: "sft-1",
        branch: "z9hG4bK-orig-1",
        via_host: "198.51.100.10",
        via_port: 5060,
        transport: Transport::Udp,
        contact: "<sip:198.51.100.10:5060;transport=udp>",
        user_agent: Some("siphon"),
    }
}

fn build_result(params: &OriginateParams) -> Result<SipMessage, OriginateError> {
    let uri = parse_uri_standalone(&params.to).expect("target parses");
    build_originate_invite(params, uri, identity(), None)
}

fn build(params: &OriginateParams) -> SipMessage {
    build_result(params).expect("invite builds")
}

/// A plain SDP offer — what the `sdp=` / `args.sdp` shorthand produces.
fn offer(sdp: &str) -> OriginateMedia {
    OriginateMedia::Offer {
        body: sdp.as_bytes().to_vec(),
        content_type: "application/sdp".to_string(),
    }
}

/// A `multipart/mixed` body of the shape a SIP-I / PIDF-LO INVITE carries:
/// the SDP offer plus one part SIP itself does not interpret.
fn multipart_offer_body() -> &'static str {
    concat!(
        "--siphon-1\r\n",
        "Content-Type: application/sdp\r\n",
        "\r\n",
        "v=0\r\n",
        "o=- 1 1 IN IP4 198.51.100.10\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
        "\r\n--siphon-1\r\n",
        "Content-Type: application/vnd.example+xml\r\n",
        "\r\n",
        "<additional-data/>\r\n",
        "--siphon-1--\r\n",
    )
}

#[test]
fn originate_invite_carries_the_uac_dialog_identity() {
    let invite = build(&params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    }));

    match &invite.start_line {
        StartLine::Request(line) => {
            assert_eq!(line.method, Method::Invite);
            assert_eq!(
                line.request_uri.to_string(),
                "sip:+14035551212@carrier.example"
            );
        }
        other => panic!("expected a request line, got {other:?}"),
    }
    assert_eq!(invite.headers.call_id().unwrap(), "b2b-originate-1");
    assert_eq!(invite.headers.cseq().unwrap(), "1 INVITE");
    // RFC 3261 §8.1.1.3: the UAC's From carries the tag it chose.
    assert!(invite.headers.from().unwrap().contains(";tag=sft-1"));
    // RFC 3261 §12.1.2: no To-tag until the callee assigns one.
    assert!(!invite.headers.to().unwrap().contains("tag="));
    assert_eq!(
        invite.headers.get("Via").unwrap(),
        "SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-orig-1"
    );
    assert_eq!(invite.headers.get("Max-Forwards").unwrap(), "70");
    assert_eq!(
        invite.headers.get("Contact").unwrap(),
        "<sip:198.51.100.10:5060;transport=udp>"
    );
    assert!(invite.headers.has("Allow"));
    assert_eq!(invite.headers.get("User-Agent").unwrap(), "siphon");
}

#[test]
fn originate_defaults_the_from_uri_to_our_own_advertised_address() {
    let invite = build(&params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    }));
    assert!(
        invite.headers.from().unwrap().contains("sip:198.51.100.10"),
        "from was: {:?}",
        invite.headers.from()
    );
}

#[test]
fn originate_applies_the_full_calling_identity() {
    let mut params = params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    });
    params.from = Some("sip:+14035550100@siphon.example".to_string());
    params.from_display = Some("Reminders".to_string());
    params.to_display = Some("Callee".to_string());
    params.p_asserted_identity = Some("sip:+14035550100@siphon.example".to_string());
    let invite = build(&params);

    let from = invite.headers.from().unwrap();
    assert!(
        from.starts_with("\"Reminders\" <sip:+14035550100@siphon.example>"),
        "from was {from}"
    );
    assert!(from.contains(";tag=sft-1"));
    assert!(invite
        .headers
        .to()
        .unwrap()
        .starts_with("\"Callee\" <sip:+14035551212@carrier.example>"));
    // RFC 3325 §9.1: PAI is a name-addr for the trusted next hop.
    assert_eq!(
        invite.headers.get("P-Asserted-Identity").unwrap(),
        "<sip:+14035550100@siphon.example>"
    );
}

#[test]
fn originate_with_restricted_privacy_anonymises_from_and_asserts_privacy_id() {
    // RFC 3323 §4.1 / TS 24.607: the real identity stays in PAI for the
    // trusted next hop while From is anonymised.
    let mut params = params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    });
    params.from = Some("sip:+14035550100@siphon.example".to_string());
    params.p_asserted_identity = Some("sip:+14035550100@siphon.example".to_string());
    params.privacy = Some(crate::sip::privacy::CallerIdPresentation::Restricted);
    let invite = build(&params);

    let from = invite.headers.from().unwrap();
    assert!(
        !from.contains("+14035550100"),
        "CLIR must not leak the CLI in From: {from}"
    );
    assert!(
        from.contains(";tag=sft-1"),
        "the dialog tag must survive CLIR: {from}"
    );
    assert!(invite
        .headers
        .get("Privacy")
        .is_some_and(|value| value.contains("id")));
    assert_eq!(
        invite.headers.get("P-Asserted-Identity").unwrap(),
        "<sip:+14035550100@siphon.example>"
    );
}

#[test]
fn originate_privacy_runs_after_custom_headers_so_it_cannot_be_undone() {
    // Ordering matters: a caller-supplied P-Preferred-Identity applied after
    // the anonymisation would re-expose the CLI.
    let mut params = params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    });
    params.from = Some("sip:+14035550100@siphon.example".to_string());
    params.headers = vec![(
        "P-Preferred-Identity".to_string(),
        "<sip:+14035550100@siphon.example>".to_string(),
    )];
    params.privacy = Some(crate::sip::privacy::CallerIdPresentation::Restricted);
    let invite = build(&params);
    assert!(
        !invite.headers.has("P-Preferred-Identity"),
        "CLIR must strip a P-Preferred-Identity added by the caller"
    );
}

#[test]
fn originate_applies_custom_headers_but_never_dialog_defining_ones() {
    let mut params = params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    });
    params.headers = vec![
        ("X-Campaign".to_string(), "reminder".to_string()),
        // Every one of these would desynchronise the stored dialog from the
        // wire, leaving the leg unaddressable for its own ACK / BYE.
        ("Call-ID".to_string(), "hijacked".to_string()),
        ("From".to_string(), "<sip:evil@elsewhere>".to_string()),
        ("Via".to_string(), "SIP/2.0/UDP nowhere".to_string()),
        ("CSeq".to_string(), "99 INVITE".to_string()),
        ("Contact".to_string(), "<sip:nowhere>".to_string()),
        ("Route".to_string(), "<sip:nowhere;lr>".to_string()),
    ];
    let invite = build(&params);

    assert_eq!(invite.headers.get("X-Campaign").unwrap(), "reminder");
    assert_eq!(invite.headers.call_id().unwrap(), "b2b-originate-1");
    assert!(invite.headers.from().unwrap().contains(";tag=sft-1"));
    assert!(invite
        .headers
        .get("Via")
        .unwrap()
        .contains("z9hG4bK-orig-1"));
    assert_eq!(invite.headers.cseq().unwrap(), "1 INVITE");
    assert_eq!(
        invite.headers.get("Contact").unwrap(),
        "<sip:198.51.100.10:5060;transport=udp>"
    );
    assert!(!invite.headers.has("Route"));
}

#[test]
fn originate_reserved_header_set_is_case_insensitive() {
    for name in [
        "Via",
        "via",
        "FROM",
        "To",
        "Call-ID",
        "call-id",
        "CSeq",
        "Contact",
        "Max-Forwards",
        "Content-Length",
        "Route",
        "Record-Route",
    ] {
        assert!(
            is_originate_reserved_header(name),
            "{name} must be reserved"
        );
    }
    for name in [
        "X-Campaign",
        "P-Asserted-Identity",
        "Subject",
        "Privacy",
        "Allow",
    ] {
        assert!(
            !is_originate_reserved_header(name),
            "{name} must be settable"
        );
    }
}

#[test]
fn a_caller_supplied_offer_rides_on_the_invite() {
    let sdp = "v=0\r\no=- 1 1 IN IP4 198.51.100.10\r\ns=-\r\nc=IN IP4 198.51.100.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
    let invite = build(&params(offer(sdp)));
    assert_eq!(invite.body, sdp.as_bytes());
    assert_eq!(
        invite.headers.get("Content-Type").unwrap(),
        "application/sdp"
    );
    assert_eq!(
        invite.headers.get("Content-Length").unwrap(),
        &sdp.len().to_string()
    );
}

#[test]
fn a_multipart_offer_keeps_its_own_content_type_and_rides_whole() {
    // RFC 5621 §3: the offer may travel as one part of a multipart body,
    // beside a part SIP does not interpret. The whole body goes on the wire
    // under the caller's Content-Type, MIME framing and all.
    let body = multipart_offer_body();
    let invite = build(&params(OriginateMedia::Offer {
        body: body.as_bytes().to_vec(),
        content_type: "multipart/mixed;boundary=siphon-1".to_string(),
    }));

    assert_eq!(invite.body, body.as_bytes());
    assert_eq!(
        invite.headers.get("Content-Type").unwrap(),
        "multipart/mixed;boundary=siphon-1"
    );
    assert_eq!(
        invite.headers.get("Content-Length").unwrap(),
        &body.len().to_string()
    );
    // What the leg records as its media description is the SDP part alone —
    // `b2bua_originate_prepare` stores exactly this expression's result.
    let recorded = crate::media::body::sdp_from_body(message_content_type(&invite), &invite.body)
        .expect("the offer is found inside the multipart body");
    let recorded = String::from_utf8(recorded).expect("SDP is text");
    assert!(recorded.starts_with("v=0\r\n"), "got: {recorded:?}");
    assert!(!recorded.contains("additional-data"));
    assert!(!recorded.contains("--siphon-1"));
}

#[test]
fn an_offer_body_carrying_no_sdp_is_refused() {
    // The plan says the caller supplied the offer while the body supplies
    // none, so the callee would offer in its 2xx with nothing here able to
    // answer it.
    let error = build_result(&params(OriginateMedia::Offer {
        body: b"hello".to_vec(),
        content_type: "text/plain".to_string(),
    }))
    .expect_err("a non-SDP body is not an offer");
    assert!(
        matches!(&error, OriginateError::InvalidBody(detail) if detail.contains("text/plain")),
        "got: {error:?}"
    );
}

#[test]
fn a_multipart_offer_without_an_sdp_part_is_refused() {
    let body = concat!(
        "--siphon-1\r\n",
        "Content-Type: application/vnd.example+xml\r\n",
        "\r\n",
        "<additional-data/>\r\n",
        "--siphon-1--\r\n",
    );
    let error = build_result(&params(OriginateMedia::Offer {
        body: body.as_bytes().to_vec(),
        content_type: "multipart/mixed;boundary=siphon-1".to_string(),
    }))
    .expect_err("a multipart body with no SDP part is not an offer");
    assert!(
        matches!(&error, OriginateError::InvalidBody(_)),
        "got: {error:?}"
    );
}

#[test]
fn a_content_type_header_cannot_strip_the_offer_off_the_invite() {
    // Content-Type is settable on purpose, but not to the point of leaving
    // an INVITE the callee reads as offerless while the plan still says the
    // caller supplied the offer.
    let mut params = params(offer("v=0\r\nm=audio 40000 RTP/AVP 0\r\n"));
    params.headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
    let error = build_result(&params).expect_err("the offer was rewritten away");
    assert!(
        matches!(&error, OriginateError::InvalidBody(_)),
        "got: {error:?}"
    );
}

#[test]
fn a_content_type_header_may_still_wrap_the_offer_in_multipart() {
    // The other half of the same rule: a caller that assembles the
    // multipart body itself and names it in `headers` keeps working,
    // because what comes out does carry an offer.
    let body = multipart_offer_body();
    let mut params = params(offer(body));
    params.headers = vec![(
        "Content-Type".to_string(),
        "multipart/mixed;boundary=siphon-1".to_string(),
    )];
    let invite = build(&params);
    assert_eq!(
        invite.headers.get("Content-Type").unwrap(),
        "multipart/mixed;boundary=siphon-1"
    );
    assert_eq!(invite.body, body.as_bytes());
}

#[test]
fn an_anchored_originate_goes_out_offerless() {
    // RFC 3261 §13.2.1: an INVITE may carry no offer; the callee then offers
    // in its 2xx and we answer in the ACK (§13.2.2.4).
    let invite = build(&params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    }));
    assert!(invite.body.is_empty());
    assert_eq!(invite.headers.get("Content-Length").unwrap(), "0");
    assert!(!invite.headers.has("Content-Type"));
}

#[test]
fn an_anchored_originate_refuses_a_content_type_header() {
    // An anchored originate carries no body, so a Content-Type from
    // `headers` describes one that is not there.
    let mut params = params(OriginateMedia::Anchor {
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
    });
    params.headers = vec![("Content-Type".to_string(), "application/sdp".to_string())];
    let error = build_result(&params).expect_err("a body-less INVITE has no content type");
    assert!(
        matches!(&error, OriginateError::InvalidBody(_)),
        "got: {error:?}"
    );
}

#[test]
fn anchor_rejection_names_the_reason_per_gate() {
    use crate::config::MediaBackendKind;
    // A backend with no answer_local cannot serve an offerless originate —
    // it has to fail here, not connect a call whose 2xx nothing can answer.
    assert!(matches!(
        originate_anchor_rejection(MediaBackendKind::Rtpengine, true, "rtp_passthrough"),
        Some(OriginateError::Unsupported(_))
    ));
    assert!(matches!(
        originate_anchor_rejection(MediaBackendKind::Rtpproxy, true, "rtp_passthrough"),
        Some(OriginateError::Unsupported(_))
    ));
    // Right backend, unknown profile.
    match originate_anchor_rejection(MediaBackendKind::SiphonRtp, false, "nope") {
        Some(OriginateError::Unsupported(message)) => {
            assert!(message.contains("nope"), "message was: {message}");
        }
        other => panic!("expected an unsupported-profile refusal, got {other:?}"),
    }
    // Right backend, known profile: no refusal.
    assert_eq!(
        originate_anchor_rejection(MediaBackendKind::SiphonRtp, true, "rtp_passthrough"),
        None
    );
}

#[test]
fn originate_error_renders_each_cause_distinctly() {
    assert_eq!(
        OriginateError::InvalidUri {
            field: "to",
            detail: "bad".to_string()
        }
        .to_string(),
        "invalid to: bad"
    );
    assert_eq!(
        OriginateError::Unroutable("no route to 'sip:x'".to_string()).to_string(),
        "no route to 'sip:x'"
    );
}

#[test]
fn originate_body_text_only_surfaces_text_bodies() {
    let raw = concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-orig-1\r\n",
        "From: <sip:a@siphon.example>;tag=sft-1\r\n",
        "To: <sip:b@carrier.example>;tag=peer\r\n",
        "Call-ID: b2b-originate-1\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let mut response = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).unwrap();
    assert_eq!(originate_body_text(&response), None);

    response.body = b"v=0\r\n".to_vec();
    assert_eq!(originate_body_text(&response), Some("v=0\r\n".to_string()));

    response.body = vec![0xff, 0xfe];
    assert_eq!(
        originate_body_text(&response),
        None,
        "a non-UTF-8 body is reported by its absence, never mangled onto a JSON rail"
    );
}
