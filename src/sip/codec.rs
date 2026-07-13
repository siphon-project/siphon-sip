//! Codec — typed header accessors on [`SipMessage`] and round-trip helpers.
//!
//! This module provides convenience methods to parse raw header strings into
//! their typed representations (Via, NameAddr, CSeq, RouteEntry) on demand.

use crate::sip::headers::cseq::CSeq;
use crate::sip::headers::nameaddr::NameAddr;
use crate::sip::headers::route::RouteEntry;
use crate::sip::headers::via::Via;
use crate::sip::message::SipMessage;

impl SipMessage {
    /// Parse all Via headers into typed [`Via`] values.
    ///
    /// Multiple Via header lines and comma-separated values within a single
    /// header are both handled. Returns them in order (topmost first).
    pub fn typed_vias(&self) -> Result<Vec<Via>, String> {
        // `get_all` canonicalizes the compact form (`v`) to `Via`
        // (RFC 3261 §7.3.3), so one lookup covers both wire forms.
        let mut result = Vec::new();
        if let Some(values) = self.headers.get_all("Via") {
            for raw in values {
                let mut vias = Via::parse_multi(raw)?;
                result.append(&mut vias);
            }
        }
        Ok(result)
    }

    /// Parse the From header into a typed [`NameAddr`].
    pub fn typed_from(&self) -> Result<Option<NameAddr>, String> {
        match self.headers.get("From") {
            Some(value) => Ok(Some(NameAddr::parse(value)?)),
            None => Ok(None),
        }
    }

    /// Parse the To header into a typed [`NameAddr`].
    pub fn typed_to(&self) -> Result<Option<NameAddr>, String> {
        match self.headers.get("To") {
            Some(value) => Ok(Some(NameAddr::parse(value)?)),
            None => Ok(None),
        }
    }

    /// Parse Contact headers into typed [`NameAddr`] values.
    pub fn typed_contacts(&self) -> Result<Vec<NameAddr>, String> {
        match self.headers.get("Contact") {
            Some(value) => NameAddr::parse_multi(value),
            None => Ok(Vec::new()),
        }
    }

    /// Parse the CSeq header into a typed [`CSeq`].
    pub fn typed_cseq(&self) -> Result<Option<CSeq>, String> {
        match self.headers.get("CSeq") {
            Some(value) => Ok(Some(CSeq::parse(value)?)),
            None => Ok(None),
        }
    }

    /// Parse Route headers into typed [`RouteEntry`] values.
    pub fn typed_routes(&self) -> Result<Vec<RouteEntry>, String> {
        let mut result = Vec::new();
        if let Some(values) = self.headers.get_all("Route") {
            for raw in values {
                let mut entries = RouteEntry::parse_multi(raw)?;
                result.append(&mut entries);
            }
        }
        Ok(result)
    }

    /// Parse Record-Route headers into typed [`RouteEntry`] values.
    pub fn typed_record_routes(&self) -> Result<Vec<RouteEntry>, String> {
        let mut result = Vec::new();
        if let Some(values) = self.headers.get_all("Record-Route") {
            for raw in values {
                let mut entries = RouteEntry::parse_multi(raw)?;
                result.append(&mut entries);
            }
        }
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::parser::parse_sip_message;
    use crate::sip::uri::SipUri;

    #[test]
    fn typed_vias_from_parsed_message() {
        let raw = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                    Via: SIP/2.0/TCP proxy.example.com:5060;branch=z9hG4bK-proxy\r\n\
                    To: <sip:bob@biloxi.com>\r\n\
                    From: \"Alice\" <sip:alice@atlanta.com>;tag=1928301774\r\n\
                    Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                    CSeq: 314159 INVITE\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();
        let vias = message.typed_vias().unwrap();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0].host, "pc33.atlanta.com");
        assert_eq!(vias[0].transport, "UDP");
        assert_eq!(vias[0].branch.as_deref(), Some("z9hG4bK776asdhds"));
        assert_eq!(vias[1].host, "proxy.example.com");
        assert_eq!(vias[1].transport, "TCP");
        assert_eq!(vias[1].port, Some(5060));
    }

    /// Regression: a REGISTER `401` whose headers are all in RFC 3261 §7.3.3
    /// compact form end-to-end (`v`/`f`/`t`/`i`/`k`/`l`), as some registrars and
    /// PBXes emit. Before compact-form canonicalization the dispatcher's
    /// `headers.get("Via")` returned `None` on this shape and the response was
    /// dropped ("response has no Via header"), leaving the peer retransmitting
    /// REGISTER forever. Two stacked Vias (comma-separated in one `v:` line)
    /// exercise the top-branch extraction the client transaction keys on.
    #[test]
    fn compact_header_response_routes_by_via() {
        let raw = "SIP/2.0 401 Unauthorized\r\n\
                    v:SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-proxytop;received=192.0.2.1;rport=5060,SIP/2.0/UDP ua.example.com:5060;branch=z9hG4bK-uabottom;received=192.0.2.9;rport=21571\r\n\
                    f:<sip:alice@example.com:5060>\r\n\
                    t:\"Bob\"<sip:bob@example.com:5060>;tag=uastag123\r\n\
                    i:call-abc@ua.example.com\r\n\
                    CSeq:1 REGISTER\r\n\
                    k:timer,path,replaces\r\n\
                    WWW-Authenticate:Digest realm=\"example.com\",nonce=\"abc123\",algorithm=MD5,qop=\"auth\"\r\n\
                    l:0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();

        // The exact lookup the response-routing path does (dispatcher.rs).
        assert!(
            message.headers.get("Via").is_some(),
            "compact `v:` must be visible as Via",
        );

        // Both stacked Vias parse; the top branch is what keys the client txn.
        let vias = message.typed_vias().unwrap();
        assert_eq!(vias.len(), 2);
        assert_eq!(vias[0].branch.as_deref(), Some("z9hG4bK-proxytop"));

        // The other compact forms resolve to their long names too.
        assert_eq!(message.headers.call_id().map(String::as_str), Some("call-abc@ua.example.com"));
        assert_eq!(message.typed_from().unwrap().unwrap().uri.user.as_deref(), Some("alice"));
        assert_eq!(message.typed_to().unwrap().unwrap().tag.as_deref(), Some("uastag123"));
        assert_eq!(message.headers.content_length(), Some(0));
        assert_eq!(message.headers.get("Supported").map(String::as_str), Some("timer,path,replaces"));
    }

    #[test]
    fn typed_from_to_from_parsed_message() {
        let raw = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                    To: Bob <sip:bob@biloxi.com>\r\n\
                    From: \"Alice\" <sip:alice@atlanta.com>;tag=1928301774\r\n\
                    Call-ID: test@host\r\n\
                    CSeq: 1 INVITE\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();

        let from = message.typed_from().unwrap().unwrap();
        assert_eq!(from.display_name.as_deref(), Some("Alice"));
        assert_eq!(from.uri.user.as_deref(), Some("alice"));
        assert_eq!(from.tag.as_deref(), Some("1928301774"));

        let to = message.typed_to().unwrap().unwrap();
        assert_eq!(to.display_name.as_deref(), Some("Bob"));
        assert_eq!(to.uri.user.as_deref(), Some("bob"));
        assert_eq!(to.tag, None);
    }

    #[test]
    fn typed_cseq_from_parsed_message() {
        let raw = "OPTIONS sip:example.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK-opt\r\n\
                    To: <sip:example.com>\r\n\
                    From: <sip:user@example.com>;tag=abc\r\n\
                    Call-ID: test123\r\n\
                    CSeq: 42 OPTIONS\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();
        let cseq = message.typed_cseq().unwrap().unwrap();
        assert_eq!(cseq.sequence, 42);
        assert_eq!(cseq.method, Method::Options);
    }

    #[test]
    fn typed_routes_from_parsed_message() {
        let raw = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP host.example.com;branch=z9hG4bK-rt\r\n\
                    Route: <sip:p1.example.com;lr>, <sip:p2.example.com;lr>\r\n\
                    To: <sip:bob@biloxi.com>\r\n\
                    From: <sip:alice@atlanta.com>;tag=xyz\r\n\
                    Call-ID: route-test\r\n\
                    CSeq: 1 INVITE\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();
        let routes = message.typed_routes().unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].uri.host, "p1.example.com");
        assert!(routes[0].is_loose_route());
        assert_eq!(routes[1].uri.host, "p2.example.com");
        assert!(routes[1].is_loose_route());
    }

    #[test]
    fn typed_contacts_from_parsed_message() {
        let raw = "REGISTER sip:registrar.biloxi.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP bobspc.biloxi.com;branch=z9hG4bKnashds7\r\n\
                    To: <sip:bob@biloxi.com>\r\n\
                    From: <sip:bob@biloxi.com>;tag=456248\r\n\
                    Call-ID: 843817637684230@998sdasdh09\r\n\
                    CSeq: 1826 REGISTER\r\n\
                    Contact: <sip:bob@192.0.2.4>;expires=7200\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, message) = parse_sip_message(raw).unwrap();
        let contacts = message.typed_contacts().unwrap();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.user.as_deref(), Some("bob"));
        assert_eq!(contacts[0].expires, Some(7200));
    }

    #[test]
    fn round_trip_parse_serialize_parse() {
        let raw = "INVITE sip:bob@biloxi.com SIP/2.0\r\n\
                    Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n\
                    Max-Forwards: 70\r\n\
                    To: Bob <sip:bob@biloxi.com>\r\n\
                    From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                    Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n\
                    CSeq: 314159 INVITE\r\n\
                    Contact: <sip:alice@pc33.atlanta.com>\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        // Parse original
        let (_, original) = parse_sip_message(raw).unwrap();

        // Serialize to bytes, then parse again
        let wire = original.to_bytes();
        let wire_str = String::from_utf8(wire).unwrap();
        let (_, reparsed) = parse_sip_message(&wire_str).unwrap();

        // Verify key fields match
        assert_eq!(original.method(), reparsed.method());
        assert_eq!(
            original.request_uri().map(|u| u.to_string()),
            reparsed.request_uri().map(|u| u.to_string())
        );
        assert_eq!(original.headers.call_id(), reparsed.headers.call_id());
        assert_eq!(original.headers.max_forwards(), reparsed.headers.max_forwards());

        // Verify typed headers survive round-trip
        let orig_from = original.typed_from().unwrap().unwrap();
        let re_from = reparsed.typed_from().unwrap().unwrap();
        assert_eq!(orig_from.uri.user, re_from.uri.user);
        assert_eq!(orig_from.tag, re_from.tag);

        let orig_vias = original.typed_vias().unwrap();
        let re_vias = reparsed.typed_vias().unwrap();
        assert_eq!(orig_vias.len(), re_vias.len());
        assert_eq!(orig_vias[0].branch, re_vias[0].branch);
    }

    #[test]
    fn round_trip_builder_to_parsed() {
        let uri = SipUri::new("biloxi.com".to_string()).with_user("bob".to_string());
        let message = SipMessageBuilder::new()
            .request(Method::Register, uri)
            .via("SIP/2.0/UDP bobspc.biloxi.com:5060;branch=z9hG4bKnashds7".to_string())
            .to("<sip:bob@biloxi.com>".to_string())
            .from("<sip:bob@biloxi.com>;tag=456248".to_string())
            .call_id("843817637684230@998sdasdh09".to_string())
            .cseq("1826 REGISTER".to_string())
            .contact("<sip:bob@192.0.2.4>".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let wire = message.to_bytes();
        let wire_str = String::from_utf8(wire).unwrap();
        let (_, reparsed) = parse_sip_message(&wire_str).unwrap();

        assert_eq!(reparsed.method(), Some(&Method::Register));
        let cseq = reparsed.typed_cseq().unwrap().unwrap();
        assert_eq!(cseq.sequence, 1826);
        assert_eq!(cseq.method, Method::Register);

        let vias = reparsed.typed_vias().unwrap();
        assert_eq!(vias[0].host, "bobspc.biloxi.com");
        assert_eq!(vias[0].port, Some(5060));
    }

    #[test]
    fn round_trip_response() {
        let raw = "SIP/2.0 200 OK\r\n\
                    Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds;received=192.0.2.1\r\n\
                    To: Bob <sip:bob@biloxi.com>;tag=a6c85cf\r\n\
                    From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n\
                    Call-ID: a84b4c76e66710\r\n\
                    CSeq: 314159 INVITE\r\n\
                    Contact: <sip:bob@192.0.2.4>\r\n\
                    Content-Length: 0\r\n\
                    \r\n";

        let (_, original) = parse_sip_message(raw).unwrap();
        assert_eq!(original.status_code(), Some(200));

        let wire = original.to_bytes();
        let wire_str = String::from_utf8(wire).unwrap();
        let (_, reparsed) = parse_sip_message(&wire_str).unwrap();

        assert_eq!(reparsed.status_code(), Some(200));
        let to = reparsed.typed_to().unwrap().unwrap();
        assert_eq!(to.tag.as_deref(), Some("a6c85cf"));

        let vias = reparsed.typed_vias().unwrap();
        assert_eq!(vias[0].received.as_deref(), Some("192.0.2.1"));
    }
}
