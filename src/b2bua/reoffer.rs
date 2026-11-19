//! An in-dialog offer on a bridged call, as a script is shown it.
//!
//! A re-INVITE or an UPDATE from either party renegotiates the session the
//! B2BUA relays between them (RFC 3264 §8, RFC 3311). `@b2bua.on_reoffer` sees
//! the offer before it is relayed and may let it through, refuse it or answer
//! it itself, and `@b2bua.on_reoffer_answered` sees the final response the
//! offerer got. These are the facts both are given, and what the first one
//! decided.

use crate::media::direction::{classify, effective_direction, ReofferKind};
use crate::media::sdp::SdpBody;

/// An in-dialog offer, read once when it arrives.
#[derive(Debug, Clone)]
pub struct ReofferFacts {
    /// `"INVITE"` or `"UPDATE"`.
    pub method: &'static str,
    /// Whether the caller sent it.
    pub from_a_leg: bool,
    /// The offer as the party sent it, `None` for an offerless re-INVITE or an
    /// UPDATE without a body.
    pub offer: Option<String>,
    /// Which way the offer has media flow ([`effective_direction`]).
    pub direction: Option<&'static str>,
    /// Which way the description the party last gave on the dialog has it.
    pub previous_direction: Option<&'static str>,
    /// What the offer does to the session in force ([`classify`]).
    pub kind: ReofferKind,
    /// Whether it crossed between early dialogs, before the call was answered
    /// (an UPDATE, RFC 3311 §5.1).
    pub early: bool,
    /// The description siphon last sent the offering party: the session in
    /// force toward it (`Dialog::last_sent_sdp`), which an answer siphon gives
    /// here is built from. `None` before siphon has sent that party one.
    pub session: Option<String>,
}

impl ReofferFacts {
    /// Read the offer `offer` (the SDP of the request, if it has one) against
    /// `in_force`, the description the sending party last gave on its dialog.
    pub fn read(
        method: &'static str,
        from_a_leg: bool,
        offer: Option<&[u8]>,
        in_force: Option<&[u8]>,
        early: bool,
    ) -> Self {
        let parse = |sdp: &[u8]| SdpBody::parse(&String::from_utf8_lossy(sdp));
        let offered = offer.filter(|sdp| !sdp.is_empty()).map(parse);
        let previous = in_force.filter(|sdp| !sdp.is_empty()).map(parse);
        Self {
            method,
            from_a_leg,
            offer: offer
                .filter(|sdp| !sdp.is_empty())
                .map(|sdp| String::from_utf8_lossy(sdp).into_owned()),
            direction: offered.as_ref().and_then(effective_direction),
            previous_direction: previous.as_ref().and_then(effective_direction),
            kind: classify(offered.as_ref(), previous.as_ref()),
            early,
            session: None,
        }
    }

    /// `"a"` for the caller and `"b"` for the callee, the convention of
    /// `call.refer_side` and `ByeInitiator.side`.
    pub fn side(&self) -> &'static str {
        if self.from_a_leg {
            "a"
        } else {
            "b"
        }
    }
}

/// What `@b2bua.on_reoffer` decided.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum ReofferDecision {
    /// Relay the offer to the other party, as without the hook.
    #[default]
    Relay,
    /// Refuse it with this final response. The session stays as it was
    /// (RFC 3261 §14.2). `extras` is what the refusal carries: a body that
    /// says why (an MCPTT controlling function's
    /// `application/vnd.3gpp.mcptt-info+xml`, TS 24.379 §6.3.3.1.14) and
    /// headers such as `Warning` (RFC 3261 §20.43) or `Retry-After`.
    Refuse {
        code: u16,
        reason: String,
        extras: AnswerExtras,
    },
    /// Answer it here and relay nothing. `sdp` is the script's answer, or
    /// `None` to have siphon answer from the session in force toward the
    /// offerer (RFC 3264 §6). `extras` is what the 2xx carries beside it.
    TakeOver {
        sdp: Option<String>,
        extras: AnswerExtras,
    },
}

/// What a script puts beside the session description: on the 2xx siphon
/// answers an offer with (`offer.answer()`), and on a re-INVITE it has siphon
/// send (`b2bua.reoffer()`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnswerExtras {
    /// A body to send with the SDP, and its `Content-Type`: a single part of
    /// any type, or a `multipart/*` body (RFC 5621 §3) the SDP joins.
    pub body: Option<(String, Vec<u8>)>,
    /// Headers added to the 2xx, in the order given. Checked against the
    /// headers siphon owns on a response it sends
    /// ([`crate::b2bua::uas_headers::validate`]) before they get here.
    pub headers: Vec<(String, String)>,
}

impl AnswerExtras {
    /// Check what a script gave `offer.reject()`: the body goes on the
    /// refusal as it was given, with no SDP to join, so it is checked only
    /// for what would break the response (a `Content-Type` that ends its
    /// header early, an empty body). `headers` are checked by the caller
    /// against the headers siphon owns.
    pub fn refusal(
        body: Option<(String, Vec<u8>)>,
        headers: Vec<(String, String)>,
    ) -> Result<Self, String> {
        if let Some((content_type, body)) = &body {
            check_content_type(content_type)?;
            if body.is_empty() {
                return Err("body is empty".to_string());
            }
        }
        Ok(Self { body, headers })
    }

    /// Sort what a script gave `offer.answer()` into the answer's SDP and the
    /// body that goes with it. `sdp` is its `sdp=`, `body` its `content_type=`
    /// and `body=`.
    ///
    /// A body that is the SDP (`application/sdp`), or a `multipart/*` body
    /// with an SDP part, gives the answer itself, and then `sdp=` beside it
    /// would be a second one. `Err` says what is wrong: an answer given twice,
    /// a `Content-Type` that would end its header early, an empty body, or a
    /// `multipart/*` body siphon could not put the SDP part in (no `boundary`
    /// parameter, no part delimited by it).
    pub fn checked(
        sdp: Option<String>,
        body: Option<(String, Vec<u8>)>,
        headers: Vec<(String, String)>,
    ) -> Result<(Option<String>, Self), String> {
        use crate::media::body::{is_multipart, is_sdp, sdp_from_body, with_sdp_part};
        let Some((content_type, body)) = body else {
            return Ok((
                sdp,
                Self {
                    body: None,
                    headers,
                },
            ));
        };
        check_content_type(&content_type)?;
        if body.is_empty() {
            return Err("body is empty".to_string());
        }
        let twice = "the body carries the SDP and sdp= gives another: pass one";
        if is_sdp(&content_type) {
            if sdp.is_some() {
                return Err(twice.to_string());
            }
            let sdp = String::from_utf8_lossy(&body).into_owned();
            return Ok((
                Some(sdp),
                Self {
                    body: None,
                    headers,
                },
            ));
        }
        let mut sdp = sdp;
        if is_multipart(&content_type) {
            // Proven now, while the script can still be told: the part is put
            // in when the answer is known.
            with_sdp_part(&content_type, &body, b"v=0\r\n")?;
            if let Ok(part) = sdp_from_body(&content_type, &body) {
                if sdp.is_some() {
                    return Err(twice.to_string());
                }
                sdp = Some(String::from_utf8_lossy(&part).into_owned());
            }
        }
        Ok((
            sdp,
            Self {
                body: Some((content_type, body)),
                headers,
            },
        ))
    }

    /// The `Content-Type` and body of a 2xx that carries `sdp` (`None` when it
    /// carries none: an UPDATE without an offer) and what the script sends
    /// with it. `Ok(None)` is a 2xx without a body.
    ///
    /// `Err` says why the script's `multipart/*` body cannot take the SDP
    /// part ([`crate::media::body::with_sdp_part`]).
    pub fn body_with(&self, sdp: Option<&[u8]>) -> Result<Option<(String, Vec<u8>)>, String> {
        match (&self.body, sdp) {
            (None, None) => Ok(None),
            (None, Some(sdp)) => Ok(Some(("application/sdp".to_string(), sdp.to_vec()))),
            (Some((content_type, body)), None) => Ok(Some((content_type.clone(), body.clone()))),
            (Some((content_type, body)), Some(sdp)) => {
                crate::media::body::with_sdp_part(content_type, body, sdp).map(Some)
            }
        }
    }

    /// Write this on `response`, a 2xx siphon built: the body that carries
    /// `sdp` with its framing headers, then the script's headers. `Err` is
    /// [`Self::body_with`]'s, and leaves `response` as it was.
    pub fn apply(
        &self,
        response: &mut crate::sip::message::SipMessage,
        sdp: Option<&[u8]>,
    ) -> Result<(), String> {
        if let Some((content_type, body)) = self.body_with(sdp)? {
            response.headers.set("Content-Type", content_type);
            response
                .headers
                .set("Content-Length", body.len().to_string());
            response.body = body;
        }
        for (name, value) in &self.headers {
            response.headers.add(name, value.clone());
        }
        Ok(())
    }
}

/// `Err` when `content_type` carries a line break or NUL, which would end the
/// `Content-Type` header early and start another.
fn check_content_type(content_type: &str) -> Result<(), String> {
    if content_type
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err("content_type contains a line break or NUL".to_string());
    }
    Ok(())
}

/// The final response the offerer got, as `@b2bua.on_reoffer_answered` is
/// shown it.
#[derive(Debug, Clone)]
pub struct ReofferAnswer {
    pub status_code: u16,
    /// The SDP of the response, as the offerer was sent it.
    pub sdp: Option<String>,
    /// Whether siphon answered it rather than the other party.
    pub local: bool,
}

impl ReofferAnswer {
    /// `sdp`'s direction ([`effective_direction`]).
    pub fn direction(&self) -> Option<&'static str> {
        self.sdp
            .as_deref()
            .map(SdpBody::parse)
            .as_ref()
            .and_then(effective_direction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TALKING: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

    fn held() -> Vec<u8> {
        [TALKING, b"a=sendonly\r\n"].concat()
    }

    #[test]
    fn a_hold_is_read_against_the_session_in_force() {
        let held = held();
        let facts = ReofferFacts::read("INVITE", true, Some(&held), Some(TALKING), false);
        assert_eq!(facts.kind, ReofferKind::Hold);
        assert_eq!(facts.direction, Some("sendonly"));
        assert_eq!(facts.previous_direction, Some("sendrecv"));
        assert_eq!(facts.side(), "a");
        assert_eq!(
            facts.offer.as_deref(),
            Some(String::from_utf8_lossy(&held).as_ref())
        );
    }

    #[test]
    fn an_offerless_request_has_no_offer_and_is_a_refresh() {
        let facts = ReofferFacts::read("INVITE", false, Some(b""), Some(TALKING), false);
        assert_eq!(facts.offer, None);
        assert_eq!(facts.direction, None);
        assert_eq!(facts.kind, ReofferKind::Refresh);
        assert_eq!(facts.side(), "b");
        let facts = ReofferFacts::read("UPDATE", false, None, None, true);
        assert_eq!(facts.previous_direction, None);
        assert!(facts.early);
    }

    #[test]
    fn the_answer_direction_is_read_off_its_sdp() {
        let answer = ReofferAnswer {
            status_code: 200,
            sdp: Some(String::from_utf8_lossy(&[TALKING, b"a=recvonly\r\n"].concat()).into_owned()),
            local: false,
        };
        assert_eq!(answer.direction(), Some("recvonly"));
        let refused = ReofferAnswer {
            status_code: 488,
            sdp: None,
            local: true,
        };
        assert_eq!(refused.direction(), None);
    }

    #[test]
    fn the_default_decision_relays() {
        assert_eq!(ReofferDecision::default(), ReofferDecision::Relay);
    }

    #[test]
    fn what_a_script_gives_is_sorted_into_the_answer_and_the_body_beside_it() {
        let sdp = String::from_utf8_lossy(TALKING).into_owned();
        // Nothing but an SDP, or nothing at all.
        let (answer, extras) =
            AnswerExtras::checked(Some(sdp.clone()), None, Vec::new()).expect("fine");
        assert_eq!(answer.as_deref(), Some(sdp.as_str()));
        assert_eq!(extras, AnswerExtras::default());
        // A body that is the SDP is the answer.
        let (answer, extras) = AnswerExtras::checked(
            None,
            Some(("application/sdp".to_string(), TALKING.to_vec())),
            Vec::new(),
        )
        .expect("fine");
        assert_eq!(answer.as_deref(), Some(sdp.as_str()));
        assert_eq!(extras.body, None);
        // A single part of another type goes beside whatever answers.
        let part = (
            "application/vnd.example+xml".to_string(),
            b"<info/>".to_vec(),
        );
        let (answer, extras) =
            AnswerExtras::checked(None, Some(part.clone()), Vec::new()).expect("fine");
        assert_eq!(answer, None);
        assert_eq!(extras.body, Some(part.clone()));
        let (answer, _) =
            AnswerExtras::checked(Some(sdp.clone()), Some(part), Vec::new()).expect("fine");
        assert_eq!(answer.as_deref(), Some(sdp.as_str()));
        // A multipart body with an SDP part gives the answer.
        let multipart = format!(
            "--b\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n--b\r\n\
             Content-Type: application/vnd.example+xml\r\n\r\n<info/>\r\n--b--\r\n"
        );
        let body = (
            "multipart/mixed;boundary=b".to_string(),
            multipart.into_bytes(),
        );
        let (answer, extras) =
            AnswerExtras::checked(None, Some(body.clone()), Vec::new()).expect("fine");
        assert_eq!(
            answer.as_deref(),
            Some(sdp.trim_end()),
            "the SDP part, as the multipart parser hands it over"
        );
        assert_eq!(extras.body, Some(body));
    }

    #[test]
    fn what_a_script_gives_wrongly_is_refused_with_the_reason() {
        let sdp = String::from_utf8_lossy(TALKING).into_owned();
        let refused = |sdp: Option<String>, content_type: &str, body: &[u8]| {
            AnswerExtras::checked(
                sdp,
                Some((content_type.to_string(), body.to_vec())),
                Vec::new(),
            )
            .expect_err("refused")
        };
        assert!(refused(Some(sdp.clone()), "application/sdp", TALKING).contains("pass one"));
        let multipart = format!("--b\r\nContent-Type: application/sdp\r\n\r\n{sdp}\r\n--b--\r\n");
        assert!(refused(
            Some(sdp),
            "multipart/mixed;boundary=b",
            multipart.as_bytes()
        )
        .contains("pass one"));
        assert!(refused(None, "text/plain\r\nX-Injected: 1", b"x").contains("line break"));
        assert!(refused(None, "text/plain", b"").contains("empty"));
        assert!(refused(None, "multipart/mixed", b"--b--\r\n").contains("boundary"));
        assert!(
            refused(None, "multipart/mixed;boundary=b", b"<info/>").contains("no part delimited")
        );
    }

    #[test]
    fn a_refusal_carries_its_body_as_given_and_refuses_what_would_break_it() {
        let info = (
            "application/vnd.3gpp.mcptt-info+xml".to_string(),
            b"<mcpttinfo/>".to_vec(),
        );
        let warning = vec![(
            "Warning".to_string(),
            "399 mcx.example.com \"not allowed\"".to_string(),
        )];
        let extras = AnswerExtras::refusal(Some(info.clone()), warning.clone()).expect("fine");
        assert_eq!(
            extras,
            AnswerExtras {
                body: Some(info.clone()),
                headers: warning,
            }
        );
        // No SDP joins a refusal: the body goes as it is, even a multipart one.
        assert_eq!(extras.body_with(None), Ok(Some(info)));
        assert_eq!(
            AnswerExtras::refusal(None, Vec::new()),
            Ok(AnswerExtras::default())
        );
        let refused = |content_type: &str, body: &[u8]| {
            AnswerExtras::refusal(Some((content_type.to_string(), body.to_vec())), Vec::new())
                .expect_err("refused")
        };
        assert!(refused("text/plain\r\nX-Injected: 1", b"x").contains("line break"));
        assert!(refused("text/plain", b"").contains("empty"));
    }

    #[test]
    fn extras_frame_the_sdp_alone_with_another_part_or_not_at_all() {
        let none = AnswerExtras::default();
        assert_eq!(none.body_with(None), Ok(None));
        assert_eq!(
            none.body_with(Some(TALKING)),
            Ok(Some(("application/sdp".to_string(), TALKING.to_vec())))
        );
        let extras = AnswerExtras {
            body: Some((
                "application/vnd.example+xml".to_string(),
                b"<info/>".to_vec(),
            )),
            headers: Vec::new(),
        };
        // No SDP to send: the script's body goes as it is.
        assert_eq!(
            extras.body_with(None),
            Ok(Some((
                "application/vnd.example+xml".to_string(),
                b"<info/>".to_vec()
            )))
        );
        let (content_type, body) = extras
            .body_with(Some(TALKING))
            .expect("composes")
            .expect("a body");
        assert!(
            content_type.starts_with("multipart/mixed;boundary="),
            "{content_type}"
        );
        assert_eq!(
            crate::media::body::sdp_from_body(&content_type, &body).expect("the SDP part"),
            TALKING.strip_suffix(b"\r\n").expect("ends in CRLF")
        );
        assert!(String::from_utf8_lossy(&body).contains("<info/>"));
    }

    #[test]
    fn extras_go_on_a_response_with_their_headers_in_order() {
        let mut response = crate::sip::parser::parse_sip_message_bytes(
            concat!(
                "SIP/2.0 200 OK\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-extras\r\n",
                "From: <sip:alice@example.com>;tag=a\r\n",
                "To: <sip:bob@example.com>;tag=b\r\n",
                "Call-ID: extras@192.0.2.10\r\n",
                "CSeq: 2 INVITE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            )
            .as_bytes(),
        )
        .expect("parses");
        let extras = AnswerExtras {
            body: None,
            headers: vec![
                ("Resource-Priority".to_string(), "example.5".to_string()),
                ("X-Second".to_string(), "2".to_string()),
            ],
        };
        extras.apply(&mut response, Some(TALKING)).expect("applies");
        assert_eq!(
            response.headers.get("Content-Type").map(String::as_str),
            Some("application/sdp")
        );
        assert_eq!(
            response.headers.get("Content-Length").map(String::as_str),
            Some(TALKING.len().to_string().as_str())
        );
        assert_eq!(response.body, TALKING);
        assert_eq!(
            response
                .headers
                .get("Resource-Priority")
                .map(String::as_str),
            Some("example.5")
        );
        let text = String::from_utf8_lossy(&response.to_bytes()).into_owned();
        assert!(
            text.find("Resource-Priority").expect("first") < text.find("X-Second").expect("second"),
            "{text}"
        );

        // A multipart body that cannot take the SDP leaves the response alone.
        let broken = AnswerExtras {
            body: Some(("multipart/mixed".to_string(), b"--b--\r\n".to_vec())),
            headers: vec![("X-Third".to_string(), "3".to_string())],
        };
        let before = response.to_bytes();
        assert!(broken.apply(&mut response, Some(TALKING)).is_err());
        assert_eq!(response.to_bytes(), before);
    }
}
