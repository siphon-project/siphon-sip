//! The `Reoffer` object `@b2bua.on_reoffer` and `@b2bua.on_reoffer_answered`
//! are handed: an in-dialog offer on a bridged call (a re-INVITE or an UPDATE)
//! and, in the second, the final response the offerer got.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use super::request::PyRequest;
use crate::b2bua::reoffer::{AnswerExtras, ReofferAnswer, ReofferDecision, ReofferFacts};

/// An in-dialog offer from one party of a bridged call.
#[pyclass(name = "Reoffer")]
pub struct PyReoffer {
    facts: Arc<ReofferFacts>,
    /// The request as it arrived. Only in `on_reoffer`.
    request: Option<Py<PyRequest>>,
    decision: ReofferDecision,
    /// The final response. Only in `on_reoffer_answered`.
    answer: Option<ReofferAnswer>,
}

impl PyReoffer {
    /// The offer as `@b2bua.on_reoffer` sees it, before it is relayed.
    pub fn offered(facts: Arc<ReofferFacts>, request: Py<PyRequest>) -> Self {
        Self {
            facts,
            request: Some(request),
            decision: ReofferDecision::Relay,
            answer: None,
        }
    }

    /// The offer and the final response it got, for `@b2bua.on_reoffer_answered`.
    pub fn answered(facts: Arc<ReofferFacts>, answer: ReofferAnswer) -> Self {
        Self {
            facts,
            request: None,
            decision: ReofferDecision::Relay,
            answer: Some(answer),
        }
    }

    /// What the handler decided.
    pub fn decision(&self) -> &ReofferDecision {
        &self.decision
    }

    fn still_open(&self, what: &str) -> PyResult<()> {
        if self.answer.is_some() {
            return Err(PyRuntimeError::new_err(format!(
                "offer.{what}() decides an offer before it is relayed; in \
                 @b2bua.on_reoffer_answered the offer has been answered already"
            )));
        }
        Ok(())
    }
}

#[pymethods]
impl PyReoffer {
    /// ``"INVITE"`` for a re-INVITE, ``"UPDATE"`` for an UPDATE (RFC 3311).
    #[getter]
    fn method(&self) -> &str {
        self.facts.method
    }

    /// Which party sent the offer: ``"a"`` for the caller, ``"b"`` for the
    /// callee (the convention of ``call.refer_side`` and ``ByeInitiator.side``).
    #[getter]
    fn side(&self) -> &str {
        self.facts.side()
    }

    /// The re-INVITE or UPDATE as it arrived, for its headers. Only in
    /// ``@b2bua.on_reoffer``, ``None`` in ``@b2bua.on_reoffer_answered``.
    ///
    /// A header set or removed on it, or a body set on it, is on the request
    /// relayed to the other party, under the same dialog rewriting and
    /// topology hiding as any relayed offer. Answer the offer with
    /// ``offer.reject()`` or ``offer.answer()``, not ``request.reply()``.
    #[getter]
    fn request(&self, python: Python<'_>) -> Option<Py<PyRequest>> {
        self.request
            .as_ref()
            .map(|request| request.clone_ref(python))
    }

    /// The offer's SDP as the party sent it, or ``None`` for an offerless
    /// re-INVITE (the other party's 2xx then carries the offer, RFC 3261
    /// §14.1) or an UPDATE without a body.
    #[getter]
    fn sdp(&self) -> Option<String> {
        self.facts.offer.clone()
    }

    /// Which way the offer has media flow, for the party that sent it:
    /// ``"sendrecv"``, ``"sendonly"``, ``"recvonly"`` or ``"inactive"``, over
    /// every stream it does not reject. A ``0.0.0.0`` connection address (the
    /// hold of RFC 2543 phones, RFC 3264 §8.4) counts as receiving nothing.
    /// ``None`` without an offer.
    #[getter]
    fn direction(&self) -> Option<&str> {
        self.facts.direction
    }

    /// The same for the description that party last gave on its dialog: the
    /// session in force before this offer. ``None`` when siphon has none.
    #[getter]
    fn previous_direction(&self) -> Option<&str> {
        self.facts.previous_direction
    }

    /// What the offer does to the session in force, compared stream by stream
    /// with the description the party last gave:
    ///
    /// - ``"hold"``: the party stops receiving (``sendonly``, ``inactive``,
    ///   ``0.0.0.0``; TS 24.610 §4.5.2),
    /// - ``"resume"``: it receives again,
    /// - ``"refresh"``: nothing changes; no offer, or the same streams,
    ///   addresses and directions, keys, ICE credentials and grouping (a
    ///   session refresh, RFC 4028 §10, which on a held call repeats
    ///   ``sendonly`` and is not a second hold). An attribute that
    ///   renegotiates nothing, such as RFC 7866's ``a=recordpref`` or a
    ///   trickled candidate, leaves it a refresh,
    /// - ``"change"``: anything else (a codec, an address, a stream, an ICE
    ///   restart, new keys, a new grouping).
    #[getter]
    fn kind(&self) -> &str {
        self.facts.kind.as_str()
    }

    /// The description siphon last sent the offering party, the session in
    /// force toward it, as text; ``None`` before siphon has sent it one.
    ///
    /// It is what ``offer.answer()`` answers from, and what a script edits
    /// when the answer has to differ from it in one attribute only, such as
    /// RFC 7866's ``a=record``, on a stream ``offer.answer()`` cannot answer
    /// for itself (keyed, ICE, grouped). Repeating it is a valid answer only to
    /// an offer that renegotiates nothing, which is what a ``"refresh"`` is.
    ///
    /// ```python
    /// @b2bua.on_reoffer
    /// def toggle(call, offer):
    ///     if offer.kind == "refresh" and offer.session_sdp:
    ///         offer.answer(sdp=offer.session_sdp)
    /// ```
    #[getter]
    fn session_sdp(&self) -> Option<String> {
        self.facts.session.clone()
    }

    /// Whether the offer crossed before the call was answered: an UPDATE
    /// between early dialogs (RFC 3311 §5.1).
    #[getter]
    fn early(&self) -> bool {
        self.facts.early
    }

    /// The final response's status code. Only in
    /// ``@b2bua.on_reoffer_answered``, ``None`` before.
    #[getter]
    fn status_code(&self) -> Option<u16> {
        self.answer.as_ref().map(|answer| answer.status_code)
    }

    /// The SDP of the final response as the offerer was sent it, ``None``
    /// when it had none (a refusal, or a 2xx to an UPDATE without an offer).
    /// For an offerless re-INVITE this is the other party's offer.
    #[getter]
    fn answer_sdp(&self) -> Option<String> {
        self.answer.as_ref().and_then(|answer| answer.sdp.clone())
    }

    /// Which way ``answer_sdp`` has media flow, for the party that answered
    /// (a ``sendonly`` hold answered ``recvonly``, RFC 3264 §6.1). After a
    /// refusal the session stays as it was (RFC 3261 §14.1), and this is
    /// ``None``.
    #[getter]
    fn answer_direction(&self) -> Option<&str> {
        self.answer.as_ref().and_then(ReofferAnswer::direction)
    }

    /// Whether siphon answered the offer itself (``offer.answer()``,
    /// ``offer.reject()``, or a media engine that would not take it) rather
    /// than the other party.
    #[getter]
    fn answered_locally(&self) -> bool {
        self.answer.as_ref().is_some_and(|answer| answer.local)
    }

    /// Refuse the offer with ``code`` (300-699) and ``reason``; nothing is
    /// relayed and the session in force stays as it was (RFC 3261 §14.2).
    /// ``488`` refuses the media, ``403`` the request.
    ///
    /// ``body`` (str or bytes) with its ``content_type`` goes on the refusal
    /// as given, for a service that says why in a document of its own (an
    /// MCPTT controlling function's ``application/vnd.3gpp.mcptt-info+xml``,
    /// TS 24.379 §6.3.3.1.14).
    ///
    /// ``headers`` is a ``{name: value}`` mapping added to the refusal, in its
    /// order, such as ``Warning`` (RFC 3261 §20.43) or ``Retry-After``. The
    /// headers siphon owns on a response it sends raise ``ValueError``, as on
    /// ``offer.answer()``.
    ///
    /// Raises ``RuntimeError`` in ``@b2bua.on_reoffer_answered``;
    /// ``ValueError`` for a code outside 300-699, an owned header, ``body``
    /// without ``content_type`` or the reverse, or an empty ``body``;
    /// ``TypeError`` for a header name or value that is not a str. Nothing is
    /// decided when it raises.
    ///
    /// ```python
    /// @b2bua.on_reoffer
    /// def no_video(call, offer):
    ///     if offer.sdp and "m=video" in offer.sdp:
    ///         offer.reject(488, "Not Acceptable Here")
    ///
    /// @b2bua.on_reoffer
    /// def upgrade(call, offer):
    ///     if not may_upgrade(call):
    ///         offer.reject(403, "Forbidden",
    ///                      body=refusal_info_xml,
    ///                      content_type="application/vnd.example.info+xml",
    ///                      headers={"Warning": '399 example.com "not allowed"'})
    /// ```
    #[pyo3(signature = (code, reason, body=None, content_type=None, headers=None))]
    fn reject(
        &mut self,
        code: u16,
        reason: &str,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
        headers: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<()> {
        self.still_open("reject")?;
        if !(300..=699).contains(&code) {
            return Err(PyValueError::new_err(format!(
                "offer.reject() takes a final non-2xx status, 300-699, not {code}"
            )));
        }
        let headers = super::call::uas_response_headers("offer.reject", headers)?;
        let body = match (body, content_type) {
            (None, None) => None,
            (Some(body), Some(content_type)) => Some((
                content_type.to_string(),
                super::request::extract_body_bytes(body)?,
            )),
            _ => {
                return Err(PyValueError::new_err(
                    "offer.reject(body=…) and content_type=… go together",
                ))
            }
        };
        let extras = AnswerExtras::refusal(body, headers)
            .map_err(|why| PyValueError::new_err(format!("offer.reject(): {why}")))?;
        self.decision = ReofferDecision::Refuse {
            code,
            reason: reason.to_string(),
            extras,
        };
        Ok(())
    }

    /// Answer the offer here and relay nothing to the other party, which
    /// carries on with the session it has.
    ///
    /// With no ``sdp``, siphon answers from the session in force toward the
    /// offerer, the description it last sent that party (the media engine's,
    /// on an anchored call): the same address and ports, the formats both
    /// list, and the direction the offer leaves (RFC 3264 §6.1, so a
    /// ``sendonly`` hold is answered ``recvonly``). The media engine is not
    /// told, so media keeps flowing between it and the other party, which a
    /// script can then play an announcement or music on hold to
    /// (``rtpengine.play_media``). Without an offer the 200 carries that
    /// session as siphon's offer (RFC 3261 §14.1).
    ///
    /// Streams that are keyed, use ICE or are grouped (DTLS-SRTP, SDES,
    /// BUNDLE) took the media engine to agree, and are answered this way only
    /// for an offer that asks for none of it again: the same streams,
    /// addresses, keys, ICE credentials and grouping the party had, with any
    /// direction. The session in force answers that offer as it answered the
    /// one before. An offer that restarts ICE, re-keys or moves a stream is
    /// refused ``488``.
    ///
    /// On a call the media engine answered itself (``answer_local``, an
    /// anchored ``call.progress()``), with no ``sdp`` the engine answers the
    /// offer as it does without a handler, and ``body`` and ``headers`` go on
    /// that 200.
    ///
    /// ``sdp`` (a str) is sent as the answer instead. Either way siphon owns
    /// its ``o=`` line (RFC 3264 §8).
    ///
    /// ``body`` (str or bytes) with its ``content_type`` is sent with the
    /// answer, for a service that carries a document of its own beside the
    /// session description (RFC 5621 §3):
    ///
    /// - a single part of any type, which siphon sends as the second part of
    ///   a ``multipart/mixed`` body after the SDP, under a boundary it draws;
    /// - a ``multipart/*`` body without an ``application/sdp`` part, which
    ///   siphon puts the SDP part first in, under the body's own boundary
    ///   (build this one to give a part its own headers);
    /// - a ``multipart/*`` body with an ``application/sdp`` part, or an
    ///   ``application/sdp`` body: that SDP is the answer, as ``sdp`` is.
    ///
    /// A 200 that carries no SDP (an UPDATE without an offer) carries
    /// ``body`` as it was given.
    ///
    /// ``headers`` is a ``{name: value}`` mapping added to the 200, in its
    /// order. The headers siphon owns on a response it sends raise
    /// ``ValueError``, as on ``call.answer()``: ``Via``, ``From``, ``To``,
    /// ``Call-ID``, ``CSeq``, ``Max-Forwards``, ``Contact``, ``Record-Route``,
    /// ``Route``, ``Content-Length``, ``Content-Type``, ``RSeq``, ``RAck``,
    /// ``Require``, ``Supported``, ``Session-Expires`` and ``Min-SE``.
    ///
    /// Raises ``RuntimeError`` in ``@b2bua.on_reoffer_answered``;
    /// ``ValueError`` for an owned header, ``body`` without ``content_type``
    /// or the reverse, an empty ``body``, an answer given both in ``sdp`` and
    /// in the body, or a ``multipart/*`` body without a ``boundary`` or a part
    /// delimited by it; ``TypeError`` for a header name or value that is not
    /// a str. Nothing is decided when it raises.
    ///
    /// ```python
    /// @b2bua.on_reoffer
    /// def hold(call, offer):
    ///     if offer.kind == "hold":
    ///         offer.answer()
    ///
    /// @b2bua.on_reoffer
    /// def upgrade(call, offer):
    ///     if offer.request.get_header("Resource-Priority"):
    ///         offer.answer(body=service_info_xml,
    ///                      content_type="application/vnd.example.info+xml",
    ///                      headers={"Resource-Priority": "example.0"})
    /// ```
    #[pyo3(signature = (sdp=None, body=None, content_type=None, headers=None))]
    fn answer(
        &mut self,
        sdp: Option<String>,
        body: Option<&Bound<'_, PyAny>>,
        content_type: Option<&str>,
        headers: Option<&Bound<'_, pyo3::types::PyDict>>,
    ) -> PyResult<()> {
        self.still_open("answer")?;
        let headers = super::call::uas_response_headers("offer.answer", headers)?;
        let body = match (body, content_type) {
            (None, None) => None,
            (Some(body), Some(content_type)) => Some((
                content_type.to_string(),
                super::request::extract_body_bytes(body)?,
            )),
            _ => {
                return Err(PyValueError::new_err(
                    "offer.answer(body=…) and content_type=… go together",
                ))
            }
        };
        let (sdp, extras) = AnswerExtras::checked(sdp, body, headers)
            .map_err(|why| PyValueError::new_err(format!("offer.answer(): {why}")))?;
        self.decision = ReofferDecision::TakeOver { sdp, extras };
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "<Reoffer {} from {} kind={} direction={}>",
            self.facts.method,
            self.facts.side(),
            self.facts.kind.as_str(),
            self.facts.direction.unwrap_or("none"),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    const HELD: &[u8] = b"v=0\r\no=- 1 2 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=sendonly\r\n";
    const TALKING: &[u8] = b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";

    fn facts() -> Arc<ReofferFacts> {
        Arc::new(ReofferFacts::read(
            "INVITE",
            true,
            Some(HELD),
            Some(TALKING),
            false,
        ))
    }

    fn request(python: Python<'_>) -> Py<PyRequest> {
        let raw = concat!(
            "INVITE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-hold\r\n",
            "From: <sip:alice@example.com>;tag=a\r\n",
            "To: <sip:bob@example.com>;tag=b\r\n",
            "Call-ID: hold@192.0.2.10\r\n",
            "CSeq: 2 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let message = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("parses");
        Py::new(
            python,
            PyRequest::new(
                Arc::new(Mutex::new(message)),
                "udp".to_string(),
                "192.0.2.10".to_string(),
                5060,
            ),
        )
        .expect("a request")
    }

    #[test]
    fn the_offer_reads_as_a_hold_and_relays_by_default() {
        Python::initialize();
        Python::attach(|python| {
            let offer = PyReoffer::offered(facts(), request(python));
            assert_eq!(offer.method(), "INVITE");
            assert_eq!(offer.side(), "a");
            assert_eq!(offer.kind(), "hold");
            assert_eq!(offer.direction(), Some("sendonly"));
            assert_eq!(offer.previous_direction(), Some("sendrecv"));
            assert!(!offer.early());
            assert!(offer.request(python).is_some());
            assert_eq!(offer.status_code(), None);
            assert!(!offer.answered_locally());
            assert_eq!(offer.decision(), &ReofferDecision::Relay);
            assert!(offer.__repr__().contains("kind=hold"));
        });
    }

    #[test]
    fn reject_takes_a_final_non_2xx_status() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            assert!(offer.reject(200, "OK", None, None, None).is_err());
            assert!(offer
                .reject(183, "Session Progress", None, None, None)
                .is_err());
            assert!(offer.reject(700, "Beyond", None, None, None).is_err());
            assert_eq!(offer.decision(), &ReofferDecision::Relay);
            offer
                .reject(488, "Not Acceptable Here", None, None, None)
                .expect("488 is a refusal");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::Refuse {
                    code: 488,
                    reason: "Not Acceptable Here".to_string(),
                    extras: AnswerExtras::default(),
                }
            );
        });
    }

    #[test]
    fn reject_takes_a_body_and_headers_for_the_refusal() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            let headers = pyo3::types::PyDict::new(python);
            headers
                .set_item("Warning", "399 mcx.example.com \"not allowed\"")
                .expect("set");
            headers.set_item("Retry-After", "30").expect("set");
            let body = pyo3::types::PyString::new(python, "<mcpttinfo/>");
            offer
                .reject(
                    403,
                    "Forbidden",
                    Some(body.as_any()),
                    Some("application/vnd.3gpp.mcptt-info+xml"),
                    Some(&headers),
                )
                .expect("open");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::Refuse {
                    code: 403,
                    reason: "Forbidden".to_string(),
                    extras: AnswerExtras {
                        body: Some((
                            "application/vnd.3gpp.mcptt-info+xml".to_string(),
                            b"<mcpttinfo/>".to_vec()
                        )),
                        headers: vec![
                            (
                                "Warning".to_string(),
                                "399 mcx.example.com \"not allowed\"".to_string()
                            ),
                            ("Retry-After".to_string(), "30".to_string()),
                        ],
                    },
                }
            );
        });
    }

    #[test]
    fn reject_refuses_what_it_cannot_send_and_decides_nothing() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            for owned in [
                "Via",
                "From",
                "To",
                "Call-ID",
                "CSeq",
                "Contact",
                "Content-Length",
                "Content-Type",
                "Require",
                "Supported",
            ] {
                let headers = pyo3::types::PyDict::new(python);
                headers.set_item(owned, "x").expect("set");
                let error = offer
                    .reject(403, "Forbidden", None, None, Some(&headers))
                    .expect_err(owned);
                assert!(
                    error.is_instance_of::<PyValueError>(python),
                    "{owned}: {error}"
                );
                assert!(error.to_string().contains(owned), "{owned}: {error}");
                assert!(
                    error.to_string().contains("offer.reject"),
                    "{owned}: {error}"
                );
            }
            let headers = pyo3::types::PyDict::new(python);
            headers.set_item("Warning", 399).expect("set");
            let error = offer
                .reject(403, "Forbidden", None, None, Some(&headers))
                .expect_err("not a str");
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(python));
            let body = pyo3::types::PyString::new(python, "<info/>");
            let empty = pyo3::types::PyString::new(python, "");
            assert!(offer
                .reject(403, "Forbidden", Some(body.as_any()), None, None)
                .is_err());
            assert!(offer
                .reject(403, "Forbidden", None, Some("text/plain"), None)
                .is_err());
            let error = offer
                .reject(
                    403,
                    "Forbidden",
                    Some(empty.as_any()),
                    Some("text/plain"),
                    None,
                )
                .expect_err("empty");
            assert!(error.to_string().contains("empty"), "{error}");
            assert_eq!(offer.decision(), &ReofferDecision::Relay);
        });
    }

    #[test]
    fn answer_takes_the_offer_over_with_or_without_an_sdp() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            offer.answer(None, None, None, None).expect("open");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::TakeOver {
                    sdp: None,
                    extras: AnswerExtras::default()
                }
            );
            offer
                .answer(Some("v=0\r\n".to_string()), None, None, None)
                .expect("open");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::TakeOver {
                    sdp: Some("v=0\r\n".to_string()),
                    extras: AnswerExtras::default()
                }
            );
        });
    }

    #[test]
    fn answer_takes_a_body_and_headers_for_the_200() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            let headers = pyo3::types::PyDict::new(python);
            headers
                .set_item("Resource-Priority", "example.0")
                .expect("set");
            headers.set_item("X-Second", "2").expect("set");
            let body = pyo3::types::PyBytes::new(python, b"<info/>");
            offer
                .answer(
                    None,
                    Some(body.as_any()),
                    Some("application/vnd.example.info+xml"),
                    Some(&headers),
                )
                .expect("open");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::TakeOver {
                    sdp: None,
                    extras: AnswerExtras {
                        body: Some((
                            "application/vnd.example.info+xml".to_string(),
                            b"<info/>".to_vec()
                        )),
                        headers: vec![
                            ("Resource-Priority".to_string(), "example.0".to_string()),
                            ("X-Second".to_string(), "2".to_string()),
                        ],
                    }
                }
            );
        });
    }

    #[test]
    fn answer_refuses_what_it_cannot_send_and_decides_nothing() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            let body = pyo3::types::PyString::new(python, "<info/>");
            // Every header siphon owns on a response it sends.
            for owned in [
                "Via",
                "From",
                "To",
                "Call-ID",
                "CSeq",
                "Max-Forwards",
                "Contact",
                "Record-Route",
                "Route",
                "Content-Length",
                "Content-Type",
                "RSeq",
                "RAck",
                "Require",
                "Supported",
                "Session-Expires",
                "Min-SE",
            ] {
                let headers = pyo3::types::PyDict::new(python);
                headers.set_item(owned, "x").expect("set");
                let error = offer
                    .answer(None, None, None, Some(&headers))
                    .expect_err(owned);
                assert!(
                    error.is_instance_of::<PyValueError>(python),
                    "{owned}: {error}"
                );
                assert!(error.to_string().contains(owned), "{owned}: {error}");
                assert!(
                    error.to_string().contains("offer.answer"),
                    "{owned}: {error}"
                );
            }
            // A header name or value that is not a str.
            let headers = pyo3::types::PyDict::new(python);
            headers.set_item("X-Number", 5).expect("set");
            let error = offer
                .answer(None, None, None, Some(&headers))
                .expect_err("not a str");
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(python));
            // A body and its type go together.
            assert!(offer.answer(None, Some(body.as_any()), None, None).is_err());
            assert!(offer.answer(None, None, Some("text/plain"), None).is_err());
            // An answer given twice.
            let sdp = pyo3::types::PyString::new(python, "v=0\r\n");
            let error = offer
                .answer(
                    Some("v=0\r\n".to_string()),
                    Some(sdp.as_any()),
                    Some("application/sdp"),
                    None,
                )
                .expect_err("twice");
            assert!(error.to_string().contains("pass one"), "{error}");
            // A multipart body with no boundary to put the SDP part under.
            let error = offer
                .answer(None, Some(body.as_any()), Some("multipart/mixed"), None)
                .expect_err("no boundary");
            assert!(error.to_string().contains("boundary"), "{error}");
            assert_eq!(offer.decision(), &ReofferDecision::Relay);
        });
    }

    #[test]
    fn an_answered_offer_reports_the_answer_and_cannot_be_decided_again() {
        let mut offer = PyReoffer::answered(
            facts(),
            ReofferAnswer {
                status_code: 200,
                sdp: Some(String::from_utf8_lossy(TALKING).replace(
                    "m=audio 40000 RTP/AVP 0\r\n",
                    "m=audio 40000 RTP/AVP 0\r\na=recvonly\r\n",
                )),
                local: true,
            },
        );
        assert_eq!(offer.status_code(), Some(200));
        assert_eq!(offer.answer_direction(), Some("recvonly"));
        assert!(offer.answered_locally());
        assert!(offer.answer_sdp().is_some());
        Python::initialize();
        Python::attach(|python| {
            assert!(offer.request(python).is_none());
            assert!(offer
                .reject(488, "Not Acceptable Here", None, None, None)
                .is_err());
            assert!(offer.answer(None, None, None, None).is_err());
        });
        assert_eq!(offer.decision(), &ReofferDecision::Relay);
    }
}
