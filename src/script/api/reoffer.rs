//! The `Reoffer` object `@b2bua.on_reoffer` and `@b2bua.on_reoffer_answered`
//! are handed: an in-dialog offer on a bridged call (a re-INVITE or an UPDATE)
//! and, in the second, the final response the offerer got.

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use super::request::PyRequest;
use crate::b2bua::reoffer::{ReofferAnswer, ReofferDecision, ReofferFacts};

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
    ///   addresses and directions (a session refresh, RFC 4028 §10, which on
    ///   a held call repeats ``sendonly`` and is not a second hold),
    /// - ``"change"``: anything else (a codec, an address, a stream).
    #[getter]
    fn kind(&self) -> &str {
        self.facts.kind.as_str()
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
    /// relayed and the session in force stays as it was (RFC 3261 §14.1).
    /// ``488`` refuses the media, ``403`` the request.
    ///
    /// Raises ``ValueError`` for a code outside 300-699, and ``RuntimeError``
    /// in ``@b2bua.on_reoffer_answered``.
    ///
    /// Example::
    ///
    ///     @b2bua.on_reoffer
    ///     def no_video(call, offer):
    ///         if offer.sdp and "m=video" in offer.sdp:
    ///             offer.reject(488, "Not Acceptable Here")
    fn reject(&mut self, code: u16, reason: &str) -> PyResult<()> {
        self.still_open("reject")?;
        if !(300..=699).contains(&code) {
            return Err(PyValueError::new_err(format!(
                "offer.reject() takes a final non-2xx status, 300-699, not {code}"
            )));
        }
        self.decision = ReofferDecision::Refuse {
            code,
            reason: reason.to_string(),
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
    /// session as siphon's offer (RFC 3261 §14.1). Streams that are keyed,
    /// use ICE or are grouped cannot be answered this way, and the offer is
    /// then refused ``488``.
    ///
    /// ``sdp`` (a str) is sent as the answer instead. Either way siphon owns
    /// its ``o=`` line (RFC 3264 §8).
    ///
    /// Raises ``RuntimeError`` in ``@b2bua.on_reoffer_answered``.
    ///
    /// Example::
    ///
    ///     @b2bua.on_reoffer
    ///     def hold(call, offer):
    ///         if offer.kind == "hold":
    ///             offer.answer()
    #[pyo3(signature = (sdp=None))]
    fn answer(&mut self, sdp: Option<String>) -> PyResult<()> {
        self.still_open("answer")?;
        self.decision = ReofferDecision::TakeOver { sdp };
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
            assert!(offer.reject(200, "OK").is_err());
            assert!(offer.reject(183, "Session Progress").is_err());
            assert!(offer.reject(700, "Beyond").is_err());
            assert_eq!(offer.decision(), &ReofferDecision::Relay);
            offer
                .reject(488, "Not Acceptable Here")
                .expect("488 is a refusal");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::Refuse {
                    code: 488,
                    reason: "Not Acceptable Here".to_string()
                }
            );
        });
    }

    #[test]
    fn answer_takes_the_offer_over_with_or_without_an_sdp() {
        Python::initialize();
        Python::attach(|python| {
            let mut offer = PyReoffer::offered(facts(), request(python));
            offer.answer(None).expect("open");
            assert_eq!(offer.decision(), &ReofferDecision::TakeOver { sdp: None });
            offer.answer(Some("v=0\r\n".to_string())).expect("open");
            assert_eq!(
                offer.decision(),
                &ReofferDecision::TakeOver {
                    sdp: Some("v=0\r\n".to_string())
                }
            );
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
            assert!(offer.reject(488, "Not Acceptable Here").is_err());
            assert!(offer.answer(None).is_err());
        });
        assert_eq!(offer.decision(), &ReofferDecision::Relay);
    }
}
