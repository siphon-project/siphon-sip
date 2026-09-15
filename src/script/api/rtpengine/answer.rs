//! What `rtpengine.answer()` sends to the media engine.
//!
//! A script hands over the SDP one of two ways. The reply mode reads the SDP and
//! To-tag off a SIP reply, and the rewritten SDP goes back into its body. The raw
//! mode (`sdp=`) is for a far side that is not a SIP agent and hands over its
//! answer some other way: the script passes that SDP and gets the rewritten one
//! back.
//!
//! Usually the SDP answers the INVITE's offer, and the engine is sent an `answer`.
//! On a delayed offer (RFC 3264 §4) the INVITE carried no SDP, so the reply's SDP
//! is the offer itself, and the caller answers it in its ACK: the engine is sent
//! an `offer` from the replying party's side, and siphon sends the matching
//! `answer` when the ACK arrives (`send_delayed_offer_ack`).
//!
//! Either command is addressed by the call-id the engine knows the call by, which
//! is not the SIP Call-ID once a transfer has re-anchored the call.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;
use tracing::debug;

use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::session::{MediaSession, MediaSessionStore};
use crate::rtpengine::{MediaBackend, RtpEngineError};
use crate::sip::message::SipMessage;

use super::{
    dialog_ids, extract_answer_params, extract_delete_params, extract_message, extract_source_ip,
    extract_tag, lock_message, PyCall, PyReply, PyRequest,
};

/// What `answer` sends to the engine, resolved from either mode.
pub(super) struct AnswerExchange {
    /// SIP Call-ID of the offer being answered: the media session's store key.
    pub(super) call_id: String,
    /// The tag of the party that sent the INVITE.
    pub(super) from_tag: String,
    /// The message the offer identifiers came from, for `{from_user}` /
    /// `{to_user}` in a `ws_uri`.
    pub(super) identity: Option<Arc<Mutex<SipMessage>>>,
    /// The reply whose body takes the rewritten SDP. `None` in raw mode.
    pub(super) body: Option<Arc<Mutex<SipMessage>>>,
    pub(super) source_ip: Option<String>,
    /// The INVITE carried no offer, so the reply's SDP is the offer and goes to
    /// the engine as one. Reply mode only: a raw SDP answers an offer the engine
    /// already has.
    pub(super) delayed_offer: bool,
    /// The tag of the party whose SDP this is.
    to_tag: String,
    sdp: Vec<u8>,
    /// The call-id the engine knows the call by: see [`engine_call_id`].
    engine_call_id: String,
}

impl AnswerExchange {
    /// Resolve the exchange from `rtpengine.answer()`'s arguments: raw mode when
    /// `sdp` is given, reply mode otherwise. Every refusal happens here, before
    /// anything reaches the engine.
    pub(super) fn resolve(
        reply: &Bound<'_, PyAny>,
        call: Option<&Bound<'_, PyAny>>,
        sdp: Option<&Bound<'_, PyAny>>,
        to_tag: Option<&str>,
        sessions: &MediaSessionStore,
    ) -> PyResult<Self> {
        match sdp.map(extract_answer_sdp).transpose()? {
            Some(sdp) => {
                if to_tag == Some("") {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "rtpengine.answer(to_tag=...) is empty",
                    ));
                }
                let target = resolve_raw_answer_target(reply, call)?;
                let stored_to_tag = sessions
                    .get(&target.call_id)
                    .and_then(|session| session.to_tag);
                Ok(Self {
                    to_tag: resolve_raw_answer_to_tag(to_tag, target.to_tag, stored_to_tag),
                    engine_call_id: engine_call_id(sessions, &target.call_id),
                    call_id: target.call_id,
                    from_tag: target.from_tag,
                    sdp,
                    identity: target.message,
                    body: None,
                    // The far side is not a SIP peer siphon heard from. Carrying the
                    // caller's address would gate the far side's media to it.
                    source_ip: None,
                    delayed_offer: false,
                })
            }
            None => {
                if to_tag.is_some() {
                    return Err(pyo3::exceptions::PyValueError::new_err(
                        "rtpengine.answer(to_tag=...) needs sdp=: a reply's own To-tag names its answerer",
                    ));
                }
                let message = extract_message(reply)?;

                // Resolve A-leg identifiers for RTPEngine correlation:
                // 1. Explicit `call` parameter (backward compat / proxy-with-call)
                // 2. Automatic: PyReply carries A-leg INVITE ref set by B2BUA dispatcher
                // 3. Fallback: extract from the reply itself (proxy mode, same Call-ID)
                let a_leg_message = match call {
                    Some(call_object) => Some(extract_message(call_object)?),
                    None => reply
                        .cast::<PyReply>()
                        .ok()
                        .and_then(|py_reply| py_reply.borrow().a_leg_message()),
                };
                let (call_id, from_tag, to_tag, sdp, delayed_offer) = match &a_leg_message {
                    Some(a_leg) => {
                        // Only the INVITE's identifiers: on a delayed offer it has no
                        // SDP, and that is what makes the reply's SDP the offer.
                        let (call_id, from_tag, delayed_offer) = {
                            let invite = lock_message(a_leg)?;
                            let (call_id, from_tag) = dialog_ids(&invite)?;
                            (call_id, from_tag, invite.body.is_empty())
                        };
                        let (_reply_call_id, _reply_from_tag, to_tag, sdp) =
                            extract_answer_params(&message)?;
                        (call_id, from_tag, to_tag, sdp, delayed_offer)
                    }
                    None => {
                        let (call_id, from_tag, to_tag, sdp) = extract_answer_params(&message)?;
                        (call_id, from_tag, to_tag, sdp, false)
                    }
                };
                Ok(Self {
                    engine_call_id: engine_call_id(sessions, &call_id),
                    call_id,
                    from_tag,
                    to_tag,
                    sdp,
                    identity: Some(a_leg_message.unwrap_or_else(|| Arc::clone(&message))),
                    body: Some(message),
                    // A reply carries no source address of its own; when the script
                    // passed `call=`, that object does.
                    source_ip: call.and_then(|object| extract_source_ip(object)),
                    delayed_offer,
                })
            }
        }
    }

    /// Send the SDP to the engine and return the SDP it rewrote.
    ///
    /// An answer records the answering party's tag on the media session, which is
    /// what a later re-offer or re-answer names it by. A delayed offer records the
    /// session with the replying party as offerer and no answerer yet, under
    /// `profile` and `ws_uri`: `send_delayed_offer_ack` completes it with the
    /// caller's answer.
    pub(super) async fn send(
        &self,
        client: &MediaBackend,
        sessions: &MediaSessionStore,
        flags: &NgFlags,
        profile: &str,
        ws_uri: Option<String>,
    ) -> PyResult<Vec<u8>> {
        if self.delayed_offer {
            let rewritten_sdp = client
                .offer(&self.engine_call_id, &self.to_tag, &self.sdp, flags)
                .await
                .map_err(engine_failure)?;
            debug!(
                call_id = %self.call_id,
                sdp_len = rewritten_sdp.len(),
                "RTPEngine: the reply carries a delayed offer, SDP rewritten as the offer"
            );
            // Keyed by the SIP Call-ID, but kept on the engine call-id the offer
            // went to: `send_delayed_offer_ack` sends the caller's answer there,
            // and the teardown deletes that engine call.
            sessions.insert(MediaSession {
                call_id: self.call_id.clone(),
                rtpengine_call_id: self.engine_call_id.clone(),
                from_tag: self.to_tag.clone(),
                to_tag: None,
                profile: profile.to_string(),
                ws_uri,
                ws_tee: flags.ws_tee.clone(),
                ws_bridge_attached: false,
                created_at: std::time::Instant::now(),
            });
            return Ok(rewritten_sdp);
        }
        let rewritten_sdp = client
            .answer(
                &self.engine_call_id,
                &self.from_tag,
                &self.to_tag,
                &self.sdp,
                flags,
            )
            .await
            .map_err(engine_failure)?;
        debug!(
            call_id = %self.call_id,
            sdp_len = rewritten_sdp.len(),
            "RTPEngine answer: SDP rewritten"
        );
        sessions.set_to_tag(&self.call_id, self.to_tag.clone());
        Ok(rewritten_sdp)
    }
}

/// An engine that refused the command, as the script sees it.
fn engine_failure(error: RtpEngineError) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(format!("rtpengine.answer failed: {error}"))
}

/// The call-id to address the engine with for the call stored under `call_id`.
///
/// The SIP Call-ID, unless a siphon-terminated transfer re-anchored the pair on a
/// fresh engine call-id while the store key stayed the SIP one. `offer` and the
/// dispatcher's re-INVITE answer address the session's own id the same way.
fn engine_call_id(sessions: &MediaSessionStore, call_id: &str) -> String {
    sessions
        .get(call_id)
        .map(|session| session.rtpengine_id().to_string())
        .unwrap_or_else(|| call_id.to_string())
}

/// The offer a raw-SDP `answer` belongs to, plus a To-tag the target carries.
struct RawAnswerTarget {
    call_id: String,
    from_tag: String,
    /// Where `call_id` / `from_tag` came from. `None` for a tuple target.
    message: Option<Arc<Mutex<SipMessage>>>,
    to_tag: Option<String>,
}

/// The SDP a script passed to `answer(sdp=...)`: `str` or `bytes`, not blank.
fn extract_answer_sdp(sdp: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    let bytes = crate::script::api::request::extract_body_bytes(sdp).map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("rtpengine.answer(sdp=...) must be str or bytes")
    })?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "rtpengine.answer(sdp=...) is empty",
        ));
    }
    Ok(bytes)
}

/// The tag on a message's To header, if it has one.
fn message_to_tag(message: &Arc<Mutex<SipMessage>>) -> PyResult<Option<String>> {
    let message = lock_message(message)?;
    Ok(message
        .headers
        .get("To")
        .or_else(|| message.headers.get("t"))
        .and_then(|value| extract_tag(value)))
}

/// Resolve the offer a raw-SDP `answer` belongs to.
///
/// Same precedence as the reply mode: `call=` names the offer, then a Reply's
/// A-leg reference, then the target itself. A `(call_id, from_tag)` tuple works
/// as it does for the media verbs. A bare `call_id` does not: the engine matches
/// an answer to its offer by from-tag, and an empty one matches nothing.
fn resolve_raw_answer_target(
    target: &Bound<'_, PyAny>,
    call: Option<&Bound<'_, PyAny>>,
) -> PyResult<RawAnswerTarget> {
    let is_sip_object = target.cast::<PyRequest>().is_ok()
        || target.cast::<PyReply>().is_ok()
        || target.cast::<PyCall>().is_ok();
    // A To-tag the target already carries: a reply's, or an in-dialog request's.
    let target_to_tag = if is_sip_object {
        message_to_tag(&extract_message(target)?)?
    } else {
        None
    };

    let identity = if let Some(call_object) = call {
        Some(extract_message(call_object)?)
    } else if let Ok(reply) = target.cast::<PyReply>() {
        let reply = reply.borrow();
        Some(reply.a_leg_message().unwrap_or_else(|| reply.message()))
    } else if is_sip_object {
        Some(extract_message(target)?)
    } else {
        None
    };
    if let Some(message) = identity {
        let (call_id, from_tag) = extract_delete_params(&message)?;
        return Ok(RawAnswerTarget {
            call_id,
            from_tag,
            message: Some(message),
            to_tag: target_to_tag,
        });
    }

    // Checked before the pair form: a `str` is itself a sequence of 1-char strings.
    if target.extract::<String>().is_ok() {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "rtpengine.answer(sdp=...) needs the offer's from-tag: pass the Call, \
             Request or Reply, or a (call_id, from_tag) tuple, not a bare call_id",
        ));
    }
    if let Ok((call_id, from_tag)) = target.extract::<(String, String)>() {
        return Ok(RawAnswerTarget {
            call_id,
            from_tag,
            message: None,
            to_tag: None,
        });
    }
    Err(pyo3::exceptions::PyTypeError::new_err(
        "rtpengine.answer(sdp=...) target must be a Call, Request or Reply, or a \
         (call_id, from_tag) tuple",
    ))
}

/// The tag naming the answering party to the engine for a raw-SDP `answer`.
///
/// The script's own tag wins, then one the target carries. Past those, the tag an
/// earlier answer on this call recorded: the engine names each party by its tag,
/// so a re-answer under a new one would describe a different party, and the
/// re-INVITE / UPDATE handling reads that stored tag back. Only a first answer
/// with nothing to go on gets a new tag.
fn resolve_raw_answer_to_tag(
    explicit: Option<&str>,
    target_to_tag: Option<String>,
    stored_to_tag: Option<String>,
) -> String {
    explicit
        .map(str::to_string)
        .or(target_to_tag)
        .or(stored_to_tag)
        .unwrap_or_else(crate::transaction::state::generate_uas_to_tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    use pyo3::types::{PyBytes, PyString, PyTuple};

    use crate::rtpengine::test_engine::{TestEngine, ENGINE_SDP};
    use crate::sip::headers::SipHeaders;
    use crate::sip::message::{Method, RequestLine, StartLine, StatusLine, Version};
    use crate::sip::uri::SipUri;

    const ANCHORED_CALL_ID: &str = "anchored-call@192.0.2.20";

    /// The callee's SDP in its 2xx.
    const CALLEE_SDP: &str = concat!(
        "v=0\r\n",
        "o=- 7 7 IN IP4 198.51.100.91\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.91\r\n",
        "t=0 0\r\n",
        "m=audio 30000 RTP/AVP 0\r\n",
    );

    /// An INVITE, or with `to_tag` the 200 OK answering it.
    fn dialog_message(call_id: &str, to_tag: Option<&str>) -> Arc<Mutex<SipMessage>> {
        let mut headers = SipHeaders::new();
        headers.set("Call-ID", call_id.to_string());
        headers.set("From", "<sip:alice@example.com>;tag=tag-a".to_string());
        headers.set("Content-Type", "application/sdp".to_string());
        let start_line = match to_tag {
            Some(tag) => {
                headers.set("To", format!("<sip:bob@example.com>;tag={tag}"));
                StartLine::Response(StatusLine {
                    version: Version::sip_2_0(),
                    status_code: 200,
                    reason_phrase: "OK".to_string(),
                })
            }
            None => {
                headers.set("To", "<sip:bob@example.com>".to_string());
                StartLine::Request(RequestLine {
                    method: Method::Invite,
                    request_uri: SipUri::new("192.0.2.1".to_string()),
                    version: Version::sip_2_0(),
                })
            }
        };
        Arc::new(Mutex::new(SipMessage {
            start_line,
            headers,
            body: b"v=0\r\nc=IN IP4 192.0.2.10\r\n".to_vec(),
        }))
    }

    /// An INVITE that carried no offer, so its 2xx carries one (RFC 3264 §4).
    fn offerless_invite(call_id: &str) -> Arc<Mutex<SipMessage>> {
        let invite = dialog_message(call_id, None);
        invite.lock().unwrap().body.clear();
        invite
    }

    fn session(call_id: &str, engine_call_id: &str, to_tag: Option<&str>) -> MediaSession {
        MediaSession {
            call_id: call_id.to_string(),
            rtpengine_call_id: engine_call_id.to_string(),
            from_tag: "tag-a".to_string(),
            to_tag: to_tag.map(str::to_string),
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        }
    }

    fn call_on(python: Python<'_>, message: Arc<Mutex<SipMessage>>) -> Bound<'_, PyCall> {
        let call = PyCall::new(
            "id-1".to_string(),
            message,
            "192.0.2.10".to_string(),
            "udp".to_string(),
        );
        Bound::new(python, call).unwrap()
    }

    /// The exchange for the callee's 2xx on an anchored call that was never
    /// re-anchored.
    fn callee_exchange(delayed_offer: bool) -> AnswerExchange {
        AnswerExchange {
            call_id: ANCHORED_CALL_ID.to_string(),
            from_tag: "caller-tag".to_string(),
            identity: None,
            body: None,
            source_ip: None,
            delayed_offer,
            to_tag: "callee-tag".to_string(),
            sdp: CALLEE_SDP.as_bytes().to_vec(),
            engine_call_id: ANCHORED_CALL_ID.to_string(),
        }
    }

    #[test]
    fn to_tag_precedence_is_explicit_then_target_then_stored_then_new() {
        let tag = |explicit: Option<&str>, target: Option<&str>, stored: Option<&str>| {
            resolve_raw_answer_to_tag(
                explicit,
                target.map(str::to_string),
                stored.map(str::to_string),
            )
        };
        assert_eq!(
            tag(Some("explicit"), Some("target"), Some("stored")),
            "explicit"
        );
        assert_eq!(tag(None, Some("target"), Some("stored")), "target");
        assert_eq!(tag(None, None, Some("stored")), "stored");
        let fresh = tag(None, None, None);
        assert!(fresh.starts_with("siphon-"), "new tag, got {fresh:?}");
        assert_ne!(
            fresh,
            tag(None, None, None),
            "each first answer gets its own tag"
        );
    }

    #[test]
    fn engine_call_id_follows_a_re_anchored_session() {
        let sessions = MediaSessionStore::new();
        assert_eq!(engine_call_id(&sessions, "call-1"), "call-1");
        sessions.insert(session("call-1", "engine-1", None));
        assert_eq!(engine_call_id(&sessions, "call-1"), "engine-1");
    }

    #[test]
    fn message_to_tag_reads_the_to_header() {
        assert_eq!(
            message_to_tag(&dialog_message("call-1", Some("tag-b"))).unwrap(),
            Some("tag-b".to_string())
        );
        assert_eq!(
            message_to_tag(&dialog_message("call-1", None)).unwrap(),
            None
        );
    }

    #[test]
    fn answer_sdp_is_str_or_bytes_and_not_blank() {
        Python::initialize();
        Python::attach(|python| {
            let text = PyString::new(python, "v=0\r\n");
            assert_eq!(extract_answer_sdp(text.as_any()).unwrap(), b"v=0\r\n");
            let bytes = PyBytes::new(python, b"v=0\r\n");
            assert_eq!(extract_answer_sdp(bytes.as_any()).unwrap(), b"v=0\r\n");

            let blank = PyString::new(python, " \r\n");
            let error = extract_answer_sdp(blank.as_any()).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            let number = 42i64.into_pyobject(python).unwrap();
            let error = extract_answer_sdp(number.as_any()).unwrap_err();
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(python));
        });
    }

    #[test]
    fn a_reply_target_answers_the_a_leg_offer_under_its_own_to_tag() {
        Python::initialize();
        Python::attach(|python| {
            let invite = dialog_message("a-leg-call", None);
            let reply = dialog_message("b-leg-call", Some("tag-b"));
            let reply = Bound::new(python, PyReply::new(reply).with_a_leg(invite)).unwrap();

            let target = resolve_raw_answer_target(reply.as_any(), None).unwrap();

            assert_eq!(target.call_id, "a-leg-call");
            assert_eq!(target.from_tag, "tag-a");
            assert_eq!(target.to_tag.as_deref(), Some("tag-b"));
            assert!(target.message.is_some());
        });
    }

    #[test]
    fn call_names_the_offer_over_the_target() {
        Python::initialize();
        Python::attach(|python| {
            let call = call_on(python, dialog_message("call-8", None));
            let tuple = PyTuple::new(python, ["other-call", "other-tag"]).unwrap();

            let target = resolve_raw_answer_target(tuple.as_any(), Some(call.as_any())).unwrap();

            assert_eq!(target.call_id, "call-8");
            assert_eq!(target.from_tag, "tag-a");
            assert_eq!(target.to_tag, None);
        });
    }

    #[test]
    fn a_tuple_names_the_offer_and_a_bare_call_id_is_refused() {
        Python::initialize();
        Python::attach(|python| {
            let tuple = PyTuple::new(python, ["call-9", "tag-9"]).unwrap();
            let target = resolve_raw_answer_target(tuple.as_any(), None).unwrap();
            assert_eq!(
                (target.call_id.as_str(), target.from_tag.as_str()),
                ("call-9", "tag-9")
            );
            assert!(target.message.is_none());

            let bare = PyString::new(python, "call-9");
            let error = resolve_raw_answer_target(bare.as_any(), None)
                .err()
                .unwrap();
            assert!(error.is_instance_of::<pyo3::exceptions::PyTypeError>(python));
        });
    }

    #[test]
    fn resolve_uses_the_stored_to_tag_and_the_engine_call_id() {
        Python::initialize();
        Python::attach(|python| {
            let sessions = MediaSessionStore::new();
            sessions.insert(session("call-3", "engine-3", Some("tag-stored")));
            let call = call_on(python, dialog_message("call-3", None));
            let sdp = PyString::new(python, "v=0\r\n");

            let exchange =
                AnswerExchange::resolve(call.as_any(), None, Some(sdp.as_any()), None, &sessions)
                    .unwrap();

            assert_eq!(exchange.call_id, "call-3");
            assert_eq!(exchange.engine_call_id, "engine-3");
            assert_eq!(exchange.to_tag, "tag-stored");
            assert!(exchange.body.is_none());
            assert!(exchange.source_ip.is_none());
            assert!(!exchange.delayed_offer, "a raw SDP answers an offer");
        });
    }

    #[test]
    fn resolve_refuses_a_to_tag_without_sdp() {
        Python::initialize();
        Python::attach(|python| {
            let reply = Bound::new(
                python,
                PyReply::new(dialog_message("call-4", Some("tag-b"))),
            )
            .unwrap();
            let sessions = MediaSessionStore::new();

            let error =
                AnswerExchange::resolve(reply.as_any(), None, None, Some("tag-x"), &sessions)
                    .err()
                    .unwrap();

            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }

    #[test]
    fn a_reply_to_an_invite_that_carried_the_offer_is_the_answer() {
        Python::initialize();
        Python::attach(|python| {
            let reply = dialog_message("b-leg-call", Some("tag-b"));
            let reply = Bound::new(
                python,
                PyReply::new(reply).with_a_leg(dialog_message("a-leg-call", None)),
            )
            .unwrap();

            let exchange = AnswerExchange::resolve(
                reply.as_any(),
                None,
                None,
                None,
                &MediaSessionStore::new(),
            )
            .unwrap();

            assert!(!exchange.delayed_offer);
            assert_eq!(exchange.call_id, "a-leg-call");
            assert_eq!(exchange.to_tag, "tag-b");
        });
    }

    /// A delayed offer (RFC 3264 §4): the 2xx to an INVITE that carried no SDP
    /// carries the offer. The engine is sent an `offer` from the callee's side,
    /// and the session is recorded with the callee as offerer and no answerer
    /// yet: `send_delayed_offer_ack` completes it with the caller's answer.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_carrying_the_offer_goes_to_the_engine_as_an_offer() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();

        let rewritten = callee_exchange(true)
            .send(
                &backend,
                &sessions,
                &NgFlags::default(),
                "rtp_passthrough",
                None,
            )
            .await
            .expect("the engine takes the offer");

        assert_eq!(rewritten, ENGINE_SDP.as_bytes());
        assert!(
            engine.commands("answer").is_empty(),
            "nothing has answered the offer yet"
        );
        let offers = engine.commands("offer");
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].call_id.as_deref(), Some(ANCHORED_CALL_ID));
        assert_eq!(
            offers[0].from_tag.as_deref(),
            Some("callee-tag"),
            "the callee is the offerer"
        );
        assert_eq!(offers[0].sdp.as_deref(), Some(CALLEE_SDP));
        let session = sessions
            .get(ANCHORED_CALL_ID)
            .expect("the session is recorded");
        assert_eq!(session.from_tag, "callee-tag");
        assert_eq!(session.to_tag, None, "the caller's answer is still to come");
        assert_eq!(session.profile, "rtp_passthrough");
    }

    /// A 2xx to an INVITE that carried the offer is the answer, as it always was.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reply_to_an_offer_goes_to_the_engine_as_an_answer() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        let mut offered = session(ANCHORED_CALL_ID, ANCHORED_CALL_ID, None);
        offered.from_tag = "caller-tag".to_string();
        sessions.insert(offered);

        callee_exchange(false)
            .send(
                &backend,
                &sessions,
                &NgFlags::default(),
                "rtp_passthrough",
                None,
            )
            .await
            .expect("the engine takes the answer");

        assert!(engine.commands("offer").is_empty());
        let answers = engine.commands("answer");
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].from_tag.as_deref(), Some("caller-tag"));
        assert_eq!(answers[0].to_tag.as_deref(), Some("callee-tag"));
        assert_eq!(
            sessions
                .get(ANCHORED_CALL_ID)
                .and_then(|session| session.to_tag),
            Some("callee-tag".to_string())
        );
    }

    /// A delayed offer on a call a siphon-terminated transfer re-anchored: the
    /// store key is still the SIP Call-ID, while the engine knows the call by the
    /// fresh engine call-id. The offer goes to that call-id, and the session it
    /// records keeps it, so the caller's answer that `send_delayed_offer_ack`
    /// sends to `rtpengine_id()` reaches the same engine call.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_delayed_offer_on_a_re_anchored_call_goes_to_the_engine_call_id() {
        let engine = TestEngine::start(false).await;
        let backend = engine.backend().await;
        let sessions = MediaSessionStore::new();
        sessions.insert(session("a-leg-call", "engine-fresh", Some("tag-old")));
        Python::initialize();
        let exchange = Python::attach(|python| {
            let reply = dialog_message("b-leg-call", Some("tag-b"));
            let reply = Bound::new(
                python,
                PyReply::new(reply).with_a_leg(offerless_invite("a-leg-call")),
            )
            .unwrap();
            AnswerExchange::resolve(reply.as_any(), None, None, None, &sessions).unwrap()
        });
        assert!(
            exchange.delayed_offer,
            "a reply to an offerless INVITE carries the offer"
        );

        exchange
            .send(
                &backend,
                &sessions,
                &NgFlags::default(),
                "rtp_passthrough",
                None,
            )
            .await
            .expect("the engine takes the offer");

        assert!(engine.commands("answer").is_empty());
        let offers = engine.commands("offer");
        assert_eq!(offers.len(), 1);
        assert_eq!(
            offers[0].call_id.as_deref(),
            Some("engine-fresh"),
            "the offer goes to the call-id the engine knows the call by"
        );
        assert_eq!(offers[0].from_tag.as_deref(), Some("tag-b"));
        let session = sessions.get("a-leg-call").expect("the session is recorded");
        assert_eq!(
            session.rtpengine_id(),
            "engine-fresh",
            "the recorded session keeps the engine call-id"
        );
        assert_eq!(session.from_tag, "tag-b", "the callee is the offerer");
        assert_eq!(session.to_tag, None, "the caller's answer is still to come");
    }
}
