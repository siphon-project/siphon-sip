//! An inbound in-dialog INFO on a B2BUA call (RFC 6086).
//!
//! INFO was not one of the methods the B2BUA intercepted, so it took the proxy
//! path: a B2BUA script with no `@proxy.on_request` covering INFO got `405
//! Method Not Allowed`, and one with such a handler sent it to proxy routing
//! instead. Either way it was not relayed across a two-leg call and never
//! reached the control plane, so a peer that signals DTMF only as SIP INFO
//! (RFC 2976 / RFC 6086 `application/dtmf-relay`, which some handsets and
//! trunks still do) had its digits dropped.

use crate::dispatcher::*;

/// Handle an in-dialog INFO on a tracked B2BUA call.
///
/// On a two-leg call it is relayed to the other leg, like any other in-dialog
/// request. On a one-legged call siphon is the far party, so it is answered
/// here — and a DTMF payload is surfaced through the same path an RFC 4733
/// digit takes, so a script's `@rtpengine.on_dtmf` and a controller's
/// `ChannelDtmfReceived` see INFO digits without knowing where they came from.
pub fn handle_b2bua_info(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let Some(call_id) = state.call_actors.find_by_message(&message) else {
        // Raced a teardown after the dispatch gate matched.
        warn!(sip_call_id = %sip_call_id, "B2BUA INFO: no matching call — 481");
        respond(
            &inbound,
            &message,
            481,
            "Call/Transaction Does Not Exist",
            state,
        );
        return;
    };

    // Direction by dialog identity (RFC 3261 §12), never by source socket — a
    // peer may send this on a new connection.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA INFO: Call-ID matches no dialog leg — 481");
            respond(
                &inbound,
                &message,
                481,
                "Call/Transaction Does Not Exist",
                state,
            );
            return;
        }
    };

    let has_far_leg = state
        .call_actors
        .get_call(&call_id)
        .map(|call| call.winner.is_some())
        .unwrap_or(false);

    // A digit is surfaced whichever way the INFO goes: on a two-leg call the
    // far end still gets the INFO itself, and siphon reporting the digit as
    // well is what makes a controller's view the same on both shapes.
    if let Some((digit, duration_ms)) = parse_dtmf_payload(&message) {
        let leg_tag = state
            .call_actors
            .get_call(&call_id)
            .map(|call| {
                if from_a_leg {
                    call.a_leg.dialog.local_tag.clone()
                } else {
                    call.winner
                        .and_then(|index| call.b_legs.get(index))
                        .map(|leg| leg.dialog.local_tag.clone())
                        .unwrap_or_else(String::new)
                }
            })
            .unwrap_or_default();
        debug!(
            call_id = %call_id,
            digit = %digit,
            "B2BUA INFO: surfacing a DTMF digit"
        );
        // The fan-out is async (it may enter Python), and this path is the
        // synchronous SIP one — so hand it to the dispatcher runtime the same
        // way the imperative control entry points do.
        let event = crate::rtpengine::events::DtmfEvent {
            call_id: sip_call_id.clone(),
            from_tag: leg_tag,
            to_tag: None,
            digit,
            duration_ms,
            // No RTP tone to measure: INFO carries a duration at most, and
            // never a level. 0 dBm0 reads as "not reported" rather than as a
            // measurement siphon did not make.
            volume: 0,
            source: None,
        };
        if let Some(control) = B2BUA_CONTROL.get() {
            let state_for_event = Arc::clone(&control.state);
            control
                .runtime
                .spawn(dispatch_dtmf_event(state_for_event, event));
        } else {
            warn!(call_id = %call_id, "B2BUA INFO: no dispatcher handle — the digit was not surfaced");
        }
    }

    // `@b2bua.on_info` sees the INFO first. On a call with a far leg it may
    // answer it itself (an application package spoken between the script
    // and that party, never meant for the other one); left unanswered it is
    // relayed as before. Without a handler a two-leg INFO is relayed at once.
    let has_handler = !state
        .engine
        .state()
        .handlers_for(&HandlerKind::B2buaInfo)
        .is_empty();
    if has_far_leg && !has_handler {
        relay_info(&inbound, &message, &call_id, from_a_leg, state);
        return;
    }

    // A retransmission of an INFO already handed to the script gets the same
    // answer again, and is not handed over twice (RFC 3261 §17.2.2).
    let key = InfoKey::of(&message);
    if let Some(key) = &key {
        match answered_infos().begin(key) {
            InfoSeen::New => {}
            InfoSeen::InProgress => {
                debug!(call_id = %call_id, "B2BUA INFO: retransmission while the script decides, absorbed");
                return;
            }
            InfoSeen::Answered(response) => {
                debug!(call_id = %call_id, "B2BUA INFO: retransmission, the answer sent again");
                send_message_from(
                    response,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    state,
                );
                return;
            }
        }
    }
    // The handler may answer it with a status and a body (RFC 6086 §4.2.2
    // lets a 200 to an INFO carry one, and an application package that
    // carries requests in INFO needs it for their results).
    let response = match run_info_hook(&call_id, &inbound, &message, state) {
        Some(response) => response,
        None if has_far_leg => {
            // Not the script's: relayed, and its retransmissions with it.
            if let Some(key) = &key {
                answered_infos().forget(key);
            }
            relay_info(&inbound, &message, &call_id, from_a_leg, state);
            return;
        }
        // One-legged and unanswered: siphon is the far party, so it is a bare
        // 200, an INFO a UAS understood with no body owed back.
        None => {
            debug!(call_id = %call_id, "B2BUA INFO: answering on a one-legged call");
            build_response(
                &message,
                200,
                "OK",
                state.identity.load().server.as_deref(),
                &[],
            )
        }
    };
    if let Some(key) = key {
        answered_infos().answered(key, &response);
    }
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

fn relay_info(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    from_a_leg: bool,
    state: &DispatcherState,
) {
    b2bua_forward_indialog_request(
        inbound,
        message,
        call_id,
        from_a_leg,
        Method::Info,
        crate::b2bua::actor::ForwardedMarker::Info,
        state,
    );
}

/// Show an INFO to `@b2bua.on_info` and build the
/// response it asked for with `request.reply()` (and `set_reply_body()` /
/// `set_reply_header()`). `None` when no handler ran, a handler raised, or
/// none answered: the caller then sends the default 200.
fn run_info_hook(
    call_id: &str,
    inbound: &InboundMessage,
    message: &SipMessage,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaInfo);
    if handlers.is_empty() {
        return None;
    }
    let py_call = py_call_for(call_id, Some(message), state)?;
    let request = Arc::new(std::sync::Mutex::new(message.clone()));
    let py_request = PyRequest::new(
        Arc::clone(&request),
        format!("{}", inbound.transport).to_lowercase(),
        inbound.remote_addr.ip().to_string(),
        inbound.remote_addr.port(),
    );
    let decided = Python::attach(|python| {
        let (call_object, request_object) = match (
            Py::new(python, py_call),
            Py::new(python, py_request),
        ) {
            (Ok(call), Ok(request)) => (call, request),
            (Err(error), _) | (_, Err(error)) => {
                error!(call_id = %call_id, "B2BUA on_info: could not build its arguments: {error}");
                return None;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            let raised =
                match callable.call1((call_object.bind(python), request_object.bind(python))) {
                    Ok(returned) if handler.is_async => run_coroutine(python, &returned).err(),
                    Ok(_) => None,
                    Err(error) => Some(error),
                };
            if let Some(error) = raised {
                record_script_error("B2BUA on_info", &error);
                return None;
            }
        }
        if !matches!(call_object.borrow(python).action(), CallAction::None) {
            warn!(call_id = %call_id, "B2BUA on_info: a call action has no effect here; answer the INFO with request.reply()");
        }
        let mut borrowed = request_object.borrow_mut(python);
        match borrowed.action().clone() {
            RequestAction::Reply { code, reason, .. } => {
                let headers = borrowed.take_reply_headers();
                let body = borrowed.take_reply_body();
                Some((code, reason, headers, body))
            }
            RequestAction::None => None,
            _ => {
                warn!(call_id = %call_id, "B2BUA on_info: only request.reply() answers an INFO here; sending the default 200");
                None
            }
        }
    })?;
    let (code, reason, headers, body) = decided;
    if !(200..=699).contains(&code) {
        warn!(call_id = %call_id, code, "B2BUA on_info: an INFO is answered with a final status; sending the default 200");
        return None;
    }
    let mut response = build_response(
        message,
        code,
        &reason,
        state.identity.load().server.as_deref(),
        &headers,
    );
    if let Some((body, content_type)) = body {
        response.headers.set("Content-Type", content_type);
        response
            .headers
            .set("Content-Length", body.len().to_string());
        response.body = body;
    }
    Some(response)
}

/// An INFO transaction on a dialog: the request's Call-ID, CSeq number and
/// top Via branch (RFC 3261 §17.2.3).
#[derive(Clone, PartialEq, Eq, Hash)]
struct InfoKey {
    call_id: String,
    cseq: u32,
    branch: String,
}

impl InfoKey {
    fn of(message: &SipMessage) -> Option<Self> {
        let call_id = message.headers.call_id()?.to_string();
        let cseq = message
            .headers
            .get("CSeq")
            .and_then(|raw| crate::sip::headers::cseq::CSeq::parse(raw).ok())?
            .sequence;
        let branch = message
            .headers
            .get("Via")
            .and_then(|raw| Via::parse_multi(raw).ok())
            .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))?;
        Some(Self {
            call_id,
            cseq,
            branch,
        })
    }
}

enum InfoSeen {
    New,
    InProgress,
    Answered(SipMessage),
}

/// INFOs answered on one-legged calls, kept for the life of a server
/// transaction (Timer J, 64·T1) so a retransmission is answered from here.
struct AnsweredInfos {
    entries: dashmap::DashMap<InfoKey, (std::time::Instant, Option<SipMessage>)>,
}

/// RFC 3261 §17.2.2 Timer J for an unreliable transport: 64·T1.
const INFO_REMEMBERED_FOR: std::time::Duration = std::time::Duration::from_secs(32);

impl AnsweredInfos {
    fn begin(&self, key: &InfoKey) -> InfoSeen {
        let now = std::time::Instant::now();
        self.entries
            .retain(|_, (seen, _)| now.duration_since(*seen) < INFO_REMEMBERED_FOR);
        match self.entries.entry(key.clone()) {
            dashmap::mapref::entry::Entry::Occupied(entry) => match &entry.get().1 {
                Some(response) => InfoSeen::Answered(response.clone()),
                None => InfoSeen::InProgress,
            },
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert((now, None));
                InfoSeen::New
            }
        }
    }

    fn forget(&self, key: &InfoKey) {
        self.entries.remove(key);
    }

    fn answered(&self, key: InfoKey, response: &SipMessage) {
        self.entries
            .insert(key, (std::time::Instant::now(), Some(response.clone())));
    }
}

fn answered_infos() -> &'static AnsweredInfos {
    static ANSWERED: std::sync::OnceLock<AnsweredInfos> = std::sync::OnceLock::new();
    ANSWERED.get_or_init(|| AnsweredInfos {
        entries: dashmap::DashMap::new(),
    })
}

/// Send a plain response on the flow the request arrived on.
fn respond(
    inbound: &InboundMessage,
    message: &SipMessage,
    code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let response = build_response(
        message,
        code,
        reason,
        state.identity.load().server.as_deref(),
        &[],
    );
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// Extract a DTMF digit and its duration from an INFO body.
///
/// Two body types are in the wild. `application/dtmf-relay` (the common one) is
/// a `Signal=<digit>` / `Duration=<ms>` pair; `application/dtmf` is the bare
/// digit. Anything else is not DTMF and is left alone — INFO carries plenty of
/// other payloads and inventing a digit from one would be worse than ignoring
/// it.
fn parse_dtmf_payload(message: &SipMessage) -> Option<(String, u32)> {
    let content_type = message
        .headers
        .get("Content-Type")
        .or_else(|| message.headers.get("c"))
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&message.body);

    if content_type.contains("application/dtmf-relay") {
        let mut digit = None;
        let mut duration_ms = 0u32;
        for line in body.lines() {
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            match name.trim().to_ascii_lowercase().as_str() {
                "signal" => digit = normalise_digit(value.trim()),
                "duration" => duration_ms = value.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
        return digit.map(|digit| (digit, duration_ms));
    }

    if content_type.contains("application/dtmf") {
        return normalise_digit(body.trim()).map(|digit| (digit, 0));
    }

    None
}

/// Accept the spellings a peer may use for a digit and reject anything else.
///
/// `10`/`11` are RFC 2833's numbering for `*` and `#`, which some devices put
/// in `Signal=`. A value that is not a single DTMF symbol is refused rather
/// than passed through, so a handler never sees a "digit" it cannot act on.
fn normalise_digit(value: &str) -> Option<String> {
    match value {
        "10" => return Some("*".to_string()),
        "11" => return Some("#".to_string()),
        _ => {}
    }
    let mut characters = value.chars();
    let (Some(first), None) = (characters.next(), characters.next()) else {
        return None;
    };
    let upper = first.to_ascii_uppercase();
    if first.is_ascii_digit() || upper == '*' || upper == '#' || ('A'..='D').contains(&upper) {
        Some(upper.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_with(content_type: &str, body: &str) -> SipMessage {
        let raw = format!(
            concat!(
                "INFO sip:bob@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n",
                "From: <sip:alice@example.com>;tag=a\r\n",
                "To: <sip:bob@example.com>;tag=b\r\n",
                "Call-ID: info-test\r\n",
                "CSeq: 2 INFO\r\n",
                "Content-Type: {}\r\n",
                "Content-Length: {}\r\n",
                "\r\n",
                "{}"
            ),
            content_type,
            body.len(),
            body
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the fixture should parse")
    }

    /// The common form, as a handset sends it.
    #[test]
    fn dtmf_relay_body_yields_the_digit_and_duration() {
        let message = info_with("application/dtmf-relay", "Signal=5\r\nDuration=160\r\n");
        assert_eq!(parse_dtmf_payload(&message), Some(("5".to_string(), 160)));
    }

    /// RFC 2833 numbering for the two symbols that are not digits.
    #[test]
    fn dtmf_relay_accepts_the_star_and_hash_encodings() {
        for (signal, expected) in [("10", "*"), ("11", "#"), ("*", "*"), ("#", "#")] {
            let message = info_with(
                "application/dtmf-relay",
                &format!("Signal={signal}\r\nDuration=100\r\n"),
            );
            assert_eq!(
                parse_dtmf_payload(&message),
                Some((expected.to_string(), 100)),
                "Signal={signal} should be {expected}"
            );
        }
    }

    /// The bare-digit form.
    #[test]
    fn dtmf_body_yields_the_digit() {
        let message = info_with("application/dtmf", "7");
        assert_eq!(parse_dtmf_payload(&message), Some(("7".to_string(), 0)));
    }

    /// INFO carries plenty that is not DTMF. Inventing a digit from a body
    /// that is not one would put a keypress into an IVR nobody made.
    #[test]
    fn a_non_dtmf_body_is_not_a_digit() {
        for (content_type, body) in [
            ("application/media_control+xml", "<?xml version=\"1.0\"?>"),
            ("application/dtmf-relay", "Duration=100\r\n"),
            ("application/dtmf-relay", "Signal=hello\r\n"),
            ("application/dtmf", "not-a-digit"),
            ("application/sdp", "v=0"),
        ] {
            assert_eq!(
                parse_dtmf_payload(&info_with(content_type, body)),
                None,
                "{content_type} / {body:?} is not a digit"
            );
        }
    }

    /// Case and the letter keys.
    #[test]
    fn letter_keys_are_upper_cased() {
        let message = info_with("application/dtmf-relay", "Signal=b\r\n");
        assert_eq!(parse_dtmf_payload(&message), Some(("B".to_string(), 0)));
    }
}
