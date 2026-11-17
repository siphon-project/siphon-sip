//! The provisional responses of a call siphon placed: the PRACK a reliable one
//! is owed (RFC 3262 §4), the answer that PRACK carries when the callee
//! offered in it (§5), what the call's creator is told, and
//! `@b2bua.on_originate_progress` for a call a script placed.
//!
//! siphon is the UAC of such a call and the only one, so nobody else can
//! acknowledge its reliable provisionals: left unacknowledged the callee
//! retransmits one for 64*T1 and then fails the INVITE (RFC 3262 §3).
use crate::dispatcher::*;

/// What the creator of a call is told when a reliable provisional's offer
/// could not be answered and the call is given up.
const UNANSWERABLE_OFFER_REASON: &str = "media_failed";

/// A provisional response (`100`-`199`) to the INVITE of a call siphon placed.
///
/// Nothing is relayed: there is no caller behind this call. The early dialog
/// is recorded (RFC 3261 §12.1.2), a reliable provisional is PRACKed, and the
/// progress is reported once to whoever placed the call: the control plane's
/// channel and originate group, or the script's handler.
pub(super) fn handle_provisional(
    internal_call_id: &str,
    sip_call_id: &str,
    message: &SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
) {
    // One that arrives behind the answer is a straggler: the callee sends
    // none after its final response (RFC 3261 §17.2.1).
    if state
        .call_actors
        .get_call(internal_call_id)
        .is_none_or(|call| call.state == CallState::Answered)
    {
        return;
    }
    // RFC 3262 §4: a reliable provisional is PRACKed before anything is made
    // of it, and a retransmission of one goes no further.
    if !prack_provisional(
        internal_call_id,
        sip_call_id,
        message,
        response_source,
        state,
    ) {
        return;
    }
    // RFC 3261 §12.1.2: the first provisional with a To-tag opens the early
    // dialog; record its identity so a CANCEL/BYE has a target before answer.
    // The call moves to ringing under the same lock that finds it unanswered,
    // so a provisional handled beside the 2xx cannot take the answer back.
    let remote_tag = crate::b2bua::actor::extract_to_tag(message);
    let ringing = state
        .call_actors
        .get_call_mut(internal_call_id)
        .is_some_and(|mut call| {
            if call.state == CallState::Answered {
                return false;
            }
            // §12.1.2 sets the remote target once from the dialog-creating
            // response; a downstream fork puts several early dialogs on this
            // one branch, so later provisionals must not overwrite the first's
            // target. The confirming 2xx refreshes both to the winner.
            if call.a_leg.dialog.remote_tag.is_none() {
                call.a_leg.dialog.remote_tag = remote_tag.clone();
            }
            if call.a_leg.dialog.remote_contact.is_none() {
                if let Some(contact) = message.headers.get("Contact") {
                    call.a_leg.dialog.remote_contact =
                        Some(crate::b2bua::actor::extract_contact_uri(contact));
                }
            }
            call.transition_to(CallState::Ringing);
            true
        });
    if !ringing {
        return;
    }
    let early_media = !message.body.is_empty();
    let phase = if early_media { "progress" } else { "ringing" };
    control_notify_channel_event(
        sip_call_id,
        "ChannelStateChange",
        serde_json::json!({
            "state": phase,
            "code": status_code,
            "early_media": early_media,
            "sdp": originate_body_text(message),
        }),
    );
    originate_group_leg_progress(
        state,
        internal_call_id,
        OriginateLegProgress {
            code: status_code,
            early_media,
            sdp: originate_body_text(message),
        },
    );
    fire_handlers(internal_call_id, sip_call_id, message, status_code, state);
    debug!(
        call_id = %internal_call_id,
        status = status_code,
        early_media,
        "originate: provisional"
    );
}

/// What a reliable provisional settled of the session before the 2xx.
enum PrackSession {
    /// Nothing: the PRACK goes out bare.
    None,
    /// The callee offered in it, and this is siphon's answer for the PRACK.
    Answer(String),
    /// A second early dialog of the call offered (a downstream fork), while
    /// the first holds the call's media: its PRACK rejects every stream (RFC
    /// 3264 §6) and the call goes on.
    Rejection(Vec<u8>),
    /// The callee offered in it and siphon cannot answer: the PRACK rejects
    /// every stream (RFC 3264 §6) and the call is given up.
    Unanswerable { rejection: Vec<u8>, reason: String },
}

/// RFC 3262 §4 on the INVITE of a call siphon placed: acknowledge the reliable
/// provisional `message` with a PRACK on the early dialog it belongs to.
///
/// Returns `false` when the response is to go no further: a retransmission of
/// a reliable provisional already acknowledged ("retransmissions of that
/// response MUST be discarded"), one that arrived ahead of its turn, or one
/// whose offer siphon could not answer, which ends the call. `true` for
/// everything else, an unreliable provisional included, with the PRACK
/// already handed to the transport.
fn prack_provisional(
    internal_call_id: &str,
    sip_call_id: &str,
    message: &SipMessage,
    response_source: SocketAddr,
    state: &DispatcherState,
) -> bool {
    if message.status_code() == Some(100)
        || !crate::sip::headers::rseq::requires_100rel(&message.headers)
    {
        return true;
    }
    let Some(rseq) = crate::sip::headers::rseq::parse_rseq(&message.headers) else {
        return true;
    };
    // Forked early dialogs number their provisionals independently (§3), so
    // the order is kept per To-tag.
    let to_tag = crate::b2bua::actor::extract_to_tag(message).unwrap_or_default();
    if !state.call_actors.try_mark_originated_prack_acked(
        internal_call_id,
        &to_tag,
        rseq.response_number,
    ) {
        debug!(
            call_id = %internal_call_id,
            rseq = rseq.response_number,
            "originate: discarding a reliable provisional that is a retransmission or out of order (RFC 3262 §4)"
        );
        return false;
    }

    let session = prack_session(
        internal_call_id,
        sip_call_id,
        &to_tag,
        message,
        response_source,
        state,
    );
    // The RAck names the response by its RSeq and the CSeq it echoes (§7.2).
    let cseq = message.headers.cseq().cloned().unwrap_or_default();
    let mut cseq_parts = cseq.split_whitespace();
    let cseq_number: u32 = cseq_parts
        .next()
        .and_then(|number| number.parse().ok())
        .unwrap_or(1);
    let cseq_method = cseq_parts.next().unwrap_or("INVITE").to_string();
    let numbered = state
        .call_actors
        .get_call_mut(internal_call_id)
        .and_then(|mut call| {
            // The claim this answer was made under is gone: the INVITE was
            // sent again meanwhile, and its session started over.
            let claim = &call.originate_progress.prack_answer;
            let claimed = matches!(claim, Some((tag, _)) if *tag == to_tag);
            if matches!(session, PrackSession::Answer(_)) && !claimed {
                return None;
            }
            // The PRACK is a new request in the dialog (RFC 3261 §12.2.1.1):
            // one past the INVITE it acknowledges a response of, or the number
            // an earlier PRACK left the counter on, which is the one after its
            // own.
            let prack_cseq = call
                .a_leg
                .dialog
                .local_cseq
                .max(cseq_number.saturating_add(1));
            call.a_leg.dialog.local_cseq = prack_cseq.saturating_add(1);
            if let PrackSession::Answer(answer) = &session {
                call.originate_progress.prack_answer = Some((to_tag.clone(), answer.clone()));
                // The callee's description, kept as the one in a 2xx is: what
                // a bridge reads the leg's media from.
                call.a_leg.last_sdp = Some(message.body.clone());
            }
            Some((call.a_leg.clone(), prack_cseq))
        });
    let Some((leg, prack_cseq)) = numbered else {
        // The call ended or moved on while the engine answered: nothing else
        // will release the session that answer opened.
        if matches!(session, PrackSession::Answer(_)) {
            originate_delete_media(sip_call_id, state);
        }
        return false;
    };
    let target = early_dialog_target_from_response(message);
    let Some(mut prack) = build_b2bua_prack(
        &leg,
        state,
        &target,
        rseq.response_number,
        cseq_number,
        &cseq_method,
        prack_cseq,
    ) else {
        error!(
            call_id = %internal_call_id,
            rseq = rseq.response_number,
            "originate: no PRACK could be built for a reliable provisional"
        );
        return true;
    };
    let unanswerable = match session {
        PrackSession::None => None,
        PrackSession::Answer(answer) => {
            set_sdp_body(&mut prack, answer.into_bytes(), "application/sdp");
            None
        }
        PrackSession::Rejection(rejection) => {
            warn!(
                call_id = %internal_call_id,
                "originate: a second early dialog offered in a reliable provisional; \
                 answering it with every stream rejected"
            );
            set_sdp_body(&mut prack, rejection, "application/sdp");
            None
        }
        PrackSession::Unanswerable { rejection, reason } => {
            set_sdp_body(&mut prack, rejection, "application/sdp");
            Some(reason)
        }
    };
    // The PRACK follows this early dialog's route set (RFC 3262 §4, RFC 3261
    // §12.2.1.1); without one it goes where the INVITE went.
    let (destination, transport) = resolve_in_dialog_destination(
        &target.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    if !send_b2bua_to_bleg_checked(
        prack,
        transport,
        destination,
        leg.transport.local_addr,
        state,
    ) {
        warn!(
            call_id = %internal_call_id,
            rseq = rseq.response_number,
            %destination,
            "originate: the transport refused the PRACK of a reliable provisional"
        );
    }
    let Some(reason) = unanswerable else {
        return true;
    };
    error!(
        call_id = %internal_call_id,
        %sip_call_id,
        %reason,
        "originate: the callee's offer in a reliable provisional could not be answered: giving the call up"
    );
    cancel_originated_call(state, sip_call_id, Some(UNANSWERABLE_OFFER_REASON));
    false
}

/// Whose offer the reliable provisional of early dialog `to_tag` makes.
enum OfferClaim {
    /// None: the INVITE carried the offer, so its SDP is the answer.
    NotAnOffer,
    /// This dialog's, to answer on the media engine under `anchor`.
    Mine(crate::b2bua::actor::OriginateAnchor),
    /// This dialog's again: a PRACK answered it already.
    Repeated,
    /// Another dialog's: that one holds the call's media.
    Another,
}

/// What the PRACK of the reliable provisional `message` carries.
///
/// SDP in a reliable provisional to an INVITE that carried none is the
/// callee's offer, and the PRACK answers it (RFC 3262 §5): on the media
/// engine, the way the offer in a 2xx is. One offer is answered per call: a
/// second early dialog offering (a downstream fork) is answered with every
/// stream rejected, and a 2xx on that dialog cannot be carried
/// ([`prack_answer`]). SDP answering siphon's own offer is kept for a 2xx
/// that does not repeat it ([`callee_answer`]).
fn prack_session(
    internal_call_id: &str,
    sip_call_id: &str,
    to_tag: &str,
    message: &SipMessage,
    response_source: SocketAddr,
    state: &DispatcherState,
) -> PrackSession {
    if message.body.iter().all(u8::is_ascii_whitespace) {
        return PrackSession::None;
    }
    // Claimed under the call's lock before the engine is asked, so two early
    // dialogs offering at once cannot both be given the call's media.
    let claim = state
        .call_actors
        .get_call_mut(internal_call_id)
        .map(|mut call| {
            let Some(anchor) = call.originate_anchor.clone() else {
                return OfferClaim::NotAnOffer;
            };
            if call.originate_offer.is_some() {
                if let Ok(answer) = offered_leg_answer(message) {
                    call.originate_progress.keep_callee_answer(to_tag, answer);
                }
                return OfferClaim::NotAnOffer;
            }
            match &call.originate_progress.prack_answer {
                Some((tag, _)) if tag == to_tag => OfferClaim::Repeated,
                Some(_) => OfferClaim::Another,
                None => {
                    call.originate_progress.prack_answer =
                        Some((to_tag.to_string(), String::new()));
                    OfferClaim::Mine(anchor)
                }
            }
        });
    match claim {
        // This dialog's offer was answered by an earlier PRACK: what it sends
        // now repeats the session (RFC 3261 §13.2.1).
        None | Some(OfferClaim::NotAnOffer | OfferClaim::Repeated) => PrackSession::None,
        Some(OfferClaim::Another) => PrackSession::Rejection(rejecting_answer(&message.body)),
        Some(OfferClaim::Mine(anchor)) => match originate_anchor_2xx(
            sip_call_id,
            to_tag,
            message,
            &anchor,
            response_source,
            state,
        ) {
            Ok(answer) => PrackSession::Answer(answer),
            Err(reason) => PrackSession::Unanswerable {
                rejection: rejecting_answer(&message.body),
                reason,
            },
        },
    }
}

/// The answer siphon's PRACK already gave the callee that now answers with
/// `remote_tag`, for an offerless originate.
///
/// `None` when no PRACK answered an offer: the 2xx carries it. `Some(Err)`
/// when the PRACK answered another early dialog's offer than the one that
/// won, which leaves the winner with every stream rejected.
pub(super) fn prack_answer(
    internal_call_id: &str,
    remote_tag: Option<&str>,
    state: &DispatcherState,
) -> Option<Result<String, String>> {
    let (tag, answer) = state
        .call_actors
        .get_call(internal_call_id)?
        .originate_progress
        .prack_answer
        .clone()?;
    Some(if remote_tag == Some(tag.as_str()) {
        Ok(answer)
    } else {
        Err(
            "the callee that answered is not the one whose reliable provisional offer siphon answered"
                .to_string(),
        )
    })
}

/// The answer to the offer in siphon's INVITE that a reliable provisional of
/// the dialog now answering with `remote_tag` already gave (RFC 3262 §5), for
/// a 2xx that does not repeat it.
pub(super) fn callee_answer(
    internal_call_id: &str,
    remote_tag: Option<&str>,
    state: &DispatcherState,
) -> Option<Vec<u8>> {
    state
        .call_actors
        .get_call(internal_call_id)?
        .originate_progress
        .callee_answer(remote_tag?)
        .map(<[u8]>::to_vec)
}

/// The 2xx of early dialog `remote_tag` is about to be answered on the media
/// engine: claim the call's media for that dialog, as a reliable provisional's
/// offer claims it ([`prack_session`]), so that another early dialog offering
/// meanwhile is answered with every stream rejected and not given a second
/// allocation.
pub(super) fn claim_media_for_answer(
    internal_call_id: &str,
    remote_tag: Option<&str>,
    state: &DispatcherState,
) {
    if let Some(mut call) = state.call_actors.get_call_mut(internal_call_id) {
        let claim = &mut call.originate_progress.prack_answer;
        if claim.is_none() {
            *claim = Some((remote_tag.unwrap_or_default().to_string(), String::new()));
        }
    }
}

/// The INVITE of the call is being sent again as a new transaction (with
/// credentials, RFC 3261 §22.2): the early dialogs of the one it replaces
/// ended with its final response (§12.3), and what their reliable
/// provisionals settled of the session goes with them, the media a PRACK's
/// answer opened included.
pub(super) fn forget_early_session(internal_call_id: &str, state: &DispatcherState) {
    let release = state
        .call_actors
        .get_call_mut(internal_call_id)
        .and_then(|mut call| {
            call.originate_progress
                .forget_session()
                .then(|| call.a_leg.dialog.call_id.clone())
        });
    if let Some(sip_call_id) = release {
        originate_delete_media(&sip_call_id, state);
    }
}

/// The dialog's CSeq counter once `answer`, the 2xx of its INVITE, confirms
/// it: the number of its next request (RFC 3261 §12.2.1.1). One past the
/// INVITE the 2xx answers, or where a PRACK left `counter`, which is the
/// number after its own.
pub(super) fn next_cseq_after(answer: &SipMessage, counter: u32) -> u32 {
    let invite_cseq = answer
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse::<u32>().ok())
        .unwrap_or(1);
    counter.max(invite_cseq.saturating_add(1))
}

/// Run `@b2bua.on_originate_progress(call_id, code, reason, reply)` for the
/// provisional `message` of a call a script placed with `b2bua.originate()`.
///
/// Called once per response, after its PRACK when it was sent reliably, and
/// never for a `100`, which is hop by hop (RFC 3261 §16.7 step 2). A call the
/// control plane placed has its progress reported as channel events and runs
/// no handler.
fn fire_handlers(
    internal_call_id: &str,
    sip_call_id: &str,
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    if !(101..=199).contains(&status_code) {
        return;
    }
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaOriginateProgress);
    if handlers.is_empty() || !state.call_actors.is_script_originated(internal_call_id) {
        return;
    }
    let reason = match &message.start_line {
        StartLine::Response(status_line) => status_line.reason_phrase.clone(),
        StartLine::Request(_) => String::new(),
    };
    let py_reply = PyReply::new(Arc::new(std::sync::Mutex::new(message.clone())));
    Python::attach(|python| {
        let reply = match Py::new(python, py_reply) {
            Ok(reply) => reply,
            Err(error) => {
                error!("failed to create PyReply for on_originate_progress: {error}");
                return;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((
                sip_call_id,
                status_code,
                reason.as_str(),
                reply.bind(python),
            )) {
                Ok(returned) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &returned) {
                            record_script_error("async on_originate_progress", &error);
                        }
                    }
                }
                Err(error) => record_script_error("on_originate_progress", &error),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer_to(cseq: &str) -> SipMessage {
        crate::sip::parser::parse_sip_message_bytes(
            format!(
                concat!(
                    "SIP/2.0 200 OK\r\n",
                    "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-next-cseq\r\n",
                    "From: <sip:server@example.com>;tag=local\r\n",
                    "To: <sip:callee@example.com>;tag=remote\r\n",
                    "Call-ID: next-cseq@example.com\r\n",
                    "CSeq: {cseq}\r\n",
                    "Content-Length: 0\r\n",
                    "\r\n",
                ),
                cseq = cseq
            )
            .as_bytes(),
        )
        .expect("the answer parses")
    }

    /// The counter after the answer is the dialog's next request: past the
    /// INVITE answered, the first or a credentialed second, and past whatever
    /// PRACKs went out before it.
    #[test]
    fn the_counter_after_the_answer_is_past_the_invite_and_every_prack() {
        // No PRACK: the counter still holds the INVITE's own number.
        assert_eq!(next_cseq_after(&answer_to("1 INVITE"), 1), 2);
        // PRACKs took 2 and 3 and left it on 4.
        assert_eq!(next_cseq_after(&answer_to("1 INVITE"), 4), 4);
        // A credentialed retry was the dialog's second INVITE.
        assert_eq!(next_cseq_after(&answer_to("2 INVITE"), 2), 3);
        assert_eq!(next_cseq_after(&answer_to("garbage"), 1), 2);
    }
}
