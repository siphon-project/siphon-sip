//! Lawful intercept and capture taps on the message path.
//!
//! Runs before routing so a warranted call is seen whatever happens to it
//! afterwards, and attaches or detaches the X3 content stream as calls start
//! and end.

use super::*;

/// Match one SIP message against the provisioned warrants and emit IRI.
///
/// Costs one `Option` test on a node with LI disabled, and one further
/// emptiness check on a node with LI enabled but nothing provisioned, so the
/// common case is a predictable branch rather than a lookup.
pub(super) fn intercept_message(
    message: &SipMessage,
    inbound: &InboundMessage,
    state: &Arc<DispatcherState>,
) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    if !li.is_intercepting() {
        return;
    }

    // Borrowed, not owned. This runs on every message, and the overwhelming
    // majority match nothing — building four Strings only to discard them is a
    // cost the hot path should not carry. The owned forms are built below,
    // after something has actually matched.
    let request_uri = match &message.start_line {
        StartLine::Request(request_line) => Some(request_line.request_uri.to_string()),
        StartLine::Response(_) => None,
    };
    let from_uri = message.headers.get("From").map(String::as_str);
    let to_uri = message.headers.get("To").map(String::as_str);
    let source_ip = Some(inbound.remote_addr.ip());

    let Some(call_id) = message.headers.call_id() else {
        // Every SIP message carries a Call-ID (RFC 3261 §8.1.1.4); one that
        // does not has already failed validation above. Without it there is no
        // session to correlate on, so the record would be unusable — and no
        // session to decide, either.
        return;
    };

    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str(),
        // A response's method is the one its CSeq names, which is what the
        // IRI record has to attribute it to.
        StartLine::Response(_) => message
            .headers
            .get("CSeq")
            .and_then(|cseq| cseq.split_whitespace().nth(1))
            .unwrap_or("UNKNOWN"),
    };
    let status_code = match &message.start_line {
        StartLine::Request(_) => None,
        StartLine::Response(status_line) => Some(status_line.status_code),
    };
    let facts = crate::li::MessageFacts {
        request: matches!(message.start_line, StartLine::Request(_)),
        method,
        status_code,
        to_tagged: to_has_tag(message),
        branch: top_via_branch(message),
    };
    let identities = crate::li::Identities {
        request_uri: request_uri.as_deref(),
        from_uri,
        to_uri,
        source_ip,
    };

    // Decided once per session, not once per message, and per *session*
    // rather than per dialog: every leg of a B2BUA call resolves to the same
    // one. See `LiManager::resolve_session`. This is what stops a warrant
    // delivering the INVITE and then missing the BYE, or the other leg, and
    // what gives the whole call one Correlation ID.
    let session = li.resolve_session_with(
        call_id,
        &facts,
        &identities,
        || b2bua_owner(state, message, call_id),
        || dialog_media(state, call_id),
    );
    if session.matches.is_empty() {
        // An unwarranted session is remembered as unwarranted, and that
        // memory has to be released when the dialog ends or the map would
        // grow with every call the node ever handles and rely on the cap to
        // save it. The cap is for traffic that never reaches an end at all.
        if terminates_dialog(message) {
            li.forget_session(&session.session_id);
        }
        return;
    }

    // A retransmission is the same message arriving again, not a new event.
    // Recording it twice would give the mediation function a duplicate and
    // re-run the session's lifecycle — a resent INVITE would restart content
    // capture on a call already being captured.
    if !li.record_message_once(&session.session_id, message_instance_key(message)) {
        debug!(
            call_id = %call_id,
            "LI: message already recorded for this session, not recording the retransmission"
        );
        return;
    }

    // The event type follows the message, not the warrant: a mediation
    // function reconstructs the session from the sequence.
    let event_type = li.note_message(&session, &facts);
    // The ACK of a failure response is recorded like any other message, but
    // the call it closes was never answered and has no content.
    let unanswered = li.acknowledges_unanswered_invite(&session, &facts);
    let method = method.to_string();
    let from_uri = from_uri.unwrap_or_default().to_string();
    let to_uri = to_uri.unwrap_or_default().to_string();

    for matched in &session.matches {
        let x_id = matched.task.details.x_id;
        let event = li.build_iri_event(
            matched,
            event_type,
            call_id,
            &session.session_id,
            &method,
            status_code,
            &from_uri,
            &to_uri,
            request_uri.clone(),
            source_ip,
            Some(inbound.data.to_vec()),
        );
        li.emit_iri(event);
        li.tasks().mark_intercept(x_id);

        li.audit(
            crate::li::AuditOperation::InterceptMatch,
            Some(&x_id.to_string()),
            format!(
                "method={method} call_id={call_id} session={} delivery={} event={event_type:?} party={:?}",
                session.session_id, matched.task.details.delivery_type, matched.party
            ),
        );

        // Content capture stops when the session ends, on whichever leg the
        // end arrives: a far end that hangs up sends its BYE on the callee
        // leg. There is no matching "start" here: the engine has no call to
        // intercept until the script has offered it one, so the attachment is
        // made when that offer reaches the engine ([`watch_engine_calls`]), or
        // at the ACK, below, on an engine that cannot take it that early.
        if event_type == crate::li::IriEventType::End {
            detach_x3(&session, state);
        }
    }

    // X3 attaches when the media session exists at the engine, not when
    // the warrant matches.
    //
    // Interception is matched here, before the script runs, so a script
    // cannot decline a warrant. The attachment cannot be made here though,
    // because the engine only learns of a call when the script offers it
    // there and this runs first: asked at the dialog-forming INVITE, the
    // engine answered "unknown call".
    //
    // Where it is made depends on the engine.
    //
    // **When the media reaches the engine**, on a siphon-rtp that lists the
    // feature for the shape the media has, in `node_info`: at the offer of a
    // call (`x3_attach_at_offer`, 0.25.1 and later), at the local answer of a
    // call siphon answers itself (`x3_single_leg`, 0.25.2), and when a party
    // is seated in a conference room (`x3_conference_seat`, 0.25.2), which is
    // attached on the seat and not on a call. That engine takes an
    // interception on a call that is offered but not answered: it opens the
    // delivery connection at once, puts the taps on at the first answer (a 183
    // with SDP included) and keeps the one connection, Correlation ID and
    // sequence through the final answer and every re-offer. So the attach is
    // sent as soon as the script's verb has succeeded
    // ([`watch_engine_calls`]), off the INVITE's path, and the first packet
    // after the answer and all early media are delivered.
    //
    // **At the ACK**, on an engine that does not list the feature (an older
    // siphon-rtp refuses an unanswered call: "no answered second leg") and for
    // whatever was not attached before: a warrant or a destination added
    // since, a leg on an engine without the feature. Asked at the answer
    // instead, the older engine refused as well, since the response had not
    // been dispatched yet and the script had not answered it to the engine.
    // The ACK is the first message that arrives with the session established:
    // RFC 3261 §13 completes the offer/answer there, both legs are answered in
    // the engine, and it is in-dialog so it cannot be confused with the
    // INVITE.
    //
    // Either way each `(leg, warrant, destination)` is asked for once per
    // engine call: the request is recorded before it is sent, and the ACK asks
    // only for what has no record ([`attach_x3`]). That matters because a
    // failed attempt is a compliance signal reported to the ADMF and must not
    // be routine.
    //
    // Only an ACK on the session's anchoring dialog. The engine knows the
    // call by that dialog's Call-ID and keys the interception on its
    // offerer's tag; an ACK on the callee leg, which a re-INVITE from the
    // far end produces, names neither, and the call is already attached.
    //
    // And only the ACK of an answer. The ACK of a 486 looks the same here,
    // but by then the media session is gone: the engine would refuse an
    // unknown call, and that refusal would reach the ADMF as warranted
    // content going undelivered on a call that never had any. The ACK of a
    // rejected re-INVITE acknowledges no new media either.
    if !is_ack(message, &method) {
        return;
    }
    if unanswered {
        debug!(
            call_id = %call_id,
            session = %session.session_id,
            "LI: ACK of a failure response, it acknowledges no media to deliver"
        );
    } else if !session.on_primary_leg {
        debug!(
            call_id = %call_id,
            session = %session.session_id,
            "LI: ACK on a callee leg, X3 stays on the caller leg's attachment"
        );
    } else {
        // The engine keys an interception on the offerer's tag, which is the
        // dialog's From-tag.
        match from_tag(message) {
            Some(from_tag) => attach_at_ack(state, session, from_tag),
            None => error!(
                session = %session.session_id,
                "a content warrant matched a message with no From-tag; cannot attach X3"
            ),
        }
    }
}

/// Ask at an ACK for whatever content delivery the session has no record of.
///
/// A session whose leg joined a conference room has its media in the seat,
/// and is attached there on an engine that says it can
/// (`x3_conference_seat`). On one that does not, the call is asked for as it
/// always was, and the engine's refusal of a call it does not hold is the
/// fault it always was: warranted content is not being delivered.
fn attach_at_ack(state: &Arc<DispatcherState>, session: crate::li::SessionView, from_tag: String) {
    let call = {
        let state = Arc::clone(state);
        let session = session.clone();
        move || {
            let site = X3Site::call_at_ack(&state, &session, &from_tag);
            for matched in &session.matches {
                attach_x3(matched, &session, &site, &state);
            }
        }
    };
    let Some(seat) = session.seats.first().cloned() else {
        return call();
    };
    let call_has_media = state
        .rtpengine_sessions
        .as_ref()
        .is_some_and(|sessions| sessions.get(&session.engine_call_id).is_some());
    let room = seat.conference_id.to_string();
    let seated = {
        let state = Arc::clone(state);
        move |listed: bool| {
            if !listed {
                return call();
            }
            let site = X3Site::seat(&state, &seat);
            for matched in &session.matches {
                attach_x3(matched, &session, &site, &state);
            }
            // A call that also holds media of its own (answered by the engine
            // before it was seated) is tapped there as well.
            if call_has_media {
                call();
            }
        }
    };
    when_seats_are_interceptable(state, &room, seated);
}

/// Run `then` with whether the engine holding `conference_id` takes an
/// interception on a joined seat, asking it off this path the first time on
/// a connection. An engine that cannot be asked is taken not to.
fn when_seats_are_interceptable(
    state: &Arc<DispatcherState>,
    conference_id: &str,
    then: impl FnOnce(bool) + Send + 'static,
) {
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return then(false);
    };
    match backend.x3_conference_seat(conference_id) {
        Some(listed) => then(listed),
        None => {
            let backend = Arc::clone(backend);
            let conference_id = conference_id.to_string();
            tokio::spawn(async move {
                match backend.learn_x3_conference_seat(&conference_id).await {
                    Ok(listed) => then(listed),
                    Err(error) => {
                        warn!(
                            %conference_id, %error,
                            "LI: could not read the media engine's features, a conference \
                             seat is taken not to be interceptable"
                        );
                        then(false);
                    }
                }
            });
        }
    }
}

/// Where a content delivery is attached at the engine, and what it is
/// recorded under.
pub(super) struct X3Site {
    /// The key of its record ([`crate::li::LiManager::register_x3_attachment`]).
    record: String,
    /// The joined conference seat it is on; `None` for an engine call.
    seat: Option<crate::rtpengine::backend::ConferenceSeat>,
    /// Whether the engine call's offerer, the engine's "caller", is the
    /// session's caller.
    offerer_is_caller: bool,
    /// The engine call-id, or the seat's room.
    call_id: String,
    /// The offerer's tag, or the seat's.
    from_tag: String,
    /// The legs to tap, each with the number of its attempt as the caller
    /// found it ([`crate::li::LiManager::x3_attempt`]).
    legs: Vec<(Option<crate::rtpengine::CallScope>, u64)>,
}

impl X3Site {
    /// The engine call of `session`, on the one leg an offer or a local
    /// answer has just anchored.
    fn call_leg(
        session: &crate::li::SessionView,
        from_tag: &str,
        scope: Option<crate::rtpengine::CallScope>,
        attempt: u64,
    ) -> Self {
        Self {
            record: session.engine_call_id.to_string(),
            seat: None,
            offerer_is_caller: session.offerer_is_caller,
            call_id: session.engine_call_id.to_string(),
            from_tag: from_tag.to_string(),
            legs: vec![(scope, attempt)],
        }
    }

    /// The engine call of `session`, on every leg it has at its ACK
    /// ([`intercepted_legs`]).
    fn call_at_ack(
        state: &DispatcherState,
        session: &crate::li::SessionView,
        from_tag: &str,
    ) -> Self {
        let mut site = Self::call_leg(session, from_tag, None, 0);
        site.legs = match state.li_manager.as_ref() {
            Some(li) => intercepted_legs(state, &session.engine_call_id)
                .into_iter()
                .map(|leg| {
                    let attempt = li.x3_attempt(&session.engine_call_id, leg.as_ref());
                    (leg, attempt)
                })
                .collect(),
            None => Vec::new(),
        };
        site
    }

    /// A seat a party joined a conference room with.
    fn seat(state: &DispatcherState, seat: &crate::li::Seat) -> Self {
        let record = seat.record();
        let attempt = state
            .li_manager
            .as_ref()
            .map_or(0, |li| li.x3_attempt(&record, None));
        Self {
            record,
            seat: Some(crate::rtpengine::backend::ConferenceSeat {
                conference_id: seat.conference_id.to_string(),
                from_tag: seat.tag.to_string(),
            }),
            offerer_is_caller: true,
            call_id: seat.conference_id.to_string(),
            from_tag: seat.tag.to_string(),
            legs: vec![(None, attempt)],
        }
    }
}

/// The B2BUA call a Call-ID is a leg of, if any.
///
/// Asked only for a Call-ID interception has not seen before, which is the
/// first message of a leg.
///
/// An INVITE that asks to replace a dialog of a call here (RFC 3891) is a new
/// leg of that call: it arrives on a Call-ID of its own, before the take-over
/// that moves it there, and everything on it belongs to the session of the
/// call it joins, under that session's Correlation ID. Only for a `Replaces`
/// that names a dialog this node holds, tags included.
fn b2bua_owner(
    state: &DispatcherState,
    message: &SipMessage,
    call_id: &str,
) -> Option<crate::li::CallOwner> {
    let held = state.call_actors.find_by_sip_call_id(call_id);
    // A dialog that takes a leg over, or the leg a transfer dials its target
    // on, brings somebody new into the call.
    let replacement_target = match held.as_deref() {
        Some(internal_id) => state
            .call_actors
            .is_replacement_target_leg(internal_id, call_id),
        None => true,
    };
    let internal_id = held.or_else(|| replaced_call(state, message))?;
    let a_leg_call_id = state
        .call_actors
        .get_call(&internal_id)?
        .a_leg
        .dialog
        .call_id
        .clone();
    Some(crate::li::CallOwner {
        internal_id,
        a_leg_call_id,
        replacement_target,
    })
}

/// The call whose dialog the dialog-forming INVITE `message` asks to replace.
fn replaced_call(state: &DispatcherState, message: &SipMessage) -> Option<String> {
    let StartLine::Request(request_line) = &message.start_line else {
        return None;
    };
    if request_line.method.as_str() != "INVITE" || to_has_tag(message) {
        return None;
    }
    let replaces =
        crate::sip::headers::refer::parse_replaces(message.headers.get("Replaces")?).ok()?;
    state
        .call_actors
        .replaced_dialog_party(&replaces.call_id, &replaces.from_tag, &replaces.to_tag)
        .map(|(party, _answered)| party.internal_call_id)
}

/// What the media path holds for the call `call_id` is a dialog of: who
/// offered its media, and the engine call it is on when that is under an id
/// siphon minted (a dial, a bridge, a transfer), with the dialog of the party
/// that offered there.
fn dialog_media(state: &DispatcherState, call_id: &str) -> Option<crate::li::DialogMedia> {
    let sessions = state.rtpengine_sessions.as_ref()?;
    // A B2BUA call's media session is kept under its caller leg's Call-ID.
    let anchoring = state
        .call_actors
        .find_by_sip_call_id(call_id)
        .and_then(|internal_id| state.call_actors.get_call(&internal_id))
        .map(|call| call.a_leg.dialog.call_id.clone())
        .unwrap_or_else(|| call_id.to_string());
    let session = sessions.get(&anchoring).or_else(|| sessions.get(call_id))?;
    let engine_call_id = session.rtpengine_id();
    let minted = (engine_call_id != anchoring).then(|| {
        let offerer = sessions
            .event_party(engine_call_id, &session.from_tag)
            .unwrap_or_else(|| session.call_id.clone());
        (engine_call_id.to_string(), offerer)
    });
    Some(crate::li::DialogMedia {
        offerer_tag: Some(session.from_tag.clone()),
        minted,
    })
}

/// Create a B2BUA call from its caller leg, under the session id interception
/// already gave the caller's INVITE when a warrant covers it. The call's
/// internal id and its Correlation ID then derive from one value.
pub(super) fn create_b2bua_call(state: &DispatcherState, a_leg: Leg) -> String {
    #[cfg(test)]
    super::inflight_invite::pause::checkpoint("create", &a_leg.dialog.call_id);
    let reserved = state
        .li_manager
        .as_ref()
        .and_then(|li| li.reserved_session_id(&a_leg.dialog.call_id));
    state.call_actors.create_call_with_id(a_leg, reserved)
}

/// Tell the media engine to start ETSI TS 103 221-2 content delivery for a
/// matched warrant.
///
/// Only for a task whose `deliveryType` asks for content — an `X2Only` warrant
/// carries no content and must not open a delivery connection. Provisioning has
/// already refused a content warrant this node cannot service, so reaching here
/// means the backend can do it; a failure at the command is therefore a real
/// delivery fault and is reported to the ADMF rather than logged and forgotten.
///
/// `site` is where: the session's engine call, on every leg it has at its ACK
/// ([`intercepted_legs`]) or on the one leg an offer or a local answer has
/// just anchored, or the conference seat a party of the session joined, which
/// the engine knows by its room and its tag and holds no call for.
///
/// Each `(leg, warrant, destination)` is recorded before the engine is asked,
/// and asked only when it had no record: an offer and an ACK, or two ACKs (a
/// re-INVITE has its own), then ask once between them, and a delivery end
/// that beats the engine's answer finds its attachment. Attaching twice would
/// open a second interception on the same leg and deliver every packet to the
/// agency twice. Nothing is asked for a leg whose engine call siphon has ended
/// since the caller looked.
///
/// Every leg of the call is tapped: on a proxy that anchored both legs of one
/// call under per-call scopes there is no single engine call that carries all
/// of its content, and a leg left untapped is content the agency never
/// receives.
pub(super) fn attach_x3(
    matched: &crate::li::x1::store::TaskMatch,
    session: &crate::li::SessionView,
    site: &X3Site,
    state: &DispatcherState,
) {
    let (call_id, from_tag): (&str, &str) = (&site.call_id, &site.from_tag);
    let record: &str = &site.record;
    if !matched.task.details.delivery_type.includes_content() {
        return;
    }
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let Some(backend) = state.rtpengine_set.as_ref() else {
        error!(
            xid = %matched.task.details.x_id,
            "a content warrant matched but no media backend is configured — no content \
             can be delivered for this intercept"
        );
        return;
    };
    let x_id = matched.task.details.x_id;
    let named = li.tasks().destinations_for_interface(x_id, true);
    if named.is_empty() {
        error!(
            xid = %x_id,
            "a content warrant named no content-capable destination — refusing to \
             attach rather than deliver nowhere"
        );
        return;
    }

    let correlation_id = li.correlation_for(&matched.task, &session.session_id);
    let xid = x_id.as_bytes();
    // TS 103 221-2 §5.2.6 measures a delivered packet's direction against the
    // target, so which end the warrant names is load-bearing rather than
    // cosmetic: getting it wrong inverts the direction on every packet.
    // The engine's caller is whoever offered the engine call. That is the
    // session's caller, except on an engine call a transfer offered with the
    // called party's media, where the two are the other way round.
    let target_is_caller = matched.party == crate::li::target::MatchedParty::Originating;
    let target_leg = match target_is_caller == site.offerer_is_caller {
        true => crate::rtpengine::backend::X3TargetLeg::Caller,
        false => crate::rtpengine::backend::X3TargetLeg::Callee,
    };

    let attachments = named
        .iter()
        .flat_map(|destination| site.legs.iter().map(move |leg| (destination, leg)));
    for (destination, (scope, attempt)) in attachments {
        let Some(delivery) = destination.details.delivery_address.socket_addr() else {
            continue;
        };
        let d_id = destination.details.d_id;
        let attempt = *attempt;
        let registered = li.x3_register(
            record,
            crate::li::ActiveIntercept {
                x_id,
                d_id,
                from_tag: from_tag.to_string(),
                correlation_id,
                session_id: Arc::clone(&session.session_id),
                scope: scope.clone(),
            },
            attempt,
        );
        match registered {
            crate::li::X3Registration::Recorded => {}
            crate::li::X3Registration::Known => continue,
            crate::li::X3Registration::OtherCorrelation { held } => {
                // An engine that keys its deliveries by Correlation ID as well
                // takes this attach beside the first: send it from here.
                second_correlation_undeliverable(li, (x_id, d_id), call_id, held, correlation_id);
                continue;
            }
        }
        let leg = backend.leg(call_id, scope.as_ref());
        let backend = Arc::clone(backend);
        let li = li.clone();
        let call_id = call_id.to_string();
        let from_tag = from_tag.to_string();
        let record = record.to_string();
        let seat = site.seat.clone();
        tokio::spawn(async move {
            let delivery_address = delivery.to_string();
            let ask = || async {
                match seat.as_ref() {
                    // A room verb: no scope, on the engine that holds the room.
                    Some(seat) => {
                        let (delivery, leg) = (&delivery_address, target_leg);
                        backend
                            .attach_x3_seat(seat, delivery, xid, correlation_id, leg)
                            .await
                    }
                    None => {
                        leg.run(backend.attach_x3(
                            leg.call_id(),
                            &from_tag,
                            &delivery_address,
                            xid,
                            correlation_id,
                            target_leg,
                        ))
                        .await
                    }
                }
            };
            // The engine refuses an attach while the call is changing shape
            // under it (a re-answer, a pipeline being rebuilt) and says to ask
            // again. That passes in a moment, so it is asked again a few times
            // before it is a fault. Nothing is held across the wait, and the
            // attempt is given up once siphon has ended its engine call.
            let mut delays = X3_ATTACH_RETRY_DELAYS.into_iter();
            let attached = loop {
                let attached = ask().await;
                let retryable = matches!(&attached, Err(error) if error.is_x3_attach_retryable());
                let Some(delay) = delays.next().filter(|_| retryable) else {
                    break attached;
                };
                tokio::time::sleep(delay).await;
                if !li.x3_attempt_in_progress(&record, leg.scope(), attempt) {
                    li.x3_attach_failed(&record, leg.scope(), x_id, d_id, attempt);
                    debug!(
                        %x_id, %d_id, %call_id,
                        "LI: the media was released while an X3 attach was being retried"
                    );
                    return;
                }
            };
            let error = match attached {
                Ok(()) => {
                    info!(
                        %x_id, %d_id, %call_id, %delivery, correlation_id,
                        scope = leg.scope().map(crate::rtpengine::CallScope::as_str),
                        "X3 content delivery attached"
                    );
                    li.audit(
                        crate::li::AuditOperation::MediaCaptureStarted,
                        Some(&x_id.to_string()),
                        format!(
                            "X3 attached call_id={call_id} leg={} destination={delivery}",
                            leg_name(leg.scope())
                        ),
                    );
                    return;
                }
                Err(error) => error,
            };
            // The record goes either way: nothing is being delivered on it.
            let failed = li.x3_attach_failed(&record, leg.scope(), x_id, d_id, attempt);
            if failed == crate::li::FailedAttach::EndedBySiphon && error.is_call_not_found() {
                // siphon deleted the engine call while the attach was on its
                // way (a CANCEL, a rejection): there is no call to intercept
                // and nothing warranted went undelivered.
                debug!(
                    %x_id, %d_id, %call_id, %error,
                    "LI: the media was released before X3 could attach, no content to deliver"
                );
                return;
            }
            // Warranted content is not being delivered. The ADMF has to
            // hear about it — this is the whole point of the
            // network-element-to-ADMF direction.
            error!(
                %x_id, %d_id, %call_id, %error,
                "could not attach X3 content delivery — warranted content is \
                 NOT being delivered for this call"
            );
            li.audit(
                crate::li::AuditOperation::MediaCaptureStarted,
                Some(&x_id.to_string()),
                format!(
                    "X3 attach FAILED call_id={call_id} leg={}: {error}",
                    leg_name(leg.scope())
                ),
            );
            report_destination_fault(
                &li,
                d_id,
                crate::li::x1::types::TaskReportType::TerminatingFault,
                format!("could not attach X3 delivery for task {x_id}: {error}"),
            )
            .await;
        });
    }
}

/// Two sessions share one engine call (two calls bridged onto it) and the same
/// warrant covers both: each is owed the content under its own Correlation
/// ID, to the same destination. The engine holds one delivery of a warrant
/// per engine call, and a second attach would replace the first, so the
/// second session's content cannot be delivered under its Correlation ID.
/// That is warranted content not being delivered as the warrant's records
/// say, and the ADMF is told, naming both: the mediation function can then
/// tie the X2 records of `wanted` to the X3 delivered under `held`.
fn second_correlation_undeliverable(
    li: &crate::li::LiManager,
    (x_id, d_id): (crate::li::x1::types::XId, crate::li::x1::types::DId),
    call_id: &str,
    held: u64,
    wanted: u64,
) {
    error!(
        %x_id, %d_id, %call_id, held, wanted,
        "X3 content of a second session on one engine call is NOT being delivered under \
         its own Correlation ID: the engine holds one delivery of a warrant per engine call"
    );
    let detail = format!(
        "X3 for task {x_id} cannot be delivered under correlation {wanted}: its content is on \
         an engine call shared with the session of correlation {held}, and is delivered \
         under {held} only"
    );
    li.audit(
        crate::li::AuditOperation::MediaCaptureStarted,
        Some(&x_id.to_string()),
        format!("X3 attach FAILED call_id={call_id}: {detail}"),
    );
    let li = li.clone();
    tokio::spawn(async move {
        let fault = crate::li::x1::types::TaskReportType::TerminatingFault;
        report_destination_fault(&li, d_id, fault, detail).await;
    });
}

/// How long to wait before each further try of an attach the engine refused
/// for a reason that passes: three more within a second.
const X3_ATTACH_RETRY_DELAYS: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(300),
    std::time::Duration::from_millis(600),
];

/// The From-tag of `message`.
fn from_tag(message: &SipMessage) -> Option<String> {
    message.headers.get("From").and_then(|from| {
        from.split(';')
            .find(|part| part.trim().starts_with("tag="))
            .map(|tag| tag.trim().trim_start_matches("tag=").to_string())
    })
}

/// Follow the engine calls siphon creates and ends, for the content delivery
/// of intercepted calls.
///
/// Registers with the media backend to be told of every engine call an
/// `offer` or an `answer_local` creates there, of every seat a party joins a
/// conference room with, and of every one siphon ends (a `delete`, an `offer`
/// replacing a call, a joined seat leaving its room), whichever path did it: a
/// script's `rtpengine.offer()` / `rtpengine.delete()` /
/// `rtpengine.conference_join()` on a proxied request or a B2BUA call, or
/// siphon's own for a dial, a route, a failure or a teardown.
///
/// The first three are where content delivery is attached on an engine that
/// accepts an interception there ([`media_offered`], [`seat_joined`]). siphon
/// ending the engine call, or taking the seat out of its room, is the one way
/// a delivery ends with its call that is not a fault, and it frees the leg
/// for the next engine call's attachment
/// ([`LiManager::x3_media_ended_by_siphon`]).
///
/// A call's leg moved into a room in place (`conference_seat`) is told of
/// nowhere here, and neither is its leaving: the engine carries the call's
/// interception into the room and back on the same connection, Correlation ID
/// and sequence, and ends it with the call. Nothing is detached and nothing
/// is asked for again.
///
/// Only the native engine tells anyone; on rtpengine and rtpproxy, which
/// cannot deliver X3, this registers nothing.
pub(super) fn watch_engine_calls(state: &Arc<DispatcherState>) {
    use crate::li::EngineCallSide;
    use crate::rtpengine::siphon_rtp::{EngineCallChange, X3Feature};
    if state.li_manager.is_none() {
        return;
    }
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    // Weak, because the state owns the backend the observer is kept by.
    let state = Arc::downgrade(state);
    backend.observe_calls(Box::new(move |call| {
        let Some(state) = state.upgrade() else {
            return;
        };
        let (Some(li), Some(backend)) = (state.li_manager.as_ref(), state.rtpengine_set.as_ref())
        else {
            return;
        };
        // The node's own scope is the call's own media, as the ACK path names it.
        let scope = call.scope.filter(|scope| !backend.is_node_scope(scope));
        let seat = || crate::li::Seat {
            conference_id: Arc::from(call.call_id),
            tag: Arc::from(call.from_tag),
        };
        match call.change {
            // Before the frame is written: one map lookup, which misses for
            // every call no content warrant covers.
            EngineCallChange::Ending => li.x3_media_ending(call.call_id, scope),
            // The command's answer. Until it comes an end the engine reports
            // is the command's; a command the engine refused ended nothing,
            // and the delivery is watched again as any live one is.
            EngineCallChange::Ended => {
                let held = li.x3_media_end_committed(call.call_id, scope);
                super::rtpengine_events::x3_end_answered(li, held);
                li.engine_call_is_live(call.call_id, false);
            }
            EngineCallChange::EndFailed => {
                let held = li.x3_media_end_failed(call.call_id, scope);
                super::rtpengine_events::x3_end_answered(li, held);
            }
            // Every allocation siphon makes says which dialog's SDP it
            // carries. That dialog's session owns the engine call, which is
            // how one under an id siphon minted (a dial, a bridge, a transfer,
            // a take-over) is tied to its call's interception, whichever path
            // made it.
            EngineCallChange::Offered | EngineCallChange::AnsweredLocally => {
                let dialog = call.sip_call_id.unwrap_or(call.call_id);
                if scope.is_none() {
                    li.adopt_engine_call(dialog, call.call_id, EngineCallSide::Offerer);
                    li.engine_call_is_live(call.call_id, true);
                }
                let feature = match call.change {
                    EngineCallChange::Offered => X3Feature::AttachAtOffer,
                    _ => X3Feature::SingleLeg,
                };
                let engine_call = (call.call_id, call.from_tag, scope.cloned());
                media_offered(&state, dialog, engine_call, feature);
            }
            EngineCallChange::Answered => {
                if scope.is_none() {
                    if let Some(dialog) = call.sip_call_id {
                        li.adopt_engine_call(dialog, call.call_id, EngineCallSide::Answerer);
                    }
                    minted_engine_call_answered(&state, call.call_id, call.from_tag);
                }
            }
            EngineCallChange::SeatJoined => {
                if let Some(sip_call_id) = call.sip_call_id {
                    seat_joined(&state, sip_call_id, seat());
                }
            }
            // Before the frame is written, as for a delete. A seated call's
            // leg leaving its room has no record under the seat and ends
            // nothing.
            EngineCallChange::SeatLeaving => {
                li.x3_media_ending(&seat().record(), None);
            }
            EngineCallChange::SeatLeft => {
                let seat = seat();
                let held = li.x3_media_end_committed(&seat.record(), None);
                super::rtpengine_events::x3_end_answered(li, held);
                if let Some(sip_call_id) = call.sip_call_id {
                    li.seat_left(sip_call_id, &seat);
                }
            }
            // The seat is still in its room, and still the session's.
            EngineCallChange::SeatLeaveFailed => {
                let held = li.x3_media_end_failed(&seat().record(), None);
                super::rtpengine_events::x3_end_answered(li, held);
            }
        }
    }));
}

/// A party of a call has just been seated in a conference room: if a content
/// warrant covers the call and the engine takes an interception on a joined
/// seat, ask for it now, on the seat.
///
/// The session learns the seat either way, so that its ACK asks for the seat
/// and not for a call the engine does not hold, and its end detaches it. Runs
/// inside the join, so it only decides, like [`media_offered`].
fn seat_joined(state: &Arc<DispatcherState>, sip_call_id: &str, seat: crate::li::Seat) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    if !li.is_intercepting() {
        return;
    }
    let Some(session) = li.note_seat(sip_call_id, seat.clone()) else {
        return;
    };
    if !session
        .matches
        .iter()
        .any(|matched| matched.task.details.delivery_type.includes_content())
    {
        return;
    }
    // Under the attempt in progress now: a seat that has left by the time the
    // engine has said what it lists is not asked for.
    let site = X3Site::seat(state, &seat);
    let attach = {
        let state = Arc::clone(state);
        move |listed: bool| {
            if !listed {
                // The ACK asks, and an engine that cannot is a loud fault.
                return;
            }
            for matched in &session.matches {
                attach_x3(matched, &session, &site, &state);
            }
        }
    };
    when_seats_are_interceptable(state, &seat.conference_id, attach);
}

/// A call's media has just reached the engine, by an `offer` or by a local
/// answer: if a content warrant covers the call and the engine takes an
/// interception on such a call this early (`feature`), ask for it now.
///
/// Runs inside the verb, between the engine accepting it and the rewritten
/// SDP going back to whoever asked, so it only decides: the attach itself
/// is spawned ([`attach_x3`]), and so is the one `node_info` round trip that
/// asks a freshly connected engine what it lists. The INVITE is neither held
/// nor failed by any of it. No Python is attached here and none is taken.
///
/// `dialog` is the SIP dialog whose SDP the verb carried, and the engine call
/// is its id, its offerer's tag and the per-call scope it is under.
fn media_offered(
    state: &Arc<DispatcherState>,
    dialog: &str,
    (call_id, from_tag, scope): (&str, &str, Option<crate::rtpengine::CallScope>),
    feature: crate::rtpengine::siphon_rtp::X3Feature,
) {
    let (Some(li), Some(backend)) = (state.li_manager.as_ref(), state.rtpengine_set.as_ref())
    else {
        return;
    };
    if !li.is_intercepting() {
        return;
    }
    // The session interception decided on the INVITE, which ran before the
    // script that made this offer. The engine call is the session's when it
    // is under the session's anchoring Call-ID, or under an id siphon minted
    // and registered with the session before offering it (a transfer
    // re-anchoring an answered call, [`LiManager::adopt_engine_call`]). An
    // offer under any other id names no session.
    let Some(session) = li.session_of_leg(dialog) else {
        return;
    };
    if &*session.engine_call_id != call_id
        || !session
            .matches
            .iter()
            .any(|matched| matched.task.details.delivery_type.includes_content())
    {
        return;
    }
    // The engine call this verb created. An attach decided for it is not
    // made once siphon has ended it, which a CANCEL can do before the engine
    // has said what it lists.
    let attempt = li.x3_attempt(call_id, scope.as_ref());
    let attach = {
        let state = Arc::clone(state);
        let site = X3Site::call_leg(&session, from_tag, scope.clone(), attempt);
        move || {
            for matched in &session.matches {
                attach_x3(matched, &session, &site, &state);
            }
        }
    };
    match backend.x3_feature(feature, call_id, scope.as_ref()) {
        Some(true) => attach(),
        // An engine that does not take it this early: the ACK attaches.
        Some(false) => {}
        // The first intercepted call on this connection: ask the engine what
        // it lists, off the verb's path.
        None => {
            let backend = Arc::clone(backend);
            let call_id = call_id.to_string();
            tokio::spawn(async move {
                match backend
                    .learn_x3_feature(feature, &call_id, scope.as_ref())
                    .await
                {
                    Ok(true) => attach(),
                    Ok(false) => {}
                    Err(error) => warn!(
                        %call_id, %error,
                        "LI: could not read the media engine's features, X3 attaches at the ACK"
                    ),
                }
            });
        }
    }
}

/// An engine call siphon minted has been answered at the engine: both
/// parties are in it now, which is what the caller's ACK says of an ordinary
/// call. No ACK says it here: siphon sends the ACKs of the legs it bridges,
/// dials and transfers itself. So each session with media on that engine call
/// is asked for whatever content delivery it has no record of there, which on
/// an engine that takes an interception at the offer is nothing.
fn minted_engine_call_answered(state: &DispatcherState, engine_call_id: &str, offerer_tag: &str) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    if !li.is_intercepting() {
        return;
    }
    for session_id in li.sessions_on_engine_call(engine_call_id) {
        // As the session stands on this engine call, and not on whichever it
        // was offered last: of a transfer forked to two targets the one that
        // answers is the one with media, whatever the order they were
        // offered in and whether the loser's engine call is gone yet.
        let Some(session) = li.session_on_engine_call(&session_id, engine_call_id) else {
            continue;
        };
        let attempt = li.x3_attempt(engine_call_id, None);
        let site = X3Site::call_leg(&session, offerer_tag, None, attempt);
        for matched in &session.matches {
            attach_x3(matched, &session, &site, state);
        }
    }
}

/// The legs of the call `engine_call_id` names whose media an interception
/// taps: the call's own media (`None`) when siphon anchored it, and every leg a
/// script anchored under a per-call scope (`rtpengine.offer(..., scope=)`).
/// With neither recorded, the call's own media, as before scopes existed: the
/// engine then answers for itself whether it holds the call.
///
/// Every leg rather than one, by choice: on a proxy anchoring the originating
/// and the terminating leg of one call each leg is an engine call of its own,
/// and tapping only one could lose content the other carries (media a leg
/// plays or bridges locally). Two deliveries of one conversation, each tagged
/// with its leg and the session's one Correlation ID, are recoverable at the
/// mediation function; a delivery never made is not.
pub(super) fn intercepted_legs(
    state: &DispatcherState,
    engine_call_id: &str,
) -> Vec<Option<crate::rtpengine::CallScope>> {
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return vec![None];
    };
    let mut legs: Vec<Option<crate::rtpengine::CallScope>> = sessions
        .scopes_holding(engine_call_id)
        .into_iter()
        .map(Some)
        .collect();
    if legs.is_empty() || sessions.get(engine_call_id).is_some() {
        legs.insert(0, None);
    }
    legs
}

/// How an audit record names a leg: its per-call scope, or `call` for the
/// call's own media.
fn leg_name(scope: Option<&crate::rtpengine::CallScope>) -> &str {
    scope.map_or("call", crate::rtpengine::CallScope::as_str)
}

/// Stop content delivery for a session, if any was attached: on its engine
/// call, each leg on the leg it was attached on, and on each conference seat
/// a party of it joined.
///
/// What is detached stays on record until the engine reports its delivery
/// ended ([`LiManager::x3_detaching`]): that report says whether content was
/// dropped on the way out, and a transport failure can beat the detach to it.
/// Either is a fault, and a fault needs the warrant it is reported against.
///
/// Not on an engine call whose leg sits in a conference room: see below.
pub(super) fn detach_x3(session: &crate::li::SessionView, state: &Arc<DispatcherState>) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let call_id: &str = &session.engine_call_id;
    // A call whose leg was moved into a conference room
    // (`b2bua.adopt_replaced`) goes on without the dialog that was merged
    // away, and a BYE on that dialog, or on any other of the session, is not
    // the end of the media the engine delivers from the room. Detached there,
    // the delivery would stop cleanly and silently with the target still in
    // the room. Its interception ends with the engine call and with nothing
    // else: siphon's `delete`, whose `call_ended` is then clean, or the
    // engine's own, which is a fault.
    let seated = crate::rtpengine::MediaBackend::seated_call_room(call_id).is_some();
    let on_call = match seated {
        true => Vec::new(),
        false => li.x3_detaching(call_id),
    };
    let on_seats: Vec<_> = session
        .seats
        .iter()
        .map(|seat| (seat.clone(), li.x3_detaching(&seat.record())))
        .filter(|(_, attachments)| !attachments.is_empty())
        .collect();
    if on_call.is_empty() && on_seats.is_empty() {
        return;
    }
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    let backend = Arc::clone(backend);
    let li = li.clone();
    let call_id = call_id.to_string();
    tokio::spawn(async move {
        for attachment in on_call {
            // Each leg's delivery is detached on the leg it was attached on.
            let leg = backend.leg(&call_id, attachment.scope.as_ref());
            // Idempotent on the engine, so a duplicate teardown is harmless.
            let detached = leg.run(backend.detach_x3(leg.call_id(), &attachment.from_tag));
            if let Err(error) = detached.await {
                warn!(
                    x_id = %attachment.x_id, %call_id, %error,
                    "could not detach X3 content delivery"
                );
            }
            li.audit(
                crate::li::AuditOperation::MediaCaptureStopped,
                Some(&attachment.x_id.to_string()),
                format!(
                    "X3 detached call_id={call_id} leg={}",
                    leg_name(attachment.scope.as_ref())
                ),
            );
        }
        for (seat, attachments) in on_seats {
            let held = crate::rtpengine::backend::ConferenceSeat {
                conference_id: seat.conference_id.to_string(),
                from_tag: seat.tag.to_string(),
            };
            for attachment in attachments {
                if let Err(error) = backend.detach_x3_seat(&held).await {
                    warn!(
                        x_id = %attachment.x_id, conference_id = %seat.conference_id, %error,
                        "could not detach X3 content delivery from a conference seat"
                    );
                }
                li.audit(
                    crate::li::AuditOperation::MediaCaptureStopped,
                    Some(&attachment.x_id.to_string()),
                    format!(
                        "X3 detached conference_id={} seat={}",
                        seat.conference_id, seat.tag
                    ),
                );
            }
        }
    });
}

/// Raise a destination-level report toward the ADMF.
///
/// Delivery faults are exactly what the network-element-to-ADMF direction
/// exists for: a mediation outage has to be *reported*, not merely survived. A
/// node with no `admf:` block configured can only log it.
pub(super) async fn report_destination_fault(
    li: &crate::li::LiManager,
    d_id: crate::li::x1::types::DId,
    report_type: crate::li::x1::types::TaskReportType,
    detail: String,
) {
    let Some(client) = li.x1_client() else {
        warn!(
            %d_id, %detail,
            "an X3 delivery fault could not be reported to the ADMF — \
             lawful_intercept.x1.admf is not configured"
        );
        return;
    };
    if let Err(error) = client
        .report_destination_issue(
            d_id,
            report_type,
            Some(crate::li::x1::ErrorCode::TerminatingFault.number()),
            Some(detail),
        )
        .await
    {
        error!(%d_id, %error, "could not report an X3 delivery fault to the ADMF");
    }
}
