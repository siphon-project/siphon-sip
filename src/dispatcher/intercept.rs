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
    let session = li.resolve_session(call_id, &facts, &identities, || b2bua_owner(state, call_id));
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
            detach_x3(&session.engine_call_id, state);
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
        // **At the offer**, on a siphon-rtp that lists `x3_attach_at_offer`
        // in `node_info` (0.25.1 and later, when it is provisioned for X3).
        // That engine takes an interception on a call that is offered but not
        // answered: it opens the delivery connection at once, puts the taps on
        // at the first answer (a 183 with SDP included) and keeps the one
        // connection, Correlation ID and sequence through the final answer and
        // every re-offer. So the attach is sent as soon as the script's offer
        // has succeeded ([`watch_engine_calls`]), off the INVITE's path, and
        // the first packet after the answer and all early media are delivered.
        //
        // **At the ACK**, on an engine that does not list the feature (an
        // older siphon-rtp refuses an unanswered call: "no answered second
        // leg") and for whatever an offer did not attach: a warrant or a
        // destination added since, a leg on an engine without the feature, a
        // call the engine answered itself. Asked at the answer instead, the
        // older engine refused as well, since the response had not been
        // dispatched yet and the script had not answered it to the engine. The
        // ACK is the first message that arrives with the session established:
        // RFC 3261 §13 completes the offer/answer there, both legs are
        // answered in the engine, and it is in-dialog so it cannot be confused
        // with the INVITE.
        //
        // Either way each `(leg, warrant, destination)` is asked for once per
        // engine call: the request is recorded before it is sent, and the ACK
        // asks only for what has no record ([`attach_x3`]). That matters
        // because a failed attempt is a compliance signal reported to the ADMF
        // and must not be routine.
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
        if is_ack(message, &method) {
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
                // The engine keys an interception on the offerer's tag, which
                // is the dialog's From-tag.
                match from_tag(message) {
                    Some(from_tag) => {
                        let legs = intercepted_legs(state, &session.engine_call_id)
                            .into_iter()
                            .map(|leg| {
                                let attempt = li.x3_attempt(&session.engine_call_id, leg.as_ref());
                                (leg, attempt)
                            })
                            .collect();
                        attach_x3(matched, &session, &from_tag, legs, state);
                    }
                    None => error!(
                        xid = %x_id,
                        "a content warrant matched a message with no From-tag; cannot attach X3"
                    ),
                }
            }
        }
    }
}

/// The B2BUA call a Call-ID is a leg of, if any.
///
/// Asked only for a Call-ID interception has not seen before, which is the
/// first message of a leg.
fn b2bua_owner(state: &DispatcherState, call_id: &str) -> Option<crate::li::CallOwner> {
    let internal_id = state.call_actors.find_by_sip_call_id(call_id)?;
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
/// `from_tag` is the offerer's tag, which the engine keys the interception on,
/// and `legs` the legs of the call to tap, each with the number of its engine
/// call's attempt as the caller found it ([`LiManager::x3_attempt`]): every
/// leg the call has at its ACK ([`intercepted_legs`]), or the one leg an offer
/// has just anchored.
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
    from_tag: &str,
    legs: Vec<(Option<crate::rtpengine::CallScope>, u64)>,
    state: &Arc<DispatcherState>,
) {
    let call_id: &str = &session.engine_call_id;
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
    let target_leg = match matched.party {
        crate::li::target::MatchedParty::Originating => {
            crate::rtpengine::backend::X3TargetLeg::Caller
        }
        crate::li::target::MatchedParty::Terminating => {
            crate::rtpengine::backend::X3TargetLeg::Callee
        }
    };

    let attachments = named
        .iter()
        .flat_map(|destination| legs.iter().map(move |leg| (destination, leg)));
    for (destination, (scope, attempt)) in attachments {
        let Some(delivery) = destination.details.delivery_address.socket_addr() else {
            continue;
        };
        let d_id = destination.details.d_id;
        let attempt = *attempt;
        let recorded = li.register_x3_attachment(
            call_id,
            crate::li::ActiveIntercept {
                x_id,
                d_id,
                from_tag: from_tag.to_string(),
                correlation_id,
                scope: scope.clone(),
            },
            attempt,
        );
        if !recorded {
            continue;
        }
        let leg = backend.leg(call_id, scope.as_ref());
        let backend = Arc::clone(backend);
        let li = li.clone();
        let call_id = call_id.to_string();
        let from_tag = from_tag.to_string();
        tokio::spawn(async move {
            let delivery_address = delivery.to_string();
            let attached = leg.run(backend.attach_x3(
                leg.call_id(),
                &from_tag,
                &delivery_address,
                xid,
                correlation_id,
                target_leg,
            ));
            let error = match attached.await {
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
            let failed = li.x3_attach_failed(&call_id, leg.scope(), x_id, d_id, attempt);
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
/// `offer` creates there and of every one siphon ends (a `delete`, or an
/// `offer` replacing a call), whichever path did it: a script's
/// `rtpengine.offer()` / `rtpengine.delete()` on a proxied request or a B2BUA
/// call, or siphon's own for a dial, a route, a failure or a teardown.
///
/// An offer is where content delivery is attached on an engine that accepts
/// an interception before the answer ([`media_offered`]). siphon ending the
/// engine call is the one way a delivery ends with its call that is not a
/// fault, and it frees the leg for the next engine call's attachment
/// ([`LiManager::x3_media_ended_by_siphon`]).
///
/// Only the native engine tells anyone; on rtpengine and rtpproxy, which
/// cannot deliver X3, this registers nothing.
pub(super) fn watch_engine_calls(state: &Arc<DispatcherState>) {
    use crate::rtpengine::siphon_rtp::EngineCallChange;
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
        match call.change {
            // Before the frame is written: one map lookup, which misses for
            // every call no content warrant covers.
            EngineCallChange::Ending => li.x3_media_ended_by_siphon(call.call_id, scope),
            EngineCallChange::Offered => {
                media_offered(&state, call.call_id, call.from_tag, scope.cloned());
            }
        }
    }));
}

/// A call's media has just been offered to the engine: if a content warrant
/// covers the call and the engine takes an interception this early, ask for
/// it now.
///
/// Runs inside the offer, between the engine accepting it and the rewritten
/// SDP going back to whoever offered, so it only decides: the attach itself
/// is spawned ([`attach_x3`]), and so is the one `node_info` round trip that
/// asks a freshly connected engine what it lists. The INVITE is neither held
/// nor failed by any of it. No Python is attached here and none is taken.
fn media_offered(
    state: &Arc<DispatcherState>,
    call_id: &str,
    from_tag: &str,
    scope: Option<crate::rtpengine::CallScope>,
) {
    let (Some(li), Some(backend)) = (state.li_manager.as_ref(), state.rtpengine_set.as_ref())
    else {
        return;
    };
    if !li.is_intercepting() {
        return;
    }
    // The session interception decided on the INVITE, which ran before the
    // script that made this offer. An offer under an engine call-id that is
    // not the session's anchoring Call-ID (a dial's own allocation, a transfer
    // re-anchoring an answered call) names no session, and its content stays
    // with the ACK's attachment.
    let Some(session) = li.session_of_leg(call_id) else {
        return;
    };
    if !session.on_primary_leg
        || !session
            .matches
            .iter()
            .any(|matched| matched.task.details.delivery_type.includes_content())
    {
        return;
    }
    // The engine call this offer created. An attach decided for it is not
    // made once siphon has ended it, which a CANCEL can do before the engine
    // has said what it lists.
    let attempt = li.x3_attempt(call_id, scope.as_ref());
    let attach = {
        let state = Arc::clone(state);
        let from_tag = from_tag.to_string();
        let legs = vec![(scope.clone(), attempt)];
        move || {
            for matched in &session.matches {
                attach_x3(matched, &session, &from_tag, legs.clone(), &state);
            }
        }
    };
    match backend.x3_attach_at_offer(call_id, scope.as_ref()) {
        Some(true) => attach(),
        // An engine that does not take it this early: the ACK attaches.
        Some(false) => {}
        // The first intercepted offer on this connection: ask the engine what
        // it lists, off the offer's path.
        None => {
            let backend = Arc::clone(backend);
            let call_id = call_id.to_string();
            tokio::spawn(async move {
                match backend
                    .learn_x3_attach_at_offer(&call_id, scope.as_ref())
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

/// Stop content delivery for a call, if any was attached.
pub(super) fn detach_x3(call_id: &str, state: &Arc<DispatcherState>) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let attachments = li.take_x3_attachments(call_id);
    if attachments.is_empty() {
        return;
    }
    let Some(backend) = state.rtpengine_set.as_ref() else {
        return;
    };
    let backend = Arc::clone(backend);
    let li = li.clone();
    let call_id = call_id.to_string();
    tokio::spawn(async move {
        for attachment in attachments {
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
