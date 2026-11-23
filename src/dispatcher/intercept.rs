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
    // Before the early return below: a call that opens before the first
    // warrant exists is the one a warrant activated in the middle of it has
    // to find.
    if li.is_enabled() {
        track_live_dialog(message, inbound, li);
    }
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
        // X2 carries what is sent to and received from the target. On a B2BUA
        // call the other party's leg is neither: what arrives there is not
        // recorded for a warrant whose target is on the other leg, and what
        // siphon sends the target on its own leg is ([`super::x2_outbound`]).
        // The session still lives by every message that arrives.
        if !li.is_on_target_leg(&session.session_id, call_id, x_id) {
            if event_type == crate::li::IriEventType::End {
                super::x3_delivery::detach_x3(&session, state);
            }
            continue;
        }
        let mut event = li.build_iri_event(
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
        event.destination_ip = Some(inbound.local_addr.ip());
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
            super::x3_delivery::detach_x3(&session, state);
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
    // call siphon answers itself (`x3_single_leg`, 0.25.2; into a WebSocket
    // server, `x3_ws_takeover`, 0.26.0), and when a party is seated in a
    // conference room (`x3_conference_seat`, 0.25.2), which is attached on
    // the seat and not on a call. That engine takes an
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
    // Either way each delivery (a leg, a warrant, a destination and the
    // session's Correlation ID) is asked for once per engine call: the request
    // is recorded before it is sent, and the ACK asks only for what has no
    // record ([`attach_x3`]). That matters because a failed attempt is a
    // compliance signal reported to the ADMF and must not be routine.
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

/// Keep [`crate::li::live_dialogs`] in step with the dialogs this message
/// opens, answers and ends.
///
/// An initial INVITE costs one lookup, and an insert when it is new. A
/// request that is not one is a method comparison. A response is a status
/// comparison, and past that nothing on a node that holds no dialog.
fn track_live_dialog(message: &SipMessage, inbound: &InboundMessage, li: &crate::li::LiManager) {
    match &message.start_line {
        StartLine::Request(request_line) => match request_line.method.as_str() {
            "INVITE" if !to_has_tag(message) => {
                let (Some(call_id), Some(from), Some(to)) = (
                    message.headers.call_id(),
                    message.headers.get("From"),
                    message.headers.get("To"),
                ) else {
                    return;
                };
                li.live_dialog_opened(
                    call_id,
                    &request_line.request_uri,
                    from,
                    to,
                    Some(inbound.remote_addr.ip()),
                );
            }
            "BYE" => {
                if let Some(call_id) = message.headers.call_id() {
                    li.live_dialog_ended(call_id);
                }
            }
            // The CANCEL of a dialog-forming INVITE. One of a re-INVITE
            // carries the dialog's To-tag and ends nothing.
            "CANCEL" if !to_has_tag(message) => {
                if let Some(call_id) = message.headers.call_id() {
                    li.live_dialog_failed(call_id);
                }
            }
            _ => {}
        },
        StartLine::Response(status_line) => {
            if status_line.status_code < 200 || !li.holds_live_dialogs() {
                return;
            }
            let Some(call_id) = message.headers.call_id() else {
                return;
            };
            let method = message
                .headers
                .get("CSeq")
                .and_then(|cseq| cseq.split_whitespace().nth(1));
            match (method, status_line.status_code) {
                (Some("BYE"), _) => li.live_dialog_ended(call_id),
                (Some("INVITE"), 200..=299) => li.live_dialog_answered(call_id),
                // Final failure of an INVITE: the dialog never formed, unless
                // this is the failure of a re-INVITE inside one that did.
                (Some("INVITE"), _) => li.live_dialog_failed(call_id),
                _ => {}
            }
        }
    }
}

/// Follow the warrants, so one activated while a call is up takes effect at
/// once and not at the call's next message, and one withdrawn stops at once.
///
/// Wakes on every change of the provisioned warrants and destinations and
/// acts on it ([`warrants_changed`]). Holds the dispatcher state weakly, as
/// [`watch_engine_calls`] does, and ends with it: on the next change, or at
/// the next poll when there is none.
pub(super) fn watch_warrants(state: &Arc<DispatcherState>) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let mut changes = li.subscribe_tasks();
    let mut destination_changes = li.subscribe_destinations();
    let mut known = known_targets(li);
    let state = Arc::downgrade(state);
    tokio::spawn(async move {
        loop {
            let woken = tokio::time::timeout(WARRANT_WATCH_POLL, async {
                tokio::select! {
                    changed = changes.changed() => changed.is_ok(),
                    changed = destination_changes.changed() => changed.is_ok(),
                }
            })
            .await;
            match woken {
                Ok(true) => {}
                // Every store is gone.
                Ok(false) => return,
                Err(_) if state.strong_count() == 0 => return,
                Err(_) => continue,
            }
            let Some(state) = state.upgrade() else {
                return;
            };
            warrants_changed(&state, &mut known).await;
        }
    });
}

/// How often the warrant watcher looks whether the dispatcher it serves is
/// still there, when no warrant has changed.
const WARRANT_WATCH_POLL: std::time::Duration = std::time::Duration::from_secs(30);

/// How many dialogs a scan looks at before it lets other tasks run.
const WARRANT_SCAN_CHUNK: usize = 256;

/// The targets each provisioned warrant names.
type KnownTargets = std::collections::HashMap<
    crate::li::x1::types::XId,
    Vec<crate::li::x1::types::TargetIdentifier>,
>;

pub(super) fn known_targets(li: &crate::li::LiManager) -> KnownTargets {
    li.tasks()
        .list()
        .into_iter()
        .map(|task| (task.details.x_id, task.details.target_identifiers))
        .collect()
}

/// The warrants or destinations have changed.
///
/// What is no longer provisioned is detached first, on every change
/// ([`x3_delivery::detach_unwarranted`]): a warrant deactivated, one that now
/// asks for no content or names another destination, a destination removed,
/// and a warrant whose target changed and no longer names a call that is up.
/// Then the live dialogs a warrant covers now are found and their interception
/// started ([`warrant_live_dialog`]).
///
/// The dialogs are copied out of the index first, so nothing is held while
/// each is matched and asked of the call stores. A dialog no warrant names is
/// left alone, and one that is already warranted is decided again, which
/// keeps what it has and adds what is new; each attach is idempotent per
/// record, attempt and delivery ([`attach_x3`]), so doing it again asks for
/// nothing twice.
pub(super) async fn warrants_changed(state: &Arc<DispatcherState>, known: &mut KnownTargets) {
    let Some(li) = state.li_manager.as_ref() else {
        return;
    };
    let now = known_targets(li);
    let retargeted: Vec<_> = now
        .iter()
        .filter(|(x_id, targets)| known.get(x_id).is_some_and(|before| before != *targets))
        .map(|(x_id, _)| *x_id)
        .collect();
    *known = now;
    let dialogs = li.live_dialogs();
    if !retargeted.is_empty() {
        retract_dropped_targets(li, &dialogs, &retargeted);
    }
    super::x3_delivery::detach_unwarranted(state);
    if !li.is_intercepting() {
        return;
    }
    for (scanned, dialog) in dialogs.into_iter().enumerate() {
        if scanned % WARRANT_SCAN_CHUNK == WARRANT_SCAN_CHUNK - 1 {
            tokio::task::yield_now().await;
        }
        warrant_live_dialog(state, li, &dialog);
    }
}

/// A warrant's target was changed: a call it covered, as the call opened, and
/// that it no longer names stops being covered. Only calls this node saw
/// open, and only warrants whose target changed, so a call matched on some
/// later message's identities is never dropped by an unrelated change.
fn retract_dropped_targets(
    li: &crate::li::LiManager,
    dialogs: &[crate::li::live_dialogs::LiveDialog],
    retargeted: &[crate::li::x1::types::XId],
) {
    for dialog in dialogs {
        let Some(session) = li.session_of_leg(&dialog.call_id) else {
            continue;
        };
        let named: Vec<_> = li
            .tasks()
            .match_message(
                Some(&dialog.request_uri),
                Some(&dialog.from),
                Some(&dialog.to),
                dialog.source_ip,
            )
            .into_iter()
            .map(|matched| matched.task.details.x_id)
            .collect();
        for matched in &session.matches {
            let x_id = matched.task.details.x_id;
            if retargeted.contains(&x_id) && !named.contains(&x_id) {
                li.drop_session_warrant(&session.session_id, x_id);
            }
        }
    }
}

/// What a live dialog's call is, as far as content is concerned.
pub(super) struct LiveCall {
    owner: Option<crate::li::CallOwner>,
    answered: bool,
    /// The Call-IDs of the call's callee legs.
    other_legs: Vec<String>,
}

/// Whether `dialog` is a call that is up, and whether it is answered.
///
/// A B2BUA call is up while its actor is not terminated, and answered in the
/// state it says. A proxied call is up while the media path holds a session
/// for it or a party of it sits in a conference room, and answered once that
/// has its answer or the party is seated. Nothing else is: a dialog whose
/// call has ended is no business of a warrant. The sweep of the dialog index
/// asks this too ([`sweep_live_dialogs`]), so what is swept is what the scan
/// would not act on.
pub(super) fn live_call(
    state: &DispatcherState,
    dialog: &crate::li::live_dialogs::LiveDialog,
) -> Option<LiveCall> {
    let call_id: &str = &dialog.call_id;
    if let Some(internal_id) = state.call_actors.find_by_sip_call_id(call_id) {
        let call_state = state.call_actors.get_call(&internal_id)?.state.clone();
        if call_state == crate::b2bua::actor::CallState::Terminated {
            return None;
        }
        let replacement_target = state
            .call_actors
            .is_replacement_target_leg(&internal_id, call_id);
        let other_legs = state
            .call_actors
            .get_call(&internal_id)?
            .b_legs
            .iter()
            .map(|leg| leg.dialog.call_id.clone())
            .collect();
        let owner = call_owner(&state.call_actors, internal_id, replacement_target)?;
        return Some(LiveCall {
            owner: Some(owner),
            answered: call_state == crate::b2bua::actor::CallState::Answered,
            other_legs,
        });
    }
    let session = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(call_id));
    // A party seated in a room has no call at the engine, and is answered by
    // being seated.
    let seated = crate::rtpengine::MediaBackend::conference_seat(call_id).is_some();
    if session.is_none() && !seated {
        return None;
    }
    Some(LiveCall {
        owner: None,
        other_legs: Vec::new(),
        answered: seated
            || dialog.answered
            || session.is_some_and(|session| session.to_tag.is_some()),
    })
}

/// Release the dialogs whose call is gone. See [`live_call`].
pub(super) fn sweep_live_dialogs(
    state: &DispatcherState,
    li: &crate::li::LiManager,
    now: std::time::Instant,
) {
    li.sweep_live_dialogs(now, |dialog| live_call(state, dialog).is_some());
}

/// A live dialog a warrant covers, decided and not yet attached.
pub(super) struct DecidedLiveDialog {
    session: crate::li::SessionView,
    answered: bool,
    offerer_tag: String,
}

/// Decide the session of one live dialog a warrant covers, and start the
/// delivery of its content where the call's media is.
///
/// The session is decided as its dialog-forming INVITE would have been
/// ([`crate::li::LiManager::decide_live_dialog`]), under the key a message of
/// the dialog decides it under, and no X2 is emitted: that resumes at the
/// call's next message. The content is attached on the sites the message
/// paths use. An answered call is attached as its ACK attaches it, a joined
/// seat on the seat. A call that is not answered is attached as its offer
/// attaches it, on an engine that takes an interception there; on one that
/// does not, its ACK asks, as before.
pub(super) fn warrant_live_dialog(
    state: &Arc<DispatcherState>,
    li: &crate::li::LiManager,
    dialog: &crate::li::live_dialogs::LiveDialog,
) {
    if let Some(decided) = decide_live_dialog(state, li, dialog) {
        attach_live_dialog(state, li, dialog, decided);
    }
}

/// The first half of [`warrant_live_dialog`]: whether a warrant covers the
/// dialog and its call is up, and the session decided.
pub(super) fn decide_live_dialog(
    state: &Arc<DispatcherState>,
    li: &crate::li::LiManager,
    dialog: &crate::li::live_dialogs::LiveDialog,
) -> Option<DecidedLiveDialog> {
    // The dialog may have ended since it was copied out of the index.
    if !li.live_dialog_held(dialog) {
        return None;
    }
    let covered = li.tasks().match_message(
        Some(&dialog.request_uri),
        Some(&dialog.from),
        Some(&dialog.to),
        dialog.source_ip,
    );
    if covered.is_empty() {
        return None;
    }
    let call_id: &str = &dialog.call_id;
    let call = live_call(state, dialog)?;
    let media = dialog_media(state, call_id);
    let offerer_tag = media
        .as_ref()
        .and_then(|media| media.offerer_tag.clone())
        .or_else(|| dialog.caller_tag().map(str::to_string));
    let session = li.decide_live_dialog(dialog, call.owner, media, call.answered, &call.other_legs);
    if session.matches.is_empty() {
        return None;
    }
    debug!(
        call_id = %call_id,
        session = %session.session_id,
        answered = call.answered,
        "LI: a warrant covers a call that is up, starting its interception"
    );
    if !session
        .matches
        .iter()
        .any(|matched| matched.task.details.delivery_type.includes_content())
    {
        return None;
    }
    let Some(offerer_tag) = offerer_tag else {
        error!(
            session = %session.session_id,
            "a content warrant matched a live call with no From-tag; cannot attach X3"
        );
        return None;
    };
    Some(DecidedLiveDialog {
        session,
        answered: call.answered,
        offerer_tag,
    })
}

/// The second half of [`warrant_live_dialog`]: attach what was decided, if the
/// call is still up. A BYE or a failure can have ended it since it was
/// decided, and what is attached for a call that has ended is warranted
/// content asked of an engine call that is not there.
pub(super) fn attach_live_dialog(
    state: &Arc<DispatcherState>,
    li: &crate::li::LiManager,
    dialog: &crate::li::live_dialogs::LiveDialog,
    decided: DecidedLiveDialog,
) {
    let call_id: &str = &dialog.call_id;
    let DecidedLiveDialog {
        mut session,
        answered,
        offerer_tag,
    } = decided;
    if !li.live_dialog_held(dialog) || live_call(state, dialog).is_none() {
        // Over: the decision made for it goes with it, as the message that
        // ended it would have released it.
        li.forget_session(&session.session_id);
        return;
    }
    // A party already seated in a room has its media in the seat.
    if let Some(held) = crate::rtpengine::MediaBackend::conference_seat(call_id) {
        let seat = crate::li::Seat {
            conference_id: Arc::from(held.conference_id),
            tag: Arc::from(held.from_tag),
        };
        if let Some(seated) = li.note_seat(call_id, seat) {
            session = seated;
        }
    }
    if answered {
        attach_at_ack(state, session, offerer_tag);
    } else {
        attach_at_offer(state, &session, call_id, &offerer_tag);
    }
}

/// Ask for the content of a call that is offered and not answered, as its
/// offer would have: on an engine that lists `x3_attach_at_offer`, and once
/// the call has media at the engine to attach to.
fn attach_at_offer(
    state: &Arc<DispatcherState>,
    session: &crate::li::SessionView,
    dialog: &str,
    offerer_tag: &str,
) {
    let Some(sessions) = state.rtpengine_sessions.as_ref() else {
        return;
    };
    let engine_call_id: &str = &session.engine_call_id;
    if sessions.get(engine_call_id).is_none() && sessions.scopes_holding(engine_call_id).is_empty()
    {
        // Not offered yet: its offer attaches it ([`watch_engine_calls`]),
        // the session being decided now.
        return;
    }
    for scope in intercepted_legs(state, engine_call_id) {
        media_offered(
            state,
            dialog,
            (engine_call_id, offerer_tag, scope),
            &[crate::rtpengine::siphon_rtp::X3Feature::AttachAtOffer],
        );
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
    /// The key of its record ([`crate::li::LiManager::x3_register`]).
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
    call_owner(&state.call_actors, internal_id, replacement_target)
}

/// The owner of the call `call_id` is a leg of, in `store`, with no message to
/// ask about a dialog it replaces: for a frame siphon sends on a leg it holds.
pub(crate) fn owner_of_leg(store: &CallActorStore, call_id: &str) -> Option<crate::li::CallOwner> {
    let internal_id = store.find_by_sip_call_id(call_id)?;
    let replacement_target = store.is_replacement_target_leg(&internal_id, call_id);
    call_owner(store, internal_id, replacement_target)
}

/// The owner of a leg of the call `internal_id`.
fn call_owner(
    store: &CallActorStore,
    internal_id: String,
    replacement_target: bool,
) -> Option<crate::li::CallOwner> {
    let a_leg_call_id = store.get_call(&internal_id)?.a_leg.dialog.call_id.clone();
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
/// Each delivery (a leg, a warrant, a destination, the session's Correlation
/// ID) is recorded before the engine is asked, and asked only when it had no
/// record: an offer and an ACK, or two ACKs (a re-INVITE has its own), then
/// ask once between them, and a delivery end that beats the engine's answer
/// finds its attachment. Attaching twice would have the engine end the
/// delivery it holds and start it again. Nothing is asked for a leg whose
/// engine call siphon has ended since the caller looked.
///
/// How many of them one engine call carries is the engine's to say
/// ([`super::x3_delivery`]): one for each warrant, destination and session
/// on a siphon-rtp that lists `x3_multi_delivery`, and one in all before
/// that, where a second is reported to the ADMF and never asked for.
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
        let ask = super::x3_delivery::X3Ask {
            record: record.to_string(),
            seat: site.seat.clone(),
            call_id: call_id.to_string(),
            attachment: crate::li::ActiveIntercept {
                x_id,
                d_id: destination.details.d_id,
                delivery: delivery.to_string(),
                from_tag: from_tag.to_string(),
                correlation_id,
                session_id: Arc::clone(&session.session_id),
                scope: scope.clone(),
            },
            attempt: *attempt,
            target_leg,
        };
        super::x3_delivery::ask_for(li, backend, ask, None);
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
                // The leg has an engine call again: what ended the last one
                // left nothing to ask for until now.
                li.x3_media_offered(call.call_id, scope);
                if scope.is_none() {
                    li.adopt_engine_call(dialog, call.call_id, EngineCallSide::Offerer);
                    li.engine_call_is_live(call.call_id, true);
                }
                // What says the engine takes an interception on the call
                // as it stands now. A call answered into a WebSocket server
                // (`ws_uri`, a hand-over to a bot) is taken by an engine
                // that lists `x3_ws_takeover`. One that lists only
                // `x3_single_leg` refuses it, and is asked as it always was:
                // its refusal is the fault it always was.
                let features: &[X3Feature] = match (call.change, call.takeover) {
                    (EngineCallChange::Offered, _) => &[X3Feature::AttachAtOffer],
                    (_, true) => &[X3Feature::WsTakeover, X3Feature::SingleLeg],
                    _ => &[X3Feature::SingleLeg],
                };
                let engine_call = (call.call_id, call.from_tag, scope.cloned());
                media_offered(&state, dialog, engine_call, features);
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
                li.x3_media_offered(&seat().record(), None);
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
/// interception on such a call this early (it lists one of `features`), ask
/// for it now.
///
/// A call handed to a bot (`call.handover(answer=True, ws_uri=...)`) is one
/// the engine answers itself into a WebSocket server. It is attached like any
/// call the engine answered: under the caller's Call-ID and the caller's tag,
/// which the `answer_local` was made under, with the server standing in for
/// the callee. An interception the call already has (one attached at its
/// offer, or at an earlier answer of the same dialog) is carried onto the
/// bridge by the engine, and is on record here, so nothing is asked twice.
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
    features: &'static [crate::rtpengine::siphon_rtp::X3Feature],
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
    // Whether the engine lists any of them; `None` while it has not been
    // asked on this connection, which is so of all of them at once.
    let listed = |backend: &crate::rtpengine::MediaBackend,
                  call_id: &str,
                  scope: Option<&crate::rtpengine::CallScope>| {
        features
            .iter()
            .map(|feature| backend.x3_feature(*feature, call_id, scope))
            .try_fold(false, |any, listed| listed.map(|listed| any || listed))
    };
    match listed(backend, call_id, scope.as_ref()) {
        Some(true) => attach(),
        // An engine that does not take it this early: the ACK attaches.
        Some(false) => {}
        // The first intercepted call on this connection: ask the engine what
        // it lists, off the verb's path. One answer says all of it.
        None => {
            let backend = Arc::clone(backend);
            let call_id = call_id.to_string();
            tokio::spawn(async move {
                let Some(first) = features.first() else {
                    return;
                };
                match backend
                    .learn_x3_feature(*first, &call_id, scope.as_ref())
                    .await
                {
                    Ok(true) => attach(),
                    Ok(false) => {
                        if listed(&backend, &call_id, scope.as_ref()) == Some(true) {
                            attach();
                        }
                    }
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
