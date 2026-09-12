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

    // Decided once per session, not once per message. See `check_session`:
    // this is what stops a warrant delivering the INVITE and then missing the
    // BYE, because a later message need not carry the target in matchable form.
    let matches = li.check_session(call_id, request_uri.as_deref(), from_uri, to_uri, source_ip);
    if matches.is_empty() {
        // An unwarranted session is remembered as unwarranted, and that
        // memory has to be released when the dialog ends or the map would
        // grow with every call the node ever handles and rely on the cap to
        // save it. The cap is for traffic that never reaches an end at all.
        if terminates_dialog(message) {
            li.forget_session(call_id);
        }
        return;
    }

    // A retransmission is the same message arriving again, not a new event.
    // Recording it twice would give the mediation function a duplicate and
    // re-run the session's lifecycle — a resent INVITE would restart content
    // capture on a call already being captured.
    if !li.record_message_once(call_id, message_instance_key(message)) {
        debug!(
            call_id = %call_id,
            "LI: message already recorded for this session, not recording the retransmission"
        );
        return;
    }

    let method = match &message.start_line {
        StartLine::Request(request_line) => request_line.method.as_str().to_string(),
        StartLine::Response(_) => message
            // A response's method is the one its CSeq names, which is what the
            // IRI record has to attribute it to.
            .headers
            .get("CSeq")
            .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
            .unwrap_or_else(|| "UNKNOWN".to_string()),
    };
    let status_code = match &message.start_line {
        StartLine::Request(_) => None,
        StartLine::Response(status_line) => Some(status_line.status_code),
    };
    let from_uri = from_uri.unwrap_or_default().to_string();
    let to_uri = to_uri.unwrap_or_default().to_string();

    // The event type follows the message, not the warrant: a mediation
    // function reconstructs the session from the sequence.
    let event_type = match (&message.start_line, method.as_str()) {
        (StartLine::Request(_), "INVITE") if !to_has_tag(message) => crate::li::IriEventType::Begin,
        (StartLine::Request(_), "BYE") | (StartLine::Request(_), "CANCEL") => {
            crate::li::IriEventType::End
        }
        (StartLine::Request(_), "REGISTER")
        | (StartLine::Request(_), "MESSAGE")
        | (StartLine::Request(_), "SUBSCRIBE")
        | (StartLine::Request(_), "PUBLISH")
        | (StartLine::Request(_), "OPTIONS") => crate::li::IriEventType::Report,
        (StartLine::Request(_), _) => crate::li::IriEventType::Continue,
        (StartLine::Response(_), _) => match status_code {
            Some(code) if code >= 300 => crate::li::IriEventType::End,
            _ => crate::li::IriEventType::Continue,
        },
    };

    for matched in &matches {
        let x_id = matched.task.details.x_id;
        let event = li.build_iri_event(
            matched,
            event_type,
            call_id,
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
                "method={method} call_id={call_id} delivery={} event={event_type:?} party={:?}",
                matched.task.details.delivery_type, matched.party
            ),
        );

        // Content capture stops when the dialog ends. There is no matching
        // "start" here: the attachment is made at the ACK, below, because the
        // engine has no call to intercept until the script has offered it one.
        if event_type == crate::li::IriEventType::End {
            detach_x3(call_id, state);
        }

        // X3 attaches when the media session is established, not when the
        // warrant matches.
        //
        // Interception is matched here, before the script runs, so a script
        // cannot decline a warrant. The attachment cannot be made here though,
        // because the engine only learns of a call when the script offers it
        // there and this runs first. Two earlier placements were both too
        // early, and the engine said so rather than accepting them:
        //
        //   at the dialog-forming INVITE  — "unknown call": the offer had not
        //                                   reached the engine yet.
        //   at the answer                 — "no answered second leg": the
        //                                   response had not been dispatched
        //                                   yet, so the script had not answered
        //                                   it to the engine.
        //
        // The ACK is the first message that arrives with the session already
        // established: RFC 3261 §13 completes the offer/answer there, both legs
        // are answered in the engine, and it is in-dialog so it cannot be
        // confused with the INVITE. Attaching there means one attempt that
        // succeeds, which matters because a failed attempt is a compliance
        // signal reported to the ADMF and must not be routine.
        if is_ack(message, &method) {
            attach_x3(matched, call_id, message, state);
        }
    }

    // Released once, after the message has been recorded, and in one place for
    // matched and unmatched sessions alike.
    //
    // Once per message rather than once per matching warrant, and *after* the
    // loop rather than inside it: the session is one thing however many
    // warrants cover it.
    if terminates_dialog(message) {
        li.forget_session(call_id);
    }
}

/// Tell the media engine to start ETSI TS 103 221-2 content delivery for a
/// matched warrant.
///
/// Only for a task whose `deliveryType` asks for content — an `X2Only` warrant
/// carries no content and must not open a delivery connection. Provisioning has
/// already refused a content warrant this node cannot service, so reaching here
/// means the backend can do it; a failure at the command is therefore a real
/// delivery fault and is reported to the ADMF rather than logged and forgotten.
pub(super) fn attach_x3(
    matched: &crate::li::x1::store::TaskMatch,
    call_id: &str,
    message: &SipMessage,
    state: &Arc<DispatcherState>,
) {
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
    // The engine keys an interception on the offerer's tag, which is the
    // dialog's From-tag.
    let from_tag = message.headers.get("From").and_then(|from| {
        from.split(';')
            .find(|part| part.trim().starts_with("tag="))
            .map(|tag| tag.trim().trim_start_matches("tag=").to_string())
    });
    let Some(from_tag) = from_tag else {
        error!(
            xid = %matched.task.details.x_id,
            "a content warrant matched a message with no From-tag; cannot attach X3"
        );
        return;
    };

    // Exactly the content-capable destinations this warrant named, less the
    // ones already being delivered to.
    //
    // Several messages in a dialog carry SDP — the 183, the 200, a re-INVITE —
    // and any of them can be the one that finds the session established, so
    // this runs more than once per call by design. Attaching twice would open a
    // second interception on the same leg and deliver every packet to the
    // agency twice.
    let already: std::collections::HashSet<_> = li
        .x3_attachments_for(call_id)
        .into_iter()
        .filter(|attachment| attachment.x_id == matched.task.details.x_id)
        .map(|attachment| attachment.d_id)
        .collect();
    let destinations: Vec<_> = li
        .tasks()
        .destinations_for_interface(matched.task.details.x_id, true)
        .into_iter()
        .filter(|destination| !already.contains(&destination.details.d_id))
        .collect();
    if !already.is_empty() && destinations.is_empty() {
        // Everything this warrant names is already attached; nothing to do and
        // nothing wrong.
        return;
    }
    if destinations.is_empty() {
        error!(
            xid = %matched.task.details.x_id,
            "a content warrant named no content-capable destination — refusing to \
             attach rather than deliver nowhere"
        );
        return;
    }

    let correlation_id = li.correlation_for(&matched.task, call_id);
    let xid = matched.task.details.x_id.as_bytes();
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

    for destination in destinations {
        let Some(delivery) = destination.details.delivery_address.socket_addr() else {
            continue;
        };
        let backend = Arc::clone(backend);
        let li = li.clone();
        let call_id = call_id.to_string();
        let from_tag = from_tag.clone();
        let x_id = matched.task.details.x_id;
        let d_id = destination.details.d_id;
        tokio::spawn(async move {
            match backend
                .attach_x3(
                    &call_id,
                    &from_tag,
                    &delivery.to_string(),
                    xid,
                    correlation_id,
                    target_leg,
                )
                .await
            {
                Ok(()) => {
                    li.record_x3_attachment(
                        &call_id,
                        crate::li::ActiveIntercept {
                            x_id,
                            d_id,
                            from_tag: from_tag.clone(),
                            correlation_id,
                        },
                    );
                    info!(
                        %x_id, %d_id, %call_id, %delivery, correlation_id,
                        "X3 content delivery attached"
                    );
                    li.audit(
                        crate::li::AuditOperation::MediaCaptureStarted,
                        Some(&x_id.to_string()),
                        format!("X3 attached call_id={call_id} destination={delivery}"),
                    );
                }
                Err(error) => {
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
                        format!("X3 attach FAILED call_id={call_id}: {error}"),
                    );
                    report_destination_fault(
                        &li,
                        d_id,
                        crate::li::x1::types::TaskReportType::TerminatingFault,
                        format!("could not attach X3 delivery for task {x_id}: {error}"),
                    )
                    .await;
                }
            }
        });
    }
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
            // Idempotent on the engine, so a duplicate teardown is harmless.
            if let Err(error) = backend.detach_x3(&call_id, &attachment.from_tag).await {
                warn!(
                    x_id = %attachment.x_id, %call_id, %error,
                    "could not detach X3 content delivery"
                );
            }
            li.audit(
                crate::li::AuditOperation::MediaCaptureStopped,
                Some(&attachment.x_id.to_string()),
                format!("X3 detached call_id={call_id}"),
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
