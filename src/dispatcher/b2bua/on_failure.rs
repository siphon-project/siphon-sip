//! How a B2BUA call that could not be connected ends, and what
//! `@b2bua.on_failure` gets to say about it.
//!
//! A call fails in several places: every branch of a fork failed, the ring
//! timeout fired, the B-leg INVITE never left the box, an LCR sequence ran out of
//! carriers, or `@b2bua.on_answer` failed an answered B-leg. Each used to run the
//! failure handlers its own way and then end the call whatever they had asked
//! for, so a `call.dial()` to a fallback or a `call.reject()` with a chosen code
//! from `@b2bua.on_failure` was silently dropped. They all conclude here: the
//! handlers run once, before the caller hears anything, and what they left on
//! the `Call` decides whether the call ends, how, or lives on.

use crate::dispatcher::*;

/// How many times `@b2bua.on_failure` may route one call again.
///
/// Every re-route that fails runs the handler again, so a handler that always
/// re-dials a target that always fails would otherwise go round forever, and one
/// whose re-dial never leaves the box (an unresolvable target) would do so
/// synchronously, recursing through the undialled-call path. Ten is well past any
/// real fallback chain: a backup trunk, voicemail, an operator queue.
pub const MAX_FAILURE_REROUTES: u32 = 10;

/// What `@b2bua.on_failure` asked for, for a call that has failed.
#[derive(Debug, PartialEq)]
pub enum FailureDecision {
    /// No decision, or `call.terminate()`: end the call with the failure it
    /// ended on, as siphon always has.
    EndWithFailure,
    /// `call.reject(code, reason)`: end the call with this response instead of
    /// the one the failure produced.
    Reject { code: u16, reason: String },
    /// `call.dial()`, `call.fork()` or `call.route()`: route the call again.
    Reroute(CallAction),
    /// `call.handover(app)`: hand the still-unanswered call to a control app.
    Handover(CallAction),
    /// `call.answer()` already sent the caller a 2xx from the handler: the call
    /// lives on, answered by siphon itself.
    Answered,
    /// A decision that cannot apply here. The call ends with its failure, and
    /// the reason is logged rather than the decision silently dropped.
    Inapplicable {
        action: CallAction,
        why: &'static str,
    },
}

/// Classify what `@b2bua.on_failure` left on the `Call`.
///
/// `originated` is a call siphon placed itself: there is no caller to answer
/// and nothing to route again, so every decision is inapplicable there.
/// `reroutes` is how many times this call has already been routed again from a
/// failure; from [`MAX_FAILURE_REROUTES`] on a re-route is refused.
pub fn classify_failure_action(
    action: CallAction,
    originated: bool,
    reroutes: u32,
) -> FailureDecision {
    match action {
        CallAction::None | CallAction::Terminate => FailureDecision::EndWithFailure,
        action if originated => FailureDecision::Inapplicable {
            action,
            why: "a call siphon placed has no caller to answer and nothing to route again",
        },
        CallAction::Reject { code, reason } if (300..700).contains(&code) => {
            FailureDecision::Reject { code, reason }
        }
        action @ CallAction::Reject { .. } => FailureDecision::Inapplicable {
            action,
            why: "call.reject() from on_failure needs a 3xx-6xx status",
        },
        action @ (CallAction::Dial { .. }
        | CallAction::Fork { .. }
        | CallAction::RouteSequence { .. }) => {
            if reroutes >= MAX_FAILURE_REROUTES {
                FailureDecision::Inapplicable {
                    action,
                    why: "the call has already been routed again from on_failure too many times",
                }
            } else {
                FailureDecision::Reroute(action)
            }
        }
        action @ CallAction::Handover { .. } => FailureDecision::Handover(action),
        CallAction::Answered => FailureDecision::Answered,
        action @ (CallAction::AcceptRefer { .. }
        | CallAction::RejectRefer { .. }
        | CallAction::SendRefer { .. }) => FailureDecision::Inapplicable {
            action,
            why: "REFER decisions only apply inside @b2bua.on_refer or to an answered call",
        },
    }
}

/// The failure a call ends on: one `@b2bua.on_failure` left be, or a refusal of
/// the caller's request, which runs no handler.
pub enum FailedCallEnd<'a> {
    /// A B-leg's own final response, relayed to the caller as the leg that
    /// sent it.
    Relayed {
        message: &'a mut SipMessage,
        snapshot: &'a BLegResponseSnapshot,
    },
    /// A final response siphon builds for the caller from its own INVITE.
    Local { status_code: u16, reason: String },
    /// A refusal of the caller's own request that siphon has already built, with
    /// the headers only that refusal carries: a 422 (Session Interval Too Small)
    /// and its `Min-SE` (RFC 4028 §9). Sent as it is.
    Refusal { response: SipMessage },
    /// `420 Bad Extension` for a caller that `Require`s extensions the call
    /// cannot honour, listed in `Unsupported` (RFC 3261 §8.2.2.3). Built from the
    /// caller's INVITE like [`FailedCallEnd::Local`].
    BadExtension { unsupported: Vec<String> },
}

impl FailedCallEnd<'_> {
    /// The status and reason phrase the caller would be sent.
    fn status_and_reason(&self) -> (u16, String) {
        let response = match self {
            FailedCallEnd::Relayed { message, .. } => &**message,
            FailedCallEnd::Refusal { response } => response,
            FailedCallEnd::Local {
                status_code,
                reason,
            } => return (*status_code, reason.clone()),
            FailedCallEnd::BadExtension { .. } => {
                return (420, "Bad Extension".to_string());
            }
        };
        match &response.start_line {
            StartLine::Response(status_line) => {
                (status_line.status_code, status_line.reason_phrase.clone())
            }
            StartLine::Request(_) => (500, best_error_reason(500).to_string()),
        }
    }
}

/// Run `@b2bua.on_failure(call, code, reason)` and collect what the handlers
/// left on the `Call`.
///
/// Every handler runs, as before. If one raised, or the `Call` could not be
/// built, the outcome is empty and the call ends with its failure: a decision
/// taken by a failure handler that failed is not one to route a call on. The
/// caller must hold no lock on the A-leg INVITE, which the `Call` locks, and the
/// handlers run inline on this thread.
pub fn run_b2bua_failure_handlers(
    call_id: &str,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) -> CallHandlerOutcome {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
    if handlers.is_empty() {
        return CallHandlerOutcome::default();
    }
    let Some((a_leg, invite_arc)) = state.call_actors.get_call(call_id).and_then(|call| {
        call.a_leg_invite
            .clone()
            .map(|invite| (call.a_leg.clone(), invite))
    }) else {
        warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_failure");
        return CallHandlerOutcome::default();
    };
    let mut py_call = PyCall::new(
        call_id.to_string(),
        invite_arc,
        a_leg.transport.remote_addr.ip().to_string(),
        format!("{}", a_leg.transport.transport).to_lowercase(),
    )
    .with_flow(py_flow_from_leg(&a_leg.transport));
    // Every carrier tried, so a handler for an exhausted sequence can report
    // which ones failed and how, not just the code the call ended on.
    py_call.set_route_attempts(state.call_actors.route_attempts(call_id));

    Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for on_failure: {error}");
                return CallHandlerOutcome::default();
            }
        };
        let mut raised = false;
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python), status_code, reason)) {
                Ok(returned) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &returned) {
                            record_script_error("async B2BUA on_failure", &error);
                            raised = true;
                        }
                    }
                }
                Err(error) => {
                    record_script_error("B2BUA on_failure", &error);
                    raised = true;
                }
            }
        }
        if raised {
            return CallHandlerOutcome::default();
        }
        let borrowed = call_obj.borrow(python);
        CallHandlerOutcome::from_call(&borrowed)
    })
}

/// Conclude a call that could not be connected.
///
/// Runs `@b2bua.on_failure` with the failure `end` carries, then does what the
/// handlers decided: end the call with that failure, end it with the handler's
/// own response, route it again, hand it over, or leave it answered.
///
/// For a call that came in: one siphon placed goes through
/// [`run_originated_failure_handlers`], since it has no caller to answer.
pub fn conclude_failed_call(call_id: &str, end: FailedCallEnd<'_>, state: &DispatcherState) {
    let Some(reroutes) = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.failure_reroutes)
    else {
        debug!(call_id = %call_id, "B2BUA: the failed call is already gone — nothing left to conclude");
        return;
    };
    let (status_code, reason) = end.status_and_reason();
    let mut outcome = run_b2bua_failure_handlers(call_id, status_code, &reason, state);
    let action = std::mem::take(&mut outcome.action);

    // The handlers may have taken a while, and a CANCEL landing meanwhile has
    // already answered the caller 487 and removed the call. Acting now would put
    // a second final response on the same INVITE transaction (RFC 3261 §17.2.1).
    if invite_action_target_gone(call_id, &state.call_actors) {
        info!(
            call_id = %call_id,
            action = action.name(),
            "B2BUA: @b2bua.on_failure returned for a call that ended while it ran — decision not applied"
        );
        return;
    }

    match classify_failure_action(action, false, reroutes) {
        FailureDecision::EndWithFailure => end_failed_call(call_id, end, state),
        FailureDecision::Reject { code, reason } => {
            info!(
                call_id = %call_id,
                failed_with = status_code,
                status = code,
                "B2BUA: @b2bua.on_failure rejected the failed call with its own response"
            );
            end_failed_call(
                call_id,
                FailedCallEnd::Local {
                    status_code: code,
                    reason,
                },
                state,
            );
        }
        FailureDecision::Reroute(action) => {
            info!(
                call_id = %call_id,
                failed_with = status_code,
                action = action.name(),
                "B2BUA: @b2bua.on_failure routed the failed call again"
            );
            let replaces_route_sequence =
                matches!(action, CallAction::Dial { .. } | CallAction::Fork { .. });
            state
                .call_actors
                .begin_failure_reroute(call_id, replaces_route_sequence);
            reroute_failed_call(call_id, action, outcome, state);
        }
        FailureDecision::Handover(action) => {
            info!(
                call_id = %call_id,
                failed_with = status_code,
                "B2BUA: @b2bua.on_failure handed the failed call over to a control app"
            );
            reroute_failed_call(call_id, action, outcome, state);
        }
        FailureDecision::Answered => info!(
            call_id = %call_id,
            failed_with = status_code,
            "B2BUA: @b2bua.on_failure answered the caller itself — the call lives on"
        ),
        FailureDecision::Inapplicable { action, why } => {
            warn!(
                call_id = %call_id,
                action = action.name(),
                why,
                "B2BUA: @b2bua.on_failure asked for something that cannot apply — the call ends with its failure"
            );
            end_failed_call(call_id, end, state);
        }
    }
}

/// Run `@b2bua.on_failure` for a call siphon placed that the callee rejected.
///
/// The handler hears about it like about any failed call, but there is no
/// caller to answer and nothing to route again, so a decision it takes is
/// logged as one that cannot apply rather than dropped without a word. The
/// caller tears the call down.
pub fn run_originated_failure_handlers(
    call_id: &str,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let outcome = run_b2bua_failure_handlers(call_id, status_code, reason, state);
    if let FailureDecision::Inapplicable { action, why } =
        classify_failure_action(outcome.action, true, 0)
    {
        warn!(
            call_id = %call_id,
            action = action.name(),
            why,
            "originate: @b2bua.on_failure asked for something that cannot apply — the call ends with its failure"
        );
    }
}

/// Route a failed call again as `@b2bua.on_failure` asked, applying the rest of
/// what the handler set on the `Call` first, the way `@b2bua.on_invite`'s is.
fn reroute_failed_call(
    call_id: &str,
    action: CallAction,
    outcome: CallHandlerOutcome,
    state: &DispatcherState,
) {
    // A response to the caller goes where the INVITE came from, which by now is
    // only on record on the A-leg rather than in an inbound message.
    let target = state.call_actors.get_call(call_id).and_then(|call| {
        call.a_leg_invite.clone().map(|invite| {
            (
                invite,
                InboundMessage {
                    connection_id: call.a_leg.transport.connection_id,
                    transport: call.a_leg.transport.transport,
                    local_addr: call.a_leg_local_addr.unwrap_or(state.local_addr),
                    remote_addr: call.a_leg.transport.remote_addr,
                    data: bytes::Bytes::new(),
                },
            )
        })
    });
    let Some((invite_arc, reply_to)) = target else {
        error!(
            call_id = %call_id,
            "B2BUA: no stored A-leg INVITE — the failed call cannot be routed again, and is dropped"
        );
        state.call_actors.remove_call(call_id);
        state.call_event_receivers.remove(call_id);
        return;
    };
    apply_handler_side_state(call_id, outcome, state);
    apply_routing_action(call_id, action, &invite_arc, &reply_to, state);
}

/// End a failed call with `end`: close the CDR on the status the caller is
/// sent, send it, tell a control app why, release the media and the Ro
/// reservation, and remove the call.
pub fn end_failed_call(call_id: &str, end: FailedCallEnd<'_>, state: &DispatcherState) {
    let (status_code, reason) = end.status_and_reason();
    let Some((a_leg, a_leg_invite, a_leg_local_addr)) =
        state.call_actors.get_call(call_id).map(|call| {
            (
                call.a_leg.clone(),
                call.a_leg_invite.clone(),
                call.a_leg_local_addr,
            )
        })
    else {
        return;
    };

    // Every carrier tried, before the record is closed: an exhausted sequence is
    // exactly where the attempt list matters most.
    cdr_stamp_route_attempts(state, call_id);
    cdr_finalize_b2bua_fail(state, call_id, status_code);

    match end {
        FailedCallEnd::Relayed { message, snapshot } => {
            relay_failure_to_a_leg(call_id, message, snapshot, state);
        }
        FailedCallEnd::Local {
            status_code,
            reason,
        } => {
            if let Some(response) = a_leg_final_response(
                call_id,
                &a_leg,
                a_leg_invite.as_ref(),
                status_code,
                &reason,
                state,
            ) {
                // From the listener the A-leg INVITE arrived on, so a multi-homed
                // UDP host answers on the port it received on.
                send_message_from(
                    response,
                    a_leg.transport.transport,
                    a_leg.transport.remote_addr,
                    a_leg.transport.connection_id,
                    a_leg_local_addr,
                    state,
                );
            }
        }
        FailedCallEnd::Refusal { response } => {
            send_message_from(
                response,
                a_leg.transport.transport,
                a_leg.transport.remote_addr,
                a_leg.transport.connection_id,
                a_leg_local_addr,
                state,
            );
        }
        FailedCallEnd::BadExtension { unsupported } => {
            if let Some(mut response) = a_leg_final_response(
                call_id,
                &a_leg,
                a_leg_invite.as_ref(),
                status_code,
                &reason,
                state,
            ) {
                // RFC 3261 §8.2.2.3: a 420 MUST list the extensions it refuses.
                response.headers.set("Unsupported", unsupported.join(", "));
                send_message_from(
                    response,
                    a_leg.transport.transport,
                    a_leg.transport.remote_addr,
                    a_leg.transport.connection_id,
                    a_leg_local_addr,
                    state,
                );
            }
        }
    }

    finish_failed_call(call_id, &a_leg, status_code, &reason, state);
}

/// What ends every failed call once the caller has its final response: tell a
/// control app why, release the media and the Ro reservation, remove the call.
fn finish_failed_call(
    call_id: &str,
    a_leg: &crate::b2bua::actor::Leg,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    // A controlled call learns which status ended it (no-op otherwise): "failed"
    // alone does not say whether nobody answered or the callee refused.
    control_notify_terminated_with_cause(
        &a_leg.dialog.call_id,
        "failed",
        Some(status_code),
        Some(reason),
    );
    release_failed_call_media(&a_leg.dialog.call_id, state);
    // Release any Ro reservation `call.ro_authorize()` made before the call was
    // routed: CCR-TERMINATION with ~0 usage, and the status the caller was sent
    // as the cause, the same one the CDR records.
    spawn_ro_b2bua_stop(
        state,
        call_id,
        crate::diameter::rf::sip_status_to_cause_code(status_code),
    );
    state.call_actors.remove_call(call_id);
    state.call_event_receivers.remove(call_id);
}

/// Refuse the caller `420 Bad Extension`, listing `unsupported`, and end the
/// call, on a path no `@b2bua.on_failure` decision applies to.
///
/// RFC 3261 §8.2.2.3. [`FailedCallEnd::BadExtension`] is the same refusal for
/// a script's own routing action, where `@b2bua.on_failure` may still route
/// again under another policy. These paths have no such decision to revisit:
/// siphon answering the call itself is siphon as the only UAS, so no policy can
/// help, and a control plane `dial` or `route` is a controller's decision, not
/// the script's. Several of them also run while holding the A-leg INVITE's
/// lock (`call.answer()` inside its handler), so the handler could not take it
/// again. `invite` is that INVITE, read as the path holds it, never locked
/// here.
pub fn refuse_bad_extension(
    call_id: &str,
    invite: &SipMessage,
    unsupported: Vec<String>,
    state: &DispatcherState,
) {
    let Some((a_leg, a_leg_local_addr)) = state
        .call_actors
        .get_call(call_id)
        .map(|call| (call.a_leg.clone(), call.a_leg_local_addr))
    else {
        return;
    };
    info!(
        call_id = %call_id,
        unsupported = %unsupported.join(", "),
        "B2BUA: the caller requires extensions this call cannot honour — refusing with 420"
    );
    cdr_finalize_b2bua_fail(state, call_id, 420);
    let mut response = build_a_leg_final_response(
        invite,
        &a_leg.dialog.local_tag,
        a_leg.stored_from.as_ref(),
        a_leg.stored_to.as_ref(),
        420,
        "Bad Extension",
        state.server_header.as_deref(),
    );
    response.headers.set("Unsupported", unsupported.join(", "));
    send_message_from(
        response,
        a_leg.transport.transport,
        a_leg.transport.remote_addr,
        a_leg.transport.connection_id,
        a_leg_local_addr,
        state,
    );
    finish_failed_call(call_id, &a_leg, 420, "Bad Extension", state);
}

/// Release the media session a call that never connected still holds. No BYE
/// will come for it, so nothing else would.
pub fn release_failed_call_media(a_sip_call_id: &str, state: &DispatcherState) {
    let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    else {
        return;
    };
    if let Some(session) = media_sessions.remove(a_sip_call_id) {
        let set = Arc::clone(rtpengine_set);
        tokio::spawn(async move {
            if let Err(error) = set.delete(session.rtpengine_id(), &session.from_tag).await {
                if error.is_call_not_found() {
                    debug!(call_id = %session.call_id, "media release for a failed call: already gone ({error})");
                } else {
                    warn!(call_id = %session.call_id, "media release for a failed call failed: {error}");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dial(target: &str) -> CallAction {
        CallAction::Dial {
            target: target.to_string(),
            next_hop: None,
            flow: None,
            route: Vec::new(),
            send_socket: None,
            timeout: 30,
        }
    }

    /// No decision keeps what siphon always did: the call ends with its failure.
    #[test]
    fn no_decision_ends_the_call_with_its_failure() {
        assert_eq!(
            classify_failure_action(CallAction::None, false, 0),
            FailureDecision::EndWithFailure
        );
        assert_eq!(
            classify_failure_action(CallAction::Terminate, false, 0),
            FailureDecision::EndWithFailure
        );
    }

    /// A reject is the handler choosing the caller's final response.
    #[test]
    fn a_reject_replaces_the_failure_the_caller_is_sent() {
        let decision = classify_failure_action(
            CallAction::Reject {
                code: 480,
                reason: "Temporarily Unavailable".to_string(),
            },
            false,
            0,
        );
        assert_eq!(
            decision,
            FailureDecision::Reject {
                code: 480,
                reason: "Temporarily Unavailable".to_string()
            }
        );
    }

    /// A 1xx or 2xx through `call.reject()` is not a failure response, and must
    /// not reach the caller as the final answer to a failed call.
    #[test]
    fn a_reject_with_a_status_that_is_no_failure_does_not_apply() {
        for code in [180, 200] {
            let decision = classify_failure_action(
                CallAction::Reject {
                    code,
                    reason: "Not A Failure".to_string(),
                },
                false,
                0,
            );
            assert!(
                matches!(decision, FailureDecision::Inapplicable { .. }),
                "{code} is no failure"
            );
        }
    }

    /// dial, fork and route from on_failure route the call again, until the cap.
    #[test]
    fn a_route_decision_routes_the_call_again_until_the_cap() {
        assert_eq!(
            classify_failure_action(dial("sip:backup@198.51.100.20"), false, 0),
            FailureDecision::Reroute(dial("sip:backup@198.51.100.20"))
        );
        assert_eq!(
            classify_failure_action(
                dial("sip:backup@198.51.100.20"),
                false,
                MAX_FAILURE_REROUTES - 1
            ),
            FailureDecision::Reroute(dial("sip:backup@198.51.100.20"))
        );
        assert!(matches!(
            classify_failure_action(
                dial("sip:backup@198.51.100.20"),
                false,
                MAX_FAILURE_REROUTES
            ),
            FailureDecision::Inapplicable { .. }
        ));
    }

    /// A handover is not a re-route and is not capped by one.
    #[test]
    fn a_handover_hands_the_failed_call_over() {
        let handover = CallAction::Handover {
            app: "ivr".to_string(),
            on_lost: None,
            deadline_ms: None,
            vars: Default::default(),
            answer: false,
            profile: None,
            ws_uri: None,
        };
        assert_eq!(
            classify_failure_action(handover.clone(), false, MAX_FAILURE_REROUTES),
            FailureDecision::Handover(handover)
        );
    }

    /// A call siphon placed has no caller to answer and nothing to route again.
    #[test]
    fn decisions_do_not_apply_to_a_call_siphon_placed() {
        assert!(matches!(
            classify_failure_action(dial("sip:backup@198.51.100.20"), true, 0),
            FailureDecision::Inapplicable { .. }
        ));
        assert!(matches!(
            classify_failure_action(
                CallAction::Reject {
                    code: 486,
                    reason: "Busy Here".to_string()
                },
                true,
                0
            ),
            FailureDecision::Inapplicable { .. }
        ));
        assert_eq!(
            classify_failure_action(CallAction::None, true, 0),
            FailureDecision::EndWithFailure
        );
    }

    /// An answer from the handler keeps the call; a REFER decision cannot apply.
    #[test]
    fn an_answer_keeps_the_call_and_a_refer_decision_does_not_apply() {
        assert_eq!(
            classify_failure_action(CallAction::Answered, false, 0),
            FailureDecision::Answered
        );
        assert!(matches!(
            classify_failure_action(
                CallAction::RejectRefer {
                    code: 603,
                    reason: "Decline".to_string()
                },
                false,
                0
            ),
            FailureDecision::Inapplicable { .. }
        ));
    }
}
