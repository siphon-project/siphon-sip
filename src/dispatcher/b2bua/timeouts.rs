//! Deadlines the B2BUA arms on a call and the teardown it runs when one
//! fires: the answer deadline, the maximum call duration, a leg replacement
//! that never completed, and an inbound REFER whose controller never decided.
use crate::dispatcher::*;

/// Arm the answer-timeout for a B2BUA call from a `call.fork`/`call.dial`
/// `timeout=` (seconds).
///
/// `timeout == 0` disables the application timeout (the 24h orphan sweep stays
/// the only backstop). Otherwise the orphan sweep fails the call if it is still
/// un-answered `timeout` seconds from now — see [`fail_b2bua_call_on_timeout`].
pub fn set_b2bua_answer_deadline(call_id: &str, timeout_secs: u32, state: &DispatcherState) {
    if timeout_secs == 0 {
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs as u64);
    state.call_actors.set_answer_deadline(call_id, deadline);
}

/// Fail (or, for an LCR sequence, re-route) every B2BUA call still un-answered
/// past its per-attempt answer deadline (`call.fork`/`call.dial`/`call.route`
/// `timeout`). Runs on a fast dispatcher-loop interval so a short per-carrier
/// LCR ring timeout re-routes promptly (CANCEL the carrier, advance to the next
/// carrier, or 408 to the A-leg when the list is exhausted) — see
/// [`fail_b2bua_call_on_timeout`].
pub fn check_b2bua_answer_timeouts(state: &DispatcherState) {
    let now = std::time::Instant::now();
    for timed_out in state.call_actors.take_timed_out_calls(now) {
        fail_b2bua_call_on_timeout(&timed_out, state);
    }
}

/// Tear down every answered B2BUA call that has been up longer than its
/// maximum duration (`call.dial(max_duration=…)`, else the configured
/// `b2bua.max_call_duration_secs`).
///
/// The answered-call sibling of [`check_b2bua_answer_timeouts`], which bounds
/// only the ring. Runs on the same fast interval so a short cap — an IVR that
/// gives a caller 30 seconds — is honoured to within half a second rather than
/// to within the 30 s cleanup sweep. Returns immediately when no call carries a
/// cap and none is configured.
pub fn check_b2bua_max_call_durations(state: &DispatcherState) {
    let now = std::time::Instant::now();
    for call_id in state
        .call_actors
        .take_calls_over_max_duration(now, state.default_max_call_duration_secs)
    {
        info!(
            call_id = %call_id,
            "B2BUA: maximum call duration reached, terminating call"
        );
        b2bua_max_duration_terminate(&call_id, state);
    }
}

/// Give up on every leg replacement whose dialed target has blown its deadline:
/// CANCEL that leg and run the ordinary replacement-failure path (`408`).
///
/// The sibling of [`check_b2bua_answer_timeouts`] for the calls that one cannot
/// see. A replacement — a siphon-terminated REFER transfer, or
/// `b2bua.replace_peer()` — dials its target on a call that is already
/// `Answered`, and the answer-timeout sweep filters on `Calling`/`Ringing`
/// precisely so a long answered call is never touched. So a target that sends a
/// `180` and then goes silent hit nothing at all: the subscription stayed
/// armed, the response path kept matching its Call-ID, and the surviving party
/// stayed bridged to a leg that was never going to answer.
///
/// The original call survives — [`b2bua_fail_terminated_transfer`] drops the
/// target leg and clears the replacement, exactly as it does for a target that
/// answers `486`. The one exception is its own: a call whose replaced leg
/// already left has nobody for the survivor to talk to, and is released.
pub fn check_b2bua_replacement_timeouts(state: &DispatcherState) {
    let now = std::time::Instant::now();
    for (call_id, target_call_id) in state.call_actors.take_timed_out_replacements(now) {
        // Re-resolve the leg under the lock: it may have answered, failed or
        // been removed between the sweep and here, and the index is only
        // meaningful for as long as `b_legs` has not shifted.
        let Some((target_idx, cancel)) = state.call_actors.get_call(&call_id).and_then(|call| {
            let index = call
                .b_legs
                .iter()
                .position(|leg| leg.dialog.call_id == target_call_id)?;
            let leg = call.b_legs.get(index)?;
            state.b2bua_retransmits.disarm_branch(&leg.branch);
            let cancel = leg.b_leg_invite.as_ref().and_then(|invite| {
                invite.lock().ok().and_then(|invite| {
                    build_cancel_from_invite(&invite).map(|message| {
                        (
                            message,
                            leg.transport.transport,
                            leg.transport.remote_addr,
                            leg.transport.connection_id,
                            leg.transport.local_addr,
                        )
                    })
                })
            });
            Some((index, cancel))
        }) else {
            continue;
        };

        // RFC 3261 §9.1: the target still has an INVITE server transaction open,
        // so abandon it rather than walking away and leaving it ringing.
        if let Some((cancel, transport, destination, connection_id, local_addr)) = cancel {
            send_message_from(
                cancel,
                transport,
                destination,
                connection_id,
                local_addr,
                state,
            );
        }

        warn!(
            call_id = %call_id,
            target_leg = %target_call_id,
            "B2BUA: leg replacement target never answered — cancelling it and keeping the original call"
        );
        b2bua_fail_terminated_transfer(&call_id, target_idx, 408, state);
    }
}

/// Answer every controlled call's inbound REFER whose decision deadline passed
/// without the owning control app calling `accept_refer` / `reject_refer` — a
/// `603 Decline`, matching the no-`@b2bua.on_refer`-handler default. Drains the
/// pending entry so the store returns to baseline (a REFER held forever would
/// strand the referrer). Modelled on [`check_b2bua_answer_timeouts`]; runs on the
/// same fast dispatcher-loop interval.
pub fn check_pending_inbound_refer_timeouts(state: &DispatcherState) {
    let now = std::time::Instant::now();
    for pending in state.pending_inbound_refer.take_expired(now) {
        let sip_call_id = pending
            .message
            .headers
            .get("Call-ID")
            .map(|value| value.to_string())
            .unwrap_or_default();
        warn!(%sip_call_id, "control plane: inbound REFER decision deadline — no accept_refer/reject_refer, applying default (603 Decline)");
        b2bua_refer_send_final(&pending.inbound, &pending.message, 603, "Decline", state);
    }
}

/// Fail a B2BUA call whose answer deadline passed while it was still
/// un-answered — the B-leg never produced a final 2xx (dead/partitioned trunk,
/// or a B-leg that silently went away).
///
/// CANCELs every B-leg still ringing (RFC 3261 §9.1), each kept answerable so a
/// 2xx that raced the CANCEL is still ACK+BYEd, then concludes the call as a
/// `408` like any other failure: `@b2bua.on_failure` decides whether the caller
/// gets it or the call is routed somewhere else. Driven from
/// [`check_b2bua_answer_timeouts`].
pub fn fail_b2bua_call_on_timeout(call_id: &str, state: &DispatcherState) {
    // Control-plane handoff deadline: a call parked under external control whose
    // controller never accepted + acted in time. Apply the parked default action
    // (503) instead of the 408 answer-timeout path.
    let handoff = state.call_actors.get_call(call_id).map(|call| {
        (
            call.is_handoff_pending(),
            call.control_app.clone().unwrap_or_default(),
        )
    });
    if let Some((true, app)) = handoff {
        warn!(call_id = %call_id, %app, "control plane: handoff deadline — no controller acted, applying default (503)");
        crate::metrics::try_metrics().inspect(|m| {
            m.control_handoff_timeouts_total
                .with_label_values(&[&app])
                .inc()
        });
        b2bua_reject_call(call_id, 503, "No Controller Response");
        return;
    }

    // A call siphon *placed* (`originate`) that nobody answered in time. siphon
    // is the UAC here, so there is no A-leg transaction to answer 408: the
    // correct give-up is to CANCEL the INVITE (RFC 3261 §9.1). Taking the path
    // below would instead aim a 408 *response* at the party being called.
    let originated = state
        .call_actors
        .get_call(call_id)
        .map(|call| (call.originated, call.a_leg.dialog.call_id.clone()));
    if let Some((true, sip_call_id)) = originated {
        warn!(
            call_id = %call_id,
            %sip_call_id,
            "originate: ring timeout — CANCELling the INVITE"
        );
        b2bua_cancel_originated_call(&sip_call_id, Some("ring timeout"));
        return;
    }

    // Snapshot everything needed, then drop the DashMap ref before the CANCEL
    // sends and Python.
    let (a_leg, a_leg_invite, handle_txs) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            // Re-check under the lock: the call may have answered or started
            // tearing down between take_timed_out_calls and here.
            if !matches!(call.state, CallState::Calling | CallState::Ringing) {
                return;
            }
            // We are giving up on this ring, so stop retransmitting every B-leg
            // INVITE that never drew a response. The CANCELs below cover the
            // legs whose INVITE was stashed; this also catches a leg whose stash
            // never landed, which would otherwise keep retransmitting until 64*T1.
            for b_leg in &call.b_legs {
                state.b2bua_retransmits.disarm_branch(&b_leg.branch);
            }
            let handle_txs: Vec<_> = call
                .b_leg_handles
                .iter()
                .flatten()
                .map(|handle| handle.tx.clone())
                .collect();
            (call.a_leg.clone(), call.a_leg_invite.clone(), handle_txs)
        }
        None => return,
    };

    // LCR / sequential failover: the current carrier did not answer within its
    // ring timeout. If more carriers remain and 408 is a reroute cause for this
    // carrier, CANCEL this attempt and advance instead of failing the call.
    if state.call_actors.has_pending_routes(call_id) && b2bua_status_reroutes(call_id, 408, state) {
        // A ring timeout is recorded as 408 — the code the attempt effectively
        // ended on, and the one the A-leg would have seen had the queue been
        // exhausted here.
        let timed_out_route = state.call_actors.active_route(call_id);
        if let Some(attempt) = state.call_actors.record_route_failure(call_id, 408) {
            info!(
                call_id = %call_id,
                carrier = %attempt.carrier_id,
                elapsed_ms = attempt.elapsed_ms,
                "LCR: carrier ring-timeout"
            );
        }
        if let Some(route) = &timed_out_route {
            b2bua_dispatch_route_failure(call_id, route, 408, &a_leg, a_leg_invite.as_ref(), state);
        }
        // CANCEL the timed-out carrier's pending B-leg(s) (RFC 3261 §9.1), each
        // kept answerable apart from the call. The next carrier can fail, and end
        // the call, before this one's 487 arrives, and that 487 is owed its ACK
        // (§17.1.1.3) either way; while the call lives, the cancelled status also
        // keeps it from counting as a fresh carrier failure.
        for tx in &handle_txs {
            let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(&cancelled, state);
        let advanced = match a_leg_invite.as_ref().map(|arc| arc.lock()) {
            Some(Ok(guard)) => b2bua_advance_route(call_id, &guard, state),
            _ => RouteAdvance::none(),
        };
        // The guard above is out of scope now, so the hook may lock the INVITE.
        b2bua_dispatch_burned_routes(call_id, &advanced.burned, state);
        if advanced.dialed {
            info!(call_id = %call_id, "LCR: advanced to next carrier after ring-timeout");
            return;
        }
        // else fall through to the normal 408 teardown (queue exhausted).
    }

    // A controller-issued `dial` that nobody answered in time. The rung legs
    // are given up on — CANCEL them (RFC 3261 §9.1) — but the caller is not:
    // it stays unanswered and parked, and the controller decides what happens
    // next. "Nobody answered, go to voicemail" is the whole point of the verb,
    // and failing the caller 408 here would take that decision away.
    if state.call_actors.is_control_dial(call_id) {
        // Each CANCELled leg stays answerable apart from the call, as on the LCR
        // ring timeout above: its 487 is owed an ACK (RFC 3261 §17.1.1.3) even if
        // the controller ends the call first.
        for tx in &handle_txs {
            let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(&cancelled, state);
        if report_control_dial_failure(call_id, 408, "Request Timeout", true, state) {
            return;
        }
        // The dial was resolved by something else in between (answered, or the
        // call went away); fall through to the ordinary teardown.
    }

    // A parallel fork some of whose branches already failed is owed the best of
    // those failures rather than a bare 408, whenever one of them outranks the
    // 408 the timeout amounts to (RFC 3261 §16.7, §16.8). The branches still
    // ringing are CANCELled as over, and the held response is relayed exactly as
    // it would have been had they failed too.
    if let Some(settlement) = state.call_actors.settle_fork_on_timeout(call_id) {
        if let Some(best) = settlement.failure {
            warn!(
                call_id = %call_id,
                status = best.status_code,
                "B2BUA: answer timeout — relaying the best failure the fork's branches already returned",
            );
            for tx in &handle_txs {
                let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
            }
            cancel_settled_branches(&settlement.cancelled, state);
            fail_forked_call(call_id, best, state);
            return;
        }
    }

    warn!(
        call_id = %call_id,
        "B2BUA: answer timeout — no final response from B-leg, failing call with 408",
    );

    // CANCEL each B-leg still ringing (RFC 3261 §9.1), each kept answerable
    // apart from the call: its 487, or a 2xx that crosses the CANCEL, is owed an
    // ACK (and a BYE) whether @b2bua.on_failure ends the call or routes it
    // somewhere else.
    for tx in &handle_txs {
        let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }
    let cancelled = state.call_actors.cancel_ringing_branches(call_id);
    cancel_settled_branches(&cancelled, state);

    // A ring that ran out is a 408 (RFC 3261 §16.8), and the call concludes on
    // it like on any other failure.
    conclude_failed_call(
        call_id,
        FailedCallEnd::Local {
            status_code: 408,
            reason: best_error_reason(408).to_string(),
        },
        state,
    );
}
