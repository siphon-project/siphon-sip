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
    check_b2bua_answer_timeouts_at(state, std::time::Instant::now());
}

/// [`check_b2bua_answer_timeouts`] as of `now`.
///
/// The deadlines are `std::time::Instant`s, which a paused tokio clock does not
/// move, so this is how a test steps past one without waiting it out.
pub fn check_b2bua_answer_timeouts_at(state: &DispatcherState, now: std::time::Instant) {
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

/// The status a call fails with when its ring timeout ends it.
///
/// A ring that ran out is a 408 (RFC 3261 §16.8): the callee was reached and did
/// not answer in time. A route sequence that ends on the ring timeout of a
/// carrier that never sent a 101-199 is a different failure. No carrier got as
/// far as the callee, so nothing rang, and the caller is told `503 Service
/// Unavailable`, as when no carrier can be dialled at all. That 503 is siphon's
/// own answer as the caller's UAS, built from its INVITE, so the rewrite of an
/// aggregated carrier 503 to 500 (RFC 3261 §16.7 step 6) never applies to it.
///
/// Progress is the carrier having sent a 101-199 at all, whether or not its
/// route kept the call for it: a hunt, whose every target has
/// `reroute_after_progress`, that ends on a phone that rang still reached a
/// callee who did not answer. Any other ring timeout, a dial's or a parallel
/// fork's, stays 408.
///
/// This is the status of a sequence that ends on the carrier that rang out. One
/// that goes on from it and finds only carriers it cannot dial ends on those
/// instead, and fails 503 even after a carrier that rang
/// ([`RouteAdvance::ended_on_undialable`]).
pub fn ring_timeout_failure_status(route_sequence: bool, carrier_progressed: bool) -> u16 {
    if route_sequence && !carrier_progressed {
        503
    } else {
        408
    }
}

/// Fail a B2BUA call whose answer deadline passed while it was still
/// un-answered — the B-leg never produced a final 2xx (dead/partitioned trunk,
/// or a B-leg that silently went away).
///
/// CANCELs every B-leg still ringing (RFC 3261 §9.1), each kept answerable so a
/// 2xx that raced the CANCEL is still ACK+BYEd, then concludes the call like any
/// other failure, with the status [`ring_timeout_failure_status`] picks:
/// `@b2bua.on_failure` decides whether the caller gets it or the call is routed
/// somewhere else. Driven from
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

    // Every branch of a controller-issued `dial` still ringing has rung out:
    // named as timed out now, ahead of the CANCELs below (which would otherwise
    // report them as cancelled) and of a sequential hunt's next attempt.
    control_dial_open_branches_ended(
        call_id,
        408,
        "Request Timeout",
        crate::b2bua::actor::DialBranchCause::Timeout,
        state,
    );

    // What the call fails with if this timeout ends it. Whether the carrier in
    // flight sent a 101-199 is read here, before anything below can advance the
    // sequence, which takes the next carrier and clears it.
    let route_sequence = state.call_actors.is_route_sequence(call_id);
    let mut failure_status = ring_timeout_failure_status(
        route_sequence,
        state.call_actors.route_attempt_progressed(call_id),
    );

    // LCR / sequential failover: the carrier in flight did not answer within its
    // ring timeout. Its attempt is recorded as 408 before anything else, the way
    // a carrier failing with a final response is recorded before its ACK: the
    // call may advance, fail, or go back to a controller, and either way
    // `@b2bua.on_route_failure` fires for this carrier once, and a
    // `@b2bua.on_failure` that concludes the call finds it on
    // `call.route_attempts`. Recording it only on the advance left the last
    // carrier, and one kept by progress, off the attempt list altogether. The
    // attempt is the carrier's outcome and stays 408 whatever the caller is told.
    if route_sequence {
        b2bua_record_carrier_failure(call_id, 408, &a_leg, a_leg_invite.as_ref(), state);
    }

    // If more carriers remain and 408 is a reroute cause for this carrier,
    // CANCEL this attempt and advance instead of failing the call.
    //
    // Unless the carrier has shown progress. A 101-199 says it reached the far
    // end and is working on the call, so its route's timer bounded only the wait
    // for that (RFC 3261 §16.7 step 2, a proxy's Timer C), and the deadline that
    // fired is the ring bound it was given instead. The callee has rung as long
    // as this call allows, so it fails 408 here rather than going to a carrier
    // that would start ringing again. `reroute_after_progress` on a route keeps
    // the old rule for a carrier that fakes progress with its own ringback.
    let kept_by_progress = state.call_actors.route_kept_by_progress(call_id);
    if kept_by_progress && state.call_actors.has_pending_routes(call_id) {
        let carrier = state
            .call_actors
            .active_route(call_id)
            .map(|route| route.carrier_id)
            .unwrap_or_default();
        info!(
            call_id = %call_id,
            carrier = %carrier,
            "LCR: carrier showed progress and rang out, failing the call 408 without trying the remaining carriers"
        );
    }
    if !kept_by_progress
        && state.call_actors.has_pending_routes(call_id)
        && b2bua_status_reroutes(call_id, 408, state)
    {
        // CANCEL the timed-out carrier's pending B-leg(s) (RFC 3261 §9.1), each
        // kept answerable apart from the call. The next carrier can fail, and end
        // the call, before this one's 487 arrives, and that 487 is owed its ACK
        // (§17.1.1.3) either way; while the call lives, the cancelled status also
        // keeps it from counting as a fresh carrier failure.
        for tx in &handle_txs {
            let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(call_id, &cancelled, state);
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
        // The queue is exhausted. When the carriers left could not be dialled,
        // the sequence ended on them rather than on this carrier's ring-out, and
        // the call fails 503 even if this carrier rang.
        if advanced.ended_on_undialable() {
            failure_status = LCR_UNDIALED_STATUS;
        }
    }

    // A controller-issued `dial` that nobody answered in time. The rung legs
    // are given up on — CANCEL them (RFC 3261 §9.1) — but the caller is not:
    // it stays unanswered and parked, and the controller decides what happens
    // next. "Nobody answered, go to voicemail" is the whole point of the verb,
    // and failing the caller here would take that decision away. A sequential
    // dial reports the code a route sequence fails with, by the same rule.
    if state.call_actors.is_control_dial(call_id) {
        // Each CANCELled leg stays answerable apart from the call, as on the LCR
        // ring timeout above: its 487 is owed an ACK (RFC 3261 §17.1.1.3) even if
        // the controller ends the call first.
        for tx in &handle_txs {
            let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
        }
        let cancelled = state.call_actors.cancel_ringing_branches(call_id);
        cancel_settled_branches(call_id, &cancelled, state);
        if report_control_dial_failure(
            call_id,
            failure_status,
            best_error_reason(failure_status),
            true,
            state,
        ) {
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
            cancel_settled_branches(call_id, &settlement.cancelled, state);
            fail_forked_call(call_id, best, state);
            return;
        }
    }

    warn!(
        call_id = %call_id,
        status = failure_status,
        "B2BUA: answer timeout — no final response from B-leg, failing the call",
    );

    // CANCEL each B-leg still ringing (RFC 3261 §9.1), each kept answerable
    // apart from the call: its 487, or a 2xx that crosses the CANCEL, is owed an
    // ACK (and a BYE) whether @b2bua.on_failure ends the call or routes it
    // somewhere else.
    for tx in &handle_txs {
        let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }
    let cancelled = state.call_actors.cancel_ringing_branches(call_id);
    cancel_settled_branches(call_id, &cancelled, state);

    // A ring that ran out is a 408 (RFC 3261 §16.8), or a 503 for a route
    // sequence no carrier of which reached the callee, and the call concludes on
    // it like on any other failure. Built locally, so a 503 stays a 503.
    conclude_failed_call(
        call_id,
        FailedCallEnd::Local {
            status_code: failure_status,
            reason: best_error_reason(failure_status).to_string(),
        },
        state,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a route sequence whose carrier never sent a 101-199 fails 503. A
    /// carrier that rang, and every ring timeout outside a sequence, stays 408.
    #[test]
    fn a_ring_timeout_fails_503_only_for_a_sequence_whose_carrier_showed_no_progress() {
        assert_eq!(ring_timeout_failure_status(true, false), 503);
        assert_eq!(ring_timeout_failure_status(true, true), 408);
        assert_eq!(ring_timeout_failure_status(false, false), 408);
        assert_eq!(ring_timeout_failure_status(false, true), 408);
    }
}
