//! The B-leg failed: the retries that may still save the call, and the
//! teardown when none does.

use crate::dispatcher::*;

/// A final failure on the B-leg: the 422 and 401/407 retries, then the fork
/// it belongs to, which fails the call only once no branch can still answer.
pub fn b_leg_failed(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) {
    // RFC 4028: 422 "Session Interval Too Small" — retry with higher Session-Expires
    if retry_after_422(call_id, message, status_code, state, snapshot) {
        return;
    }

    // 401/407 — auto-retry with digest credentials if available.
    //
    // The retry MUST be built from the B-leg's last-sent INVITE, NOT the
    // raw A-leg INVITE. The first B-leg INVITE went through the full
    // hygiene chain in `b2bua_send_b_leg_invite` (strip Record-Route /
    // Route / Authorization, replace Via / Contact / User-Agent, rewrite
    // From / To / P-Asserted-Identity host, regenerate Call-ID, set
    // CSeq=1, decrement Max-Forwards, sanitize SDP origin), plus any
    // script-side mutations applied before send. Cloning the A-leg INVITE
    // and only patching Via / RURI / Authorization (the old behaviour)
    // leaks every other A-leg header back to the B-leg.
    if retry_with_credentials(call_id, branch, message, status_code, state, snapshot) {
        return;
    }

    // A parallel fork: one branch failing is not the call failing while another
    // can still answer (RFC 3261 §16.7). The failure is recorded, the best one
    // kept, and the call fails only once no branch is left. A plain dial is a
    // fork of one and settles here at once. An LCR sequence keeps one carrier
    // live at a time under its own failover rules, and a response matching no
    // leg has no fork to settle, so both go straight on.
    let fork_index = snapshot
        .b_leg_index
        .filter(|_| !state.call_actors.is_route_sequence(call_id));
    let Some(index) = fork_index else {
        fail_call_on_b_leg_failure(
            call_id,
            branch,
            message,
            status_code,
            state,
            snapshot,
            false,
        );
        return;
    };
    let Some(settlement) =
        state
            .call_actors
            .record_branch_failure(call_id, index, status_code, message)
    else {
        // The call went away underneath this response; it is still owed its ACK.
        ack_b_leg_non2xx(branch, message, state, snapshot);
        return;
    };
    cancel_settled_branches(&settlement.cancelled, state);
    match settlement.failure {
        None => {
            ack_b_leg_non2xx(branch, message, state, snapshot);
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: fork branch failed, another can still answer"
            );
        }
        Some(best) if best.branch == branch => {
            fail_call_on_b_leg_failure(
                call_id,
                branch,
                message,
                status_code,
                state,
                snapshot,
                false,
            );
        }
        Some(best) => {
            ack_b_leg_non2xx(branch, message, state, snapshot);
            fail_forked_call(call_id, best, state);
        }
    }
}

/// ACK a B-leg's final non-2xx (RFC 3261 §17.1.1.3). It belongs to the INVITE's
/// client transaction, so it rides the INVITE's branch and leaves from the leg's
/// own socket. Returns `false` when the leg's flow is unknown and nothing could
/// be sent.
pub fn ack_b_leg_non2xx(
    branch: &str,
    message: &SipMessage,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let Some((b_dest, b_transport)) = snapshot.b_leg_dest else {
        return false;
    };
    let (ack_via_host, ack_via_port) =
        b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
    let ack = build_b2bua_ack_for_non2xx(
        message,
        branch,
        snapshot.b_leg_target.as_deref(),
        b_transport,
        &ack_via_host,
        ack_via_port,
    );
    send_b2bua_to_bleg(ack, b_transport, b_dest, snapshot.b_leg_local_addr, state);
    true
}

/// Fail a parallel fork with the best failure its branches produced
/// (RFC 3261 §16.7), relayed as the leg that sent it. That response was ACKed
/// when it arrived, while a sibling could still answer.
pub fn fail_forked_call(
    call_id: &str,
    best: crate::b2bua::actor::BranchFailure,
    state: &DispatcherState,
) {
    let Some(snapshot) = b_leg_response_snapshot(call_id, &best.branch, state) else {
        warn!(call_id = %call_id, "B2BUA: response for unknown call");
        return;
    };
    let mut response = best.response;
    fail_call_on_b_leg_failure(
        call_id,
        &best.branch,
        &mut response,
        best.status_code,
        state,
        &snapshot,
        true,
    );
}

/// The call fails on `message`, a B-leg's final failure: the LCR route sequence
/// gets its chance first, then the ACK (unless `acked`), then the call concludes
/// — `@b2bua.on_failure` decides between ending it and routing it again.
fn fail_call_on_b_leg_failure(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
    acked: bool,
) {
    // auth_passthrough: a B-leg 401/407 with no siphon-side credentials is a
    // NON-terminal challenge that we relay to the caller for end-to-end
    // authentication (RFC 3261 §22.3). We still ACK the B-leg and forward the
    // challenge to the A-leg below, but must NOT treat the call as failed: no
    // CDR, no @b2bua.on_failure, no media teardown. The call actor is still
    // removed (the caller re-INVITEs as a fresh call); the media session — keyed
    // by SIP Call-ID, which the re-INVITE reuses — is deliberately left in place.
    // The caller's ACK for the forwarded challenge matches no live call and is
    // dropped by the unmatched-ACK guard (never answered with a 502).
    let relay_challenge = (status_code == 401 || status_code == 407)
        && snapshot.outbound_credentials.is_none()
        && state
            .call_actors
            .get_call(call_id)
            .map(|call| call.auth_passthrough)
            .unwrap_or(false);
    if relay_challenge {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: relaying auth challenge to A-leg (auth_passthrough) — not a failure"
        );
    }

    // LCR / sequential failover: this carrier produced a final failure. If it is
    // a configured reroute cause and more carriers remain, advance to the next
    // instead of failing the call — the A-leg sees an error only once the list is
    // exhausted or the response is definitive.
    let Some(sequence_end) = advance_route_sequence(
        call_id,
        branch,
        message,
        status_code,
        state,
        snapshot,
        relay_challenge,
    ) else {
        return;
    };

    // ACK the B-leg's non-2xx final response (RFC 3261 §17.1.1.3), and before
    // anything else: the transaction is over whatever @b2bua.on_failure goes on to
    // decide, and a call it routes somewhere else must not leave this leg
    // retransmitting. Skipped when the LCR reroute path already ACKed this carrier
    // before trying (and failing to route) the next one, and for a fork's best
    // failure, ACKed when it arrived — no double ACK.
    if !sequence_end.b_leg_acked && !acked {
        ack_b_leg_non2xx(branch, message, state, snapshot);
    }

    if relay_challenge {
        relay_failure_to_a_leg(call_id, message, snapshot, state);
        state.call_actors.remove_call(call_id);
        state.call_event_receivers.remove(call_id);
        return;
    }

    // A route sequence that went on from this carrier and found only carriers it
    // could not dial ends on those, not on this carrier's failure: siphon's own
    // 503, whatever this carrier sent and whatever the §16.7 ranking of the
    // attempts would pick. A controller's sequential `dial` reports the same code.
    let undialable_status = sequence_end
        .ended_on_undialable
        .then_some(LCR_UNDIALED_STATUS);

    // A controller-issued `dial` owns this outcome: the caller is still unanswered
    // and still the controller's, so the failure is reported to it rather than the
    // call being failed — no @b2bua.on_failure, no CDR close, no teardown. The
    // B-leg has been ACKed above, which is all it is owed.
    let (reported_status, reported_reason) = match undialable_status {
        Some(undialable) => (undialable, best_error_reason(undialable)),
        None => (status_code, response_reason_phrase(message)),
    };
    if report_control_dial_failure(call_id, reported_status, reported_reason, false, state) {
        return;
    }

    if let Some(undialable) = undialable_status {
        warn!(
            call_id = %call_id,
            status = undialable,
            "LCR: no carrier left that could be dialled, failing the call"
        );
        conclude_failed_call(
            call_id,
            FailedCallEnd::Local {
                status_code: undialable,
                reason: best_error_reason(undialable).to_string(),
            },
            state,
        );
        return;
    }

    // RFC 3261 §16.7 step 6: a 503 says one downstream element is unavailable,
    // not that this call cannot be served, so the caller is sent a 500 generated
    // from its own INVITE instead of the B-leg's 503 and its Retry-After. The
    // route sequence has already had its chance to fail over on the 503 above.
    //
    // An exhausted route sequence ends on the best of its carriers' failures
    // (§16.7 step 6 over every attempt, this one included), not on whichever
    // carrier happened to be tried last. When that best came from an earlier
    // carrier, only its status was kept, so the caller's failure is generated
    // from the A-leg INVITE with that status. @b2bua.on_failure, the CDR and Ro
    // all see the status the caller is sent.
    let chosen_status = state
        .call_actors
        .best_route_error(call_id)
        .unwrap_or(status_code);
    let upstream = crate::sip::best_response::upstream_status(chosen_status);
    let end = if upstream != status_code {
        FailedCallEnd::Local {
            status_code: upstream,
            reason: best_error_reason(upstream).to_string(),
        }
    } else {
        FailedCallEnd::Relayed { message, snapshot }
    };
    conclude_failed_call(call_id, end, state);
}

/// Relay a B-leg's final failure to the caller: the A-leg's own dialog
/// identifiers, Via and CSeq (RFC 3261 §8.2.6.2 — a response echoes its
/// request's CSeq, and the B-leg numbers its own), the caller's own From and To
/// with the A-leg dialog's tag, sanitised like every B-leg response that crosses
/// to the A-leg. The status, reason phrase and body stay the B-leg's.
pub fn relay_failure_to_a_leg(
    call_id: &str,
    message: &mut SipMessage,
    snapshot: &BLegResponseSnapshot,
    state: &DispatcherState,
) {
    if let Some((_, b_from_tag)) = &snapshot.b_leg_dialog {
        crate::b2bua::actor::Dialog::rewrite_headers(
            message,
            &snapshot.a_leg.dialog.call_id,
            b_from_tag,
            snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            Some(&snapshot.a_leg.dialog.local_tag),
        );
    }
    if let Some(invite_arc) = &snapshot.a_leg_invite {
        if let Ok(invite) = invite_arc.lock() {
            if let Some(vias) = invite.headers.get_all("Via") {
                message.headers.set_all("Via", vias.clone());
            }
            if let Some(cseq) = invite.headers.cseq() {
                message.headers.set("CSeq", cseq.clone());
            }
            echo_caller_identity(message, &snapshot.a_leg, &invite, RelayedToTag::ALegDialog);
        }
    }
    sanitize_b2bua_response(
        message,
        state,
        snapshot.a_leg.transport.transport,
        snapshot.a_leg_local_addr,
        snapshot.a_leg_supports_100rel,
        call_id,
    );
    // A failure can carry SDP too: a 488 may describe the media the callee does
    // support (RFC 3261 §21.4.26).
    strip_relayed_sdp_attributes(message, state);
    // Pin the reply egress socket to the A-leg INVITE's arrival listener so a
    // multi-homed UDP host answers on the port it received on. No-op for stream
    // transports and single-listener hosts.
    send_message_from(
        message.clone(),
        snapshot.a_leg.transport.transport,
        snapshot.a_leg.transport.remote_addr,
        snapshot.a_leg.transport.connection_id,
        snapshot.a_leg_local_addr,
        state,
    );
}

/// RFC 4028 §6: the trunk rejected our Session-Expires as too small, so
/// re-INVITE with the interval it asked for. Returns `true` when it did.
pub fn retry_after_422(
    call_id: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    if status_code == 422 {
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                let remote_min_se = message
                    .headers
                    .get("Min-SE")
                    .and_then(|v| v.split(';').next())
                    .and_then(|v| v.trim().parse::<u32>().ok());

                if let (Some(min_se), Some(target_uri), Some(invite_arc)) = (
                    remote_min_se,
                    &snapshot.b_leg_target,
                    &snapshot.a_leg_invite,
                ) {
                    if min_se > timer_config.session_expires {
                        info!(
                            call_id = %call_id,
                            min_se = min_se,
                            "B2BUA: 422 received, retrying with Session-Expires={min_se}"
                        );

                        // RFC 5923 connection reuse: keep the higher-
                        // Session-Expires retry on the SAME trunk member the
                        // 422'd INVITE traversed, instead of re-resolving the
                        // trunk hostname and round-robining onto a sibling
                        // member (see select_b2bua_retry_destination).
                        {
                            let (destination, transport, reuse_connection_id, relay_target) =
                                match select_b2bua_retry_destination(
                                    snapshot.b_leg_dest,
                                    snapshot.b_leg_connection_id,
                                    target_uri,
                                    &state.dns_resolver,
                                ) {
                                    Some(resolved) => resolved,
                                    None => return true,
                                };

                            // Build retry INVITE from stored A-leg INVITE
                            let Ok(original) = invite_arc.lock() else {
                                error!(call_id = %call_id, "invite_arc lock poisoned during fork retry");
                                return true;
                            };
                            let mut retry = original.clone();
                            drop(original);

                            // Replace Via with new branch. The retry continues
                            // the same B-leg, so it keeps the leg's sent-by —
                            // the flow socket when it was dialled over one.
                            let new_branch = TransactionKey::generate_branch();
                            let (retry_via_host, retry_via_port) =
                                b_leg_sent_by(snapshot.b_leg_local_addr, state, &transport);
                            let via_value = format!(
                                "SIP/2.0/{} {}:{};branch={}",
                                transport, retry_via_host, retry_via_port, new_branch,
                            );
                            retry.headers.set("Via", via_value);

                            // Update Request-URI
                            if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                retry.start_line =
                                    StartLine::Request(crate::sip::message::RequestLine {
                                        method: crate::sip::message::Method::Invite,
                                        request_uri: target_parsed,
                                        version: crate::sip::message::Version::sip_2_0(),
                                    });
                            }

                            // Set updated session timer headers
                            retry.headers.remove("Session-Expires");
                            retry.headers.remove("Min-SE");
                            retry
                                .headers
                                .add("Session-Expires", format!("{};refresher=uac", min_se));
                            retry.headers.add("Min-SE", min_se.to_string());

                            // Reuse B-leg dialog identifiers from the failed attempt.
                            // Retry source is the original A-leg INVITE — out-of-dialog,
                            // To has no tag, so pass None for new_to_tag.
                            let (retry_call_id, retry_from_tag) =
                                snapshot.b_leg_dialog.clone().unwrap_or_else(|| {
                                    (
                                        snapshot.a_leg.dialog.call_id.clone(),
                                        snapshot
                                            .a_leg
                                            .dialog
                                            .remote_tag
                                            .clone()
                                            .unwrap_or_default(),
                                    )
                                });
                            crate::b2bua::actor::Dialog::rewrite_headers(
                                &mut retry,
                                &retry_call_id,
                                snapshot.a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                                &retry_from_tag,
                                None,
                            );
                            // Rebuilt from the caller's INVITE rather than from
                            // the stripped one the callee refused, so it needs its
                            // own `media.sdp_strip_attributes` pass.
                            strip_relayed_sdp_attributes(&mut retry, state);

                            let mut b_leg = Leg::new_b_leg(
                                retry_call_id,
                                retry_from_tag,
                                target_uri.clone(),
                                new_branch,
                                LegTransport {
                                    remote_addr: destination,
                                    connection_id: reuse_connection_id,
                                    transport,
                                    // The retry IS this B-leg continuing, so
                                    // it keeps the leg's anchored socket.
                                    local_addr: snapshot.b_leg_local_addr,
                                },
                            );
                            // Stash the retry INVITE so a caller CANCEL during
                            // alerting can rebuild the CANCEL from it (RFC 3261
                            // §9.1 — same Via branch + CSeq). The original 422'd
                            // leg's stash is discarded by the in-place supersede
                            // below; without re-stashing here the live retry
                            // transaction would be left un-cancellable.
                            b_leg.b_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));

                            // RFC 4028: the 422'd INVITE transaction is complete,
                            // so the higher-Session-Expires retry continues the
                            // same logical B-leg — supersede in place rather than
                            // append (see the 401/407 path for why appending
                            // strands a dead leg that a later CANCEL hits).
                            match snapshot.b_leg_index {
                                Some(idx) => {
                                    state.call_actors.replace_b_leg(call_id, idx, b_leg.clone());
                                    spawn_b_leg_actor_at(call_id, &b_leg, idx, state);
                                }
                                None => {
                                    state.call_actors.add_b_leg(call_id, b_leg.clone());
                                    spawn_b_leg_actor(call_id, &b_leg, state);
                                }
                            }

                            let data = Bytes::from(retry.to_bytes());
                            // Egress from the leg's anchored socket (UDP only —
                            // a stream leg is reached over its connection).
                            let retry_source = match transport {
                                Transport::Udp => snapshot.b_leg_local_addr,
                                _ => None,
                            };
                            send_to_target(
                                data,
                                &relay_target,
                                transport,
                                reuse_connection_id,
                                retry_source,
                                state,
                            );
                        }
                        return true; // don't forward 422 to A-leg or fire on_failure
                    }
                }
            }
        }
    }

    false
}

/// RFC 3261 §22: answer a 401/407 from the trunk with a credentialed
/// re-INVITE. Returns `true` when a retry went out.
pub fn retry_with_credentials(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    if status_code == 401 || status_code == 407 {
        // Cap credentialed retries per call. The per-leg dedup below stops a
        // *retransmitted* challenge from spawning a duplicate INVITE, but a
        // trunk that rejects every *fresh* credentialed attempt (wrong
        // password, or a new nonce each time) would otherwise re-auth
        // forever — each retry lands on a new branch, so there's no 482 to
        // self-terminate the loop (that was the pre-dedup failure mode).
        // Once MAX_B2BUA_AUTH_RETRIES credentialed INVITEs have gone out,
        // treat a further challenge as a persistent auth failure: ACK it and
        // surface the response upstream (fall through to @b2bua.on_failure +
        // forward to the A-leg) instead of looping. The per-leg dedup makes
        // this one-shot — retransmits of the surfaced challenge are absorbed.
        if snapshot.outbound_credentials.is_some()
            && state.call_actors.auth_retry_count(call_id) >= MAX_B2BUA_AUTH_RETRIES
        {
            if let Some((b_dest, b_transport)) = snapshot.b_leg_dest {
                // RFC 3261 §17.1.1.3 — this ACK belongs to the INVITE's own
                // client transaction, so its Via sent-by must be the one the
                // INVITE used: the leg's flow socket when it has one.
                let (ack_via_host, ack_via_port) =
                    b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
                let ack = build_b2bua_ack_for_non2xx(
                    message,
                    branch,
                    snapshot.b_leg_target.as_deref(),
                    b_transport,
                    &ack_via_host,
                    ack_via_port,
                );
                send_b2bua_to_bleg(ack, b_transport, b_dest, snapshot.b_leg_local_addr, state);
            }
            let first = snapshot
                .b_leg_index
                .map(|idx| state.call_actors.try_mark_auth_challenged(call_id, idx))
                .unwrap_or(true);
            if !first {
                // Retransmit of an already-surfaced challenge — absorb.
                return true;
            }
            warn!(
                call_id = %call_id,
                status = status_code,
                limit = MAX_B2BUA_AUTH_RETRIES,
                "B2BUA: outbound auth retry limit reached — surfacing {status_code} upstream instead of re-authing"
            );
            // fall through to the failure path (on_failure + forward to A-leg)
        } else if let Some((username, password)) = &snapshot.outbound_credentials {
            let challenge_header = if status_code == 401 {
                message.headers.get("WWW-Authenticate")
            } else {
                message.headers.get("Proxy-Authenticate")
            };

            if let Some(challenge_value) = challenge_header {
                if let Some(challenge) = crate::auth::parse_challenge(challenge_value) {
                    if let (Some(target_uri), Some(stored_invite_arc)) =
                        (&snapshot.b_leg_target, &snapshot.b_leg_stored_invite)
                    {
                        // RFC 3261 §17.1.1.3: the INVITE client transaction
                        // MUST ACK every non-2xx final response on the branch
                        // it arrived on — the first 401/407 AND every
                        // retransmit. The trunk's server transaction keeps
                        // retransmitting the challenge until this ACK lands;
                        // skipping it (the old behaviour — this path returned
                        // before the non-2xx ACK below) leaves the trunk
                        // retransmitting until Timer B and feeds the re-retry
                        // bug guarded against next.
                        if let Some((b_dest, b_transport)) = snapshot.b_leg_dest {
                            // RFC 3261 §17.1.1.3 — same client transaction as
                            // the INVITE, so the same sent-by (flow socket
                            // when the leg is pinned).
                            let (ack_via_host, ack_via_port) =
                                b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
                            let ack = build_b2bua_ack_for_non2xx(
                                message,
                                branch,
                                snapshot.b_leg_target.as_deref(),
                                b_transport,
                                &ack_via_host,
                                ack_via_port,
                            );
                            send_b2bua_to_bleg(
                                ack,
                                b_transport,
                                b_dest,
                                snapshot.b_leg_local_addr,
                                state,
                            );
                        }

                        // Only the FIRST challenge on this leg drives a retry.
                        // A retransmitted 401/407 on the same branch is the
                        // trunk re-sending its non-2xx (we just re-ACKed it),
                        // NOT a fresh challenge. Re-challenging would emit a
                        // second authenticated INVITE at the same CSeq on a
                        // new branch; the trunk sees a merged request
                        // (RFC 3261 §8.2.2.2) and replies 482, and we end up
                        // with two outstanding UAC branches where the real
                        // 2xx lands on the first while our state tracks the
                        // second — the 2xx then never gets ACKed and the
                        // trunk BYEs the call. A chained re-challenge (stale
                        // nonce) lands on the *retry* leg's branch, a distinct
                        // B-leg, so legitimate re-auth still proceeds.
                        let first_challenge = snapshot
                            .b_leg_index
                            .map(|idx| state.call_actors.try_mark_auth_challenged(call_id, idx))
                            .unwrap_or(true);
                        if !first_challenge {
                            debug!(
                                call_id = %call_id,
                                branch = %branch,
                                status = status_code,
                                "B2BUA: absorbing retransmitted challenge (auth retry already sent on this leg)"
                            );
                            return true;
                        }

                        // Count this committed credentialed retry against the
                        // per-call cap checked at the top of the 401/407
                        // block. Placed after the per-leg dedup so retransmits
                        // (which returned above) never inflate the count.
                        state.call_actors.incr_auth_retry_count(call_id);

                        // RFC 7616 §3.3: nc starts at 1 for a fresh server
                        // nonce and increments on every reuse. The
                        // per-call NonceCounter resets internally when
                        // the nonce changes, so this is correct for both
                        // first challenge and same-nonce re-challenge
                        // (e.g. authenticated re-INVITE in the dialog).
                        let nc = state
                            .call_actors
                            .get_call(call_id)
                            .map(|call| call.digest_nc.next_for(&challenge.nonce))
                            .unwrap_or(1);

                        info!(
                            call_id = %call_id,
                            status = status_code,
                            realm = %challenge.realm,
                            nc = nc,
                            "B2BUA: {status_code} received, retrying with credentials"
                        );

                        let credentials = crate::auth::DigestCredentials {
                            username: username.clone(),
                            password: password.clone(),
                        };

                        let auth_header_name = if status_code == 401 {
                            "Authorization"
                        } else {
                            "Proxy-Authorization"
                        };

                        let auth_value = crate::auth::format_authorization_header(
                            &challenge,
                            &credentials,
                            "INVITE",
                            target_uri,
                            Some(nc),
                            None,
                        );

                        // RFC 5923 connection reuse: keep the authenticated
                        // retry on the SAME trunk member the CSeq-1 INVITE
                        // (and its 401 + nonce) traversed, instead of
                        // re-resolving the trunk hostname and round-robining
                        // onto a sibling member that never issued the nonce.
                        // See select_b2bua_retry_destination for the full
                        // rationale; it falls back to a fresh DNS resolution
                        // only when the leg has no recorded destination.
                        {
                            let (destination, transport, reuse_connection_id, relay_target) =
                                match select_b2bua_retry_destination(
                                    snapshot.b_leg_dest,
                                    snapshot.b_leg_connection_id,
                                    target_uri,
                                    &state.dns_resolver,
                                ) {
                                    Some(resolved) => resolved,
                                    None => return true,
                                };

                            // Build retry from the stored, hygiene-processed B-leg INVITE.
                            // Call-ID, From-tag, From-host, To, RURI, Contact, User-Agent,
                            // P-Asserted-Identity, Record-Route stripping, and the SDP body
                            // (anchored by rtpengine if applicable) are all already correct.
                            let new_branch = TransactionKey::generate_branch();
                            // The credentialed retry continues the same B-leg,
                            // so it keeps the leg's sent-by (flow socket when
                            // it was dialled over one).
                            let (retry_via_host, retry_via_port) =
                                b_leg_sent_by(snapshot.b_leg_local_addr, state, &transport);
                            let via_value = format!(
                                "SIP/2.0/{} {}:{};branch={}",
                                transport, retry_via_host, retry_via_port, new_branch,
                            );
                            let retry = {
                                let Ok(original) = stored_invite_arc.lock() else {
                                    error!(call_id = %call_id, "b_leg_invite lock poisoned during 401/407 retry");
                                    return true;
                                };
                                // RFC 3261 §22.2: incremented CSeq for the retried request.
                                // local_cseq was bumped past the original after first send,
                                // so it now points at the next number to use.
                                build_digest_retry_invite(
                                    &original,
                                    via_value,
                                    snapshot.b_leg_local_cseq,
                                    auth_header_name,
                                    auth_value,
                                )
                            };

                            // Reuse the failed B-leg's dialog identity (Call-ID +
                            // From-tag); the stored INVITE already carries them.
                            let (retry_call_id, retry_from_tag) =
                                snapshot.b_leg_dialog.clone().unwrap_or_else(|| {
                                    (
                                        snapshot.a_leg.dialog.call_id.clone(),
                                        snapshot
                                            .a_leg
                                            .dialog
                                            .remote_tag
                                            .clone()
                                            .unwrap_or_default(),
                                    )
                                });

                            let mut b_leg = Leg::new_b_leg(
                                retry_call_id,
                                retry_from_tag,
                                target_uri.clone(),
                                new_branch,
                                LegTransport {
                                    remote_addr: destination,
                                    connection_id: reuse_connection_id,
                                    transport,
                                    // The retry IS this B-leg continuing, so
                                    // it keeps the leg's anchored socket.
                                    local_addr: snapshot.b_leg_local_addr,
                                },
                            );
                            // Preserve dialog state from the failed attempt:
                            //  - local_cseq advances past the retry CSeq.
                            //  - local_contact / from_uri / to_uri stay so mid-dialog
                            //    requests on this leg work.
                            b_leg.dialog.local_cseq = snapshot.b_leg_local_cseq.saturating_add(1);
                            b_leg.dialog.local_contact = retry.headers.get("Contact").cloned();
                            b_leg.dialog.local_from_uri = retry.headers.from().cloned();
                            b_leg.dialog.remote_to_uri = retry.headers.to().cloned();
                            if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                b_leg.dialog.remote_aor_host =
                                    Some(if let Some(port) = target_parsed.port {
                                        format!("{}:{}", target_parsed.host, port)
                                    } else {
                                        target_parsed.host.clone()
                                    });
                            }
                            // Persist the retry INVITE so a chained re-challenge
                            // (e.g. nonce stale) rebuilds from the right snapshot.
                            b_leg.b_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));

                            // RFC 3261 §9.1: the CSeq-1 INVITE transaction is
                            // complete after its 401/407 + ACK, so the retry is
                            // the *same* logical B-leg continuing with credentials
                            // — supersede the failed leg in place rather than
                            // appending. Appending leaves the dead leg in
                            // `b_legs`, so a later CANCEL fans out to its
                            // already-final-responded transaction too (→ a
                            // spurious 481). `snapshot.b_leg_index` is the slot the
                            // challenged response matched; it is always Some here
                            // (a B-leg response only reaches this path with a
                            // matched leg), but fall back to append defensively.
                            match snapshot.b_leg_index {
                                Some(idx) => {
                                    state.call_actors.replace_b_leg(call_id, idx, b_leg.clone());
                                    spawn_b_leg_actor_at(call_id, &b_leg, idx, state);
                                }
                                None => {
                                    state.call_actors.add_b_leg(call_id, b_leg.clone());
                                    spawn_b_leg_actor(call_id, &b_leg, state);
                                }
                            }

                            let data = Bytes::from(retry.to_bytes());
                            // Egress from the leg's anchored socket (UDP only —
                            // a stream leg is reached over its connection).
                            let retry_source = match transport {
                                Transport::Udp => snapshot.b_leg_local_addr,
                                _ => None,
                            };
                            send_to_target(
                                data,
                                &relay_target,
                                transport,
                                reuse_connection_id,
                                retry_source,
                                state,
                            );
                        }
                        return true; // don't forward 401/407 to A-leg or fire on_failure
                    }
                }
            }
        }
    }

    false
}

/// Where a carrier's final failure left its route sequence, when the call is to
/// fail on it rather than go on to another carrier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouteSequenceEnd {
    /// Whether the carrier's non-2xx was already ACKed, on the way to trying
    /// the next carrier.
    pub b_leg_acked: bool,
    /// Whether the sequence went on and found only carriers it could not dial
    /// ([`RouteAdvance::ended_on_undialable`]).
    pub ended_on_undialable: bool,
}

/// LCR: try the next carrier in the route sequence. `None` when the failure
/// was consumed by a retry or another carrier was dialled; otherwise how the
/// sequence ended.
pub fn advance_route_sequence(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
    relay_challenge: bool,
) -> Option<RouteSequenceEnd> {
    let mut sequence_end = RouteSequenceEnd::default();
    if !relay_challenge && state.call_actors.is_route_sequence(call_id) {
        // Settle this carrier's leg on its final response before anything else
        // looks at the call, so nothing later takes it for a carrier still
        // ringing and CANCELs it (RFC 3261 §9.1).
        //
        // A leg that was already settled makes this a straggler that must
        // NEVER reach the A-leg or the sequence: a retransmission of this
        // carrier's own final response (our ACK was lost), or a response from a
        // leg we cancelled during a failover-advance. So is a `487 Request
        // Terminated`, and ANY non-2xx arriving after another carrier already
        // answered. Without this a cancelled carrier's 487 tears down the
        // bridged call, and a retransmitted 503 is recorded against the carrier
        // now in flight and advances the sequence past it. We still ACK it
        // (RFC 3261 §17.1.1.3) so the carrier stops retransmitting, then drop it
        // — no forward, no teardown, no advance.
        //
        // `map_or(true, …)` not `is_none_or`: MSRV 1.80, and that is 1.82.
        let newly_settled = snapshot.b_leg_index.map_or(true, |index| {
            state
                .call_actors
                .settle_route_branch(call_id, index, status_code)
        });
        if !newly_settled || status_code == 487 || snapshot.call_state == CallState::Answered {
            ack_b_leg_non2xx(branch, message, state, snapshot);
            info!(call_id = %call_id, status = status_code,
    "LCR: absorbing straggler carrier response (cancelled / post-answer / 487)");
            return None;
        }
        // Record the attempt against the carrier that was in flight, and report
        // it, before this carrier is ACKed and the sequence advances or ends.
        b2bua_record_carrier_failure(
            call_id,
            status_code,
            &snapshot.a_leg,
            snapshot.a_leg_invite.as_ref(),
            state,
        );
        // Fail over only on a configured reroute cause (per-route from the
        // API > per-gateway override > global set). A definitive response
        // (486 Busy, 603 Decline, …) is forwarded to the A-leg as-is —
        // trying another carrier won't help.
        let reroute = b2bua_status_reroutes(call_id, status_code, state);
        if reroute && state.call_actors.has_pending_routes(call_id) {
            // ACK this carrier's non-2xx (RFC 3261 §17.1.1.3) before the
            // next try. The failed carrier's media session is keyed by the
            // A-leg Call-ID and reused by the next carrier's B-leg, so it is
            // intentionally NOT torn down here.
            if let Some((b_dest, b_transport)) = snapshot.b_leg_dest {
                // RFC 3261 §17.1.1.3 — same client transaction as the INVITE.
                let (ack_via_host, ack_via_port) =
                    b_leg_sent_by(snapshot.b_leg_local_addr, state, &b_transport);
                let ack = build_b2bua_ack_for_non2xx(
                    message,
                    branch,
                    snapshot.b_leg_target.as_deref(),
                    b_transport,
                    &ack_via_host,
                    ack_via_port,
                );
                send_b2bua_to_bleg(ack, b_transport, b_dest, snapshot.b_leg_local_addr, state);
                sequence_end.b_leg_acked = true;
            }
            let advanced = match snapshot.a_leg_invite.as_ref().map(|arc| arc.lock()) {
                Some(Ok(guard)) => b2bua_advance_route(call_id, &guard, state),
                _ => RouteAdvance::none(),
            };
            // Guard released — safe to run the hook (it re-locks).
            b2bua_dispatch_burned_routes(call_id, &advanced.burned, state);
            if advanced.dialed {
                info!(call_id = %call_id, status = status_code,
        "LCR: advanced to next carrier");
                return None;
            }
            sequence_end.ended_on_undialable = advanced.ended_on_undialable();
        }
        info!(call_id = %call_id, status = status_code, reroute,
"LCR: forwarding carrier response to A-leg (definitive or exhausted)");
    }

    Some(sequence_end)
}
