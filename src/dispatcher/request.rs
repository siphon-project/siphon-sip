//! Inbound request handling: the proxy side of the datapath.
//!
//! Security filter, method intercepts, server transaction, the Python handler,
//! then whichever action it asked for.

use super::*;

/// Does this request carry a To-tag, i.e. is it in-dialog (RFC 3261 §12)?
pub(super) fn to_has_tag(message: &SipMessage) -> bool {
    message
        .headers
        .get("To")
        .map(|value| value.split(';').any(|p| p.trim().starts_with("tag=")))
        .unwrap_or(false)
}

/// Must this request be answered 481 because its B2BUA dialog is already gone?
///
/// RFC 3261 §12.2.2 — a request whose dialog identifier matches no existing
/// dialog gets 481 Call/Transaction Does Not Exist; §15.1.2 says the same for
/// BYE specifically. The case that matters in the field is hang-up glare: both
/// parties send BYE within a few hundred ms, so the second one arrives after the
/// call was torn down. It then misses every B2BUA intercept (they gate on the
/// same Call-ID lookup that has just started failing) and falls through to the
/// proxy path, where a script with no route for it produces a silent drop. The
/// peer is left retransmitting to its own timer F — 32 s of silence, which a
/// VoNR UE treats as a dead IMS and answers by releasing its IMS PDU session and
/// re-registering, costing ~40 s of terminating service.
///
/// Conditions are ordered so a live call pays one hash and stops.
pub(super) fn terminated_dialog_needs_481(
    method: &str,
    message: &SipMessage,
    calls: &crate::b2bua::actor::CallActorStore,
) -> bool {
    // ACK is never answered (RFC 3261 §17.1.1.3). CANCEL for an unknown
    // transaction is already 481'd by `handle_cancel`'s fall-through.
    if method == "ACK" || method == "CANCEL" {
        return false;
    }
    let Some(call_id) = message.headers.call_id() else {
        return false;
    };
    if !calls.is_recently_terminated(call_id) {
        return false;
    }
    // In-dialog only. A peer that reuses a Call-ID for a brand-new dialog sends
    // no To-tag, and must reach the normal INVITE path rather than a 481.
    if !to_has_tag(message) {
        return false;
    }
    // A live call always beats a tombstone, so Call-ID reuse can't 481 a call
    // that is up right now.
    calls.find_by_sip_call_id(call_id).is_none()
}

/// The final response an in-dialog request gets when the B2BUA has no far leg to
/// forward it to.
///
/// A call with one leg is not an error state: a UAS-mode answer, a `handover()`,
/// an IVR and a WebSocket-takeover leg all have exactly one party by
/// construction — the media engine or the control app *is* the far side — so
/// `winner` is never set and there is nothing to bridge to. Whatever the routing
/// decides, the request still has to be answered: a non-INVITE server
/// transaction with no response retransmits on Timer E (T1 doubling to T2) for
/// the full 32 s of Timer F, and a peer that receives nothing cannot tell
/// "refused" from "unreachable".
pub(super) fn no_far_leg_final_response(method: &Method) -> (u16, &'static str) {
    match method {
        // RFC 6665 §8.2.1 — a NOTIFY that matches no subscription on this side
        // is answered 481, which is exactly the case here: siphon owns no REFER
        // subscription for it (that arm absorbed it already) and has no peer
        // dialog to bridge it onto.
        Method::Notify => (481, "Call/Transaction Does Not Exist"),
        // The dialog this arrived on is alive, so 481 would be a lie. siphon
        // simply cannot fulfil the request — RFC 3261 §21.5.1.
        _ => (500, "Server Internal Error"),
    }
}

/// True when an `@b2bua.on_invite` action must not be applied because the call
/// it targets is gone.
///
/// An async handler can `await` (a lookup, a queue position, a model loading,
/// `asyncio.sleep` to ring), and the caller is free to give up while it does.
/// The CANCEL is processed on the dispatcher's own pool, not behind the handler:
/// [`handle_b2bua_cancel`] answers `487`, fires `@b2bua.on_cancel` and
/// `remove_call_after_cancel` deletes the actor. Applying the returned action
/// afterwards puts a second final response on one INVITE server transaction
/// (RFC 3261 §17.2.1) — an answer-first `handover` sends a `200 OK` behind the
/// `487` the caller already saw — and registers a control channel, a B-leg or an
/// LCR sequence for a call nobody is on.
///
/// `Terminated` counts as gone as well as absent: the CANCEL path sets the state
/// before it removes the call, and a teardown from any other direction (script
/// `terminate()`, max-duration, session timer) leaves the same marker.
pub(super) fn invite_action_target_gone(
    call_id: &str,
    calls: &crate::b2bua::actor::CallActorStore,
) -> bool {
    // `map_or(true, …)` not `is_none_or` — MSRV 1.80, see the note in `run`.
    #[allow(clippy::unnecessary_map_or)]
    calls
        .get_call(call_id)
        .map_or(true, |call| call.state == CallState::Terminated)
}

/// Handle an inbound SIP request — run through Python handlers.
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_request: security, method intercepts, script dispatch, action arms
pub(super) fn handle_request(
    inbound: InboundMessage,
    message: SipMessage,
    method: String,
    state: &Arc<DispatcherState>,
) {
    // --- Request security filter (scanner_block + rate_limit) ---
    // Runs before any transaction/dialog/script processing. trusted_cidrs are
    // exempt (handled inside the filter). A blocked request is dropped silently
    // (no response) so we never fingerprint the server to scanners — the same
    // silent-drop policy the Python blocking API uses. Opt-in: a cheap OnceLock
    // read that no-ops until security.rate_limit / security.scanner_block is set.
    if let Some(filter) = crate::security::security_filter() {
        let source = inbound.remote_addr.ip();
        let user_agent = message.headers.get("User-Agent").map(String::as_str);
        match filter.evaluate(source, user_agent) {
            crate::security::SecurityVerdict::Allow => {}
            crate::security::SecurityVerdict::Scanner => {
                debug!(source = %source, %method, "security: dropping request (scanner User-Agent)");
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.scanner_blocked_total.inc();
                }
                // Escalate to an IP ban so the scanner's *other* probes (across
                // methods and transports) are dropped at the ACL too — but only
                // over a connection-oriented transport, where the TCP/TLS/WS/SCTP
                // handshake validates the source address. A scanner User-Agent in
                // a lone UDP datagram has a spoofable source, so banning on it
                // would let an attacker get a victim's IP banned (reflected ban).
                if inbound.transport != crate::transport::Transport::Udp {
                    if let Some(ban) = crate::security::auto_ban() {
                        if ban.record_strong_failure(source) {
                            warn!(source = %source, "auto-ban: source banned (scanner User-Agent)");
                        }
                    }
                }
                return;
            }
            crate::security::SecurityVerdict::RateLimited => {
                debug!(source = %source, %method, "security: dropping request (rate limit exceeded)");
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.rate_limited_total.inc();
                }
                return;
            }
        }
    }

    // --- Extract the UAC's Via branch and sent-by ---
    let uac_via = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next());
    let uac_branch = uac_via.as_ref().and_then(|v| v.branch.clone());
    let uac_sent_by = uac_via
        .as_ref()
        .map(|v| TransactionKey::format_sent_by(&v.host, v.port))
        .unwrap_or_default();

    // --- CANCEL handling ---
    // CANCEL has the same branch as the INVITE it cancels, so we must
    // intercept it BEFORE retransmission detection (which keys on branch).
    if method == "CANCEL" {
        handle_cancel(inbound, message, uac_branch.as_deref(), &uac_sent_by, state);
        return;
    }

    // --- ACK handling (RFC 3261 §17.2.1) ---
    // ACK for non-2xx is hop-by-hop: the transaction layer absorbs it.
    // ACK for 2xx is end-to-end: no IST exists (it terminated on 2xx),
    // so handle_ack returns None and we fall through to the script.
    if method == "ACK" {
        match state.transaction_manager.handle_ack(&message) {
            Ok(Some((key, actions))) => {
                debug!(
                    key = %key,
                    "ACK absorbed by INVITE server transaction"
                );
                process_timer_actions(
                    &actions,
                    &key,
                    Some(inbound.remote_addr),
                    Some(inbound.transport),
                    Some(inbound.connection_id),
                    Some(inbound.local_addr),
                    state,
                );
                return;
            }
            Ok(None) => {
                // No IST found — ACK for 2xx (end-to-end) or stale.
                // Route via ProxySession using Call-ID + From-tag dialog key.
                // Using both fields avoids ambiguity when a B2BUA (e.g. FreeSWITCH)
                // reuses the same Call-ID for both call legs through this proxy.
                let call_id = message.headers.get("Call-ID");
                let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
                if let (Some(cid), Some(ftag)) = (call_id, from_tag.as_deref()) {
                    if let Some(session_arc) = state.session_store.get_by_dialog_key(cid, ftag) {
                        // Stamp before forwarding: the entry existed only to
                        // route this ACK, and what is still owed afterwards is
                        // absorbing a *retransmitted* ACK (the UAS sends one per
                        // retransmitted 2xx), which Timer I bounds. Retiring on
                        // that window instead of 64*T1 is what stops a proxy
                        // pinning a whole `original_request` per answered call.
                        // Stamped here rather than after the call because
                        // `handle_ack_via_session` consumes `message`, which
                        // `cid` borrows from; the ACK is routed either way.
                        ProxySessionStore::mark_dialog_acked(&session_arc);
                        handle_ack_via_session(inbound, message, session_arc, state);
                        return;
                    }

                    // B2BUA late ACK: absorb A-leg's ACK, then send deferred
                    // ACK to the winning B-leg. This completes both legs of the
                    // INVITE transaction simultaneously (RFC 3261 §14.1).
                    if let Some(internal_id) = state.call_actors.find_by_sip_call_id(cid) {
                        // The caller's ACK stops A-leg 2xx retransmission
                        // (RFC 3261 §13.3.1.4). Fire the Notify so the retransmit
                        // task exits; no-op if none is armed (non-2xx ACK).
                        if let Some((_, notify)) = state.uas_2xx_retransmits.remove(&internal_id) {
                            notify.notify_one();
                        }
                        // Take the pending ACK and mark both legs as ACKed.
                        // Grab the winning B-leg's anchored egress socket in the
                        // same pass — the ACK has to leave from where its INVITE
                        // did (flow-dialled legs; see `send_b2bua_to_bleg`).
                        let (pending_ack, b_leg_local_addr) = if let Some(mut call) =
                            state.call_actors.get_call_mut(&internal_id)
                        {
                            call.a_leg.initial_acked = true;
                            let mut b_leg_local_addr = None;
                            if let Some(b_leg) = call.winner.and_then(|i| call.b_legs.get_mut(i)) {
                                b_leg.initial_acked = true;
                                b_leg_local_addr = b_leg.transport.local_addr;
                            }
                            (call.pending_b_leg_ack.take(), b_leg_local_addr)
                        } else {
                            (None, None)
                        };

                        // Send the pre-built ACK to B-leg
                        if let Some((ack, b_transport, b_dest)) = pending_ack {
                            send_b2bua_to_bleg(ack, b_transport, b_dest, b_leg_local_addr, state);
                            debug!(
                                call_id = %internal_id,
                                "B2BUA: sent deferred ACK to B-leg (A-leg ACKed)"
                            );
                        } else {
                            debug!(
                                call_id = %internal_id,
                                "B2BUA: absorbed A-leg ACK (no pending B-leg ACK)"
                            );
                        }
                        return;
                    }
                }
                debug!("ACK matched no IST/session/dialog — dropping (RFC 3261: never respond to or route an ACK)");
            }
            Err(error) => {
                debug!("failed to match ACK to transaction: {error} — dropping ACK");
            }
        }
        // An ACK that matched no server transaction, dialog session, or B2BUA
        // call is a stray/orphan — e.g. the caller's ACK for a B2BUA-forwarded
        // non-2xx (407/486/…) whose call was already torn down, or an ACK that
        // arrives after teardown. RFC 3261 §17: a stateful element MUST NOT
        // respond to an ACK, and an ACK is never a routable standalone request.
        // Drop it silently — never fall through to request routing, which would
        // otherwise fabricate a 502 back to the ACK when its R-URI does not
        // resolve (a response to an ACK — itself a protocol violation).
        return;
    }

    // --- Server transaction retransmission detection ---
    // Check if a server transaction already exists for this request.
    // If so, the state machine handles retransmission (resending cached response).
    match state.transaction_manager.handle_server_retransmit(&message) {
        Ok(Some((key, actions))) => {
            debug!(
                method = %method,
                key = %key,
                "request retransmit handled by server transaction"
            );
            // Process actions — typically SendMessage to resend cached response.
            // Look up ProxySession for source routing, fall back to inbound info.
            for action in &actions {
                if let Action::SendMessage(response) = action {
                    // Send response back to the UAC (the original request source)
                    send_message_from(
                        response.clone(),
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        state,
                    );
                }
            }
            return;
        }
        Ok(None) => {
            // No existing server transaction — this is a new request, proceed below.
        }
        Err(error) => {
            debug!(method = %method, "failed to check server retransmit: {error}");
        }
    }

    debug!(
        method = %method,
        remote = %inbound.remote_addr,
        "processing request"
    );

    // --- SRS: detect inbound SIPREC INVITEs, ACKs, and BYEs ---
    if let Some(ref srs_manager) = state.srs_manager {
        if method == "INVITE" && is_siprec_invite(&message) {
            handle_srs_invite(inbound, message, Arc::clone(srs_manager), state);
            return;
        }
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref call_id) = sip_call_id {
            if srs_manager.is_srs_session(call_id) {
                if method == "ACK" {
                    debug!(call_id = %call_id, "SRS: absorbed ACK for recording session");
                    return;
                }
                if method == "BYE" {
                    handle_srs_bye(inbound, message, call_id, Arc::clone(srs_manager), state);
                    return;
                }
            }
        }
    }

    // Graceful drain — reject NEW INVITEs only (in-dialog re-INVITEs identified
    // by To-tag must still flow so active calls can finish their renegotiation).
    // ACK/BYE/PRACK/CANCEL and all responses are unaffected.
    if method == "INVITE"
        && state
            .is_draining
            .is_draining
            .load(std::sync::atomic::Ordering::Relaxed)
        && !to_has_tag(&message)
    {
        debug!("draining — rejecting new INVITE with 503 Service Unavailable");
        let response = build_response(
            &message,
            503,
            "Service Unavailable",
            state.server_header.as_deref(),
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
        return;
    }

    // In-dialog request for a B2BUA call this node already tore down: 481 rather
    // than a silent drop (see `terminated_dialog_needs_481` for the why). Runs
    // ahead of the B2BUA intercepts below so a re-INVITE for a dead call is also
    // caught here — otherwise `handle_b2bua_invite` takes it for a new call.
    if terminated_dialog_needs_481(&method, &message, &state.call_actors) {
        debug!(
            method = %method,
            call_id = %message.headers.call_id().map(|s| s.as_str()).unwrap_or(""),
            "in-dialog request for a torn-down B2BUA call — 481",
        );
        let response = build_response(
            &message,
            481,
            "Call/Transaction Does Not Exist",
            state.server_header.as_deref(),
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
        return;
    }

    // Check if B2BUA mode should handle this INVITE
    let engine_state = state.engine.state();
    if method == "INVITE" && engine_state.has_b2bua_handlers() {
        // Detect re-INVITE (has To-tag + matches existing call)
        let to_tag = message.headers.get("To").and_then(|t| {
            t.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        });
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());

        let is_reinvite = to_tag.is_some()
            && sip_call_id
                .as_ref()
                .map(|cid| state.call_actors.find_by_sip_call_id(cid).is_some())
                .unwrap_or(false);

        if is_reinvite {
            drop(engine_state);
            handle_b2bua_reinvite(inbound, message, state);
            return;
        }

        drop(engine_state);
        handle_b2bua_invite(inbound, message, state);
        return;
    }
    if method == "BYE" && engine_state.has_b2bua_handlers() {
        // Check if this BYE belongs to a B2BUA call
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_bye(inbound, message, state);
                return;
            }
        }
    }
    // Rf ACR-STOP on inbound proxy BYE (TS 32.299 §6.2.2).  Fires
    // before the script handler so accounting is closed even if the
    // script chooses to drop or reject the BYE; the SIP path itself
    // is unaffected (spawn is fire-and-forget).
    if method == "BYE" {
        spawn_rf_proxy_stop_if_tracked(state, &message);
    }
    // CDR: the call record is written when this scope ends — i.e. *after* the
    // script's BYE handler ran, so `cdr.write(request, extra=…)` from
    // `@proxy.on_request("BYE")` still lands on it. A drop guard rather than a
    // call at the end of the function because the record must be written on
    // every exit path, including the one a dropped or rejected BYE takes —
    // same "accounting closes regardless of what the script decides" rule as
    // the ACR-STOP above.
    let _cdr_stop_guard = if method == "BYE" && crate::cdr::auto_emit_enabled() {
        CdrProxyStop::from_bye(&message).map(|parts| CdrProxyStopGuard {
            sessions: Arc::clone(&state.cdr_sessions),
            parts: Some(parts),
        })
    } else {
        None
    };
    if method == "UPDATE" && engine_state.has_b2bua_handlers() {
        // RFC 3311 in-dialog UPDATE belonging to a B2BUA call: bridge it
        // across like a re-INVITE. Calls that don't match a tracked B2BUA
        // dialog fall through to proxy mode (correct for stateless UPDATE
        // forwarding by non-B2BUA scripts).
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_update(inbound, message, state);
                return;
            }
        }
    }
    if method == "REFER" && engine_state.has_b2bua_handlers() {
        // RFC 3515 in-dialog REFER belonging to a B2BUA call: siphon owns the
        // transfer (fire @b2bua.on_refer, then terminate / forward / reject).
        // This intercept MUST run before the generic proxy path below — an
        // in-dialog REFER routed by Request-URI would be relayed straight back
        // at siphon's advertised address and loop (the storm this fixes). A
        // REFER on a Call-ID that matches no tracked B2BUA call falls through
        // (out-of-dialog REFER handled by proxy scripts, unchanged).
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_refer(inbound, message, state);
                return;
            }
        }
    }
    if method == "NOTIFY" && engine_state.has_b2bua_handlers() {
        // In-dialog NOTIFY belonging to a B2BUA call — the sipfrag progress of a
        // REFER subscription (RFC 3515 §2.4). Either a subscription siphon owns
        // (siphon-originated transfer: 200 OK + read the sipfrag) or the far
        // end's NOTIFY on a transparent transfer (bridge it to the referrer).
        // A NOTIFY on a Call-ID matching no tracked call falls through to the
        // proxy path (presence/reg-event etc., unchanged).
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_notify(inbound, message, state);
                return;
            }
        }
    }
    if method == "PRACK" {
        // RFC 3262 §3 — does this PRACK acknowledge a reliable provisional we
        // sent ourselves (script called reply(reliable=True))? If so: cancel
        // retransmits, send 200 OK PRACK, done. Runs in both proxy and B2BUA
        // modes; the B2BUA-specific auto-200 path below only fires when no
        // tracked entry matches (e.g. A-leg PRACKs that originated from the
        // UAC's own 100rel handling, not from us).
        if let Some(rack) = crate::sip::headers::rseq::parse_rack(&message.headers) {
            let sip_call_id = message
                .headers
                .get("Call-ID")
                .map(|s| s.to_string())
                .unwrap_or_default();
            let key = (sip_call_id.clone(), rack.response_number);
            let matched = state
                .reliable_provisionals
                .get(&key)
                .map(|r| Arc::clone(r.value()))
                .filter(|entry| entry.cseq_num == rack.cseq_number);
            if let Some(entry) = matched {
                state.reliable_provisionals.remove(&key);
                entry.cancel.notify_one();
                debug!(
                    call_id = %sip_call_id, rseq = rack.response_number,
                    "PRACK matches our reliable 1xx — cancelling retransmits and sending 200 OK"
                );
                let response =
                    build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
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

        if engine_state.has_b2bua_handlers() {
            // RFC 3262: the A-leg PRACK acknowledges our reliable provisional.
            // In B2BUA mode siphon already PRACKed the B-leg locally (see the
            // auto-PRACK path in the response handler), so the A-leg PRACK has
            // no upstream peer to relay to — terminate it here with 200 OK.
            let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
            if let Some(ref sip_call_id) = sip_call_id {
                if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                    drop(engine_state);
                    handle_b2bua_prack(inbound, message, state);
                    return;
                }
            }
        }
    }

    // --- Create server transaction ---
    // The server transaction handles retransmission absorption and timer management.
    // ACK is excluded (handled by existing IST), as are requests going to B2BUA.
    let txn_transport = crate::transaction::state::Transport::from(inbound.transport);
    let server_key = match state
        .transaction_manager
        .new_server_transaction(&message, txn_transport)
    {
        Ok(outcome) if !outcome.is_new => {
            // Another worker created this transaction between our
            // `handle_server_retransmit` check above and the create — i.e. a
            // retransmission arrived while the original was still being
            // processed, and both landed on different workers. It is already
            // being handled; running the script for this copy too would fork
            // the call a second time downstream on a fresh branch.
            debug!(
                method = %method,
                key = %outcome.key,
                "request raced an in-flight copy of itself — absorbed"
            );
            return;
        }
        Ok(crate::transaction::ServerTransactionOutcome { key, actions, .. }) => {
            // Schedule any initial server-side timers
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", key, name);
                    state.timer_wheel.insert(
                        timer_id,
                        Box::new(TimerEntry {
                            key: key.clone(),
                            name: *name,
                            fires_at: std::time::Instant::now() + *duration,
                            // Server transaction timers send responses upstream (to UAC)
                            destination: Some(inbound.remote_addr),
                            transport: Some(inbound.transport),
                            connection_id: Some(inbound.connection_id),
                            // Retransmit cached responses on the same SA's
                            // local endpoint (TS 33.203 §7.4).
                            source_local_addr: Some(inbound.local_addr),
                        }),
                    );
                }
            }
            Some(key)
        }
        Err(error) => {
            // The request is still processed, statelessly — but with no
            // transaction there is no retransmission absorption, so every
            // retransmission runs the script again. Overwhelmingly this is a
            // topmost Via with no `branch` (mandatory since RFC 3261 §8.1.1.7;
            // siphon has no RFC 2543 legacy matching — see
            // `transaction::key`), which is worth counting rather than
            // learning about later from a duplicate-call report.
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.requests_without_branch_total.inc();
            }
            debug!(method = %method, "failed to create server transaction: {error}");
            None
        }
    };

    // --- Max-Forwards enforcement (RFC 3261 §16.3) ---
    // Check BEFORE invoking scripts — if MF == 0, reject immediately.
    if message.headers.max_forwards() == Some(0) {
        debug!(method = %method, "Max-Forwards is 0, rejecting with 483");
        let response = build_response(
            &message,
            483,
            "Too Many Hops",
            state.server_header.as_deref(),
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
        return;
    }

    // Look up matching Python handlers
    let handlers = engine_state.proxy_request_handlers(&method);

    if handlers.is_empty() {
        // No script handler claims this method, and that means two different
        // things depending on the method, so it gets two different answers.
        //
        // OPTIONS is a liveness probe, and answering it is the stack's job
        // rather than every script's. A registrar qualifies its bindings —
        // Asterisk's `qualify_frequency` and its equivalents send OPTIONS to the
        // registered contact on a timer for the life of the registration — so a
        // siphon that registers to a provider answers one of these forever. RFC
        // 3261 §11.2 has a UAS respond 200 with its capabilities. Requiring each
        // deployment to hand-write that handler got it wrong twice over: the
        // answer was a 5xx (below), and the failure was invisible, because a
        // qualifying registrar accepts *any* final response as proof of life and
        // shows the contact reachable with a healthy RTT. A peer with the
        // stricter reading — 5xx is a failed probe — stops sending calls while
        // the siphon side still shows a perfectly healthy registration.
        //
        // Everything else gets 405 + `Allow` (RFC 3261 §8.2.1: a UAS that does
        // not support the method "MUST generate a 405 (Method Not Allowed)
        // response" and "MUST add an Allow header field"). That is what is
        // actually true and it is something the sender can act on; 500 says this
        // server is broken, and invites a retry that fails identically.
        //
        // `Allow` states what the *stack* implements, not what this script
        // routes, and the difference is deliberate. Deriving the set from the
        // registered handlers would under-advertise every method the framework
        // dispatches somewhere other than `@proxy.on_request` — REFER to
        // `@b2bua.on_refer`, CANCEL and ACK to the transaction layer — and
        // under-advertising `Allow` is exactly how Teams Direct Routing stopped
        // offering REFER once already (see `crate::sip::SUPPORTED_METHODS`).
        let Some(response) = build_no_handler_response(
            &message,
            &method,
            state.auto_options,
            state.server_header.as_deref(),
            // Family-matched to the socket the probe arrived on, so a v6 probe
            // gets a v6 Contact and the exact arrival port.
            &state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
            inbound.local_addr.port(),
            inbound.transport,
        ) else {
            debug!(
                method = %method,
                "no script handler and server.auto_options is off — dropping OPTIONS silently"
            );
            // Reap the server transaction exactly as the script's own silent
            // drop does (`RequestAction::None` below): a NIST whose TU never
            // sends a final response never reaches Terminated (RFC 3261 §17.2
            // assumes the TU always answers), so it would sit in the map holding
            // a full SipMessage clone — an unbounded leak under exactly the
            // probe flood this knob exists for. Dropping the auto-100 timer with
            // it is what makes the drop actually silent: leave it armed and RFC
            // 4320 §4.2's synthesized `100 Trying` goes out anyway, which both
            // strands the transaction and tells the scanner something is
            // listening — the one thing turning this off was meant to prevent.
            if let Some(ref key) = server_key {
                state.transaction_manager.remove(key);
                state
                    .timer_wheel
                    .remove(&format!("{}:{:?}", key, TimerName::Trying100));
            }
            return;
        };
        if method == "OPTIONS" {
            debug!(method = %method, "no script handler — answering OPTIONS locally (RFC 3261 §11.2)");
        } else {
            warn!(method = %method, "no script handler registered — answering 405");
        }

        // Feed it to the server transaction the way a script's own reply is fed
        // (RFC 3261 §17.2.1/§17.2.2), so a retransmitted request is answered
        // from the cached response instead of falling into silence — over UDP
        // that lost-probe case is the whole reason this path matters. Falls back
        // to a direct send when no transaction was created (a topmost Via
        // carrying no branch).
        let mut sent_by_transaction = false;
        if let Some(ref key) = server_key {
            let event = if key.method == crate::sip::message::Method::Invite {
                // Only reachable as the 405 — an OPTIONS never keys an IST.
                ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone()))
            } else {
                ServerEvent::Nist(NistEvent::TuFinal(response.clone()))
            };
            match state.transaction_manager.process_server_event(key, event) {
                Ok(actions) => {
                    sent_by_transaction =
                        actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                    process_timer_actions(
                        &actions,
                        key,
                        Some(inbound.remote_addr),
                        Some(inbound.transport),
                        Some(inbound.connection_id),
                        Some(inbound.local_addr),
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %key, "failed to feed no-handler reply to server transaction: {error}");
                }
            }
        }
        if !sent_by_transaction {
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
        }
        return;
    }

    // CDR: open the record before the script runs (cdr.auto_emit), so
    // `cdr.write(request, extra=…)` from the handler attaches its fields to the
    // call's own record instead of queueing a second, timing-less one beside
    // it. Settled below once the script's decision is known — an INVITE the
    // proxy never forwards is not a call and its record is dropped again.
    let cdr_key = if method == "INVITE" {
        cdr_track_proxy_start(
            &state.cdr_sessions,
            &message,
            &inbound.remote_addr.ip().to_string(),
            &format!("{}", inbound.transport).to_lowercase(),
        )
    } else {
        None
    };

    // Create PyRequest wrapping the message
    let transport_name = format!("{}", inbound.transport).to_lowercase();
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let mut request = PyRequest::with_local_domains(
        message_arc.clone(),
        transport_name,
        inbound.remote_addr.ip().to_string(),
        inbound.remote_addr.port(),
        Arc::clone(&state.local_domains),
    )
    .with_self_identity(Arc::clone(&state.self_identity));
    // Tag the request with its arrival local port so `is_ipsec_protected`
    // / `matched_sa` can resolve when running as P-CSCF (3GPP TS 33.203).
    request.set_local_port(inbound.local_addr.port());
    // Capture the full inbound flow for token-keyed MT routing
    // (`registrar.save(flow_token=...)` and `request.relay(flow=...)`).
    request.set_inbound_flow(inbound.local_addr, inbound.connection_id.0);

    // Call Python handlers
    let (
        action,
        record_routed,
        on_reply_cb,
        on_failure_cb,
        send_via_transport,
        send_via_target,
        reply_headers,
        reply_body,
        auth_user,
    ) = Python::attach(|python| {
        let py_request = match Py::new(python, request) {
            Ok(py) => py,
            Err(error) => {
                error!("failed to create PyRequest: {error}");
                return (
                    RequestAction::None,
                    false,
                    None,
                    None,
                    None,
                    None,
                    vec![],
                    None,
                    None,
                );
            }
        };

        // Enable deferred sends so presence.notify() etc. queue messages
        // until after the reply is sent (RFC 3265 §3.1.6.2).
        crate::script::api::proxy_utils::enable_deferred_sends();

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python),));
            match result {
                Ok(ret) => {
                    // If the handler is async, the return value is a coroutine — await it.
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async Python", &error);
                            return (
                                RequestAction::Reply {
                                    code: 500,
                                    reason: "Script Error".to_string(),
                                    reliable: false,
                                },
                                false,
                                None,
                                None,
                                None,
                                None,
                                vec![],
                                None,
                                None,
                            );
                        }
                    }
                }
                Err(error) => {
                    record_script_error("Python", &error);
                    return (
                        RequestAction::Reply {
                            code: 500,
                            reason: "Script Error".to_string(),
                            reliable: false,
                        },
                        false,
                        None,
                        None,
                        None,
                        None,
                        vec![],
                        None,
                        None,
                    );
                }
            }

            // `request.stop_propagation()` — this handler owns the outcome.
            // Every matching handler shares one action slot, and only its final
            // value executes, so without this a later handler silently replaces
            // an earlier one's decision (registration order decides). Checked
            // after the handler returns so an async one has already been driven
            // to completion above.
            if py_request.borrow(python).is_propagation_stopped() {
                break;
            }
        }

        let mut borrowed = py_request.borrow_mut(python);
        let action = borrowed.action().clone();
        let record_routed = borrowed.is_record_routed();
        let on_reply = borrowed.take_on_reply_callback();
        let on_failure = borrowed.take_on_failure_callback();
        let send_via_transport = borrowed.via_transport_override().map(|s| s.to_string());
        let send_via_target = borrowed.via_target_override().map(|s| s.to_string());
        let reply_headers = borrowed.take_reply_headers();
        let reply_body = borrowed.take_reply_body();
        // Read *after* the handler ran, so a script that authenticated the
        // caller — or normalised the identity afterwards — is what reaches the
        // CDR. Reading it before would always be empty.
        let auth_user = borrowed.get_auth_user().map(String::from);
        (
            action,
            record_routed,
            on_reply,
            on_failure,
            send_via_transport,
            send_via_target,
            reply_headers,
            reply_body,
            auth_user,
        )
    });

    // Process the action
    let Ok(message_guard) = message_arc.lock() else {
        error!("message_arc lock poisoned");
        return;
    };
    match &action {
        RequestAction::None => {
            debug!("silent drop (no action from script)");
            // Reap the server transaction created for this request. A NIST/IST
            // whose TU never sends a final response never reaches Terminated
            // (RFC 3261 §17.2 has no absolute server-side timeout — it assumes
            // the TU always responds), so a silent drop would otherwise strand
            // it in the transaction map forever, each entry holding a full
            // SipMessage clone. Under unhandled-request churn (e.g. SUBSCRIBE to
            // a call-only B2BUA) or a scanner / rate-limit flood that is an
            // unbounded leak — and a memory-DoS vector. A dropped request has
            // nothing to retransmit-absorb; a later UDP retransmit just
            // recreates a fresh transaction and re-runs the handler (which drops
            // again). Also drop the auto-100 timer so the wheel entry is freed
            // immediately and the drop stays silent (no synthesized 100 Trying).
            if let Some(ref key) = server_key {
                state.transaction_manager.remove(key);
                state
                    .timer_wheel
                    .remove(&format!("{}:{:?}", key, TimerName::Trying100));
            }
        }
        RequestAction::Reply {
            code,
            reason,
            reliable,
        } => {
            let mut response = build_response(
                &message_guard,
                *code,
                reason,
                state.server_header.as_deref(),
                &reply_headers,
            );

            // Script-provided reply body — PIDF-LO, XCAP/Ut, custom failure body, etc.
            if let Some((body_bytes, content_type)) = &reply_body {
                response.headers.set("Content-Type", content_type.clone());
                response
                    .headers
                    .set("Content-Length", body_bytes.len().to_string());
                response.body = body_bytes.clone();
            }

            // RFC 3261 §11.2 — make a 2xx OPTIONS a proper capability response: a
            // Contact (Microsoft Teams Direct Routing rejects an OPTIONS answer
            // carrying neither Contact nor Record-Route) plus an Allow advertising
            // siphon's supported methods (peers read transfer capability from it).
            // Both are added only when absent, so a script-set header still wins.
            if method == "OPTIONS" && (200..300).contains(code) {
                augment_options_response(
                    &mut response,
                    // Family-matched to the socket the OPTIONS arrived on, so a v6
                    // probe gets a v6 Contact/Via and the exact arrival port.
                    &state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
                    inbound.local_addr.port(),
                    inbound.transport,
                );
            }

            // RFC 3262 — script asked for a reliable provisional. Only valid for
            // 101..199 INVITE responses, and only when the UAC advertised 100rel.
            // We attach Require: 100rel + a fresh RSeq, then arm a retransmit
            // task that fires until a matching PRACK arrives or the deadline
            // (32s = 64×T1) elapses.
            let mut reliable_provisional_armed = false;
            if *reliable && (101..200).contains(code) {
                if !crate::sip::headers::rseq::supports_100rel(&message_guard.headers) {
                    warn!(
                        method = %method, code = %code,
                        "reliable=True ignored: UAC didn't advertise 100rel in Supported/Require"
                    );
                } else if method != "INVITE" {
                    warn!(method = %method, code = %code,
                        "reliable=True ignored: only valid on responses to INVITE");
                } else {
                    let rseq = crate::sip::headers::rseq::next_rseq();
                    // Merge 100rel into existing Require if present, else set fresh.
                    let new_require = match response.headers.get("Require") {
                        Some(existing)
                            if existing
                                .split(',')
                                .any(|t| t.trim().eq_ignore_ascii_case("100rel")) =>
                        {
                            existing.clone()
                        }
                        Some(existing) => format!("{}, 100rel", existing),
                        None => "100rel".to_string(),
                    };
                    response.headers.set("Require", new_require);
                    response.headers.set("RSeq", rseq.to_string());
                    arm_reliable_provisional_retransmit(
                        rseq,
                        &message_guard,
                        response.clone(),
                        &inbound,
                        state,
                    );
                    reliable_provisional_armed = true;
                }
            }
            let _ = reliable_provisional_armed;

            // IPsec Security-Server / SA setup on 401 REGISTER is now driven
            // by the P-CSCF script (see `siphon.ipsec` and `reply.take_av()`).
            // The dispatcher only retains de-register auto-cleanup as a safety
            // net for SA leaks.

            // IPsec: delete SA pair on deregistration (REGISTER with Expires: 0)
            if *code == 200 && method == "REGISTER" {
                if let (Some(ref _ipsec_config), Some(ref ipsec_manager)) =
                    (&state.ipsec_config, &state.ipsec_manager)
                {
                    let is_deregister = message_guard
                        .headers
                        .get("Expires")
                        .map(|value| value.trim() == "0")
                        .unwrap_or(false)
                        || message_guard
                            .headers
                            .get("Contact")
                            .map(|value| value.contains("expires=0"))
                            .unwrap_or(false);

                    if is_deregister {
                        let ue_addr = inbound.remote_addr.ip();
                        let ue_port = inbound.remote_addr.port();
                        let ipsec_manager = Arc::clone(ipsec_manager);
                        tokio::spawn(async move {
                            if let Err(error) =
                                ipsec_manager.delete_sa_pair(&ue_addr, ue_port).await
                            {
                                warn!(ue = %ue_addr, %error, "IPsec: failed to delete SA pair");
                            }
                        });
                    }
                }
            }

            // Messages the handler deferred (subscribe_state.notify(),
            // presence.notify()) that are addressed to the peer this reply goes
            // to must leave AFTER it: RFC 6665 §4.1.2.3 has the notifier send
            // the initial NOTIFY once the subscription is accepted, i.e. after
            // the 2xx to the SUBSCRIBE. §4.4.1 obliges a subscriber to cope with
            // the reverse arrival order, but that allowance exists for a network
            // that reorders — it is not licence for the notifier to emit out of
            // order, which is what queueing them as two independent messages did
            // (the UDP workers share the outbound channel and each owns a
            // socket, so the NOTIFY could overtake the reply).
            //
            // They ride along as followups of the reply instead. Deferred
            // messages for any OTHER peer are untouched and still go out via
            // `flush_deferred_sends` at the end of the request.
            let mut reply_followups: Vec<Bytes> =
                crate::script::api::proxy_utils::drain_deferred_sends_for(
                    inbound.remote_addr,
                    inbound.transport,
                )
                .into_iter()
                .map(|deferred| Bytes::from(deferred.message.to_bytes()))
                .collect();

            // Feed response into server transaction so it can cache it for
            // retransmit handling and manage Timer J/G/H.
            // The state machine emits SendMessage which process_timer_actions
            // delivers, so we only send manually if the transaction path didn't fire.
            let mut sent_by_transaction = false;
            if let Some(ref key) = server_key {
                let server_event = if *code < 200 {
                    // Provisional
                    if key.method == crate::sip::message::Method::Invite {
                        Some(ServerEvent::Ist(IstEvent::TuProvisional(response.clone())))
                    } else {
                        Some(ServerEvent::Nist(NistEvent::TuProvisional(
                            response.clone(),
                        )))
                    }
                } else if *code < 300 && key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::Tu2xx(response.clone())))
                } else if key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuFinal(response.clone())))
                };

                if let Some(event) = server_event {
                    match state.transaction_manager.process_server_event(key, event) {
                        Ok(actions) => {
                            sent_by_transaction =
                                actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                            process_timer_actions_with_followups(
                                &actions,
                                key,
                                Some(inbound.remote_addr),
                                Some(inbound.transport),
                                Some(inbound.connection_id),
                                Some(inbound.local_addr),
                                if sent_by_transaction {
                                    std::mem::take(&mut reply_followups)
                                } else {
                                    Vec::new()
                                },
                                state,
                            );
                        }
                        Err(error) => {
                            debug!(key = %key, "failed to feed reply to server transaction: {error}");
                        }
                    }
                }
            }
            if !sent_by_transaction {
                send_frames_in_order_from(
                    Bytes::from(response.to_bytes()),
                    std::mem::take(&mut reply_followups),
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    state,
                );
            }
            // Anything still held (no reply path fired at all) must not be lost.
            if !reply_followups.is_empty() {
                if let Some(uac_sender) = crate::script::api::proxy_utils::uac_sender() {
                    for frame in std::mem::take(&mut reply_followups) {
                        uac_sender.send_bytes(frame, inbound.remote_addr, inbound.transport);
                    }
                }
            }
        }
        RequestAction::Relay {
            next_hop,
            flow,
            send_socket,
        } => {
            // RFC 3261 §16.2: a stateful proxy SHOULD send 100 Trying
            // immediately upon receiving an INVITE to stop UAC retransmissions.
            if method == "INVITE" {
                let trying = build_response(
                    &message_guard,
                    100,
                    "Trying",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(
                    trying,
                    inbound.transport,
                    inbound.remote_addr,
                    inbound.connection_id,
                    Some(inbound.local_addr),
                    state,
                );
            }
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            relay_request(
                &message_guard,
                next_hop.as_deref(),
                record_routed,
                &inbound,
                server_key.as_ref(),
                state,
                on_reply_cb,
                on_failure_cb,
                send_via_transport.as_deref(),
                send_via_target.as_deref(),
                flow.as_ref(),
                send_socket.as_ref(),
            );
        }
        RequestAction::Fork {
            targets,
            flows,
            routes,
            strategy,
            send_socket,
        } => {
            if targets.is_empty() {
                warn!("fork with empty targets list");
                let response = build_response(
                    &message_guard,
                    500,
                    "No Targets",
                    state.server_header.as_deref(),
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
            } else {
                if method == "INVITE" {
                    let trying = build_response(
                        &message_guard,
                        100,
                        "Trying",
                        state.server_header.as_deref(),
                        &[],
                    );
                    send_message_from(
                        trying,
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        state,
                    );
                }
                let fork_strategy = match strategy.as_str() {
                    "sequential" => crate::proxy::fork::ForkStrategy::Sequential,
                    _ => crate::proxy::fork::ForkStrategy::Parallel,
                };
                let send_socket = state.resolve_send_socket(send_socket.as_deref());
                relay_fork_request(
                    &message_guard,
                    targets,
                    flows,
                    routes,
                    fork_strategy,
                    record_routed,
                    &inbound,
                    server_key.as_ref(),
                    state,
                    send_socket.as_ref(),
                    on_reply_cb,
                    on_failure_cb,
                );
            }
        }
    }

    // CDR: settle the record opened before the handler ran. A forwarded INVITE
    // keeps it (and takes the identity the script authenticated); anything else
    // is not a call, so the record is dropped — unless the script attached
    // fields to it, which is an explicit ask for a record of the attempt.
    if let Some(cdr_key) = &cdr_key {
        let outcome = match &action {
            RequestAction::Relay { .. } | RequestAction::Fork { .. } => {
                ProxyInviteOutcome::Forwarded {
                    auth_user: auth_user.as_deref(),
                }
            }
            RequestAction::Reply { code, .. } => ProxyInviteOutcome::Rejected { code: *code },
            _ => ProxyInviteOutcome::Dropped,
        };
        cdr_settle_proxy_start(&state.cdr_sessions, cdr_key, outcome);
    }

    // Flush deferred messages (e.g. in-dialog NOTIFY) after the reply/relay
    // has been dispatched, per RFC 3265 §3.1.6.2 (200 OK before NOTIFY).
    flush_deferred_sends(state);
}
