//! Inbound response handling.
//!
//! Matches the response to a transaction or session, runs the script reply
//! handlers, and forwards upstream with the top Via stripped.

use super::*;

/// Handle an inbound SIP response — route back to the original sender.
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_response: pre-session guards + session forwarding; splits in two
pub(super) fn handle_response(
    inbound: InboundMessage,
    mut message: SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    // RFC 3261 §17.1.1.2 / §17.1.2.2: the first response on a branch ends
    // retransmission of the request that provoked it — a provisional moves an
    // INVITE client transaction Calling -> Proceeding and cancels Timer A, and
    // any final ends the transaction.
    //
    // The B2BUA runs its own schedule (it registers no client transaction), so
    // it needs its own cancel, and it has to happen *here*: several responses
    // never reach `handle_b2bua_response` — a 100 Trying is absorbed below
    // (§16.7 step 3), a 2xx for an already-cancelled call is diverted to the
    // zombie path — and a leg that kept retransmitting behind a peer which
    // already holds the request is exactly the spurious duplicate that trips
    // merged-request detection (482).
    //
    // Keyed on the CSeq method so a CANCEL's own response does not stop the
    // INVITE it shares a branch with (§9.1). Non-B2BUA responses simply miss.
    disarm_b2bua_retransmit_for_response(&message, state);

    // A referrer that just answered the terminating sipfrag NOTIFY has learned
    // the transfer completed, so the BYE that ends the dialog underneath it is
    // now safe to send (RFC 3515 §2.4.4). Ahead of every other match: the
    // NOTIFY is siphon's own request on the referrer's dialog and belongs to no
    // leg, so nothing below would claim it, and the response itself still falls
    // through to the paths that absorb it.
    release_deferred_referrer_bye(&message, status_code, state);

    // Check if this response matches a UAC request (keepalive, health probe)
    if state.uac_sender.match_response(&message) {
        debug!(status_code = status_code, "UAC response matched");
        return;
    }

    // Check if this response matches an outbound registration (z9hG4bK-reg- branch)
    if let Some(ref registrant) = state.registrant_manager {
        if let Some(top_via_raw) = message.headers.get("Via") {
            if let Ok(vias) = Via::parse_multi(top_via_raw) {
                if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                    if branch.starts_with("z9hG4bK-reg-") {
                        handle_registrant_response(
                            registrant,
                            &message,
                            status_code,
                            branch,
                            state,
                        );
                        return;
                    }
                }
            }
        }
    }

    // Check if this response matches a SIPREC recording INVITE (z9hG4bK-rec- branch)
    if let Some(top_via_raw) = message.headers.get("Via") {
        if let Ok(vias) = Via::parse_multi(top_via_raw) {
            if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                if branch.starts_with("z9hG4bK-rec-") {
                    if let Some(session_id) = state.recording_manager.session_for_branch(branch) {
                        if (200..300).contains(&status_code) {
                            let to_tag = message
                                .headers
                                .get("To")
                                .and_then(|to| to.split("tag=").nth(1))
                                .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string());

                            // RTPEngine subscribe_answer: complete the media fork
                            // by sending the SRS's answer SDP back to RTPEngine.
                            if !message.body.is_empty() {
                                if let Some(ref rtpengine_set) = state.rtpengine_set {
                                    if let Some((
                                        original_call_id,
                                        original_from_tag,
                                        original_to_tag,
                                    )) = state.recording_manager.original_call_info(&session_id)
                                    {
                                        info!(
                                            session_id = %session_id,
                                            original_call_id = %original_call_id,
                                            from_tag = %original_from_tag,
                                            to_tag = %original_to_tag,
                                            sdp_len = message.body.len(),
                                            "SIPREC: sending subscribe_answer to RTPEngine"
                                        );
                                        let flags = crate::rtpengine::NgFlags::default();
                                        match tokio::task::block_in_place(|| {
                                            tokio::runtime::Handle::current().block_on(
                                                rtpengine_set.subscribe_answer(
                                                    &original_call_id,
                                                    &original_from_tag,
                                                    &original_to_tag,
                                                    &message.body,
                                                    &flags,
                                                ),
                                            )
                                        }) {
                                            Ok(_rewritten_sdp) => {
                                                info!(
                                                    session_id = %session_id,
                                                    "SIPREC: RTPEngine subscribe_answer completed, media fork active"
                                                );
                                            }
                                            Err(error) => {
                                                warn!(
                                                    session_id = %session_id,
                                                    %error,
                                                    "SIPREC: RTPEngine subscribe_answer failed"
                                                );
                                            }
                                        }
                                    } else {
                                        warn!(
                                            session_id = %session_id,
                                            "SIPREC: no original call info for subscribe_answer"
                                        );
                                    }
                                }
                            }

                            // Build and send ACK for 2xx (RFC 3261 §13.2.2.4).
                            if let Some((ack, destination, transport)) = state
                                .recording_manager
                                .handle_success(&session_id, to_tag, state.local_addr)
                            {
                                let data = Bytes::from(ack.to_bytes());
                                let target = RelayTarget {
                                    address: destination,
                                    transport: Some(transport),
                                    server_name: None,
                                };
                                send_to_target(
                                    data,
                                    &target,
                                    transport,
                                    ConnectionId::default(),
                                    None,
                                    state,
                                );
                            }
                        } else if status_code >= 300 {
                            state
                                .recording_manager
                                .handle_failure(&session_id, status_code);
                        }
                    }
                    return;
                }
            }
        }
    }

    // RFC 3261 §16.7 step 3: a proxy MUST NOT forward 100 Trying upstream.
    // It is hop-by-hop; the proxy already sends its own 100 Trying to the UAC.
    //
    // BUT the 100 still has to drive the *client* transaction: RFC 3261
    // §17.1.1.2 says the first provisional moves an INVITE client transaction
    // Calling -> Proceeding and cancels Timer A (the INVITE retransmit timer).
    // Returning here without feeding the FSM (the old behaviour) leaves Timer A
    // armed, so the proxy spuriously retransmits the forwarded INVITE at ~T1
    // (~500 ms) even though it already holds a 100 — wasted signalling, and on a
    // lossy/slow trunk the duplicate can trip the peer's merged-request/loop
    // detection (482). Feed the transaction here (cancelling Timer A / capping
    // Timer E for NICT), then absorb without forwarding.
    //
    // For a B2BUA leg there is no client transaction registered under this key
    // (the B2BUA manages its own legs and drives its own retransmit schedule
    // instead — see `b2bua_retransmits` below), so process_client_event returns
    // Err and that part is a harmless no-op.
    if status_code == 100 {
        // Drive only the INVITE client transaction (cancel Timer A). A
        // non-INVITE client transaction (NICT) treats a provisional as a
        // Timer-E cap rather than a stop, and 100 Trying is INVITE-specific in
        // practice, so for non-INVITE we keep the historical absorb-only
        // behaviour to avoid disturbing the NICT retransmit timer's pinned
        // destination.
        if let Ok(key) = TransactionManager::key_from_message(&message) {
            if key.method == crate::sip::message::Method::Invite {
                if let Ok(actions) = state.transaction_manager.process_client_event(
                    &key,
                    ClientEvent::Ict(IctEvent::Provisional(message.clone())),
                ) {
                    for action in &actions {
                        if let Action::CancelTimer(name) = action {
                            state.timer_wheel.remove(&format!("{}:{:?}", key, name));
                        }
                    }
                }
            }
        }
        debug!(
            "absorbing 100 Trying from downstream (cancelled INVITE client Timer A; not forwarded)"
        );
        return;
    }

    // Get the topmost Via to find the branch
    let top_via = match message.headers.get("Via") {
        Some(raw) => match Via::parse_multi(raw) {
            Ok(vias) if !vias.is_empty() => vias[0].clone(),
            _ => {
                warn!("response has unparseable Via header");
                return;
            }
        },
        None => {
            warn!("response has no Via header");
            return;
        }
    };

    let branch = match &top_via.branch {
        Some(branch) => branch.clone(),
        None => {
            warn!("topmost Via has no branch parameter");
            return;
        }
    };

    // A response to a REFER siphon originated on one of its own legs. Checked
    // before the leg-branch lookup because this is a non-INVITE transaction that
    // must not run the INVITE/B-leg response machinery below.
    if state.call_actors.lookup_originated_refer(&branch).is_some() {
        handle_originated_refer_response(&branch, &message, status_code, state);
        return;
    }

    // A response to an INVITE *siphon originated*. Checked before the leg-branch
    // lookup for the same reason: `handle_b2bua_response` relays what it gets to
    // an A-leg and reasons about B-legs, and an originated call has neither — it
    // *is* the A-leg, so relaying its own 180 would put it back on the wire at
    // the party we are calling.
    if let Some(internal_call_id) = state.call_actors.lookup_originated_call(&branch) {
        handle_originated_call_response(&internal_call_id, &message, status_code, state);
        return;
    }

    // Check if this response belongs to a B2BUA call
    if let Some(call_id) = state.call_actors.call_id_for_branch(&branch) {
        handle_b2bua_response(
            &call_id,
            &branch,
            &mut message,
            status_code,
            inbound.remote_addr,
            state,
        );
        return;
    }

    // Post-teardown: re-ACK retransmitted re-INVITE 200 OKs for calls already
    // torn down by BYE. The zombie map holds destination info for B-leg entries
    // that had active re-INVITE tracking when the call was removed.
    if (200..300).contains(&status_code) {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some(zombie) = state.call_actors.get_zombie_reinvite(sip_call_id) {
                        let transport_str = format!("{}", zombie.transport).to_uppercase();
                        // Anchor the re-ACK Via to the zombie leg's socket (the A-leg's
                        // arrival listener for a B→A re-INVITE) so it matches the source.
                        let outbound_port = a_leg_advertised_port(
                            zombie.local_addr,
                            state
                                .listen_addrs
                                .get(&zombie.transport)
                                .map(|a| a.port())
                                .unwrap_or(state.local_addr.port()),
                        );
                        let cseq_num = cseq_raw
                            .split_whitespace()
                            .next()
                            .unwrap_or("1")
                            .to_string();
                        let from = message.headers.from().cloned().unwrap_or_default();
                        let to = message.headers.to().cloned().unwrap_or_default();
                        let ack_uri = SipUri::new(zombie.destination.ip().to_string())
                            .with_port(zombie.destination.port());
                        let ack = match SipMessageBuilder::new()
                            .request(Method::Ack, ack_uri)
                            .via(format!(
                                "SIP/2.0/{} {}:{};branch={}",
                                transport_str,
                                state.a_leg_advertised_host(zombie.local_addr, &zombie.transport),
                                outbound_port,
                                TransactionKey::generate_branch(),
                            ))
                            .from(from.to_string())
                            .to(to.to_string())
                            .call_id(sip_call_id.to_string())
                            .cseq(format!("{} ACK", cseq_num))
                            .header("Max-Forwards", "70".to_string())
                            .content_length(0)
                            .build()
                        {
                            Ok(ack) => ack,
                            Err(error) => {
                                error!("B2BUA zombie ACK build failed: {error}");
                                return;
                            }
                        };
                        // Source from the zombie leg's anchored socket (multi-homed
                        // parity); reuse an established connection as before.
                        let data = Bytes::from(ack.to_bytes());
                        let target = RelayTarget {
                            address: zombie.destination,
                            transport: Some(zombie.transport),
                            server_name: None,
                        };
                        send_to_target(
                            data,
                            &target,
                            zombie.transport,
                            ConnectionId::default(),
                            zombie.local_addr,
                            state,
                        );
                        debug!(
                            call_id = sip_call_id,
                            "B2BUA: zombie re-ACK for post-teardown re-INVITE 200 OK retransmission"
                        );
                        return;
                    }
                }
            }
        }
    }

    // Post-CANCEL glare (RFC 3261 §9.1): a 2xx that raced an outbound CANCEL.
    // handle_b2bua_cancel removed the call (unregistering the B-leg branch), so
    // this 2xx no longer resolves above. ACK it (§13.2.2.4) and BYE it (§15) via
    // the captured leg so the callee stops retransmitting and the dialog it just
    // established is released.
    if (200..300).contains(&status_code) {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some((leg, first_2xx)) =
                        state.call_actors.zombie_cancelled_for_2xx(sip_call_id)
                    {
                        handle_zombie_cancelled_2xx(leg, first_2xx, &message, state);
                        return;
                    }
                }
            }
        }
    }

    // Post-CANCEL, the ORDINARY outcome: the `487 Request Terminated` the peer
    // answers a CANCELled INVITE with (RFC 3261 §9.1). RFC 3261 §17.1.1.3 makes
    // ACKing any final non-2xx to an INVITE the client transaction's job, and
    // the B2BUA has no client transaction — it runs its own retransmit schedule
    // (see the top of this function) — so nothing below generates it either.
    // The CANCEL paths removed the call and with it the leg's branch index, so
    // this response no longer resolves above; unanswered, the peer's INVITE
    // server transaction retransmits on Timer G to Timer H (64*T1 = 32 s,
    // §17.2.1), holding transaction state at both ends of every abandoned call.
    //
    // Matched via the same `zombie_cancelled` capture as the glare 2xx, which
    // covers both shapes of pending leg: an ordinary B2BUA B-leg and the A-leg
    // of a call siphon placed itself (`originate`).
    //
    // Gated on a CSeq of INVITE so the CANCEL's own final response — which
    // shares the INVITE's branch (§9.1) — is never ACKed: a non-INVITE
    // transaction takes no ACK (§17.1.2).
    if status_code >= 300 {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some((leg, invite_ruri)) =
                        state.call_actors.zombie_cancelled_for_non2xx(sip_call_id)
                    {
                        handle_zombie_cancelled_non2xx(
                            &leg,
                            invite_ruri.as_deref(),
                            &message,
                            status_code,
                            state,
                        );
                        return;
                    }
                }
            }
        }
    }

    // Parse CSeq once for both transaction processing and session routing.
    let sent_by = TransactionKey::format_sent_by(&top_via.host, top_via.port);
    let client_txn_key = message
        .headers
        .get("CSeq")
        .and_then(|cseq_raw| crate::sip::headers::cseq::CSeq::parse(cseq_raw).ok())
        .map(|cseq| TransactionKey::new(branch.clone(), cseq.method, sent_by.clone()));

    // Feed response to client transaction (if one exists).
    // The state machine handles retransmit absorption and timer cancellation.
    if let Some(ref key) = client_txn_key {
        let event = if status_code < 200 {
            if key.method == crate::sip::message::Method::Invite {
                Some(ClientEvent::Ict(IctEvent::Provisional(message.clone())))
            } else {
                Some(ClientEvent::Nict(NictEvent::Provisional(message.clone())))
            }
        } else if status_code < 300 && key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::Response2xx(message.clone())))
        } else if key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::ResponseNon2xx(message.clone())))
        } else {
            Some(ClientEvent::Nict(NictEvent::FinalResponse(message.clone())))
        };

        if let Some(event) = event {
            match state.transaction_manager.process_client_event(key, event) {
                Ok(actions) => {
                    for action in &actions {
                        match action {
                            Action::SendMessage(ack_message) => {
                                // RFC 3261 §17.1.1.3: send ACK for non-2xx back toward
                                // the UAS, from the socket the response arrived on
                                // (multi-homed source-port parity).
                                send_message_from(
                                    ack_message.clone(),
                                    inbound.transport,
                                    inbound.remote_addr,
                                    inbound.connection_id,
                                    Some(inbound.local_addr),
                                    state,
                                );
                            }
                            Action::CancelTimer(name) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.remove(&timer_id);
                            }
                            Action::StartTimer(name, duration) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.insert(
                                    timer_id,
                                    Box::new(TimerEntry {
                                        key: key.clone(),
                                        name: *name,
                                        fires_at: std::time::Instant::now() + *duration,
                                        destination: None,
                                        transport: None,
                                        connection_id: None,
                                        source_local_addr: None,
                                    }),
                                );
                            }
                            Action::ProtocolError(message) => {
                                warn!(key = %key, "client transaction protocol error: {message}");
                            }
                            _ => {}
                        }
                    }

                    // If the state machine did NOT produce PassToTu, it absorbed the response
                    let should_forward = actions.iter().any(|a| matches!(a, Action::PassToTu(_)));
                    if !should_forward && status_code >= 200 {
                        debug!(
                            branch = %branch,
                            status = status_code,
                            "response absorbed by client transaction"
                        );
                        return;
                    }
                }
                Err(_) => {
                    // No transaction found — fall through to normal processing
                }
            }
        }
    }

    if let Some(ref client_key) = client_txn_key {
        if let Some(session_arc) = state.session_store.get_by_client_key(client_key) {
            let (
                source_addr,
                inbound_local_addr,
                connection_id,
                transport,
                server_key,
                fork_agg,
                branch_index,
                original_request,
                relay_on_reply,
                relay_on_failure,
                client_branch,
                final_response_sent,
                record_routed,
                failure_retargets,
            ) = {
                let session = match session_arc.read() {
                    Ok(s) => s,
                    Err(error) => {
                        error!("proxy session lock poisoned: {error}");
                        return;
                    }
                };
                // Free-threaded CPython (3.14t) requires an attached thread to
                // touch a `Py<…>` refcount; clone the relay callbacks through a
                // `Python` token rather than the bare `Clone` impl, which would
                // panic on this (unattached) executor worker. See
                // `ProxySession::clone_relay_callbacks`.
                let (relay_on_reply, relay_on_failure) = session.clone_relay_callbacks();
                (
                    session.source_addr,
                    session.inbound_local_addr,
                    session.connection_id,
                    session.transport,
                    session.server_key.clone(),
                    session.fork_aggregator.clone(),
                    session.branch_index_map.get(client_key).copied(),
                    session.original_request.clone(),
                    relay_on_reply,
                    relay_on_failure,
                    session.client_branches.get(client_key).cloned(),
                    session.final_response_sent,
                    session.record_routed,
                    session.failure_retargets,
                )
            };

            // RFC 3261 §17.1.1.3: the client transaction MUST generate an ACK
            // for non-2xx final responses to INVITE, sent hop-by-hop to the
            // same downstream destination.
            if status_code >= 300 && client_key.method == crate::sip::message::Method::Invite {
                match client_branch {
                    Some(ref cb) => {
                        let ack = build_ack_for_non2xx(
                            &original_request,
                            &message,
                            &branch,
                            cb.transport,
                            state.local_addr,
                        );
                        send_to_target(
                            ack.to_bytes().into(),
                            &RelayTarget {
                                address: cb.destination,
                                transport: Some(cb.transport),
                                server_name: None,
                            },
                            cb.transport,
                            cb.connection_id,
                            None,
                            state,
                        );
                        info!(
                            branch = %branch,
                            destination = %cb.destination,
                            transport = %cb.transport,
                            "ACK for {status_code} sent downstream"
                        );
                    }
                    None => {
                        warn!(
                            branch = %branch,
                            status = status_code,
                            "cannot send ACK for non-2xx: no client branch in session"
                        );
                    }
                }
            }

            // A reply-time `reply.reject()` already committed a final response
            // upstream for this server transaction and CANCELled the pending
            // branch(es).  This response is the straggler that CANCEL drew back
            // (typically the `487` answering it, or a late provisional).  Any
            // non-2xx final was ACKed downstream just above (and by the client
            // transaction), so absorb it here — forwarding it would put a second
            // final response on the wire to the UAC.  The single-target relay
            // path has no fork aggregator to dedup, so this flag is the guard.
            if final_response_sent {
                debug!(
                    status = status_code,
                    branch = %branch,
                    "absorbing straggler after reply-time reject (final already sent)"
                );
                if status_code >= 200 {
                    state.session_store.remove_client_key(client_key);
                }
                return;
            }

            // Strip our topmost Via before forwarding
            core::strip_top_via(&mut message.headers);

            // Run Python reply handlers
            let (updated_message, should_forward, reject_action) = run_reply_handlers(
                message,
                status_code,
                &branch,
                state,
                original_request.clone(),
                source_addr,
                transport,
                inbound.remote_addr,
                inbound_local_addr,
                connection_id,
            );

            // `reply.reject(code, reason)` from `@proxy.on_reply`: fail the
            // in-progress INVITE.  Send the error upstream to the UAC and
            // CANCEL the pending downstream branch(es).  Takes precedence over
            // the relay/drop decision.  Only ever `Some` for a provisional
            // (the PyReply method no-ops on a final), so this never races a
            // real upstream 2xx.
            if let Some((reject_code, reject_reason)) = reject_action {
                reject_pending_invite(
                    &server_key,
                    &session_arc,
                    reject_code,
                    &reject_reason,
                    &original_request,
                    transport,
                    source_addr,
                    connection_id,
                    inbound_local_addr,
                    state,
                );
                return;
            }

            if !should_forward {
                state.session_store.remove_client_key(client_key);
                return;
            }
            message = updated_message;

            // IPsec CK/IK extraction from relayed 401 REGISTER responses is
            // now driven by the P-CSCF script via `reply.take_av()` (see
            // `siphon.ipsec`).  The dispatcher no longer transparently
            // strips/installs SAs on this path.

            // Invoke per-relay on_reply / on_failure callbacks if set
            if relay_on_reply.is_some() || (relay_on_failure.is_some() && status_code >= 400) {
                let msg_arc = Arc::new(std::sync::Mutex::new(message));
                let req_arc = Arc::new(std::sync::Mutex::new(original_request.clone()));
                type RelayCallbackOutcome = (
                    bool,
                    Option<(u16, String)>,
                    // Set only when the on_failure callback ran and re-targeted
                    // the request: (action, on_reply, on_failure, via transport,
                    // via target).  Scoped to that callback so an on_reply
                    // callback calling relay() can never be mistaken for one.
                    Option<(
                        RequestAction,
                        Option<Py<PyAny>>,
                        Option<Py<PyAny>>,
                        Option<String>,
                        Option<String>,
                    )>,
                );
                let (cb_forward, cb_reject, cb_retarget): RelayCallbackOutcome = Python::attach(
                    |python| {
                        let py_reply_obj = PyReply::new(Arc::clone(&msg_arc)).with_response_source(
                            inbound.remote_addr.ip().to_string(),
                            inbound.remote_addr.port(),
                        );
                        let py_reply = match Py::new(python, py_reply_obj) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for relay callback: {error}");
                                return (true, None, None);
                            }
                        };
                        let py_req = {
                            let mut req = PyRequest::with_local_domains(
                                Arc::clone(&req_arc),
                                transport.to_string(),
                                source_addr.ip().to_string(),
                                source_addr.port(),
                                Arc::clone(&state.local_domains),
                            )
                            .with_self_identity(Arc::clone(&state.self_identity));
                            // Replay the inbound flow capture so
                            // registrar.save(flow_token=…) /
                            // request.relay(flow=…) called from the
                            // on_reply / on_failure callback see the
                            // same listener context as the on_request
                            // handler did (P-CSCF Path-token MT routing
                            // — TS 24.229 §5.2.7.2).
                            req.set_local_port(inbound_local_addr.port());
                            req.set_inbound_flow(inbound_local_addr, connection_id.0);
                            match Py::new(python, req) {
                                Ok(obj) => obj,
                                Err(error) => {
                                    error!(
                                        "failed to create PyRequest for relay callback: {error}"
                                    );
                                    return (true, None, None);
                                }
                            }
                        };
                        let mut retarget = None;

                        // on_reply callback: (request, reply)
                        if let Some(ref on_reply) = relay_on_reply {
                            let callable = on_reply.bind(python);
                            match callable.call1((py_req.bind(python), py_reply.bind(python))) {
                                Ok(ret) => {
                                    if let Ok(true) = is_coroutine(python, &ret) {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async relay on_reply callback error: {error}");
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("relay on_reply callback error: {error}");
                                }
                            }
                        }

                        // on_failure callback: (request, code, reason)
                        if status_code >= 400 {
                            if let Some(ref on_failure) = relay_on_failure {
                                let reason = best_error_reason(status_code);
                                let callable = on_failure.bind(python);
                                match callable.call1((py_req.bind(python), status_code, reason)) {
                                    Ok(ret) => {
                                        if let Ok(true) = is_coroutine(python, &ret) {
                                            if let Err(error) = run_coroutine(python, &ret) {
                                                error!("async relay on_failure callback error: {error}");
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        error!("relay on_failure callback error: {error}");
                                    }
                                }
                                // A per-relay on_failure callback may re-target the
                                // request too, on the same terms as the global
                                // `@proxy.on_failure` handler.  Read the action here
                                // — inside the on_failure arm — so an on_reply
                                // callback that calls relay() is never mistaken for
                                // a failure retarget.
                                let mut borrowed = py_req.borrow_mut(python);
                                if matches!(
                                    borrowed.action(),
                                    RequestAction::Relay { .. } | RequestAction::Fork { .. }
                                ) {
                                    retarget = Some((
                                        borrowed.action().clone(),
                                        borrowed.take_on_reply_callback(),
                                        borrowed.take_on_failure_callback(),
                                        borrowed.via_transport_override().map(|s| s.to_string()),
                                        borrowed.via_target_override().map(|s| s.to_string()),
                                    ));
                                }
                            }
                        }

                        let reply_ref = py_reply.borrow(python);
                        (
                            reply_ref.was_forwarded(),
                            reply_ref.reject_action(),
                            retarget,
                        )
                    },
                );
                // A per-relay on_reply callback can reject too (same contract as
                // the global `@proxy.on_reply` handler) — fail the in-progress
                // INVITE upstream + CANCEL downstream.  Reached only when the
                // global handler did not already reject (that path returned).
                if let Some((reject_code, reject_reason)) = cb_reject {
                    reject_pending_invite(
                        &server_key,
                        &session_arc,
                        reject_code,
                        &reject_reason,
                        &original_request,
                        transport,
                        source_addr,
                        connection_id,
                        inbound_local_addr,
                        state,
                    );
                    return;
                }
                // The per-relay on_failure callback re-targeted the request —
                // start it on the same server transaction instead of answering
                // the UAC with this failure.
                if let Some((action, on_reply_cb, on_failure_cb, via_transport, via_target)) =
                    cb_retarget
                {
                    let retargeted_request = match Arc::try_unwrap(req_arc) {
                        Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                        Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                    };
                    if execute_failure_retarget(
                        FailureRetarget {
                            action,
                            request: retargeted_request,
                            on_reply_callback: on_reply_cb,
                            on_failure_callback: on_failure_cb,
                            send_via_transport: via_transport,
                            send_via_target: via_target,
                        },
                        &server_key,
                        record_routed,
                        transport,
                        source_addr,
                        inbound_local_addr,
                        connection_id,
                        failure_retargets,
                        state,
                    ) {
                        return;
                    }
                    // Budget exhausted — fall through and answer the UAC.
                }
                if !cb_forward {
                    state.session_store.remove_client_key(client_key);
                    return;
                }
                // Recover the message from the Arc
                message = match Arc::try_unwrap(msg_arc) {
                    Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                    Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                };
            }

            // --- Global @proxy.on_failure for a single-target relay ---
            //
            // A fork reaches the handlers through the aggregator's
            // ForwardBestError arm below.  A plain `request.relay()` has no
            // aggregator at all, so before this the global failure policy was
            // simply never invoked for the commonest case in a proxy — a script
            // could register `@proxy.on_failure`, see it never fire, and have
            // no way to express failover (the shipped I-CSCF S-CSCF failover
            // example depended on exactly this).  With one branch there is
            // nothing to aggregate: every non-2xx final response *is* "all
            // branches failed".
            //
            // 487 is excluded: the transaction was cancelled by the UAC, so a
            // retarget would resurrect a call the caller has already abandoned.
            // `@proxy.on_cancel` is the hook for that teardown.
            if fork_agg.is_none()
                && (300..700).contains(&status_code)
                && status_code != 487
                && !final_response_sent
            {
                let outcome = run_proxy_failure_handlers(
                    message,
                    original_request.clone(),
                    transport,
                    source_addr,
                    inbound_local_addr,
                    connection_id,
                    state,
                );

                if let Some(retarget) = outcome.retarget {
                    if execute_failure_retarget(
                        retarget,
                        &server_key,
                        record_routed,
                        transport,
                        source_addr,
                        inbound_local_addr,
                        connection_id,
                        failure_retargets,
                        state,
                    ) {
                        return;
                    }
                    // Budget exhausted — fall through and answer the UAC.
                }

                if !outcome.forwarded {
                    debug!(
                        status = status_code,
                        "on_failure handler suppressed error response (single relay)"
                    );
                    state.session_store.remove_client_key(client_key);
                    return;
                }
                message = outcome.response;
            }

            // --- Fork aggregator decision ---
            if let (Some(ref aggregator), Some(index)) = (&fork_agg, branch_index) {
                let fork_action = match aggregator.lock() {
                    Ok(mut agg) => agg.on_branch_response(index, status_code),
                    Err(_) => {
                        error!("fork aggregator lock poisoned");
                        crate::proxy::fork::ForkAction::ContinueWaiting
                    }
                };

                match fork_action {
                    crate::proxy::fork::ForkAction::ContinueWaiting => {
                        debug!(
                            status = status_code,
                            branch_index = index,
                            "fork: waiting for more branches"
                        );
                        return;
                    }
                    crate::proxy::fork::ForkAction::Forward2xx => {
                        debug!(
                            status = status_code,
                            "fork: forwarding 2xx, cancelling others"
                        );
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::Forward6xx => {
                        debug!(
                            status = status_code,
                            "fork: forwarding 6xx, cancelling others"
                        );
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::ForwardProvisional(_code) => {
                        // Forward provisional upstream (no cleanup)
                    }
                    crate::proxy::fork::ForkAction::ForwardBestError(best_code) => {
                        debug!(best_code = best_code, "fork: all branches failed");
                        // RFC 3261 §16.7 step 6 — the proxy does not pass a 503
                        // upstream even when it is the best error it has (which
                        // it will be whenever every branch hit a transport
                        // error, §16.9).  This arm builds and sends its own
                        // response, so it needs the rule applied at the source
                        // rather than at the shared forward path below.
                        let best_code = if best_code == 503 {
                            debug!("fork: best error is 503 — forwarding 500 (RFC 3261 §16.7)");
                            500
                        } else {
                            best_code
                        };
                        let reason = best_error_reason(best_code);
                        let Ok(session) = session_arc.read() else {
                            error!("session_arc read lock poisoned");
                            return;
                        };
                        let original_request = session.original_request.clone();
                        let best_response = build_response(
                            &original_request,
                            best_code,
                            reason,
                            state.server_header.as_deref(),
                            &[],
                        );
                        drop(session);

                        // CDR: capture the dialog key before `original_request`
                        // may be moved into the on_failure PyRequest, so the
                        // failed-call record can be written at the convergence
                        // point below — but only when the failure is actually
                        // forwarded (a handler that retries via request.relay()
                        // returns early and must NOT emit a failed CDR).
                        let cdr_fail_key = if crate::cdr::auto_emit_enabled() {
                            original_request
                                .headers
                                .get("Call-ID")
                                .map(|s| s.to_string())
                                .zip(
                                    original_request
                                        .typed_from()
                                        .ok()
                                        .flatten()
                                        .and_then(|na| na.tag),
                                )
                                .map(|(call_id, tag)| cdr_dialog_key(&call_id, &tag))
                        } else {
                            None
                        };

                        // Rf: same story — the INVITE is about to be moved into
                        // the on_failure PyRequest, and the ACR-EVENT for an
                        // unsuccessful setup may only be emitted once the
                        // failure is actually forwarded upstream.
                        let rf_fail_request = state
                            .rf_charger
                            .as_ref()
                            .filter(|charger| charger.auto_emit_proxy())
                            .map(|_| original_request.clone());

                        // Invoke @proxy.on_failure handlers before forwarding
                        let outcome = run_proxy_failure_handlers(
                            best_response,
                            original_request,
                            transport,
                            source_addr,
                            inbound_local_addr,
                            connection_id,
                            state,
                        );

                        // The handler re-targeted the request (`request.relay()`
                        // / `request.fork()`) — start it on the same server
                        // transaction and leave the UAC waiting rather than
                        // answering the failure.  Nothing else may run: no
                        // response upstream, no failed CDR.
                        if let Some(retarget) = outcome.retarget {
                            if execute_failure_retarget(
                                retarget,
                                &server_key,
                                record_routed,
                                transport,
                                source_addr,
                                inbound_local_addr,
                                connection_id,
                                failure_retargets,
                                state,
                            ) {
                                return;
                            }
                            // Budget exhausted — fall through and answer the UAC.
                        }

                        if !outcome.forwarded {
                            debug!("on_failure handler suppressed error response");
                            state.session_store.remove_by_server_key(&server_key);
                            return;
                        }

                        // 3GPP TS 33.203 §7.4: the relayed-back response must
                        // egress on the same SA's local endpoint that the
                        // request arrived on.  Pass the session's captured
                        // inbound_local_addr so the OutboundRouter hits the
                        // right per-listener UDP channel.
                        send_message_from(
                            outcome.response,
                            transport,
                            source_addr,
                            connection_id,
                            Some(inbound_local_addr),
                            state,
                        );

                        // CDR: both forwarded paths converge here (a retrying /
                        // suppressing on_failure handler already returned above),
                        // so the failed-call record is written exactly once.
                        if let Some(key) = &cdr_fail_key {
                            cdr_finalize(
                                &state.cdr_sessions,
                                key,
                                cdr_disconnect_for_failure(best_code),
                                Some(best_code),
                                None,
                            );
                        }

                        // Rf ACR-EVENT for the forked failure, at the same
                        // convergence point and under the same once-only rule
                        // (TS 32.260 §5.2.2.1).
                        if let Some(invite) = &rf_fail_request {
                            spawn_rf_proxy_event_on_failed_invite(
                                state,
                                &server_key,
                                invite,
                                best_code,
                                &session_arc,
                            );
                        }

                        state.session_store.remove_by_server_key(&server_key);
                        return;
                    }
                    crate::proxy::fork::ForkAction::TryNext(next_index) => {
                        debug!(
                            next_index = next_index,
                            "fork: trying next branch (sequential)"
                        );
                        start_next_fork_branch(next_index, &session_arc, &server_key, state);
                        return;
                    }
                }
            }

            // Rf ACR-START on INVITE 2xx (TS 32.299 §6.2.2).
            //
            // Fires for both single-destination `request.relay(target)`
            // (which has no fork aggregator) and multi-branch
            // `request.fork(...)` (Forward2xx after the aggregator
            // selects a winner), so any path that lands a 2xx on a
            // confirmed proxy session opens an accounting record.
            // Idempotency inside spawn_rf_proxy_start_if_invite +
            // RfChargingService prevents double-emission if 2xx
            // retransmits arrive on the same session.  Fire-and-forget
            // per TS 32.299 §6.5.
            if (200..300).contains(&status_code)
                && server_key.method == crate::sip::message::Method::Invite
            {
                spawn_rf_proxy_start_if_invite(state, &server_key, &original_request, &session_arc);
                // CDR: stamp the answer time on the tracked call (cdr.auto_emit).
                cdr_mark_proxy_answer(state, &original_request, status_code);
            } else if (300..700).contains(&status_code)
                && status_code != 401
                && status_code != 407
                && server_key.method == crate::sip::message::Method::Invite
            {
                // Rf ACR-EVENT on unsuccessful session establishment
                // (TS 32.260 §5.2.2.1). Without it, moving ACR-START to the 2xx
                // would drop every unanswered and rejected call from the record
                // set entirely — and it is the only record that ever carries a
                // non-zero Cause-Code.
                spawn_rf_proxy_event_on_failed_invite(
                    state,
                    &server_key,
                    &original_request,
                    status_code,
                    &session_arc,
                );
                // CDR: a single-relay INVITE received a final non-2xx (not an
                // auth challenge — the UA re-sends those) → the call failed
                // (cdr.auto_emit). Forked failures finalize at ForwardBestError.
                cdr_finalize_proxy_fail(state, &original_request, status_code);
            }

            // RFC 3261 §16.7 step 6: a proxy does not pass a 503 upstream — a
            // downstream element being unavailable is not the caller's
            // business, and a UAC that saw it would take the whole proxy out of
            // service. It forwards 500 instead. This covers a 503 the proxy
            // synthesized for a transport error (§16.9) as well as one a
            // downstream server actually sent.
            //
            // Script-generated finals (`request.reply(503)`,
            // `reply.reject(503)`) never reach here — they are not responses
            // this proxy is forwarding on behalf of a branch — so the IMS
            // P-CSCF media-authorization 503 is unaffected.
            let status_code = downgrade_503_for_upstream(&mut message, status_code, &server_key);

            // Feed the response into the server transaction for caching
            let server_event = if status_code < 200 {
                if server_key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuProvisional(message.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuProvisional(message.clone())))
                }
            } else if status_code < 300 && server_key.method == crate::sip::message::Method::Invite
            {
                Some(ServerEvent::Ist(IstEvent::Tu2xx(message.clone())))
            } else if server_key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(message.clone())))
            } else {
                Some(ServerEvent::Nist(NistEvent::TuFinal(message.clone())))
            };

            // Feed response to server transaction. If the transaction emits
            // SendMessage, it handles delivery — we must not send again ourselves.
            let mut sent_by_transaction = false;
            if let Some(event) = server_event {
                if let Ok(actions) = state
                    .transaction_manager
                    .process_server_event(&server_key, event)
                {
                    sent_by_transaction =
                        actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                    process_timer_actions(
                        &actions,
                        &server_key,
                        Some(source_addr),
                        Some(transport),
                        Some(connection_id),
                        Some(inbound_local_addr),
                        state,
                    );
                }
            }

            if !sent_by_transaction {
                debug!(
                    status = status_code,
                    destination = %source_addr,
                    branch = %branch,
                    "forwarding response via session"
                );
                send_message_from(
                    message,
                    transport,
                    source_addr,
                    connection_id,
                    Some(inbound_local_addr),
                    state,
                );
            }

            // Clean up on final response
            if status_code >= 200 {
                state.session_store.remove_client_key(client_key);
            }
            return;
        }
    }

    // No matching session or B2BUA call — response is not ours
    debug!(branch = %branch, "response for unknown branch (not ours)");
}

/// Run `@proxy.on_reply` Python handlers on a response message.
///
/// Returns `(message, forwarded, reject_action)`:
/// - `forwarded` is false when the script chose to drop the response (no
///   `relay()` called).
/// - `reject_action` is `Some((code, reason))` when the script called
///   `reply.reject(code, reason)` on a provisional — the caller then sends a
///   final error upstream and CANCELs the pending downstream branch(es).  When
///   set it takes precedence over `forwarded`.
///
/// `response_source` is the observed source address of the entity that sent
/// this response (for `reply.fix_nated_contact()`).
pub(super) fn run_reply_handlers(
    message: SipMessage,
    status_code: u16,
    branch: &str,
    state: &DispatcherState,
    original_request: SipMessage,
    source_addr: SocketAddr,
    transport: crate::transport::Transport,
    response_source: SocketAddr,
    inbound_local_addr: SocketAddr,
    inbound_connection_id: ConnectionId,
) -> (SipMessage, bool, Option<(u16, String)>) {
    // Automatic NAT Contact fixup on responses (nat.fix_contact: true).
    // Rewrites the Contact URI host:port with the observed source address
    // of the entity that sent this response — before Python handlers run,
    // so scripts see the corrected Contact.
    let message = if state.nat_fix_contact {
        fix_response_contact(message, response_source)
    } else {
        message
    };

    let engine_state = state.engine.state();
    let reply_handlers = engine_state.handlers_for(&HandlerKind::ProxyReply);

    if reply_handlers.is_empty() {
        return (message, true, None);
    }

    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let reply = PyReply::new(Arc::clone(&message_arc))
        .with_response_source(response_source.ip().to_string(), response_source.port());

    // Build a PyRequest from the original request so scripts get (request, reply)
    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let mut py_request_obj = PyRequest::with_local_domains(
        request_arc,
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
        Arc::clone(&state.local_domains),
    )
    .with_self_identity(Arc::clone(&state.self_identity));
    // Replay the inbound flow capture so `@proxy.on_reply` handlers
    // that call `registrar.save(flow_token=…)` /
    // `registrar.save_proxy(flow_token=…)` see the same listener
    // context as the on_request handler did.  Without this,
    // PyContact.flow comes back None on a later
    // `registrar.lookup_by_token` (P-CSCF Path-token MT routing —
    // RFC 3327 §5 / TS 24.229 §5.2.7.2).
    py_request_obj.set_local_port(inbound_local_addr.port());
    py_request_obj.set_inbound_flow(inbound_local_addr, inbound_connection_id.0);

    let (forwarded, reject_action) = Python::attach(|python| {
        let py_reply = match Py::new(python, reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply: {error}");
                return (true, None); // forward on error
            }
        };
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for reply handler: {error}");
                return (true, None);
            }
        };

        for handler in &reply_handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python), py_reply.bind(python)));
            match result {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async Python reply", &error);
                            return (true, None);
                        }
                    }
                }
                Err(error) => {
                    record_script_error("Python reply", &error);
                    return (true, None); // forward on error to avoid silent drops
                }
            }
        }

        let reply_ref = py_reply.borrow(python);
        (reply_ref.was_forwarded(), reply_ref.reject_action())
    });

    if reject_action.is_none() && !forwarded {
        debug!(
            status = status_code,
            branch = %branch,
            "reply dropped by script (no relay() called)"
        );
    }

    // Extract the (possibly modified) message back.  Under the
    // long-lived asyncio loops in `script::async_pool`, the asyncio
    // Task object retains the coroutine frame — and therefore the
    // `Py<PyReply>` argument — until the loop's next garbage-collection
    // pass.  That keeps `PyReply`'s `Arc::clone` of `message_arc` alive
    // a moment longer than the dispatcher closure, so `Arc::try_unwrap`
    // sometimes hits strong_count > 1 here and falls back to a clone.
    // The clone is correctness-neutral (mutations from the script are
    // visible through the lock) and bounded (one `SipMessage::clone`
    // per response with an async on_reply handler), so the fallback
    // logs at `debug!` rather than `warn!`.
    let extracted = match Arc::try_unwrap(message_arc) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|error| {
            warn!("message mutex poisoned in reply handler: {error}");
            error.into_inner()
        }),
        Err(arc) => {
            debug!(
                "PyReply still holds message arc (async Task frame retains \
                 Py<PyReply>); cloning"
            );
            arc.lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        }
    };

    (extracted, forwarded, reject_action)
}

/// Fire `@proxy.on_cancel` handlers for a relayed INVITE that was CANCELled
/// before any final response (RFC 3261 §9).
///
/// Fire-and-forget cleanup: the 487 to the UAC has already been sent at the
/// transaction layer and is not gated by the script — there is no
/// `relay()`/`reply()` decision. This is the only teardown signal a script
/// gets for a cancelled-before-answer call (neither `on_reply` nor
/// `on_failure` ever fires — the session is torn down with the CANCEL), so it
/// exists to release per-call resources that no BYE will ever clear (Diameter
/// Rx/N5 QoS, rtpengine media).
///
/// Mirrors `run_reply_handlers`' PyRequest construction — including the
/// inbound-flow replay — so the handler sees the same listener context the
/// `on_request` handler did (`registrar.lookup_by_token`, `request.flow`).
pub(super) fn run_proxy_cancel_handlers(
    original_request: SipMessage,
    transport: crate::transport::Transport,
    source_addr: SocketAddr,
    inbound_local_addr: SocketAddr,
    inbound_connection_id: ConnectionId,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::ProxyCancel);
    if handlers.is_empty() {
        return;
    }

    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let mut py_request_obj = PyRequest::with_local_domains(
        request_arc,
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
        Arc::clone(&state.local_domains),
    )
    .with_self_identity(Arc::clone(&state.self_identity));
    py_request_obj.set_local_port(inbound_local_addr.port());
    py_request_obj.set_inbound_flow(inbound_local_addr, inbound_connection_id.0);

    Python::attach(|python| {
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for on_cancel handler: {error}");
                return;
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((py_request.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async Python on_cancel", &error);
                        }
                    }
                }
                Err(error) => {
                    record_script_error("Python on_cancel", &error);
                }
            }
        }
    });
}

/// Rewrite the Contact URI in a response with the observed source address.
///
/// This is the automatic equivalent of OpenSIPS's `fix_nated_contact()` in
/// onreply_route.  When `nat.fix_contact` is enabled, every response gets
/// its Contact rewritten before forwarding upstream, so in-dialog requests
/// from the upstream UAC will reach the NATed endpoint's public address.
pub(super) fn fix_response_contact(mut message: SipMessage, source: SocketAddr) -> SipMessage {
    use crate::sip::headers::nameaddr::NameAddr;

    if let Some(raw) = message.headers.get("Contact").cloned() {
        if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
            let host = source.ip().to_string();
            nameaddr.uri.host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host
            };
            nameaddr.uri.port = Some(source.port());
            message.headers.set("Contact", nameaddr.to_string());
        }
    }
    message
}
