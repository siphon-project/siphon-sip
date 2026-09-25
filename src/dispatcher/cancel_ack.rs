//! CANCEL and ACK on the proxy path.
//!
//! A 2xx ACK is a new transaction (RFC 3261 §13.2.2.4), not part of the INVITE
//! one, so it is routed by dialog rather than by branch. CANCEL fans out to
//! every fork branch still in flight.

use super::*;

// ---------------------------------------------------------------------------
// Fork helpers
// ---------------------------------------------------------------------------

/// Cancel all fork branches except the winning one.
pub(super) fn cancel_other_fork_branches(
    winning_key: &TransactionKey,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    cancel_fork_branches(server_key, Some(winning_key), state);
}

/// CANCEL the pending downstream branches of a proxy session.
///
/// `exclude` skips one branch — the branch that won (`Some(winning_key)`, used
/// by fork aggregation when a 2xx/6xx settles the fork).  Pass `None` to CANCEL
/// every branch, which is what a reply-time `reply.reject(code, reason)` needs:
/// it aborts the whole in-progress INVITE, including the branch whose
/// provisional triggered the reject.
///
/// RFC 3261 §9.1: each branch's CANCEL MUST carry the same topmost Via branch
/// (and CSeq number) siphon used for that branch's INVITE, so we rebuild the
/// per-branch outbound-INVITE view and run it through `build_cancel_from_invite`.
pub(super) fn cancel_fork_branches(
    server_key: &TransactionKey,
    exclude: Option<&TransactionKey>,
    state: &DispatcherState,
) {
    let session_arc = match state.session_store.get_by_server_key(server_key) {
        Some(arc) => arc,
        None => return,
    };
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => return,
    };
    // The registered callees among the branches CANCELled stop ringing.
    proxy_dialog_branches_cancelled(
        &session.original_request,
        exclude.map(|key| key.branch.as_str()),
        state,
    );

    for client_key in &session.client_keys {
        if Some(client_key) == exclude {
            continue;
        }
        if let Some(client_branch) = session.get_client_branch(client_key) {
            // RFC 3261 §9.1 — the CANCEL on each branch MUST share the
            // topmost Via branch siphon used when sending the INVITE
            // downstream on that branch (which IS client_key.branch),
            // and the same CSeq sequence number as the INVITE.  Build
            // a synthetic outbound-INVITE view (clone of the inbound
            // request with topmost Via swapped for siphon's per-branch
            // Via), then run it through build_cancel_from_invite which
            // enforces every other RFC-§9.1 invariant (single Via, CSeq
            // method=CANCEL, no body, no body-bearing headers).
            let transport_str = format!("{}", client_branch.transport);
            let siphon_via = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                client_key.branch,
            );
            let mut as_outbound_invite = session.original_request.clone();
            as_outbound_invite.headers.set("Via", siphon_via);
            let cancel = match build_cancel_from_invite(&as_outbound_invite) {
                Some(c) => c,
                None => {
                    warn!(
                        client_key = %client_key,
                        "fork: failed to build CANCEL from outbound INVITE view"
                    );
                    continue;
                }
            };

            let data = Bytes::from(cancel.to_bytes());

            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "fork: cancelling branch"
            );

            send_outbound(
                data,
                client_branch.transport,
                client_branch.destination,
                client_branch.connection_id,
                state,
            );
        }
    }
}

/// Fail an in-progress proxied INVITE from the reply context.
///
/// Driven by `reply.reject(code, reason)` in a `@proxy.on_reply` handler (the
/// IMS P-CSCF media-authorization reject — N5/Rx fails at answer time, so the
/// leg must be rejected with a SIP error rather than proceed medialess).
///
/// Two halves, in order:
/// 1. Mark the session finalized *first* so any branch response that races in
///    (the `487` the CANCEL draws back, or a late provisional) is absorbed by
///    the straggler guard in `handle_response` rather than forwarded upstream.
/// 2. CANCEL every pending downstream branch (RFC 3261 §9 — we have received a
///    provisional, so CANCEL is well-formed), then send `code reason` upstream
///    to the UAC through the server transaction so retransmission and ACK
///    absorption are handled by the transaction layer.
///
/// The session is deliberately left in the store: the in-flight `487`(s) from
/// the CANCEL still need to resolve to it (to be ACKed downstream and absorbed).
/// Per-branch final cleanup (`remove_client_key`) and the session TTL sweep
/// tear it down afterwards.
pub(super) fn reject_pending_invite(
    server_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    code: u16,
    reason: &str,
    original_request: &SipMessage,
    transport: crate::transport::Transport,
    source_addr: SocketAddr,
    connection_id: ConnectionId,
    inbound_local_addr: SocketAddr,
    state: &DispatcherState,
) {
    // 1. Latch the finalized flag before anything goes on the wire.
    match session_arc.write() {
        Ok(mut session) => session.final_response_sent = true,
        Err(error) => {
            error!("proxy session lock poisoned during reject: {error}");
            return;
        }
    }

    // A rejected INVITE is over for every party it was tracked for.
    proxy_dialog_invite_abandoned(original_request, state);

    // Hygiene: a rejected INVITE establishes no dialog, so its `by_dialog_key`
    // entry (which exists only to route the end-to-end 2xx ACK) is now dead.
    // Drop it so a stray/non-compliant ACK can't match this rejected call's
    // dialog and reach the ACK relay path.  The client-key indices stay intact
    // so the CANCEL's `487` straggler is still matched and absorbed.
    state.session_store.remove_dialog_key(original_request);

    info!(
        server_key = %server_key,
        code = code,
        "reply-time reject: failing in-progress INVITE and cancelling downstream"
    );

    // 2a. CANCEL all pending downstream branches (no winner to exclude).
    cancel_fork_branches(server_key, None, state);

    // 2b. Build and send the error response upstream via the server
    // transaction (handles retransmission + UAC-ACK absorption for INVITE).
    let response = build_response(
        original_request,
        code,
        reason,
        state.server_header.as_deref(),
        &[],
    );

    let event = ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone()));
    let mut sent_by_transaction = false;
    if let Ok(actions) = state
        .transaction_manager
        .process_server_event(server_key, event)
    {
        sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
        process_timer_actions(
            &actions,
            server_key,
            Some(source_addr),
            Some(transport),
            Some(connection_id),
            Some(inbound_local_addr),
            state,
        );
    }

    if !sent_by_transaction {
        // No live server transaction (or it emitted no SendMessage) — send the
        // error directly, pinning the inbound listener's local address so an
        // IPsec-protected response egresses on the right SA (TS 33.203 §7.4).
        send_message_from(
            response,
            transport,
            source_addr,
            connection_id,
            Some(inbound_local_addr),
            state,
        );
    }
}

/// Start the next branch in a sequential fork.
pub(super) fn start_next_fork_branch(
    next_index: usize,
    session_arc: &Arc<RwLock<ProxySession>>,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    let (
        original_request,
        record_routed,
        source_addr,
        connection_id,
        transport,
        agg,
        branch_flow,
        branch_path,
        send_socket,
    ) = {
        let session = match session_arc.read() {
            Ok(s) => s,
            Err(_) => return,
        };
        (
            session.original_request.clone(),
            session.record_routed,
            session.source_addr,
            session.connection_id,
            session.transport,
            session.fork_aggregator.clone(),
            session.fork_flows.get(next_index).cloned().flatten(),
            // The failover branch's own Path route set — the whole reason
            // sequential forking across an AoR's bindings can work at all.
            session
                .fork_routes
                .get(next_index)
                .cloned()
                .unwrap_or_default(),
            session.fork_send_socket.clone(),
        )
    };

    let agg = match agg {
        Some(a) => a,
        None => return,
    };

    let target = {
        let agg_lock = match agg.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        agg_lock
            .branches
            .get(next_index)
            .map(|b| b.target.to_string())
    };

    if let Some(target_str) = target {
        let inbound_info = InboundMessage {
            client_transport: None,
            remote_addr: source_addr,
            local_addr: state.local_addr,
            connection_id,
            transport,
            data: Bytes::new(),
        };
        relay_fork_branch(
            &original_request,
            &target_str,
            next_index,
            record_routed,
            &inbound_info,
            server_key,
            session_arc,
            &agg,
            branch_flow.as_ref(),
            &branch_path,
            send_socket.as_ref(),
            state,
        );
    }
}

/// Map a SIP error code to its reason phrase: RFC 3261 §21, plus the session
/// timer (RFC 4028) and precondition (RFC 3312) codes siphon speaks.
///
/// A failure siphon generates for the caller, rather than relays, carries this
/// phrase, so an unlisted code reads "Error" and a listed one reads as the RFC
/// names it.
pub(super) fn best_error_reason(code: u16) -> &'static str {
    match code {
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Long",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        420 => "Bad Extension",
        421 => "Extension Required",
        422 => "Session Interval Too Small",
        423 => "Interval Too Brief",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        493 => "Undecipherable",
        500 => "Server Internal Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "Version Not Supported",
        513 => "Message Too Large",
        580 => "Precondition Failure",
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------
// CANCEL handling
// ---------------------------------------------------------------------------

/// Handle an inbound CANCEL request (RFC 3261 §9.2).
///
/// CANCEL shares the same Via branch as the INVITE it cancels.
/// We look up the original INVITE's relay destination and forward CANCEL there.
pub(super) fn handle_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    uac_branch: Option<&str>,
    uac_sent_by: &str,
    state: &DispatcherState,
) {
    let uac_branch = match uac_branch {
        Some(branch) => branch,
        None => {
            warn!("CANCEL without Via branch — dropping");
            return;
        }
    };

    // Check if this CANCEL belongs to a B2BUA call
    let engine_state = state.engine.state();
    if engine_state.has_b2bua_handlers() {
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_cancel(inbound, message, state);
                return;
            }
        }
    }
    drop(engine_state);

    // --- Try ProxySession-based CANCEL routing first ---
    // CANCEL shares the same Via branch as the INVITE it cancels.
    // Build the server key for the original INVITE transaction.
    let invite_server_key = TransactionKey::new(
        uac_branch.to_string(),
        crate::sip::message::Method::Invite,
        uac_sent_by.to_string(),
    );

    // Already accepted a CANCEL for this INVITE — this is a retransmission
    // (RFC 3261 §9.2). Answer 200 as the CANCEL's own server transaction would
    // have, and do nothing else: the downstream branches were cancelled and the
    // 487 sent on the first copy, and repeating either would put a second final
    // response on one INVITE server transaction (§17.2.1).
    if state.cancelled_invites.contains_key(&invite_server_key) {
        debug!(uac_branch = %uac_branch, "CANCEL retransmission — answering 200, side effects already done");
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
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

    if let Some(session_arc) = state.session_store.get_by_server_key(&invite_server_key) {
        handle_cancel_via_session(inbound, message, &invite_server_key, session_arc, state);
        return;
    }

    // No matching session or B2BUA call
    debug!(uac_branch = %uac_branch, "CANCEL for unknown transaction");
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
}

/// Remember that a CANCEL was accepted for `key`, for the 64×T1 window a
/// CANCEL's own server transaction would have held its cached response
/// (RFC 3261 Timer J). Mirrors [`schedule_zombie_cancelled_cleanup`].
pub(super) fn remember_cancelled_invite(
    store: &Arc<DashMap<TransactionKey, ()>>,
    key: TransactionKey,
) {
    store.insert(key.clone(), ());
    let store = Arc::clone(store);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(32)).await;
        store.remove(&key);
    });
}

// ---------------------------------------------------------------------------
// ProxySession-based ACK (2xx) handling
// ---------------------------------------------------------------------------

/// Determine the next-hop URI for an end-to-end 2xx ACK after the proxy has
/// popped its own Route (RFC 3261 §16.12): the top remaining Route URI, or the
/// Request-URI when the route set is empty.
///
/// This is what makes the ACK follow the dialog route set rather than the
/// cached INVITE forward path. Returns `None` only for a non-request message
/// (an ACK is always a request, so this is a defensive guard).
pub(super) fn ack_next_hop_uri(headers: &SipHeaders, start_line: &StartLine) -> Option<String> {
    core::next_hop_from_route(headers).or_else(|| match start_line {
        StartLine::Request(request_line) => Some(request_line.request_uri.to_string()),
        _ => None,
    })
}

/// Handle ACK for 2xx responses by relaying it downstream via the ProxySession.
///
/// ACK for 2xx is end-to-end (RFC 3261 §13.2.2.4): the proxy must relay it
/// downstream to the UAS. Unlike ACK for non-2xx (which is hop-by-hop and
/// absorbed by the transaction layer), this ACK has a new Via branch and must
/// be matched by Call-ID.
pub(super) fn handle_ack_via_session(
    _inbound: InboundMessage,
    message: SipMessage,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during ACK handling");
            return;
        }
    };

    // Forward the ACK once per distinct downstream destination.
    //
    // A 2xx ACK is a new request routed by the *dialog route set* (RFC 3261
    // §13.2.2.4), so every branch of a fork resolves it to the same place: the
    // one UAS that answered.  Iterating the branches without this guard sent
    // the UAS one ACK per branch — harmless on the wire only if the UAS is
    // forgiving, but a strict one treats the duplicate as an out-of-sequence
    // request on a dialog it has already confirmed.  The dedupe key is the
    // resolved hop, not the branch, so a session that genuinely has two remote
    // targets still gets one ACK each.
    // Keyed on the resolved hop only — NOT on the connection id, which is
    // derived per branch (for UDP it is a hash of the branch's own remote
    // address) and would make two branches that resolve to the same UAS look
    // like different hops.
    let mut sent_destinations: Vec<(SocketAddr, Transport)> = Vec::new();
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut ack_downstream = message.clone();

            // Consume our own Route entries (loose routing — RFC 3261 §16.4 /
            // §16.12), mirroring the script-side loose_route() that the
            // in-dialog BYE/UPDATE path uses. A doubly-Record-Routed dialog
            // (transport bridging, e.g. an IMS P-CSCF/S-CSCF spanning UDP and
            // TCP) leaves two consecutive self-Routes, and consuming only the
            // top would leave our own second Route as the apparent next hop (a
            // routing loop) — so pop every leading self-Route in one pass.
            //
            // Matching on `self_identity` is what keeps this identical to the
            // BYE: both paths ask the same "does this Route indicate me"
            // question about the same dialog. It also stops the ACK stripping a
            // Route that belongs to a *downstream* proxy, which the previous
            // unconditional `pop_top_route` did in violation of §16.4.
            //
            // The identity must cover every listener, not just the first per
            // transport: an unrecognised self-Route stays on, becomes the
            // computed next hop, and is then silently dropped by the
            // `is_own_address` loop guard below — which *does* consult the full
            // listener registry. That asymmetry turns a 404 into a lost ACK.
            core::consume_self_routes(&mut ack_downstream.headers, &state.self_identity);

            // The 2xx ACK is end-to-end (RFC 3261 §13.2.2.4 / §17.1.1.3): it is
            // a new request routed by the *dialog route set*, NOT retraced along
            // the INVITE's forward path. After popping our own Route, the next
            // hop is the top remaining Route URI, or the Request-URI when the
            // route set is empty (RFC 3261 §16.12). For an INVITE forwarded
            // through a hop that did not Record-Route (a transparent iFC AS, an
            // IMS I-CSCF), the cached branch destination and the dialog route set
            // diverge; sending to the cached destination retraces the INVITE
            // path and the ACK never reaches the UAS. This is the proxy-mode
            // sibling of the B2BUA in-dialog route-set fix.
            //
            // `resolve_in_dialog_flow_uri` keeps the established connection
            // (RFC 5923) whenever the route-set next hop still resolves to the
            // member the INVITE was relayed to (`client_branch`): re-resolving a
            // load-balanced trunk domain would, since the RFC 3263 §4.2 shuffle,
            // pick a sibling member at random and `send_to_target` would then ACK
            // the wrong node (or reuse an unrelated keepalive connection to it).
            // It falls back to the cached branch on resolution failure, so
            // non-routed dialogs (loopback baseline) are unaffected.
            let next_hop_uri =
                ack_next_hop_uri(&ack_downstream.headers, &ack_downstream.start_line);
            let (destination, out_transport, ack_connection_id) = resolve_in_dialog_flow_uri(
                next_hop_uri.as_deref(),
                &state.dns_resolver,
                client_branch.destination,
                client_branch.transport,
                client_branch.connection_id,
            );

            // Loop guard (RFC 3261 §16.3): never forward an ACK back to one of
            // our own listen addresses.  A next hop that resolves to us means
            // the UAC kept the proxy's address in the ACK's R-URI instead of
            // the dialog's remote target (RFC 3261 §12.2.1.1) — but the ACK is
            // dialog-matched, and the session's established branch IS the
            // remote target, so fall back to it rather than dropping an ACK we
            // can deliver (a dropped 2xx ACK leaves the UAS retransmitting its
            // 200 until Timer H and tearing the dialog down).  Only when the
            // established branch is *also* one of our own addresses is this a
            // genuine loop; ACK gets no response (RFC 3261 §17.1.1.3), so drop
            // silently — mirroring the relay-path guard in `relay_request`.
            let (destination, out_transport, ack_connection_id) = match ack_forward_hop(
                (destination, out_transport, ack_connection_id),
                (
                    client_branch.destination,
                    client_branch.transport,
                    client_branch.connection_id,
                ),
                &|address| state.is_own_address(address),
            ) {
                Some(hop) => {
                    if hop.0 != destination {
                        debug!(
                            client_key = %client_key,
                            resolved = %destination,
                            destination = %hop.0,
                            "2xx ACK next hop resolves to ourselves — falling back to the dialog's established branch (RFC 3261 §12.2.1.1)"
                        );
                    }
                    hop
                }
                None => {
                    debug!(
                        client_key = %client_key,
                        %destination,
                        "ACK to self via dialog route set — dropping (loop guard)"
                    );
                    continue;
                }
            };

            // Add our Via on top (preserving existing Vias), reflecting the
            // transport we will actually send over.
            let transport_str = format!("{out_transport}");
            core::add_via(
                &mut ack_downstream.headers,
                &transport_str,
                &state.via_host(&out_transport),
                Some(state.via_port(&out_transport)),
            );

            let hop = (destination, out_transport);
            if sent_destinations.contains(&hop) {
                debug!(
                    client_key = %client_key,
                    %destination,
                    "2xx ACK already relayed to this hop by another fork branch — skipping"
                );
                continue;
            }
            sent_destinations.push(hop);

            let data = Bytes::from(ack_downstream.to_bytes());
            debug!(
                client_key = %client_key,
                %destination,
                transport = %out_transport,
                "relaying ACK for 2xx downstream via dialog route set"
            );

            // Send to the resolved dialog next hop. `send_to_target` picks the
            // right connection per transport (TCP/TLS pool, UDP outbound + IPsec
            // source), using the established connection as the UDP fallback.
            let target = RelayTarget {
                address: destination,
                transport: Some(out_transport),
                server_name: None,
            };
            send_to_target(
                data,
                &target,
                client_branch.transport,
                ack_connection_id,
                None,
                state,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ProxySession-based CANCEL handling
// ---------------------------------------------------------------------------

/// Build the topmost `Via` value for a CANCEL forwarded on a proxy client
/// branch.
///
/// RFC 3261 §9.1 makes CANCEL the one request that MUST share the topmost
/// `Via` branch of the request it cancels; §16.10 has a stateful proxy
/// generate, for each pending branch, a CANCEL whose single `Via` equals the
/// top `Via` of the INVITE it forwarded on that branch.  The downstream
/// UAS/proxy matches CANCEL→INVITE on that branch + sent-by (RFC 3261 §9.2 /
/// §17.2.3) to find the in-progress INVITE server transaction.
///
/// The proxy's client transaction key already holds exactly the branch and
/// sent-by siphon stamped on that INVITE's topmost `Via` (see
/// [`TransactionManager::key_from_message`]), so we reuse them verbatim —
/// reusing `sent_by` also keeps the CANCEL aligned with the INVITE in the
/// IPsec / flow / `force_send_via` cases where the advertised sent-by differs
/// from the default per-transport `via_host`.  Minting a fresh branch here
/// (as siphon did before) makes the forwarded CANCEL unmatchable downstream:
/// it is dropped, the INVITE leg below is never torn down, and the callee
/// keeps ringing after the caller abandons during alerting.
pub(super) fn cancel_via_for_client_branch(
    client_key: &TransactionKey,
    transport: Transport,
) -> String {
    format!(
        "SIP/2.0/{} {};branch={}",
        format!("{transport}").to_uppercase(),
        client_key.sent_by,
        client_key.branch,
    )
}

/// Handle CANCEL using ProxySession — forwards CANCEL to all client branches
/// and sends 487 Request Terminated upstream.
pub(super) fn handle_cancel_via_session(
    inbound: InboundMessage,
    message: SipMessage,
    invite_server_key: &TransactionKey,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during CANCEL handling");
            let response = build_response(
                &message,
                500,
                "Internal Server Error",
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
    };

    // Send 200 OK to CANCEL (RFC 3261 §9.2: always 200) on the arrival socket —
    // the 487 below already pins `session.inbound_local_addr`; keep the 200 on the
    // same listener so a multi-homed UDP host answers both from one source port.
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Forward CANCEL to each client branch
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut cancel_downstream = message.clone();
            // RFC 3261 §9.1 / §16.10: the forwarded CANCEL MUST carry the SAME
            // topmost Via branch (and sent-by) as the INVITE siphon sent on
            // this branch, so the downstream matches CANCEL→INVITE (RFC 3261
            // §9.2 / §17.2.3) and tears the alerting branch down.  Minting a
            // fresh branch makes the CANCEL unmatchable: it's dropped, the
            // INVITE leg below is never cancelled, and the callee keeps
            // ringing after the caller abandons.  `headers.set` collapses the
            // inbound CANCEL's Via stack to this single Via (§9.1 — a proxy
            // CANCEL carries exactly one Via).
            let via_value = cancel_via_for_client_branch(client_key, client_branch.transport);
            cancel_downstream.headers.set("Via", via_value);

            let data = Bytes::from(cancel_downstream.to_bytes());

            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "forwarding CANCEL downstream via session"
            );

            send_outbound(
                data,
                client_branch.transport,
                client_branch.destination,
                client_branch.connection_id,
                state,
            );
        }
    }

    // Send 487 Request Terminated upstream using the original INVITE from the session
    let response_487 = build_response(
        &session.original_request,
        487,
        "Request Terminated",
        state.server_header.as_deref(),
        &[],
    );
    send_message_from(
        response_487,
        session.transport,
        session.source_addr,
        session.connection_id,
        Some(session.inbound_local_addr),
        state,
    );
    // The caller abandoned the INVITE: its dialog, and every branch's, is over.
    proxy_dialog_invite_abandoned(&session.original_request, state);

    // Fire @proxy.on_cancel before the session is evicted so scripts can
    // release per-call resources (Diameter Rx/N5 QoS, rtpengine media) that
    // no BYE will ever clear — the only teardown signal for a
    // CANCELled-before-answer INVITE (RFC 3261 §9). Guard the clone: the
    // common no-handler path stays allocation-free.
    let server_key = invite_server_key.clone();
    let has_cancel_handlers = !state
        .engine
        .state()
        .handlers_for(&HandlerKind::ProxyCancel)
        .is_empty();
    if has_cancel_handlers {
        let cancel_request = session.original_request.clone();
        let cancel_transport = session.transport;
        let cancel_source_addr = session.source_addr;
        let cancel_inbound_local_addr = session.inbound_local_addr;
        let cancel_connection_id = session.connection_id;
        drop(session);
        run_proxy_cancel_handlers(
            cancel_request,
            cancel_transport,
            cancel_source_addr,
            cancel_inbound_local_addr,
            cancel_connection_id,
            state,
        );
    } else {
        drop(session);
    }

    state.session_store.remove_by_server_key(&server_key);
    // Removing the session is what makes a retransmitted CANCEL unmatchable, so
    // record the acceptance in the same breath (RFC 3261 §9.2).
    remember_cancelled_invite(&state.cancelled_invites, server_key);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL handling
// ---------------------------------------------------------------------------

/// Build a CANCEL for an outbound INVITE per RFC 3261 §9.1.
///
/// The CANCEL MUST share the topmost Via branch and CSeq sequence number
/// of the request being cancelled — that is the contract that lets the
/// downstream UAS (and every proxy on the path) match the CANCEL to the
/// in-progress server transaction of the INVITE.  Building a CANCEL with
/// a fresh branch, or with the wrong CSeq number, makes every proxy hop
/// return 481 Call/Transaction Does Not Exist and the UAS keeps ringing.
///
/// The caller passes the outbound INVITE as siphon put it on the wire —
/// for B2BUA that's [Leg::b_leg_invite]; for proxy fork it's a clone of
/// the inbound request with the topmost Via swapped for siphon's
/// per-branch Via.
///
/// Other headers (From, To, Call-ID, R-URI, Max-Forwards, Route) are
/// preserved verbatim from the INVITE.  Content-Length is forced to 0;
/// the body is dropped.  Everything else (Contact, Allow, Supported,
/// PAI, Session-Expires, SDP, …) is stripped — CANCEL is hop-by-hop and
/// carries no payload.
pub(super) fn build_cancel_from_invite(invite: &SipMessage) -> Option<SipMessage> {
    // Method swap: INVITE → CANCEL on the request line.
    let mut cancel = invite.clone();
    let request_uri = match &mut cancel.start_line {
        StartLine::Request(rl) => {
            rl.method = crate::sip::message::Method::Cancel;
            rl.request_uri.clone()
        }
        StartLine::Response(_) => return None,
    };
    let _ = request_uri; // touched only to enforce the variant guard above

    // CSeq: keep the INVITE's sequence number, swap the method to CANCEL
    // (RFC 3261 §9.1 — "MUST contain the same value for the sequence
    //  number as was present in the request being cancelled, but the
    //  method parameter MUST be equal to CANCEL").
    let cseq_seq = invite
        .headers
        .cseq()?
        .split_whitespace()
        .next()?
        .to_string();
    cancel.headers.set("CSeq", format!("{} CANCEL", cseq_seq));

    // Topmost Via only.  The stashed B-leg INVITE has exactly one Via
    // (siphon overwrites Via on B-leg INVITE build), so set_all with a
    // single value is fine — but be defensive in case the assumption
    // ever drifts.
    if let Some(vias) = invite.headers.get_all("Via") {
        if let Some(top) = vias.first() {
            cancel.headers.set("Via", top.clone());
        }
    }

    // Drop the payload — CANCEL never carries a body.
    cancel.body.clear();
    cancel.headers.set("Content-Length", "0".to_string());

    // Strip headers that have no place on a CANCEL.  We keep:
    //   Via (topmost only — set above)
    //   From, To, Call-ID, CSeq, Max-Forwards, Route
    //   Content-Length
    // Everything else is dropped per RFC 3261 §9.1 + §20 (CANCEL is
    // hop-by-hop, carries no offer/answer, no dialog-establishing data).
    const KEEP: &[&str] = &[
        "via",
        "from",
        "to",
        "call-id",
        "cseq",
        "max-forwards",
        "route",
        "content-length",
    ];
    let to_remove: Vec<String> = cancel
        .headers
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|n| !KEEP.contains(&n.as_str()))
        .collect();
    for name in to_remove {
        cancel.headers.remove(&name);
    }

    Some(cancel)
}
