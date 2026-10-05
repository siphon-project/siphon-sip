//! CANCEL and ACK on the proxy path.
//!
//! A 2xx ACK is a new transaction (RFC 3261 §13.2.2.4), not part of the INVITE
//! one, so it is routed by dialog rather than by branch. CANCEL fans out to
//! every fork branch still pending: one that has drawn a provisional is sent
//! it at once, and one that has drawn nothing when it does (RFC 3261 §9.1,
//! [`cancel_proxy_branch`]).

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
/// "Pending" is RFC 3261 §9.1's: each branch is offered to
/// [`cancel_proxy_branch`], which sends the CANCEL to a branch that has drawn a
/// provisional, keeps it for one that has drawn nothing, and sends none to one
/// that has its final response.
///
/// RFC 3261 §9.1: each branch's CANCEL is built from that branch's own INVITE
/// as its client transaction sent it, so its Request-URI is the branch target,
/// its Route set the branch's, and its one Via the INVITE's top Via.
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
            cancel_proxy_branch(client_key, client_branch, &[], state);
        }
    }
}

/// CANCEL one branch of a proxied INVITE, when RFC 3261 §9.1 allows it;
/// `reasons` are the `Reason` values the CANCEL carries (RFC 3326). The one place the proxy decides to send a branch its CANCEL,
/// whatever gave up on the branch: another branch's 2xx or 6xx, a
/// `reply.reject()`, the caller's own CANCEL.
///
/// §9.1: "If no provisional response has been received, the CANCEL request
/// MUST NOT be sent; rather, the client MUST wait for the arrival of a
/// provisional response before sending the request", and a CANCEL "SHOULD NOT
/// be sent" for a request with its final response. §16.10 and §16.7 step 10
/// have a proxy CANCEL its *pending* client transactions, which are those.
///
/// What the branch has drawn is the state of its INVITE client transaction,
/// and the decision is taken there, under the lock the response path holds
/// for the same transaction:
///
/// * a provisional and no final: the CANCEL is sent now;
/// * nothing yet: the CANCEL is left with the transaction. The INVITE stays an
///   unanswered request, retransmitted on Timer A, and its first provisional
///   (a `100 Trying` counts) sends the CANCEL from the response path. A final
///   response instead drops it unsent, and so does Timer B;
/// * a final response, or a transaction that is over: nothing is sent.
///
/// The waiting CANCEL does not depend on the proxy session, which the caller's
/// CANCEL removes at once.
fn cancel_proxy_branch(
    client_key: &TransactionKey,
    client_branch: &ClientBranch,
    reasons: &[String],
    state: &DispatcherState,
) {
    use crate::transaction::state::{BranchHop, CancelOutcome};

    let hop = BranchHop {
        destination: client_branch.destination,
        transport: client_branch.transport,
        connection_id: client_branch.connection_id,
        source_local_addr: None,
    };
    match state
        .transaction_manager
        .cancel_invite_client(client_key, hop, reasons)
    {
        CancelOutcome::SendNow(cancel) => send_proxy_branch_cancel(&cancel, state),
        CancelOutcome::Deferred => debug!(
            client_key = %client_key,
            destination = %client_branch.destination,
            "proxy: no provisional on this branch yet — its INVITE keeps retransmitting and the CANCEL follows its first provisional (RFC 3261 §9.1)"
        ),
        CancelOutcome::NothingToSend => debug!(
            client_key = %client_key,
            destination = %client_branch.destination,
            "proxy: branch has its final response or its CANCEL already — nothing to send (RFC 3261 §9.1)"
        ),
        CancelOutcome::Unbuildable(error) => warn!(
            client_key = %client_key,
            destination = %client_branch.destination,
            "proxy: cannot build the CANCEL of a branch from its INVITE as sent ({error}) — it rings on until it answers or times out"
        ),
    }
}

/// Where the proxy sent the request of client transaction `client_key`:
/// transport, address and connection, as its session's branch records them.
/// `None` once the session no longer holds the branch.
pub(super) fn proxy_branch_hop(
    client_key: &TransactionKey,
    state: &DispatcherState,
) -> Option<(Transport, SocketAddr, ConnectionId)> {
    let session_arc = state.session_store.get_by_client_key(client_key)?;
    let session = session_arc.read().ok()?;
    let branch = session.get_client_branch(client_key)?;
    Some((branch.transport, branch.destination, branch.connection_id))
}

/// Put the CANCEL of a proxied INVITE on the wire, to the hop that INVITE went
/// to (RFC 3261 §9.1: the same destination address, port and transport).
///
/// Reached from the two places a branch's CANCEL is released: at once, when
/// the branch already had a provisional, and from the response path, on the
/// first provisional of a branch that had none ([`Action::SendCancel`]).
pub(super) fn send_proxy_branch_cancel(
    cancel: &crate::transaction::state::BranchCancel,
    state: &DispatcherState,
) {
    debug!(
        destination = %cancel.hop.destination,
        transport = %cancel.hop.transport,
        "proxy: sending a branch its CANCEL"
    );
    send_outbound_from(
        cancel.frame.clone(),
        cancel.hop.transport,
        cancel.hop.destination,
        cancel.hop.connection_id,
        cancel.hop.source_local_addr,
        state,
    );
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
/// 2. CANCEL every pending downstream branch (RFC 3261 §9.1 — the branch whose
///    provisional drew the reject at once, any other when it has drawn a
///    provisional of its own), then send `code reason` upstream
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

    // Does this CANCEL belong to a B2BUA call? The call actor's existence is the
    // whole test. It used to be reached only when the script had registered a
    // B2BUA handler, which asks the wrong question: a call created over
    // `control.inbound` and driven by a control application has an actor and no
    // script handlers, so its CANCEL fell through to the ProxySession lookup —
    // which cannot match a B2BUA call — and was answered 481 while the callee
    // kept ringing and the flow went on to answer a call the caller had already
    // abandoned. `handle_b2bua_cancel` does its own lookup and answers 481
    // itself when there is genuinely no actor, so a proxy CANCEL still falls
    // through to the branch below.
    if let Some(sip_call_id) = message.headers.get("Call-ID") {
        if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
            handle_b2bua_cancel(inbound, message, state);
            return;
        }
    }

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

/// Handle CANCEL using ProxySession — forwards CANCEL to the pending client
/// branches and sends 487 Request Terminated upstream.
///
/// The caller is answered, and the session removed, at once. A branch that
/// has drawn no response yet is not sent the CANCEL then (RFC 3261 §9.1): it
/// stays with the branch's INVITE client transaction, which outlives the
/// session, and goes on that INVITE's first provisional
/// ([`cancel_proxy_branch`]).
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

    // Forward CANCEL to each client branch still pending
    let reasons = message
        .headers
        .get_all("Reason")
        .cloned()
        .unwrap_or_default();
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            // RFC 3261 §9.1 / §16.10: the CANCEL of a branch is that
            // branch's INVITE over again (Request-URI, Route, From, To,
            // Call-ID, CSeq number, and its top Via as the one Via), so it is
            // built from the INVITE as sent, not from the caller's CANCEL,
            // whose Request-URI and route set are the caller's. What the
            // caller's CANCEL adds is why (RFC 3326), and that is relayed.
            //
            // Sent now to a branch that has answered with a provisional, kept
            // for one that has answered nothing, dropped for one that already
            // has its final response (RFC 3261 §9.1).
            cancel_proxy_branch(client_key, client_branch, &reasons, state);
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

    release_cancelled_session(&session_arc, state);
    // A retransmitted CANCEL is answered 200 and does none of this again
    // (RFC 3261 §9.2).
    remember_cancelled_invite(&state.cancelled_invites, server_key);
}

/// Leave a cancelled INVITE's session to its branches still owed a final
/// response, and to nothing else.
///
/// The caller has its `487`, so the session is marked as finally answered:
/// whatever a branch still sends is absorbed, except a 2xx, which RFC 3261
/// §16.7 step 5 has forwarded even now and which needs the session to reach
/// the caller. The dialog index goes at once (no dialog was established; a
/// late 2xx puts it back for its own ACK), and so does every branch that has
/// nothing more to send. A branch still pending is released by its final
/// response or by its transaction timing out; with none left the session is
/// gone here.
fn release_cancelled_session(session_arc: &Arc<RwLock<ProxySession>>, state: &DispatcherState) {
    let (original_request, client_keys) = match session_arc.write() {
        Ok(mut session) => {
            session.final_response_sent = true;
            (
                session.original_request.clone(),
                session.client_keys.clone(),
            )
        }
        Err(error) => {
            error!("proxy session lock poisoned while releasing a cancelled INVITE: {error}");
            return;
        }
    };
    state.session_store.remove_dialog_key(&original_request);
    for client_key in &client_keys {
        if !state
            .transaction_manager
            .invite_client_is_pending(client_key)
        {
            state.session_store.remove_client_key(client_key);
        }
    }
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL handling
// ---------------------------------------------------------------------------

/// Build a CANCEL for an outbound INVITE per RFC 3261 §9.1, from that INVITE
/// as siphon put it on the wire: for the B2BUA the leg's stashed INVITE, for
/// the proxy the octets the branch's client transaction sent.
///
/// See [`crate::transaction::cancel::build_cancel`], which this is.
pub(super) fn build_cancel_from_invite(invite: &SipMessage) -> Option<SipMessage> {
    crate::transaction::cancel::build_cancel(invite, &[])
}
