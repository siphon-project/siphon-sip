//! What happens when every branch of a relayed request failed.
//!
//! Picks the best error (6xx > 5xx > 4xx), runs the script failure handler,
//! and honours a retarget without letting it loop.

use super::*;

/// Upper bound on how many times `@proxy.on_failure` may re-target one server
/// transaction.  A retarget is a fresh client transaction on the same server
/// transaction, so no protocol timer bounds the chain — a script that always
/// retries would loop until the UAC gave up.  Eight is far above any real
/// failover depth (an AoR's bindings, a gateway list) and low enough that a
/// runaway script fails fast and loudly.
pub(super) const MAX_FAILURE_RETARGETS: u8 = 8;

/// A retarget requested by an `@proxy.on_failure` handler (or by a per-relay
/// `on_failure=` callback) — the script called `request.relay()` /
/// `request.fork()` instead of forwarding the error.
pub(super) struct FailureRetarget {
    /// The Relay/Fork action the handler set.
    pub(super) action: RequestAction,
    /// The request as the handler left it — Route, Request-URI and headers may
    /// all have been rewritten to point at the next candidate.
    pub(super) request: SipMessage,
    pub(super) on_reply_callback: Option<Py<PyAny>>,
    pub(super) on_failure_callback: Option<Py<PyAny>>,
    pub(super) send_via_transport: Option<String>,
    pub(super) send_via_target: Option<String>,
}

/// What the `@proxy.on_failure` handlers decided.
pub(super) struct FailureHandlerOutcome {
    /// The error response, as the handlers left it.
    pub(super) response: SipMessage,
    /// Whether a handler called `reply.relay()` — false means "suppress".
    pub(super) forwarded: bool,
    /// Set when a handler re-targeted the request instead.
    pub(super) retarget: Option<FailureRetarget>,
}

/// Run the `@proxy.on_failure` handlers for a failed relay or fork.
///
/// The handlers get the original request (with its inbound flow replayed, so
/// Path-token MT routing works on the retry) and the error response.  They may
/// forward the error (`reply.relay()`), replace it (`request.reply()`), drop it
/// silently, or re-target the request (`request.relay()` / `request.fork()`) —
/// the last of which is returned as a [`FailureRetarget`] for the caller to
/// execute.
pub(super) fn run_proxy_failure_handlers(
    response: SipMessage,
    original_request: SipMessage,
    transport: Transport,
    source_addr: SocketAddr,
    inbound_local_addr: SocketAddr,
    connection_id: ConnectionId,
    state: &DispatcherState,
) -> FailureHandlerOutcome {
    let engine_state = state.engine.state();
    let failure_handlers = engine_state.handlers_for(&HandlerKind::ProxyFailure);
    if failure_handlers.is_empty() {
        return FailureHandlerOutcome {
            response,
            forwarded: true,
            retarget: None,
        };
    }

    let response_arc = Arc::new(std::sync::Mutex::new(response));
    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let reply = PyReply::new(Arc::clone(&response_arc));
    let mut py_request = PyRequest::with_local_domains(
        Arc::clone(&request_arc),
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
        Arc::clone(&state.local_domains),
    )
    .with_self_identity(Arc::clone(&state.self_identity));
    // Replay the inbound flow capture so the failure handler can do Path-token
    // MT routing (`registrar.lookup_by_token` + `request.relay(flow=…)`) on the
    // retry — the same context the on_request handler saw.
    py_request.set_local_port(inbound_local_addr.port());
    py_request.set_inbound_flow(inbound_local_addr, connection_id.0);

    let (
        forwarded,
        action,
        on_reply_callback,
        on_failure_callback,
        send_via_transport,
        send_via_target,
    ) = Python::attach(|python| {
        let py_reply = match Py::new(python, reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply for on_failure: {error}");
                return (true, RequestAction::None, None, None, None, None);
            }
        };
        let py_req = match Py::new(python, py_request) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for on_failure: {error}");
                return (true, RequestAction::None, None, None, None, None);
            }
        };

        for handler in &failure_handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((py_req.bind(python), py_reply.bind(python))) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async on_failure", &error);
                            return (true, RequestAction::None, None, None, None, None);
                        }
                    }
                }
                Err(error) => {
                    record_script_error("on_failure", &error);
                    return (true, RequestAction::None, None, None, None, None);
                }
            }
        }

        let forwarded = py_reply.borrow(python).was_forwarded();
        let mut borrowed = py_req.borrow_mut(python);
        (
            forwarded,
            borrowed.action().clone(),
            borrowed.take_on_reply_callback(),
            borrowed.take_on_failure_callback(),
            borrowed.via_transport_override().map(|s| s.to_string()),
            borrowed.via_target_override().map(|s| s.to_string()),
        )
    });

    let response = match Arc::try_unwrap(response_arc) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
        Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
    };

    // Only Relay/Fork is a retarget.  `RequestAction::Reply` is the script
    // answering the UAC itself — that lands on the normal reply path below via
    // the response the handler mutated; `None` is the documented silent drop.
    let retarget = match action {
        RequestAction::Relay { .. } | RequestAction::Fork { .. } => {
            let request = match Arc::try_unwrap(request_arc) {
                Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            };
            Some(FailureRetarget {
                action,
                request,
                on_reply_callback,
                on_failure_callback,
                send_via_transport,
                send_via_target,
            })
        }
        _ => None,
    };

    FailureHandlerOutcome {
        response,
        forwarded,
        retarget,
    }
}

/// Execute a retarget an `@proxy.on_failure` handler asked for: start a fresh
/// client transaction (or fork) on the *same* server transaction, so the UAC
/// keeps waiting on its original request instead of seeing the failure.
///
/// Returns `false` when the retarget was refused (retry budget exhausted); the
/// caller then forwards the error response as if no retarget had been asked
/// for, which is the only outcome that still answers the UAC.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_failure_retarget(
    retarget: FailureRetarget,
    server_key: &TransactionKey,
    record_routed: bool,
    transport: Transport,
    source_addr: SocketAddr,
    inbound_local_addr: SocketAddr,
    connection_id: ConnectionId,
    previous_retargets: u8,
    state: &DispatcherState,
) -> bool {
    if previous_retargets >= MAX_FAILURE_RETARGETS {
        warn!(
            server_key = %server_key,
            retargets = previous_retargets,
            "on_failure: retarget budget exhausted — forwarding the failure instead"
        );
        return false;
    }

    // Drop the exhausted session (and its client-key indices) before the new
    // one is inserted for the same server key — otherwise the retry's response
    // would find the old, completed session.
    state.session_store.remove_by_server_key(server_key);

    let inbound = InboundMessage {
        remote_addr: source_addr,
        local_addr: inbound_local_addr,
        connection_id,
        transport,
        data: Bytes::new(),
    };

    match retarget.action {
        RequestAction::Relay {
            ref next_hop,
            ref flow,
            ref send_socket,
        } => {
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            relay_request(
                &retarget.request,
                next_hop.as_deref(),
                record_routed,
                &inbound,
                Some(server_key),
                state,
                retarget.on_reply_callback,
                retarget.on_failure_callback,
                retarget.send_via_transport.as_deref(),
                retarget.send_via_target.as_deref(),
                flow.as_ref(),
                send_socket.as_ref(),
            );
        }
        RequestAction::Fork {
            ref targets,
            ref flows,
            ref routes,
            ref strategy,
            ref send_socket,
        } => {
            if targets.is_empty() {
                warn!(server_key = %server_key, "on_failure: fork with no targets — forwarding the failure");
                return false;
            }
            let fork_strategy = match strategy.as_str() {
                "sequential" => crate::proxy::fork::ForkStrategy::Sequential,
                _ => crate::proxy::fork::ForkStrategy::Parallel,
            };
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            relay_fork_request(
                &retarget.request,
                targets,
                flows,
                routes,
                fork_strategy,
                record_routed,
                &inbound,
                Some(server_key),
                state,
                send_socket.as_ref(),
                retarget.on_reply_callback,
                retarget.on_failure_callback,
            );
        }
        _ => return false,
    }

    // Carry the retry count onto the session the relay just created so the
    // chain stays bounded.  Looked up rather than threaded through the relay
    // signatures; a response that beats this write only costs one extra
    // permitted retarget, which the budget still bounds.
    if let Some(session_arc) = state.session_store.get_by_server_key(server_key) {
        if let Ok(mut session) = session_arc.write() {
            session.failure_retargets = previous_retargets.saturating_add(1);
        }
    }

    debug!(
        server_key = %server_key,
        retarget = previous_retargets + 1,
        "on_failure: re-targeted the request"
    );
    true
}

/// Rewrite a 503 the proxy is about to forward upstream into a 500
/// (RFC 3261 §16.7 step 6), returning the status code actually forwarded.
///
/// A 503 means *this* next hop is unavailable. Passing it to the UAC would
/// invite it to treat the proxy itself as out of service (RFC 3261 §20.33
/// Retry-After semantics), which is both wrong and self-inflicted: the proxy is
/// fine, one downstream target is not.
///
/// Any other status is returned unchanged.
pub(super) fn downgrade_503_for_upstream(
    message: &mut SipMessage,
    status_code: u16,
    server_key: &TransactionKey,
) -> u16 {
    if status_code != 503 {
        return status_code;
    }
    if let StartLine::Response(ref mut status_line) = message.start_line {
        status_line.status_code = 500;
        status_line.reason_phrase = "Server Internal Error".to_string();
    }
    // Retry-After on a 503 is about the unavailable downstream, not about us.
    message.headers.remove("Retry-After");
    debug!(
        key = %server_key,
        "forwarding 503 upstream as 500 (RFC 3261 §16.7)"
    );
    500
}

/// Answer a proxy client branch that will never be answered from the network,
/// by injecting the response RFC 3261 says the proxy must behave as if it had
/// received.
///
/// Two callers, one rule each:
///
/// * **§16.9** — a transport error on forwarding is a **503** on that branch.
/// * **§16.7 step 2** — a client transaction that times out (Timer B / Timer F)
///   is a **408** on that branch.
///
/// Both used to end at a `warn!` and nothing else, so the upstream UAC was left
/// holding a `100 Trying` until its own Timer F fired: 32 s of silence where
/// the proxy already knew the answer.
///
/// The response is routed through the ordinary [`handle_response`] path rather
/// than being forwarded directly, because everything that has to happen next is
/// already implemented there and only there — fork aggregation (so a parallel
/// fork keeps waiting on its live branches and a sequential fork advances to
/// the next target), `@proxy.on_reply` / `@proxy.on_failure`, CDR finalisation,
/// and the handoff to the server transaction. A direct forward would need its
/// own copy of all of it and would drift.
///
/// No-ops when the branch has no proxy session: a B2BUA leg registers no client
/// transaction, and a session already torn down by a winning branch has nothing
/// left to answer.
pub(super) fn fail_branch_locally(
    client_key: &TransactionKey,
    status_code: u16,
    reason: &str,
    cause: &str,
    state: &DispatcherState,
) {
    let Some(session_arc) = state.session_store.get_by_client_key(client_key) else {
        debug!(
            key = %client_key,
            status = status_code,
            "no proxy session for branch — nothing to answer ({cause})"
        );
        return;
    };

    let (original_request, inbound_local_addr, branch, fork_aggregator, branch_index) = {
        let Ok(session) = session_arc.read() else {
            error!("proxy session lock poisoned while failing a branch");
            return;
        };
        (
            session.original_request.clone(),
            session.inbound_local_addr,
            session.client_branches.get(client_key).cloned(),
            session.fork_aggregator.clone(),
            session.branch_index_map.get(client_key).copied(),
        )
    };

    // Tell the aggregator this branch's answer is ours, not the callee's,
    // *before* injecting it.  A sibling branch that actually reached an
    // endpoint must win the best-error selection: without this a transport
    // error (503, class 5xx) would outrank a real `486 Busy Here` (class 4xx)
    // and the caller would hear "Server Internal Error" instead of "Busy".
    if let (Some(aggregator), Some(index)) = (&fork_aggregator, branch_index) {
        match aggregator.lock() {
            Ok(mut agg) => agg.mark_local_failure(index),
            Err(_) => error!("fork aggregator lock poisoned while failing a branch"),
        }
    }

    // RFC 3261 §17.1.4: on a transport failure the client transaction goes
    // straight to Terminated. Dropping it here also stops the synthetic
    // response below from being fed back into it — which for an INVITE would
    // otherwise emit an ACK to a peer that never sent anything.
    state.transaction_manager.remove(client_key);

    let mut response = build_response(
        &original_request,
        status_code,
        reason,
        state.server_header.as_deref(),
        &[],
    );

    // `build_response` copies the request's Via stack, whose top is the UAC's.
    // The response path keys the branch off the *topmost* Via and strips it, so
    // put back the Via this proxy stamped on the outbound request — the one the
    // transaction key was built from — or the injected response matches no
    // branch and is dropped as an orphan.
    let branch_transport = branch
        .as_ref()
        .map(|b| b.transport)
        .unwrap_or(Transport::Udp);
    let via_value = format!(
        "SIP/2.0/{} {};branch={}",
        branch_transport, client_key.sent_by, client_key.branch,
    );
    let mut vias = vec![via_value];
    vias.extend(response.headers.get_all("Via").cloned().unwrap_or_default());
    response.headers.set_all("Via", vias);

    warn!(
        key = %client_key,
        status = status_code,
        "answering branch locally: {cause}"
    );

    let inbound = InboundMessage {
        remote_addr: branch
            .as_ref()
            .map(|b| b.destination)
            .unwrap_or(inbound_local_addr),
        local_addr: inbound_local_addr,
        connection_id: branch.as_ref().map(|b| b.connection_id).unwrap_or_default(),
        transport: branch_transport,
        data: Bytes::new(),
    };
    handle_response(inbound, response, status_code, state);
}
