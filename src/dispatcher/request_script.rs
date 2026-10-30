//! The script half of inbound request handling: running the
//! `@proxy.on_request` handlers, across an async one's await, and acting on
//! what they decided.

use super::*;
// The B2BUA builders and send path live in their own subtree.
use super::b2bua::*;

/// What `handle_request` carries from before the script runs to the work it
/// does once the handlers have decided — across a suspended handler too, when
/// that work runs on another worker.
pub(super) struct ScriptedRequest {
    pub(super) inbound: InboundMessage,
    pub(super) method: String,
    pub(super) state: Arc<DispatcherState>,
    pub(super) server_key: Option<TransactionKey>,
    pub(super) message_arc: Arc<std::sync::Mutex<SipMessage>>,
    pub(super) cdr_key: Option<String>,
    pub(super) reply_gate: Option<Arc<crate::script::api::proxy_utils::ReplyGate>>,
    /// A subscription this NOTIFY terminates: it lasts until the handlers have
    /// finished, which is when this drops.
    pub(super) ended_subscription: Option<crate::subscribe_state::EndedSubscription>,
    /// The script the handlers come from, held so a reload while one is
    /// suspended neither changes nor frees the handlers still to run.
    pub(super) script: Arc<crate::script::engine::ScriptState>,
}

/// What the handlers left on the request, read once every one has returned.
pub(super) struct ScriptDecision {
    action: RequestAction,
    record_routed: bool,
    on_reply_cb: Option<Py<PyAny>>,
    on_failure_cb: Option<Py<PyAny>>,
    send_via_transport: Option<String>,
    send_via_target: Option<String>,
    reply_headers: Vec<(crate::script::api::request::ReplyHeaderOp, String, String)>,
    reply_body: Option<(Vec<u8>, String)>,
    auth_user: Option<String>,
    /// The registrar events the handlers' `save()` calls held back. Published
    /// once the reply is out; whatever path ends the request without that
    /// (a relay, a drop, an early return) drops it, and the drop publishes.
    registrar_events: Option<crate::registrar::RegisterEventHold>,
}

impl ScriptDecision {
    /// No action: the request is dropped silently.
    pub(super) fn nothing() -> Self {
        Self {
            action: RequestAction::None,
            record_routed: false,
            on_reply_cb: None,
            on_failure_cb: None,
            send_via_transport: None,
            send_via_target: None,
            reply_headers: vec![],
            reply_body: None,
            auth_user: None,
            registrar_events: None,
        }
    }

    /// A handler raised: answer 500, whatever it had decided before.
    fn script_error() -> Self {
        Self {
            action: RequestAction::Reply {
                code: 500,
                reason: "Script Error".to_string(),
                reliable: false,
            },
            ..Self::nothing()
        }
    }

    fn take_from(request: &mut PyRequest) -> Self {
        Self {
            action: request.action().clone(),
            record_routed: request.is_record_routed(),
            on_reply_cb: request.take_on_reply_callback(),
            on_failure_cb: request.take_on_failure_callback(),
            send_via_transport: request.via_transport_override().map(|s| s.to_string()),
            send_via_target: request.via_target_override().map(|s| s.to_string()),
            reply_headers: request.take_reply_headers(),
            reply_body: request.take_reply_body(),
            // Read *after* the handler ran, so a script that authenticated the
            // caller — or normalised the identity afterwards — is what reaches
            // the CDR. Reading it before would always be empty.
            auth_user: request.get_auth_user().map(String::from),
            registrar_events: request.take_registrar_hold(),
        }
    }
}

/// Where running the handlers stopped.
enum HandlerStep {
    /// Every handler that runs has returned.
    Decided(Box<ScriptDecision>),
    /// The async handler before `next` is awaiting on an asyncio driver.
    Suspended {
        pending: crate::script::async_pool::PendingCoroutine,
        py_request: Py<PyRequest>,
        next: usize,
    },
}

/// Run the request's handlers from index `first` on, then act on what they
/// decided.
///
/// An `async def` handler that suspends ends this job instead of holding its
/// worker for the await: the coroutine stays on its asyncio driver, and once
/// it settles the remaining handlers and the action run as a new executor job
/// — this function again, from the next handler. Awaiting therefore costs a
/// pending coroutine, not a thread, and a handler awaiting a slow downstream
/// request no longer caps the node at `workers / latency`. Off an executor
/// worker (tests, direct callers) a coroutine is waited for in place, as it
/// always was.
///
/// `carried` is what the request had queued for after its reply on the worker
/// it ran on before suspending.
pub(super) fn run_request_handlers(
    scripted: ScriptedRequest,
    py_request: Py<PyRequest>,
    first: usize,
    carried: Vec<crate::script::api::proxy_utils::DeferredMessage>,
) {
    let script = &scripted.script;
    let method = scripted.method.as_str();
    let step = Python::attach(move |python| {
        // Deferred sends: presence.notify() etc. queue messages until after
        // the reply is sent (RFC 3265 §3.1.6.2).
        crate::script::api::proxy_utils::resume_deferred_sends(carried);

        let handlers = script.proxy_request_handlers(method);
        for (index, handler) in handlers.iter().enumerate().skip(first) {
            // `request.stop_propagation()` — the handler before this one owns
            // the outcome. Every matching handler shares one action slot, and
            // only its final value executes, so without this a later handler
            // silently replaces an earlier one's decision (registration order
            // decides). Checked once the previous handler has returned, after
            // its await when it was async.
            if index > 0 && py_request.borrow(python).is_propagation_stopped() {
                break;
            }
            let returned = match handler
                .callable
                .bind(python)
                .call1((py_request.bind(python),))
            {
                Ok(returned) => returned,
                Err(error) => {
                    record_script_error("Python", &error);
                    return HandlerStep::Decided(Box::new(ScriptDecision::script_error()));
                }
            };
            // If the handler is async, the return value is a coroutine.
            if handler.is_async {
                match crate::script::inline_dispatch::start_coroutine(python, &returned) {
                    Ok(crate::script::inline_dispatch::CoroutineStart::Finished(_)) => {}
                    Ok(crate::script::inline_dispatch::CoroutineStart::Suspended(pending)) => {
                        return HandlerStep::Suspended {
                            pending,
                            py_request,
                            next: index + 1,
                        };
                    }
                    Err(error) => {
                        record_script_error("async Python", &error);
                        return HandlerStep::Decided(Box::new(ScriptDecision::script_error()));
                    }
                }
            }
        }
        let decision = ScriptDecision::take_from(&mut py_request.borrow_mut(python));
        HandlerStep::Decided(Box::new(decision))
    });

    match step {
        HandlerStep::Decided(decision) => finish_request(scripted, *decision),
        HandlerStep::Suspended {
            pending,
            py_request,
            next,
        } => {
            // This worker goes on to other jobs, and the deferred queue is per
            // thread: take what the request queued so far with it, and leave
            // deferral off here for whatever runs next.
            let carried = crate::script::api::proxy_utils::drain_deferred_sends();
            // Resumed detached: `run_request_handlers` attaches for the
            // handlers only, and `finish_request` — the reply or relay, DNS,
            // connects, IPsec — runs detached as on the first pass.
            pending.resume_on_executor(move |result| match result {
                // The handler's return value means nothing; dropped detached,
                // its reference goes to pyo3's deferred pool.
                Ok(_) => run_request_handlers(scripted, py_request, next, carried),
                Err(error) => {
                    crate::script::api::proxy_utils::resume_deferred_sends(carried);
                    record_script_error("async Python", &error);
                    Python::attach(|_| drop(py_request));
                    finish_request(scripted, ScriptDecision::script_error());
                }
            });
        }
    }
}

/// Act on what the handlers decided: release what the reply gate held, send
/// the reply or relay the request, settle the CDR, flush deferred sends.
pub(super) fn finish_request(scripted: ScriptedRequest, decision: ScriptDecision) {
    let ScriptedRequest {
        inbound,
        method,
        state,
        server_key,
        message_arc,
        cdr_key,
        reply_gate,
        ended_subscription,
        script: _,
    } = scripted;
    let state = &state;
    let ScriptDecision {
        action,
        record_routed,
        on_reply_cb,
        on_failure_cb,
        send_via_transport,
        send_via_target,
        reply_headers,
        reply_body,
        auth_user,
        registrar_events,
    } = decision;
    // Dropped wherever this function returns, which publishes what is still
    // held; the reply arm below publishes it sooner, once the reply is out.
    let mut registrar_events = registrar_events;

    // Every handler has returned, so whatever the gate holds was sent while
    // the script was still deciding. Move it onto this thread's deferred queue,
    // where the reply path picks up what goes to the same peer and the flush at
    // the end sends the rest. A send after this point bypasses the gate.
    if let Some(gate) = reply_gate {
        for held in gate.close() {
            if !crate::script::api::proxy_utils::try_defer_send(
                held.message.clone(),
                held.destination,
                held.transport,
            ) {
                // Deferred mode never switched on (the PyRequest could not be
                // built): nothing is going to be ordered against, send now.
                match crate::script::api::proxy_utils::uac_sender() {
                    Some(uac_sender) => {
                        uac_sender.send_request(held.message, held.destination, held.transport)
                    }
                    None => warn!("held in-dialog message dropped: UAC sender not available"),
                }
            }
        }
    }

    // Process the action, on a copy of the request rather than under its lock.
    // The action waits (DNS, a connect, a send), and the request is still
    // shared with the script: a task it left running can lock it through an
    // auth, IPsec or QoS call, attached to the interpreter. Holding the lock
    // across the wait would park that thread attached, and a garbage
    // collection's stop-the-world would then wait on it while the wait needs
    // the tokio workers the stop-the-world has parked.
    let request_message = match message_arc.lock() {
        Ok(guard) => guard.clone(),
        Err(_) => {
            error!("message_arc lock poisoned");
            return;
        }
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
            send_scripted_reply(
                &request_message,
                ScriptedReply {
                    code: *code,
                    reason,
                    reliable: *reliable,
                    headers: &reply_headers,
                    body: reply_body.as_ref(),
                    exchange: registrar_events
                        .as_ref()
                        .and_then(|held| held.exchange().cloned()),
                },
                &method,
                &inbound,
                server_key.as_ref(),
                state,
            );
            // The reply is with the transport: `@registrar.on_change` may run.
            if let Some(held) = registrar_events.as_mut() {
                held.flush();
            }
        }
        RequestAction::Relay {
            next_hop,
            flow,
            send_socket,
            strip,
            no_response,
        } => {
            // RFC 3261 §16.2: a stateful proxy SHOULD send 100 Trying
            // immediately upon receiving an INVITE to stop UAC retransmissions.
            if method == "INVITE" {
                let trying = build_response(
                    &request_message,
                    100,
                    "Trying",
                    state.identity.load().server.as_deref(),
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
            // A registered phone's INVITE: its dialog is tracked from here,
            // with the identity the script authenticated.
            proxy_dialog_begin(&request_message, auth_user.as_deref(), &inbound, state);
            relay_request(
                &request_message,
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
                strip,
                *no_response,
            );
            proxy_dialog_after_relay(&request_message, state);
        }
        RequestAction::Fork {
            targets,
            flows,
            routes,
            strategy,
            send_socket,
            strip,
            no_response,
        } => {
            if targets.is_empty() {
                warn!("fork with empty targets list");
                let response = build_response(
                    &request_message,
                    500,
                    "No Targets",
                    state.identity.load().server.as_deref(),
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
                        &request_message,
                        100,
                        "Trying",
                        state.identity.load().server.as_deref(),
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
                proxy_dialog_begin(&request_message, auth_user.as_deref(), &inbound, state);
                relay_fork_request(
                    &request_message,
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
                    strip,
                    *no_response,
                );
                proxy_dialog_after_relay(&request_message, state);
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
    drop(ended_subscription);
}

/// A reply the script asked for with `request.reply()`.
struct ScriptedReply<'a> {
    code: u16,
    reason: &'a str,
    reliable: bool,
    headers: &'a [(crate::script::api::request::ReplyHeaderOp, String, String)],
    body: Option<&'a (Vec<u8>, String)>,
    /// The REGISTER exchange this reply completes: it is given the reply's wire
    /// form before the registrar events that carry it are published.
    exchange: Option<Arc<crate::registrar::RegisterExchange>>,
}

/// Send the reply the script decided on through the server transaction, with
/// the messages deferred to the same peer behind it.
fn send_scripted_reply(
    request_message: &SipMessage,
    reply: ScriptedReply<'_>,
    method: &str,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &Arc<DispatcherState>,
) {
    let ScriptedReply {
        code,
        reason,
        reliable,
        ref exchange,
        ..
    } = reply;
    // Only a final response answers the REGISTER.
    let exchange = exchange.as_ref().filter(|_| code >= 200);
    let mut response = build_response(
        request_message,
        code,
        reason,
        state.identity.load().server.as_deref(),
        reply.headers,
    );

    // Script-provided reply body — PIDF-LO, XCAP/Ut, custom failure body, etc.
    if let Some((body_bytes, content_type)) = reply.body {
        response.headers.set("Content-Type", content_type.clone());
        response
            .headers
            .set("Content-Length", body_bytes.len().to_string());
        response.body = body_bytes.clone();
    }

    // RFC 3261 §11.2 — make a 2xx OPTIONS a proper capability response: a
    // Contact (some peers reject an OPTIONS answer carrying neither
    // Contact nor Record-Route) plus an Allow advertising
    // siphon's supported methods (peers read transfer capability from it).
    // Both are added only when absent, so a script-set header still wins.
    if method == "OPTIONS" && (200..300).contains(&code) {
        augment_options_response(
            &mut response,
            // Family-matched to the socket the OPTIONS arrived on, so a v6
            // probe gets a v6 Contact/Via and the exact arrival port.
            &state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
            state.a_leg_advertised_port(Some(inbound.local_addr), &inbound.transport),
            inbound.transport,
            allow_value(&allow_toward(state, || Some(inbound.remote_addr.ip()))),
        );
    }

    // RFC 3262 — script asked for a reliable provisional. Only valid for
    // 101..199 INVITE responses, and only when the UAC advertised 100rel.
    // We attach Require: 100rel + a fresh RSeq, then arm a retransmit
    // task that fires until a matching PRACK arrives or the deadline
    // (32s = 64×T1) elapses.
    let mut reliable_provisional_armed = false;
    if reliable && (101..200).contains(&code) {
        if !crate::sip::headers::rseq::supports_100rel(&request_message.headers) {
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
                request_message,
                response.clone(),
                inbound,
                state,
            );
            reliable_provisional_armed = true;
        }
    }
    let _ = reliable_provisional_armed;

    // IPsec Security-Server / SA setup on 401 REGISTER is driven by the
    // P-CSCF script (see `siphon.ipsec` and `reply.take_av()`). A 2xx the
    // script answered a REGISTER with moves the SA lifecycle as a
    // relayed one does: a de-REGISTER that removed the UE's last binding
    // deletes its pair once this server transaction is over (TS 24.229
    // clause 5.2.5.1).
    if (200..300).contains(&code) && method == "REGISTER" {
        super::ipsec_lifecycle::take_into_use_before_2xx(state, inbound.remote_addr);
        super::ipsec_lifecycle::on_register_2xx(
            state,
            request_message,
            inbound.remote_addr,
            inbound.transport,
        );
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
    if let Some(key) = server_key {
        let server_event = if code < 200 {
            // Provisional
            if key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::TuProvisional(response.clone())))
            } else {
                Some(ServerEvent::Nist(NistEvent::TuProvisional(
                    response.clone(),
                )))
            }
        } else if code < 300 && key.method == crate::sip::message::Method::Invite {
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
                    // The reply as the transaction sends it, To-tag included.
                    if let Some(exchange) = exchange {
                        if let Some(Action::SendMessage(sent)) =
                            actions.iter().find(|a| matches!(a, Action::SendMessage(_)))
                        {
                            exchange.set_response(Bytes::from(sent.to_bytes()));
                        }
                    }
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
        let frame = Bytes::from(response.to_bytes());
        if let Some(exchange) = exchange {
            exchange.set_response(frame.clone());
        }
        send_frames_in_order_from(
            frame,
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
