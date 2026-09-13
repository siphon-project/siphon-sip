//! An inbound REFER on a tracked call (RFC 3515 / 3891 / 5589): the pending
//! decision, the deferred referrer BYE, and the dispatch to the script.
use crate::dispatcher::*;

/// A REFER received on a *controlled* B2BUA call, held un-answered while the
/// owning control app decides via `accept_refer` / `reject_refer`.
///
/// The inbound datagram + parsed message are owned here so the deferred decision
/// can drive [`b2bua_refer_accept`] (accept) or build the final SIP response
/// (reject / deadline) — both need the original request to route the answer back
/// on the flow the REFER arrived on. The entry is removed on accept, reject, OR
/// the decision deadline (a `603 Decline`, matching the no-`@b2bua.on_refer`
/// -handler default). A REFER left pending forever would strand the referrer's
/// transaction, so the deadline is a hard backstop, never optional.
pub struct PendingInboundRefer {
    /// The inbound datagram (transport + flow) the REFER arrived on.
    pub inbound: InboundMessage,
    /// The parsed REFER request.
    pub message: SipMessage,
    /// Parsed Refer-To — target URI + any embedded Replaces (attended transfer).
    pub refer_to: crate::sip::headers::refer::ReferTo,
    /// Whether the REFER arrived on the A-leg dialog (drives survivor selection in
    /// terminate mode — see [`b2bua_refer_accept`]).
    pub from_a_leg: bool,
    /// When the decision deadline expires and the sweep applies the 603 default.
    pub deadline: std::time::Instant,
}

/// Per-call store of inbound REFERs on *controlled* calls awaiting a control-app
/// decision, keyed by the REFER's SIP Call-ID (byte-identical to the control
/// channel's `sip_call_id` for a controlled single-`CallActor` call).
///
/// New per-call state: every entry is removed on accept, reject, or the decision
/// deadline, so the store drains back to baseline under a completed workload (the
/// classic never-evicted-per-call-entry leak). Covered by the co-located
/// steady-state leak test `pending_inbound_refer_store_drains_to_baseline`.
#[derive(Default)]
pub struct PendingInboundReferStore {
    pub entries: DashMap<String, PendingInboundRefer>,
}

impl PendingInboundReferStore {
    /// Record a pending REFER. Returns `false` (dropping `pending`) when an entry
    /// already exists for this call — a REFER retransmit is absorbed rather than
    /// pushing a duplicate `TransferRequested` to the app or resetting the
    /// deadline. Race-safe via the map entry API (the junction is not guaranteed
    /// serialized per Call-ID across workers).
    pub fn insert(&self, sip_call_id: &str, pending: PendingInboundRefer) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.entries.entry(sip_call_id.to_string()) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(pending);
                true
            }
        }
    }

    /// Remove + return the pending REFER for a call (accept / reject path). `None`
    /// when nothing is pending (already decided, timed out, or never controlled).
    pub fn take(&self, sip_call_id: &str) -> Option<PendingInboundRefer> {
        self.entries.remove(sip_call_id).map(|(_, pending)| pending)
    }

    /// Drain every entry whose decision deadline has passed; the sweep applies the
    /// 603 default to each drained REFER.
    pub fn take_expired(&self, now: std::time::Instant) -> Vec<PendingInboundRefer> {
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.value().deadline <= now)
            .map(|entry| entry.key().clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|(_, pending)| pending))
            .collect()
    }

    /// The number of pending REFERs (leak-test + observability accessor).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A `BYE` for a replaced referrer leg, held back until the terminating
/// `NOTIFY` that shares its dialog has been answered.
///
/// Serialized at registration rather than rebuilt at send time: the leg it is
/// addressed to has already been promoted out of the call by then, so there is
/// nothing left to build it from. The frame is byte-identical to the one the
/// immediate send produced.
pub struct DeferredReferrerBye {
    /// The fully built `BYE`, ready to serialize.
    pub message: SipMessage,
    /// The flow the terminating `NOTIFY` went out on — the `BYE` follows it.
    pub transport: Transport,
    pub destination: SocketAddr,
    pub connection_id: ConnectionId,
    pub local_addr: Option<SocketAddr>,
    /// When the sweep gives up waiting for the `NOTIFY` to be answered.
    pub deadline: std::time::Instant,
    /// For the log line on either path.
    pub call_id: String,
}

/// Store of `BYE`s owed to a transfer referrer, keyed by the `Via` branch of
/// the terminating `NOTIFY` whose answer releases them.
///
/// New per-transfer state: every entry leaves on the `NOTIFY`'s final response
/// or on the deadline, so the store drains back to baseline under a completed
/// workload (the classic never-evicted-per-call-entry leak). Covered by the
/// co-located steady-state leak test
/// `deferred_referrer_bye_store_drains_to_baseline`.
#[derive(Default)]
pub struct DeferredReferrerByeStore {
    pub entries: DashMap<String, DeferredReferrerBye>,
}

impl DeferredReferrerByeStore {
    /// Hold a `BYE` until the `NOTIFY` on `branch` is answered.
    pub fn insert(&self, branch: &str, deferred: DeferredReferrerBye) {
        self.entries.insert(branch.to_string(), deferred);
    }

    /// Release the `BYE` waiting on this branch, if any. Called from the
    /// response path for every inbound response, so it must stay cheap when
    /// nothing is in flight — which is the steady state.
    pub fn take(&self, branch: &str) -> Option<DeferredReferrerBye> {
        if self.entries.is_empty() {
            return None;
        }
        self.entries.remove(branch).map(|(_, deferred)| deferred)
    }

    /// The `BYE` this response releases, if it is the one the parked `BYE` was
    /// waiting for.
    ///
    /// Any final response releases it, not just a `2xx`: a `481` means the
    /// referrer has already dropped the dialog, so the `BYE` is moot but
    /// harmless, and every other failure still ends the `NOTIFY` transaction
    /// and with it any reason to keep waiting. A provisional does not — the
    /// transaction is still running and the referrer has not read the sipfrag
    /// yet.
    pub fn take_for_response(
        &self,
        message: &SipMessage,
        status_code: u16,
    ) -> Option<DeferredReferrerBye> {
        if status_code < 200 {
            return None;
        }
        self.take(top_via_branch(message)?)
    }

    /// Drain every `BYE` whose referrer never answered its `NOTIFY`.
    pub fn take_expired(&self, now: std::time::Instant) -> Vec<DeferredReferrerBye> {
        if self.entries.is_empty() {
            return Vec::new();
        }
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| entry.value().deadline <= now)
            .map(|entry| entry.key().clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|key| self.entries.remove(&key).map(|(_, deferred)| deferred))
            .collect()
    }

    /// The number of `BYE`s in flight (leak-test accessor).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// How long a deferred referrer `BYE` waits for its `NOTIFY` to be answered.
///
/// RFC 3261 §17.1.2.2 Timer F (`64*T1`) is the bound on the `NOTIFY`'s own
/// non-INVITE client transaction, so a referrer that has not answered by then
/// is never going to: releasing the `BYE` at exactly that point means the leg
/// is torn down no later than it would have been, and the wait costs nothing
/// against a referrer that answers — which a live one does in milliseconds.
pub const DEFERRED_REFERRER_BYE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_millis(64 * 500);

/// Send a `BYE` that was held back for its terminating `NOTIFY`.
pub fn send_deferred_referrer_bye(deferred: DeferredReferrerBye, state: &DispatcherState) {
    let DeferredReferrerBye {
        message,
        transport,
        destination,
        connection_id,
        local_addr,
        call_id,
        ..
    } = deferred;
    debug!(
        call_id = %call_id,
        "B2BUA REFER (terminate): terminating NOTIFY settled — releasing the referrer BYE"
    );
    send_message_from(
        message,
        transport,
        destination,
        connection_id,
        local_addr,
        state,
    );
}

/// Release the referrer `BYE` waiting on this response's branch, if there is
/// one — see [`DeferredReferrerByeStore::take_for_response`] for which
/// responses qualify. Driven from [`handle_response`] for every inbound
/// response.
pub fn release_deferred_referrer_bye(
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    if let Some(deferred) = state
        .deferred_referrer_bye
        .take_for_response(message, status_code)
    {
        send_deferred_referrer_bye(deferred, state);
    }
}

/// Release every referrer `BYE` whose `NOTIFY` was never answered. Driven from
/// the 500 ms maintenance tick.
pub fn check_deferred_referrer_byes(state: &DispatcherState) {
    for deferred in state
        .deferred_referrer_bye
        .take_expired(std::time::Instant::now())
    {
        warn!(
            call_id = %deferred.call_id,
            "B2BUA REFER (terminate): referrer never answered the terminating NOTIFY — sending the BYE anyway"
        );
        send_deferred_referrer_bye(deferred, state);
    }
}

/// Send the final SIP response to an inbound REFER on the flow it arrived on.
///
/// The single builder every "answer the REFER now" path funnels through — the
/// no-`@b2bua.on_refer`-handler and script-reject arms of [`handle_b2bua_refer`],
/// the control-plane `reject_refer` verb, and the decision-deadline 603 default.
/// RFC 3515 §2.4.2: a REFER is always answered, never silently dropped.
pub fn b2bua_refer_send_final(
    inbound: &InboundMessage,
    message: &SipMessage,
    code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    let response = build_response(message, code, reason, state.server_header.as_deref(), &[]);
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// The window a controlled call's inbound REFER waits for an `accept_refer` /
/// `reject_refer` decision before the sweep applies the 603 default.
///
/// Reuses the control app's handoff-deadline knob (the same "how long to wait for
/// the controller to act" budget), flooring a disabled (`0`) value at 30 s so the
/// REFER is always answered inside the referrer's transaction (RFC 3261 Timer F =
/// 64·T1 ≈ 32 s) — a REFER left pending forever would strand the referrer.
pub fn refer_decision_deadline(bus: &crate::control::ControlBus) -> std::time::Duration {
    match bus.handoff_deadline_ms() {
        0 => std::time::Duration::from_secs(30),
        ms => std::time::Duration::from_millis(ms),
    }
}

/// Handle an in-dialog REFER (RFC 3515) belonging to a tracked B2BUA call.
///
/// This is the intercept that stops the REFER loop: without it, an in-dialog
/// REFER whose Request-URI names siphon is proxy-relayed by R-URI back at
/// siphon's advertised address and ping-pongs against the trunk until
/// Max-Forwards drains. Here siphon owns the transfer instead.
///
/// Flow: resolve the dialog leg the REFER arrived on (by dialog identity, never
/// source socket — Teams reconnects per transaction over TLS), parse Refer-To,
/// then split on ownership:
///   - **Controlled call** (handed to an external control app): hold the REFER
///     un-answered, emit a `TransferRequested` event to the owning connection,
///     and arm the decision deadline. The app decides via `accept_refer` /
///     `reject_refer`; a missed deadline applies the 603 default. The in-process
///     `@b2bua.on_refer` path does NOT run.
///   - **Uncontrolled call**: fire `@b2bua.on_refer(call)`, then act on the
///     deferred action:
///     - no `@b2bua.on_refer` handler registered → local `603 Decline` (siphon
///       *does* implement REFER, so `501 Not Implemented` would be untruthful),
///     - `reject_refer(code, reason)` → that final response,
///     - `accept_refer(...)` → run the transfer in the resolved mode
///       (siphon-terminated by default, transparent forward when selected).
///
/// Every path answers the REFER — never a silent drop, never a proxy relay.
pub fn handle_b2bua_refer(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            // Raced a concurrent teardown. 481 like the no-dialog-leg arm below,
            // never a silent drop (RFC 3515 §2.4.2 defers to RFC 3261 §12.2.2).
            warn!(sip_call_id = %sip_call_id, "B2BUA REFER: no matching call — 481");
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
    };

    // In-dialog direction by dialog identity (RFC 3261 §12), never source
    // socket — a Call-ID matching no live dialog leg is answered 481.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA REFER: Call-ID matches no dialog leg — 481");
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
    };

    // Parse Refer-To (+ any embedded Replaces). A missing/malformed Refer-To is
    // a client error (RFC 3515 §2.4.1) — 400, don't relay.
    let refer_to = match message
        .headers
        .get("Refer-To")
        .or_else(|| message.headers.get("r"))
        .map(|value| crate::sip::headers::refer::parse_refer_to(value))
    {
        Some(Ok(refer_to)) => refer_to,
        _ => {
            warn!(call_id = %call_id, "B2BUA REFER: missing or malformed Refer-To — 400");
            b2bua_refer_send_final(&inbound, &message, 400, "Bad Request", state);
            return;
        }
    };

    // Control-plane interception (RFC 3515 on a *controlled* call): when the call
    // has been handed to an external control app, that app owns the transfer
    // decision — NOT the in-process `@b2bua.on_refer` path. Hold the REFER
    // un-answered, surface it as a `TransferRequested` event on the owning
    // connection, and arm the decision deadline (603 Decline default on timeout,
    // matching the no-handler default below). An UNCONTROLLED call falls through
    // to the Python path unchanged — the control interception is only for
    // controlled calls.
    if let Some(bus) = crate::control::ControlBus::global() {
        if let Some(channel_id) = bus.channel_id_for_sip_call_id(&sip_call_id) {
            let emitted = state.pending_inbound_refer.insert(
                &sip_call_id,
                PendingInboundRefer {
                    inbound,
                    message,
                    refer_to: refer_to.clone(),
                    from_a_leg,
                    deadline: std::time::Instant::now() + refer_decision_deadline(&bus),
                },
            );
            if emitted {
                bus.forward_transfer_requested(
                    &channel_id,
                    &sip_call_id,
                    &refer_to,
                    from_tag.as_deref(),
                );
                info!(
                    call_id = %call_id,
                    %sip_call_id,
                    channel = %channel_id,
                    target = %refer_to.uri,
                    "B2BUA REFER: controlled call — TransferRequested, awaiting accept/reject"
                );
            } else {
                // A REFER retransmit (non-INVITE over UDP retransmits to Timer F):
                // a decision is already pending, so absorb it rather than emit a
                // duplicate event or reset the deadline.
                debug!(call_id = %call_id, %sip_call_id, "B2BUA REFER: retransmit for a pending controlled transfer — absorbed");
            }
            return;
        }
    }

    // Fire @b2bua.on_refer(call). No handler → local 603 Decline (loop killer for
    // scripts that don't handle REFER at all).
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaRefer);
    if handlers.is_empty() {
        debug!(call_id = %call_id, "B2BUA REFER: no @b2bua.on_refer handler — 603 Decline");
        b2bua_refer_send_final(&inbound, &message, 603, "Decline", state);
        return;
    }

    let mut py_call = PyCall::new(
        call_id.clone(),
        Arc::new(std::sync::Mutex::new(message.clone())),
        inbound.remote_addr.ip().to_string(),
        format!("{}", inbound.transport).to_lowercase(),
    )
    .with_flow(py_flow_from_inbound(&inbound));
    py_call.set_refer_to(refer_to.uri.clone(), refer_to.replaces.clone());
    // Which side referred decides which side survives, and therefore what the
    // surviving pair's media profile has to be (see `accept_refer(profile=…)`).
    py_call.set_refer_from_a_leg(from_a_leg);

    let (action, ignored_overrides) = Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for on_refer: {error}");
                return (
                    CallAction::RejectRefer {
                        code: 500,
                        reason: "Script Error".to_string(),
                    },
                    false,
                );
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async B2BUA on_refer", &error);
                            return (
                                CallAction::RejectRefer {
                                    code: 500,
                                    reason: "Script Error".to_string(),
                                },
                                false,
                            );
                        }
                    }
                }
                Err(error) => {
                    record_script_error("B2BUA on_refer", &error);
                    return (
                        CallAction::RejectRefer {
                            code: 500,
                            reason: "Script Error".to_string(),
                        },
                        false,
                    );
                }
            }
        }
        let borrowed = call_obj.borrow(python);
        // The B-leg shaping setters belong to the `on_invite` → `dial()` path:
        // they are read off the PyCall built there, and this one is a throwaway
        // whose only surviving output is the action below. Silently doing
        // nothing is the expensive failure — the script looks like it steered
        // the transferred leg and the wire says otherwise — so say so.
        //
        // Message mutations (`set_header`, `rewrite_identities`) are the same
        // shape and worse to detect: they land on this call's own clone of the
        // REFER, while the leg is dialled from a clone of the *stored* A-leg
        // INVITE. `accept_refer`'s own arguments are what reach the new leg.
        let ignored_overrides = borrowed.contact_override().is_some()
            || borrowed.contact_user_override().is_some()
            || borrowed.from_host_override().is_some()
            || borrowed.to_host_override().is_some();
        (borrowed.action().clone(), ignored_overrides)
    });

    if ignored_overrides {
        warn!(
            call_id = %call_id,
            "B2BUA on_refer: set_contact_uri / set_contact_user / set_from_host / set_to_host have no effect in this handler — they shape a leg dialled by call.dial(), and a transfer leg is dialled from the stored A-leg INVITE. Use accept_refer(target=…, next_hop=…, number_policy=…) instead"
        );
    }

    match action {
        CallAction::RejectRefer { code, reason } => {
            debug!(call_id = %call_id, code, "B2BUA REFER: script rejected");
            b2bua_refer_send_final(&inbound, &message, code, &reason, state);
        }
        CallAction::AcceptRefer {
            target,
            next_hop,
            mode,
            profile,
            number_shape,
        } => {
            let mode = mode.unwrap_or(state.default_refer_mode);
            let target_uri = target.unwrap_or_else(|| refer_to.uri.clone());
            b2bua_refer_accept(
                inbound,
                message,
                &call_id,
                from_a_leg,
                &target_uri,
                next_hop.as_deref(),
                refer_to.replaces.clone(),
                mode,
                profile.as_deref(),
                number_shape.as_ref(),
                state,
            );
        }
        // Any other (or no) action from the handler: the script neither accepted
        // nor rejected. Decline locally rather than leave the referrer hanging or
        // fall through to a relay (RFC 3515 — the recipient must answer).
        other => {
            debug!(call_id = %call_id, ?other, "B2BUA REFER: handler took no accept/reject action — 603 Decline");
            b2bua_refer_send_final(&inbound, &message, 603, "Decline", state);
        }
    }
}
