//! Tearing a B2BUA call down from the response path: the ACK and BYE a
//! failure owes each leg, and the zombie-leg sweeps behind a cancelled or
//! superseded B-leg.

use crate::dispatcher::*;

/// Invoke `@b2bua.on_route_failure` for one failed carrier of a sequential
/// failover sequence.
///
/// Fires once per failed attempt, including the last one before the A-leg is
/// given up on, and for every non-2xx a carrier returns — a definitive `486`
/// as much as a `503`. That is deliberate: the same set is what
/// `call.route_attempts` records, so the hook and the attempt list can never
/// disagree, and the script filters on `code` for whatever it counts as a
/// carrier's fault.
///
/// Purely a notification. The failover decision has already been made by the
/// time this runs, and unlike `@b2bua.on_answer` a raise here does not change
/// the call's outcome — it is logged and the sequence carries on.
pub fn b2bua_dispatch_route_failure(
    call_id: &str,
    route: &crate::lcr::Route,
    status_code: u16,
    a_leg: &crate::b2bua::actor::Leg,
    a_leg_invite: Option<&Arc<std::sync::Mutex<SipMessage>>>,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaRouteFailure);
    if handlers.is_empty() {
        return;
    }
    let Some(invite_arc) = a_leg_invite else {
        warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_route_failure");
        return;
    };

    let mut py_call = PyCall::new(
        call_id.to_string(),
        Arc::clone(invite_arc),
        a_leg.transport.remote_addr.ip().to_string(),
        format!("{}", a_leg.transport.transport).to_lowercase(),
    )
    .with_flow(py_flow_from_leg(&a_leg.transport));
    py_call.set_route_attempts(state.call_actors.route_attempts(call_id));
    let py_route = crate::script::api::lcr::PyRoute::from_route(route.clone());

    Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for on_route_failure: {error}");
                return;
            }
        };
        let route_obj = match Py::new(python, py_route) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRoute for on_route_failure: {error}");
                return;
            }
        };
        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python), route_obj.bind(python), status_code)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async B2BUA on_route_failure", &error);
                        }
                    }
                }
                Err(error) => record_script_error("B2BUA on_route_failure", &error),
            }
        }
    });
}

/// Schedule cleanup of zombie re-INVITE entries after Timer H (32 seconds).
///
/// Called after `remove_call()` which may have moved `reinvite_done:` or
/// `reinvite:` B-leg entries to the zombie map. After 32 seconds the remote
/// UAS stops retransmitting per RFC 3261 §17.2.1, so the entries are no longer needed.
pub fn schedule_zombie_reinvite_cleanup(call_actors: &crate::b2bua::actor::CallActorStore) {
    if call_actors.zombie_reinvites.is_empty() {
        return;
    }
    let zombie_map = call_actors.zombie_reinvites.clone();
    let zombie_keys: Vec<String> = zombie_map.iter().map(|entry| entry.key().clone()).collect();
    if !zombie_keys.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(32)).await;
            for key in zombie_keys {
                zombie_map.remove(&key);
            }
        });
    }
}

/// Expire post-CANCEL glare entries after 32 s (Timer H / 64·T1).
///
/// Unlike [`schedule_zombie_reinvite_cleanup`], this removes from the *shared*
/// store via the `Arc` rather than from a `DashMap` clone, so entries that
/// never see a racing 2xx (the CANCEL won the race) are still reaped.
pub fn schedule_zombie_cancelled_cleanup(call_actors: Arc<crate::b2bua::actor::CallActorStore>) {
    let keys: Vec<String> = call_actors
        .zombie_cancelled
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    schedule_zombie_cancelled_expiry(call_actors, keys);
}

/// Expire the named post-CANCEL entries after 32 s (Timer H / 64·T1).
///
/// For a caller that knows which entries it just created. A fork cancels its
/// losing branches on every answered call, and re-arming the expiry of every
/// entry in the map each time, as [`schedule_zombie_cancelled_cleanup`] does,
/// would copy all of them per call.
pub fn schedule_zombie_cancelled_expiry(
    call_actors: Arc<crate::b2bua::actor::CallActorStore>,
    keys: Vec<String>,
) {
    if keys.is_empty() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(32)).await;
        for key in keys {
            call_actors.zombie_cancelled.remove(&key);
        }
    });
}

/// CANCEL the fork branches a settlement ended (RFC 3261 §9.1): those still
/// ringing when another branch answered, or when one declined with a 6xx.
///
/// The store has already kept each one answerable, so the 487 its CANCEL draws
/// gets an ACK and a 2xx that crosses the CANCEL an ACK and a BYE. This puts the
/// CANCELs on the wire and arms the expiry of what was kept.
pub fn cancel_settled_branches(legs: &[crate::b2bua::actor::Leg], state: &DispatcherState) {
    if legs.is_empty() {
        return;
    }
    let mut kept = Vec::with_capacity(legs.len());
    for leg in legs {
        // Stop retransmitting the INVITE, as the ring-timeout CANCEL does: an
        // INVITE delivered after its own CANCEL would start the branch ringing
        // again, with nothing left to cancel it.
        state.b2bua_retransmits.disarm_branch(&leg.branch);
        let Some(invite_arc) = leg.b_leg_invite.as_ref() else {
            continue;
        };
        // The store kept exactly the legs with a stashed INVITE, under this key.
        kept.push(leg.branch.clone());
        let cancel = match invite_arc.lock() {
            Ok(invite) => build_cancel_from_invite(&invite),
            Err(_) => None,
        };
        match cancel {
            Some(cancel) => send_b2bua_to_bleg(
                cancel,
                leg.transport.transport,
                leg.transport.remote_addr,
                leg.transport.local_addr,
                state,
            ),
            None => warn!(
                branch = %leg.branch,
                "B2BUA: cannot build the CANCEL for a fork branch from its stored INVITE — it rings on until it answers or times out"
            ),
        }
    }
    schedule_zombie_cancelled_expiry(state.call_actors.clone(), kept);
}

/// Build an ACK for a 2xx INVITE response on a B2BUA B-leg (RFC 3261 §13.2.2.4).
///
/// The ACK for a 2xx is its own transaction: a fresh Via branch, R-URI set to
/// the response's Contact (the remote target), and the INVITE's CSeq number
/// with method ACK. From / To / Call-ID are echoed from the 2xx (its To already
/// carries the remote tag).
///
/// Pure w.r.t. dispatcher state — the caller supplies the local `via_host` /
/// `via_port` (from `DispatcherState::via_host`/`via_port`) so this is directly
/// unit-testable.
pub fn build_b2bua_ack_for_2xx(
    response: &SipMessage,
    transport: Transport,
    via_host: &str,
    via_port: u16,
) -> Option<SipMessage> {
    let request_uri = response
        .headers
        .get("Contact")
        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
        .and_then(|u| parse_uri_standalone(&u).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));
    let transport_str = format!("{}", transport).to_uppercase();
    let cseq_num = response
        .headers
        .cseq()
        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
        .unwrap_or_else(|| "1".to_string());
    let from = response.headers.from().cloned().unwrap_or_default();
    let to = response.headers.to().cloned().unwrap_or_default();
    let call_id = response
        .headers
        .call_id()
        .map(|s| s.to_string())
        .unwrap_or_default();
    // RFC 3261 §12.1.2: this 2xx establishes the dialog, so its Record-Route
    // reversed IS the UAC's route set — and §12.2.1.1 has every request in the
    // dialog, the ACK included, carry it. Taken from the response rather than the
    // leg because both callers reach here with a leg that predates the 2xx.
    let route_set = uac_route_set_from_record_routes(
        &response
            .headers
            .get_all("Record-Route")
            .cloned()
            .unwrap_or_default(),
    );
    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri)
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            via_host,
            via_port,
            TransactionKey::generate_branch(),
        ))
        .from(from.to_string())
        .to(to.to_string())
        .call_id(call_id)
        .cseq(format!("{} ACK", cseq_num))
        .header("Max-Forwards", "70".to_string());
    for route in &route_set {
        builder = builder.header("Route", route.clone());
    }
    match builder.content_length(0).build() {
        Ok(ack) => Some(ack),
        Err(error) => {
            warn!("B2BUA: failed to build ACK for raced 2xx: {error}");
            None
        }
    }
}

/// ACK a B-leg 2xx and, when asked, BYE the dialog that 2xx established.
///
/// RFC 3261 §13.2.2.4 makes the ACK the UAC's confirmation of the dialog, and §15
/// makes the BYE the only way to release it once confirmed — so a 2xx siphon does
/// not intend to keep needs both, in that order, or the callee retransmits its 200
/// and holds the session open with nothing ever releasing it.
///
/// Every piece of dialog state is taken from `response`, not from `leg`: both
/// callers hold a leg captured *before* the answer, so the remote tag, the remote
/// Contact and the route set (§12.1.2) exist only on the response, and the BYE's
/// CSeq — which MUST exceed the INVITE's — has to be derived from the 2xx too.
///
/// Returns whether the BYE went out.
pub fn b2bua_ack_and_bye_answered_leg(
    mut leg: crate::b2bua::actor::Leg,
    response: &SipMessage,
    send_bye: bool,
    state: &DispatcherState,
) -> bool {
    let transport = leg.transport.transport;
    let destination = leg.transport.remote_addr;
    // The socket this leg was dialled from (flow-pinned legs) — the ACK and BYE
    // below have to leave from it and advertise it, exactly as the INVITE did.
    let local_addr = leg.transport.local_addr;
    let (via_host, via_port) = b_leg_sent_by(local_addr, state, &transport);

    // The 2xx established a dialog and with it a route set (RFC 3261 §12.1.2) — the
    // ACK below carries it, and the BYE needs it on the leg, which predates this
    // response and cannot have picked it up.
    let route_set = uac_route_set_from_record_routes(
        &response
            .headers
            .get_all("Record-Route")
            .cloned()
            .unwrap_or_default(),
    );
    let (destination, transport) =
        resolve_in_dialog_destination(&route_set, state, destination, transport);

    // ACK on every call — a lost ACK leaves the callee retransmitting.
    let ack = build_b2bua_ack_for_2xx(response, transport, &via_host, via_port);

    if !send_bye {
        if let Some(ack) = ack {
            send_b2bua_to_bleg(ack, transport, destination, local_addr, state);
        }
        return false;
    }

    // Fill the remote dialog identity from the 2xx (unknown when the leg was captured).
    if let Some(tag) = crate::b2bua::actor::extract_to_tag(response) {
        leg.dialog.remote_tag = Some(tag);
    }
    if let Some(contact) = response.headers.get("Contact") {
        leg.dialog.remote_contact = Some(crate::b2bua::actor::extract_contact_uri(contact));
    }
    leg.dialog.route_set = route_set;
    // The BYE CSeq must exceed the INVITE's; derive it from the 2xx's CSeq.
    let invite_cseq = response
        .headers
        .cseq()
        .and_then(|c| c.split_whitespace().next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(leg.dialog.local_cseq);
    leg.dialog.local_cseq = invite_cseq.saturating_add(1);

    let bye = build_b2bua_bye(&leg, state);
    let bye_sent = bye.is_some();
    // The ACK confirms the dialog the BYE ends, so the two leave as one ordered
    // unit: sent separately on UDP they can reach the callee BYE first.
    let messages: Vec<SipMessage> = ack.into_iter().chain(bye).collect();
    send_b2bua_sequence_to_bleg(messages, transport, destination, local_addr, state);
    bye_sent
}

/// Handle a 2xx that raced an outbound CANCEL (RFC 3261 §9.1 glare).
///
/// The callee answered the B-leg INVITE before our CANCEL landed, so the 2xx
/// established a dialog even though the call is gone. ACK it (§13.2.2.4) to stop
/// the 200 OK retransmissions, then — on the first 2xx only — BYE it (§15) to
/// release the session. All dialog state comes from the captured leg plus this
/// response (the remote tag / Contact were unknown when the INVITE was CANCELled).
pub fn handle_zombie_cancelled_2xx(
    leg: crate::b2bua::actor::Leg,
    first_2xx: bool,
    response: &SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = leg.dialog.call_id.clone();
    // A retransmit re-ACKs only — the BYE went out on the first 2xx.
    if b2bua_ack_and_bye_answered_leg(leg, response, first_2xx, state) {
        debug!(
            sip_call_id = %sip_call_id,
            "B2BUA: ACK+BYE for a 2xx that raced our CANCEL (RFC 3261 §9.1 glare)"
        );
    }
}

/// What `@b2bua.on_answer` does with the deferred action a handler left behind.
#[derive(Debug, PartialEq)]
pub enum AnswerAction {
    /// Nothing deferred — carry on and connect the call.
    Connect,
    /// `call.refer()` — an outbound REFER to the caller, held until its 2xx is on
    /// the wire (RFC 3261 §13.2.2.4: the UAC confirms the dialog on the 2xx, so a
    /// REFER sent ahead of it is answered 481).
    DeferRefer(crate::sip::headers::refer::ReferTo),
    /// `call.terminate()` — fail the call instead of connecting it.
    Terminate,
    /// Not actionable once the B-leg has answered.
    Inapplicable(CallAction),
}

/// Classify what a `@b2bua.on_answer` handler asked for.
///
/// `Terminate` is honoured from this handler, which it was not before: the
/// comment that replaced it held that deferred actions cannot apply because "the
/// call is already answered", and that is true of the B-leg and false of the A-leg
/// — the caller's 2xx is only sent later in `handle_b2bua_response`. So a script
/// that discovers in `on_answer` that the call cannot work (no media path, a
/// policy check that needed the answer) can still stop it, and the action that
/// says so is no longer dropped on the floor.
pub fn classify_answer_action(action: Option<CallAction>) -> AnswerAction {
    match action {
        Some(CallAction::SendRefer { refer_to }) => AnswerAction::DeferRefer(refer_to),
        Some(CallAction::Terminate) => AnswerAction::Terminate,
        None | Some(CallAction::None) => AnswerAction::Connect,
        Some(other) => AnswerAction::Inapplicable(other),
    }
}

/// Fail a call whose B-leg has answered but whose `@b2bua.on_answer` did not
/// survive — the handler raised, or it asked for the call to end.
///
/// The B-leg answered, so its dialog is real and has to be released properly
/// (ACK per RFC 3261 §13.2.2.4, then BYE per §15). The A-leg has NOT been
/// answered — its 2xx is only sent further down `handle_b2bua_response` — so the
/// caller is still in an INVITE transaction and takes a final failure response
/// instead, which is the whole point: no dialog is created toward the caller and
/// nothing downstream treats the call as connected.
///
/// This mirrors the ordinary B-leg-failure teardown at the end of that function
/// (script `on_failure`, CDR, the media safety-net, the Ro release), because the
/// call has failed in exactly the sense those steps exist for. The one asymmetry
/// worth knowing when writing a handler: `@b2bua.on_failure` fires here for a
/// call whose B-leg *did* answer and has already been BYEd.
#[allow(clippy::too_many_arguments)]
pub fn b2bua_fail_after_answer(
    call_id: &str,
    cause: &str,
    a_leg: &crate::b2bua::actor::Leg,
    a_leg_invite: Option<&Arc<std::sync::Mutex<SipMessage>>>,
    a_leg_local_addr: Option<SocketAddr>,
    b_leg_index: Option<usize>,
    response: &SipMessage,
    state: &DispatcherState,
) {
    const STATUS: u16 = 500;
    const REASON: &str = "Server Internal Error";

    error!(
        call_id = %call_id,
        cause = %cause,
        "B2BUA: failing a call whose B-leg answered — the caller gets {STATUS} and the answered B-leg is released"
    );

    // The caller's final response. Built from the stored A-leg INVITE, so it
    // already carries the A-leg's own Via / From / To / Call-ID / CSeq and needs
    // none of the B-leg sanitisation the forwarded-error path does. The To-tag is
    // the A-leg dialog's own (RFC 3261 §8.2.6.2 — a UAS tags every response bar
    // 100), the same tag its 2xx would have carried.
    match a_leg_invite {
        Some(invite_arc) => match invite_arc.lock() {
            Ok(invite) => {
                let mut failure =
                    build_response(&invite, STATUS, REASON, state.server_header.as_deref(), &[]);
                drop(invite);
                if let Some(to) = failure.headers.to().cloned() {
                    failure.headers.set(
                        "To",
                        crate::b2bua::actor::ensure_tag(&to, Some(&a_leg.dialog.local_tag)),
                    );
                }
                send_message_from(
                    failure,
                    a_leg.transport.transport,
                    a_leg.transport.remote_addr,
                    a_leg.transport.connection_id,
                    a_leg_local_addr,
                    state,
                );
            }
            Err(error) => error!(
                call_id = %call_id,
                "B2BUA: A-leg INVITE lock poisoned while failing an answered call: {error}"
            ),
        },
        None => warn!(
            call_id = %call_id,
            "B2BUA: no stored A-leg INVITE — the caller cannot be sent a failure response"
        ),
    }

    // Release the answered B-leg dialog. The leg is re-read here rather than
    // carried in: `handle_b2bua_response` drops its actor reference before running
    // Python, and the handler that just failed may itself have touched the call.
    let b_leg = b_leg_index.and_then(|index| {
        state
            .call_actors
            .get_call(call_id)
            .and_then(|call| call.b_legs.get(index).cloned())
    });
    match b_leg {
        Some(leg) => {
            b2bua_ack_and_bye_answered_leg(leg, response, true, state);
        }
        None => warn!(
            call_id = %call_id,
            "B2BUA: answered B-leg is gone — its dialog cannot be released and may linger"
        ),
    }

    // @b2bua.on_failure — the script's per-call teardown hook. Fired before the
    // actor is removed so a handler can still read the call.
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
    if !handlers.is_empty() {
        match a_leg_invite {
            Some(invite_arc) => {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
                    format!("{}", a_leg.transport.transport).to_lowercase(),
                )
                .with_flow(py_flow_from_leg(&a_leg.transport));

                Python::attach(|python| {
                    let call_obj = match Py::new(python, py_call) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyCall for on_failure: {error}");
                            return;
                        }
                    };
                    for handler in &handlers {
                        let callable = handler.callable.bind(python);
                        match callable.call1((call_obj.bind(python), STATUS, REASON)) {
                            Ok(ret) => {
                                if handler.is_async {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        record_script_error("async B2BUA on_failure", &error);
                                    }
                                }
                            }
                            Err(error) => record_script_error("B2BUA on_failure", &error),
                        }
                    }
                });
            }
            None => warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_failure"),
        }
    }

    // CDR: the answer stamp was already taken when the 2xx arrived, so finalise as
    // a failure to correct it — the call never connected.
    cdr_finalize_b2bua_fail(state, call_id, STATUS);

    // Safety-net media release. `@b2bua.on_bye` never runs for this call (no BYE
    // arrives from a caller that was never answered), so without this the media
    // session outlives the call it belonged to.
    let a_sip_call_id = a_leg.dialog.call_id.clone();
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&a_sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(session.rtpengine_id(), &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "media delete after a failed answer: call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "media delete after a failed answer failed: {error}");
                    }
                }
            });
        }
    }

    // Release any Ro reservation `call.ro_authorize()` made before the B-leg was
    // dialed. The answer-time CCR-UPDATE is deliberately never sent on this path,
    // so the OCS sees a reservation that opened and closed without a chargeable
    // clock ever starting.
    spawn_ro_b2bua_stop(
        state,
        call_id,
        crate::diameter::rf::sip_status_to_cause_code(STATUS),
    );

    state.call_actors.remove_call(call_id);
    state.call_event_receivers.remove(call_id);
}

/// ACK the final non-2xx that a CANCELled INVITE draws — in practice the
/// `487 Request Terminated` of RFC 3261 §9.1, the ordinary end of every
/// CANCELled leg.
///
/// RFC 3261 §17.1.1.3: an INVITE client transaction MUST generate an ACK for
/// any final non-2xx response, on the INVITE's *own* branch and carrying the
/// response's To-tag, so the peer's server transaction can match it (§17.2.3).
/// Everything the ACK needs beyond the response itself — the branch, the
/// INVITE's Request-URI, the socket to leave from and advertise — comes from
/// the leg captured at CANCEL time, because the call itself is already gone.
///
/// Unlike the 2xx glare path there is no BYE and no first-response guard: a
/// non-2xx establishes no dialog to release, and §17.1.1.3 has the client
/// transaction re-pass the ACK to the transport on every retransmission of the
/// response while it sits in `Completed`.
pub fn handle_zombie_cancelled_non2xx(
    leg: &crate::b2bua::actor::Leg,
    invite_ruri: Option<&str>,
    response: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    let transport = leg.transport.transport;
    let destination = leg.transport.remote_addr;
    // The socket this leg was dialled from (flow-pinned legs) — the ACK has to
    // leave from it and advertise it, exactly as the INVITE did, or the peer's
    // server transaction will not match it on sent-by (§17.2.3).
    let local_addr = leg.transport.local_addr;
    let (via_host, via_port) = b_leg_sent_by(local_addr, state, &transport);

    let Some(ack) = build_cancelled_leg_ack(leg, invite_ruri, response, &via_host, via_port) else {
        // No Request-URI means the stashed INVITE could not be read back. Say
        // so rather than putting a placeholder R-URI on the wire — an ACK the
        // peer cannot match is no better than none, and this must be
        // diagnosable when the peer keeps retransmitting.
        error!(
            sip_call_id = %leg.dialog.call_id,
            status = status_code,
            "B2BUA: cannot ACK a CANCELled leg's final response — the CANCELled \
             INVITE's Request-URI was not captured (RFC 3261 §17.1.1.3)"
        );
        return;
    };

    send_b2bua_to_bleg(ack, transport, destination, local_addr, state);
    debug!(
        sip_call_id = %leg.dialog.call_id,
        status = status_code,
        branch = %leg.branch,
        "B2BUA: ACK for the final response to a CANCELled leg (RFC 3261 §17.1.1.3)"
    );
}

/// Build the ACK a CANCELled leg's final non-2xx is owed (RFC 3261 §17.1.1.3).
///
/// Pure half of [`handle_zombie_cancelled_non2xx`], split out so the invariants
/// that actually matter are unit-testable without a `DispatcherState` fixture:
/// the ACK rides the INVITE's **own** branch and Request-URI, and carries the
/// **response's** To-tag — the three fields the peer's server transaction
/// matches on (§17.2.3). `None` when the Request-URI was never captured.
pub fn build_cancelled_leg_ack(
    leg: &crate::b2bua::actor::Leg,
    invite_ruri: Option<&str>,
    response: &SipMessage,
    via_host: &str,
    via_port: u16,
) -> Option<SipMessage> {
    let target_uri = invite_ruri?;
    Some(build_b2bua_ack_for_non2xx(
        response,
        &leg.branch,
        Some(target_uri),
        leg.transport.transport,
        via_host,
        via_port,
    ))
}
