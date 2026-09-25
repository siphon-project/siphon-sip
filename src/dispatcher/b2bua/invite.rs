//! The inbound INVITE that starts a B2BUA call.
//!
//! Guards, Replaces matching, call creation, the script handler, then whichever
//! action it asked for: dial, fork, route, handover, reject.

use crate::dispatcher::*;

// ---------------------------------------------------------------------------
// B2BUA handlers
// ---------------------------------------------------------------------------

/// Everything a B2BUA handler (`@b2bua.on_invite`, `@b2bua.on_failure`) left on
/// the `Call` for the framework to act on, carried back out across the
/// `Python::attach` boundary in one value.
///
/// A named struct rather than the positional tuple this was: the handler can
/// set a dozen unrelated things, each early-return path had to spell every one
/// of them out as a bare `None`/`false` in the right order, and adding a
/// thirteenth meant editing three lists of anonymous placeholders correctly.
#[derive(Default)]
pub struct CallHandlerOutcome {
    pub action: CallAction,
    pub timer_override: Option<crate::script::api::call::SessionTimerOverride>,
    /// Outbound digest credentials for the B-leg 401/407 retry.
    pub credentials: Option<Arc<crate::auth::StoredCredentials>>,
    pub li_record: bool,
    pub preserve_call_id: bool,
    pub policy_input: Option<crate::script::api::call::HeaderPolicyInput>,
    pub from_host_override: Option<String>,
    pub to_host_override: Option<String>,
    pub contact_user_override: Option<String>,
    pub contact_override: Option<String>,
    pub auth_passthrough: bool,
    pub auth_user: Option<String>,
    /// `call.dial(max_duration=…)` / `call.set_max_duration()` — the ceiling on
    /// how long the call may stay answered. `None` inherits
    /// `b2bua.max_call_duration_secs`.
    pub max_duration_secs: Option<u32>,
    /// Headers the script set or removed on the A-leg INVITE (`set_header`,
    /// `remove_header`, `remove_headers_matching`). Where the B-leg builder
    /// would put siphon's own value (`Supported`, `Allow`), it keeps the
    /// script's instead.
    pub script_shaped_headers: Vec<String>,
}

impl CallHandlerOutcome {
    /// The outcome for a handler that raised: reject the call `500`, and take
    /// nothing else the script may have set on its way to failing.
    pub fn script_error() -> Self {
        Self {
            action: CallAction::Reject {
                code: 500,
                reason: "Script Error".to_string(),
            },
            ..Self::default()
        }
    }

    /// What the handlers left on `call`, read once they have all returned.
    pub fn from_call(call: &PyCall) -> Self {
        Self {
            action: call.action().clone(),
            timer_override: call.session_timer_override().cloned(),
            // A script hands over a password; the stored-ha1 form only ever
            // comes from a gateway or registrant credential store.
            credentials: call.outbound_credentials().map(|(user, password)| {
                Arc::new(crate::auth::StoredCredentials {
                    username: user.to_string(),
                    secret: crate::auth::StoredSecret::Password(password.to_string()),
                })
            }),
            li_record: call.li_record(),
            preserve_call_id: call.preserve_call_id(),
            policy_input: call.header_policy_input().cloned(),
            from_host_override: call.from_host_override().map(String::from),
            to_host_override: call.to_host_override().map(String::from),
            contact_user_override: call.contact_user_override().map(String::from),
            contact_override: call.contact_override().map(String::from),
            auth_passthrough: call.auth_passthrough(),
            auth_user: call.get_auth_user().map(String::from),
            max_duration_secs: call.max_duration_secs(),
            script_shaped_headers: call.script_shaped_headers().to_vec(),
        }
    }
}

/// Handle an INVITE in B2BUA mode.
///
/// Creates a Call object, invokes `@b2bua.on_invite`, and processes the
/// script's action (dial, fork, reject).
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_b2bua_invite: guards, call creation, script dispatch, action arms
pub fn handle_b2bua_invite(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .unwrap_or(&"unknown".to_string())
        .clone();
    let from_tag = message
        .headers
        .get("From")
        .and_then(|f| {
            f.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
        .unwrap_or_default();

    let via_branch = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|v| v.branch)
        .unwrap_or_default();

    // Snapshot the A-leg peer's reliable-provisional capability from the
    // on-wire INVITE, BEFORE the `@b2bua.on_invite` handler runs.  The script
    // may add `Supported: 100rel` to the shared INVITE to advertise reliable
    // provisionals toward the B-leg (IR.92 UEs need it to alert) — that must
    // not poison the gate that decides whether to strip `Require:100rel`/`RSeq`
    // from provisionals relayed back to this A-leg.  See CallActor.a_leg_supports_100rel.
    let a_leg_supports_100rel = crate::sip::headers::rseq::supports_100rel(&message.headers);
    let a_leg_requires_100rel = crate::sip::headers::rseq::requires_100rel(&message.headers);

    // Guard against INVITE retransmissions: if we already have a call for this
    // SIP Call-ID, this is a retransmission — absorb it silently.
    // Without this check, each UDP retransmission would create a new call and
    // spawn duplicate B-leg INVITEs.
    if state
        .call_actors
        .find_by_sip_call_id(&sip_call_id)
        .is_some()
    {
        debug!(
            call_id = %sip_call_id,
            "B2BUA: absorbing INVITE retransmission (call already exists)"
        );
        return;
    }

    // RFC 3329 §2.3.1: a request that requires the security agreement is checked
    // against the association it arrived over before anything is done with it. An
    // unprotected one, or one whose Security-Verify does not mirror that
    // association, is answered 494 here, before any call or script exists. The
    // 494 carries "the server's unmodified list": the association's recorded
    // Security-Server, or with no association the mechanisms siphon supports.
    let protected_sa = crate::ipsec::runtime::is_protected_local_port(inbound.local_addr.port())
        .then(|| {
            crate::ipsec::runtime::find_sa_for_ue(
                &inbound.remote_addr.ip(),
                inbound.remote_addr.port(),
            )
        })
        .flatten();
    let sec_agree_verified = match crate::ipsec::sec_agree::verify_sec_agree(
        &message.headers,
        protected_sa.as_ref(),
    ) {
        crate::ipsec::sec_agree::SecAgreeVerdict::NotRequired => false,
        crate::ipsec::sec_agree::SecAgreeVerdict::Verified => true,
        crate::ipsec::sec_agree::SecAgreeVerdict::Refused(refusal) => {
            info!(
                call_id = %sip_call_id,
                source = %inbound.remote_addr,
                ?refusal,
                "B2BUA: refusing INVITE with 494 — the security agreement it requires is not verified"
            );
            let mut response = build_response(
                &message,
                494,
                "Security Agreement Required",
                state.server_header.as_deref(),
                &[],
            );
            for line in crate::ipsec::sec_agree::refusal_security_server(protected_sa.as_ref()) {
                response.headers.add("Security-Server", line);
            }
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

    // RFC 3891: if the INVITE carries a `Replaces` header it must match an
    // existing dialog, otherwise we MUST reject with 481 Call/Transaction
    // Does Not Exist. Silently treating it as a fresh INVITE would defeat
    // the attended-transfer semantics (the referrer expects the old dialog
    // to go away once this INVITE succeeds).
    //
    // A match is only *recorded* here, never acted on. The takeover itself runs
    // after `@b2bua.on_invite` has admitted the request, because RFC 3891 §5
    // makes this header a call-hijack primitive for anyone who learns a dialog's
    // identifiers, and the script's `auth.require_proxy_digest()` is siphon's
    // admission control for an INVITE. Acting at parse time would take a live
    // call away on the say-so of an unauthenticated request.
    let mut pending_replaces: Option<crate::b2bua::actor::PendingReplaces> = None;
    if let Some(replaces_raw) = message.headers.get("Replaces") {
        match crate::sip::headers::refer::parse_replaces(replaces_raw) {
            Ok(replaces) => {
                match state.call_actors.find_call_by_replaces_dialog(
                    &replaces.call_id,
                    &replaces.from_tag,
                    &replaces.to_tag,
                ) {
                    Some(matched) => {
                        // RFC 3891 §3: `early-only` asks to replace a dialog that
                        // has not been answered. siphon only ever takes over a
                        // confirmed one — an early dialog has no negotiated media
                        // to hand across and no answered party to keep — so the
                        // flag is honoured by declining, which is the response
                        // the section names for this exact case.
                        let confirmed = state
                            .call_actors
                            .get_call(&matched.call_id)
                            .map(|call| call.state == CallState::Answered)
                            .unwrap_or(false);
                        if replaces.early_only && confirmed {
                            debug!(
                                call_id = %sip_call_id,
                                matched_call = %matched.call_id,
                                "B2BUA: rejecting INVITE with 486 — Replaces carries early-only but the dialog is confirmed"
                            );
                            let response = build_response(
                                &message,
                                486,
                                "Busy Here",
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
                        if !confirmed {
                            debug!(
                                call_id = %sip_call_id,
                                matched_call = %matched.call_id,
                                "B2BUA: rejecting INVITE with 486 — Replaces names a dialog that is not answered"
                            );
                            let response = build_response(
                                &message,
                                486,
                                "Busy Here",
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
                        // Off unless the operator enabled it. Taking a party
                        // out of a live call on the strength of identifiers that
                        // are handed to the transferee by design — and readable
                        // by anyone who can see unprotected signalling — is a
                        // capability, not a default (RFC 3891 §5). Declined
                        // rather than ignored: §3's answer for a dialog the UA
                        // is unwilling to replace, and it stops the INVITE
                        // becoming an unrelated second call.
                        if !state.accept_replaces {
                            info!(
                                call_id = %sip_call_id,
                                matched_call = %matched.call_id,
                                source = %inbound.remote_addr,
                                "B2BUA: declining INVITE with Replaces — b2bua.accept_replaces is not enabled"
                            );
                            let response = build_response(
                                &message,
                                603,
                                "Decline",
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
                        debug!(
                            call_id = %sip_call_id,
                            matched_call = %matched.call_id,
                            replaced_on_a_leg = matched.on_a_leg,
                            source = %inbound.remote_addr,
                            "B2BUA: INVITE with Replaces matched a confirmed dialog — takeover deferred to script admission"
                        );
                        pending_replaces = Some(crate::b2bua::actor::PendingReplaces {
                            replaced_call_id: matched.call_id,
                            replaced_on_a_leg: matched.on_a_leg,
                            early_only: replaces.early_only,
                        });
                    }
                    None => {
                        debug!(
                            call_id = %sip_call_id,
                            replaces_call_id = %replaces.call_id,
                            "B2BUA: rejecting INVITE with 481 — Replaces target dialog does not exist"
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
                }
            }
            Err(error) => {
                debug!(
                    call_id = %sip_call_id,
                    error = %error,
                    "B2BUA: rejecting INVITE with 400 — malformed Replaces header"
                );
                let response = build_response(
                    &message,
                    400,
                    "Bad Replaces Header",
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
        }
    }

    // Send 100 Trying immediately to suppress A-leg retransmissions
    // (RFC 3261 §8.2.6.1: SHOULD send 100 within 200ms for INVITE)
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref(), &[]);
    // Answer on the same listener the request arrived on so a multi-homed UDP
    // host keeps a symmetric source port (a peer that sent to :5066 rejects a
    // reply sourced from :5060). No-op for stream transports / single listener.
    send_message_from(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Create the call in the manager
    let mut a_leg = Leg::new_a_leg(
        sip_call_id.clone(),
        from_tag,
        via_branch,
        LegTransport {
            remote_addr: inbound.remote_addr,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            // Anchor the A-leg on the listener the INVITE arrived on (multi-homed
            // source-port parity for siphon-originated requests + Via/Contact).
            local_addr: Some(inbound.local_addr),
        },
    );

    // Store our Contact for the A-leg direction (what we advertise to the caller).
    // via_host() applies the advertised_address fallback and substitutes the
    // sanitized local_addr when bound to 0.0.0.0/[::]. The PORT is the listener the
    // INVITE arrived on (`inbound.local_addr.port()`), NOT via_port() (the
    // first-configured listener), so a multi-homed host anchors the dialog on the
    // socket the call actually landed on — matches sanitize_b2bua_response's Contact.
    a_leg.dialog.local_contact = Some(format!(
        "<sip:{}:{};transport={}>",
        state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport),
        inbound.local_addr.port(),
        inbound.transport.to_string().to_lowercase(),
    ));

    // Capture the caller's Contact URI (remote_contact for A-leg)
    if let Some(contact) = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
    {
        a_leg.dialog.remote_contact = Some(crate::b2bua::actor::extract_contact_uri(contact));
    }

    // Store A-leg's remote AoR host (caller's From URI host) for in-dialog To headers.
    if let Some(from) = message.headers.from() {
        let from_str = crate::b2bua::actor::extract_contact_uri(from);
        if let Ok(parsed) = parse_uri_standalone(&from_str) {
            a_leg.dialog.remote_aor_host = Some(if let Some(port) = parsed.port {
                format!("{}:{}", parsed.host, port)
            } else {
                parsed.host.clone()
            });
        }
    }

    // Store A-leg From/To for mid-dialog requests. As UAS, our From in BYE
    // is the INVITE's To (with our local_tag), our To is the INVITE's From.
    if let Some(to) = message.headers.to() {
        // Replace/add our tag (the INVITE's To may not have a tag yet)
        let tag_stripped = to.split(";tag=").next().unwrap_or(to);
        a_leg.dialog.local_from_uri =
            Some(format!("{};tag={}", tag_stripped, a_leg.dialog.local_tag));
    }
    if let Some(from) = message.headers.from() {
        a_leg.dialog.remote_to_uri = Some(from.clone());
    }

    // The caller's From/To exactly as they arrived, snapshotted here — before the
    // script runs — for the same reason as `a_leg_supports_100rel` below: the
    // stored A-leg INVITE is a *shared, mutable* buffer that the handler shapes
    // for the B-leg, and every response siphon sends the caller was echoing that
    // mutated buffer.
    //
    // RFC 3261 §8.2.6.2 is unconditional: the response From MUST equal the
    // request's, and the response To MUST equal the request's To (plus our tag).
    // B-leg identity shaping — `call.rewrite_identities()`, `set_from_user` /
    // `set_to_user`, a `number_policy` — is by design a mutation of this buffer,
    // so its effect leaked back onto the A-leg answer: a caller that offered
    // `To: <sip:+15551000001@…>` was answered `To: <sip:15551000001@…>` because
    // the dial plan wanted the B-leg in plain form. The caller is entitled to see
    // its own request echoed whatever siphon does downstream, so the echo reads
    // this snapshot and the shaping stays where it was aimed.
    a_leg.stored_from = message.headers.from().cloned();
    a_leg.stored_to = message.headers.to().cloned();

    // Record the A-leg's own raw endpoint SDP (the caller's offer, before any
    // script/rtpengine rewrite) so a later siphon-terminated transfer where the
    // A-leg is the survivor can offer its real media to the transfer target.
    if !message.body.is_empty() {
        a_leg.last_sdp = Some(message.body.clone());
    }

    let call_id = state.call_actors.create_call(a_leg);

    // Create the event channel for B-leg actors → dispatcher.
    // All B-leg actors for this call share the same sender.
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        call.event_tx = Some(event_tx);
        // Persist the pre-handler on-wire 100rel capability (immutable for the
        // call's life) so the reliable-1xx strip gate can't be defeated by the
        // script mutating the shared INVITE for B-leg header shaping.
        call.a_leg_supports_100rel = a_leg_supports_100rel;
        call.a_leg_requires_100rel = a_leg_requires_100rel;
        // Decided before the script ran, by the RFC 3329 check above.
        call.sec_agree_verified = sec_agree_verified;
        // Listener the INVITE arrived on, so an imperative call.answer() /
        // call.progress() (which has no `inbound` in scope) sends the UAS
        // response back out the same socket.
        call.a_leg_local_addr = Some(inbound.local_addr);
    }
    state.call_event_receivers.insert(call_id.clone(), event_rx);

    // Carry the resolved `Replaces` match onto the call so the post-admission
    // step below can find it.
    if let Some(pending) = pending_replaces {
        state.call_actors.set_pending_replaces(&call_id, pending);
    }

    // CDR: start tracking this call at INVITE time (cdr.auto_emit).
    cdr_track_b2bua_start(
        state,
        &call_id,
        &message,
        &inbound.remote_addr.ip().to_string(),
        // Descriptive field: the caller's own transport, which behind a
        // TLS-terminating front is not the hop siphon accepted.
        inbound.client_or_hop_transport().as_scheme(),
    );

    // Invoke @b2bua.on_invite
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let py_call = PyCall::new(
        call_id.clone(),
        Arc::clone(&message_arc),
        inbound.remote_addr.ip().to_string(),
        format!("{}", inbound.transport).to_lowercase(),
    )
    .with_flow(py_flow_from_inbound(&inbound));

    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaInvite);

    let mut outcome = Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall: {error}");
                return CallHandlerOutcome::default();
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            record_script_error("async B2BUA on_invite", &error);
                            return CallHandlerOutcome::script_error();
                        }
                    }
                }
                Err(error) => {
                    record_script_error("B2BUA on_invite", &error);
                    return CallHandlerOutcome::script_error();
                }
            }
        }

        let borrowed = call_obj.borrow(python);
        CallHandlerOutcome::from_call(&borrowed)
    });
    let action = std::mem::take(&mut outcome.action);

    // The handler may have awaited — and the caller is free to give up while it
    // does. A CANCEL that landed in that window has already answered the A-leg
    // `487`, fired `@b2bua.on_cancel` and removed the actor, so every action
    // below is now addressed at a call nobody is on. Applying one anyway puts a
    // second final response on the same INVITE server transaction (RFC 3261
    // §17.2.1) — most visibly an answer-first `handover`, which sends its
    // `200 OK` off the stored INVITE and would land behind the 487. One guard
    // here rather than per arm, because it covers the `script_error` reject too.
    // Nothing is left to clean up: the CANCEL path removed the call, its
    // registry entries and its event receiver.
    if invite_action_target_gone(&call_id, &state.call_actors) {
        info!(
            call_id = %call_id,
            action = action.name(),
            "B2BUA: @b2bua.on_invite returned for a call that ended while the handler ran \
             (CANCELled / torn down) — action not applied"
        );
        return;
    }

    // Store the A-leg INVITE for later use by on_answer/on_failure/on_bye handlers
    state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::clone(&message_arc));

    apply_handler_side_state(&call_id, outcome, state);

    // The INVITE carried a `Replaces` naming a dialog this node hosts, and the
    // script has now had its say. A reject (a digest challenge, a policy refusal)
    // is honoured below like any other; anything else means the request was
    // admitted, so the takeover runs instead of the routing the script asked for
    // — an INVITE with `Replaces` is a request to join an existing call, not a
    // new one to route, and the dial plan has no say in where it goes.
    if !matches!(action, CallAction::Reject { .. } | CallAction::None) {
        if let Some(pending) = state.call_actors.take_pending_replaces(&call_id) {
            if refuse_too_brief_invite(&call_id, &message_arc, state) {
                return;
            }
            let Ok(message_guard) = message_arc.lock() else {
                error!("message_arc lock poisoned in B2BUA invite handler");
                return;
            };
            b2bua_bridge_inbound_replaces(&inbound, &message_guard, &call_id, &pending, state);
            return;
        }
    }

    match action {
        CallAction::None if handlers.is_empty() && state.control_inbound.is_some() => {
            // No `@b2bua.on_invite` handler exists to decide, and
            // `control.inbound` says where an undecided call goes. This is the
            // script-free path: the controller is the policy, so there is no
            // script to write one in.
            //
            // Deliberately gated on there being no handler at all rather than
            // on the action: a script that ran and returned nothing chose the
            // silent drop below, and overriding that would take a decision away
            // from the thing that made it.
            let policy = state.control_inbound.clone().unwrap_or_default();
            debug!(
                call_id = %call_id,
                app = %policy.app,
                answer = policy.answer_first(),
                "B2BUA: handing over to the control plane (control.inbound, no script)"
            );
            if refuse_too_brief_invite(&call_id, &message_arc, state) {
                return;
            }
            let Ok(message_guard) = message_arc.lock() else {
                error!("message_arc lock poisoned in B2BUA invite handler");
                return;
            };
            control_handover(
                &call_id,
                &message_guard,
                &inbound,
                ControlHandoverParams {
                    app: &policy.app,
                    on_lost: None,
                    deadline_ms: policy.deadline_ms,
                    vars: std::collections::HashMap::new(),
                    answer: policy.answer_first(),
                    profile: policy.profile.as_deref(),
                    ws_uri: policy.ws_uri.as_deref(),
                },
                state,
            );
        }
        CallAction::None => {
            debug!(call_id = %call_id, "B2BUA: silent drop (no action from script)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::Reject { code, reason } => {
            debug!(call_id = %call_id, code, "B2BUA: rejecting call");
            let Ok(message_guard) = message_arc.lock() else {
                error!("message_arc lock poisoned in B2BUA invite handler");
                return;
            };
            let mut response = build_response(
                &message_guard,
                code,
                &reason,
                state.server_header.as_deref(),
                &[],
            );
            drop(message_guard);
            // siphon is the UAS on the A-leg, so this locally-generated final
            // response needs the dialog's UAS To-tag (RFC 3261 §8.2.6.2) — same
            // as the 408-timeout path. Load-bearing for a digest challenge:
            // the caller matches our 407 to its transaction and echoes the tag
            // on its ACK (RFC 3261 §17.1.1.3) before re-INVITEing with
            // credentials. Same section requires the From/To it carries to be
            // the caller's own, not the B-leg form the handler shaped before
            // deciding to reject.
            if let Some((stored_from, stored_to, local_tag)) =
                state.call_actors.get_call(&call_id).map(|call| {
                    (
                        call.a_leg.stored_from.clone(),
                        call.a_leg.stored_to.clone(),
                        call.a_leg.dialog.local_tag.clone(),
                    )
                })
            {
                stamp_uas_echo(
                    &mut response,
                    stored_from.as_ref(),
                    stored_to.as_ref(),
                    &local_tag,
                );
            }
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        routing @ (CallAction::Dial { .. }
        | CallAction::Fork { .. }
        | CallAction::RouteSequence { .. }
        | CallAction::Handover { .. }) => {
            apply_routing_action(&call_id, routing, &message_arc, &inbound, state);
        }
        CallAction::Terminate => {
            debug!(call_id = %call_id, "B2BUA: terminate on invite (unusual)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::AcceptRefer { .. } => {
            debug!(call_id = %call_id, "B2BUA: accept_refer() during on_invite has no effect — it only applies inside @b2bua.on_refer");
        }
        CallAction::RejectRefer { code, reason } => {
            debug!(call_id = %call_id, code, reason = %reason, "B2BUA: reject_refer() during on_invite has no effect — it only applies inside @b2bua.on_refer");
        }
        CallAction::SendRefer { .. } => {
            debug!(call_id = %call_id, "B2BUA: call.refer() during on_invite has no effect — the call is not yet established; use it from @b2bua.on_answer or the imperative b2bua.refer()");
        }
        CallAction::Answered => {
            // The script called call.answer() imperatively — the 2xx has already
            // been sent (see b2bua_answer_call). This marker only tells the
            // dispatcher the actor was answered so the CallAction::None arm above
            // doesn't remove_call() it as a silent drop. The A-leg dialog is
            // confirmed and @b2bua.on_bye takes over when the UAC BYEs.
            debug!(call_id = %call_id, "B2BUA: UAS-mode answer already sent (imperative)");
        }
    }
}

/// Carry out a routing decision a handler took for a call nobody has answered
/// yet: `call.dial()`, `call.fork()`, `call.route()` or `call.handover()`, from
/// `@b2bua.on_invite` or, for a call that failed, `@b2bua.on_failure`.
///
/// `reply_to` is where a response to the caller goes. Called with no lock held
/// on `invite_arc`: routing takes it, and a route that fails on the spot runs
/// `@b2bua.on_failure`, which takes it again through the `Call` it is handed.
pub fn apply_routing_action(
    call_id: &str,
    action: CallAction,
    invite_arc: &Arc<Mutex<SipMessage>>,
    reply_to: &InboundMessage,
    state: &DispatcherState,
) {
    // RFC 4028 §9: a caller asking for less than the minimum session interval of
    // the timer siphon runs on the call is refused before the call goes anywhere.
    // Checked after the handler, which may have set that timer.
    if refuse_too_brief_invite(call_id, invite_arc, state) {
        return;
    }
    let Ok(message_guard) = invite_arc.lock() else {
        error!(call_id = %call_id, "B2BUA: A-leg INVITE lock poisoned — the call cannot be routed");
        return;
    };

    // Filled by the LCR arm below and acted on after the match, once
    // `message_guard` is released — `@b2bua.on_route_failure` re-locks the A-leg
    // INVITE.
    let mut burned_routes: Vec<(crate::lcr::Route, u16)> = Vec::new();
    // The call could not be routed as asked: nothing is on the wire, so nothing
    // will ever answer it, and it fails now with this status and reason.
    let mut fail_now: Option<(u16, &'static str)> = None;
    // What a parallel fork's branches settled while they were still being sent.
    let mut fork_settlement: Option<crate::b2bua::actor::BranchSettlement> = None;

    // RFC 3261 §8.2.2.3: siphon is the caller's UAS, so a `Require` the call
    // cannot honour is refused `420 Bad Extension` before any B-leg goes out. It
    // runs here, not at INVITE receipt, because honouring depends on the header
    // policy and the script only picks that with `call.dial(header_policy=…)`;
    // this is the one place both `@b2bua.on_invite` and a re-route from
    // `@b2bua.on_failure` pass through with the policy settled. A handover is not
    // checked: the control app has not routed anything yet.
    if matches!(
        action,
        CallAction::Dial { .. } | CallAction::Fork { .. } | CallAction::RouteSequence { .. }
    ) {
        let (script_shaped_headers, sec_agree_verified) = state
            .call_actors
            .get_call(call_id)
            .map(|call| (call.script_shaped_headers.clone(), call.sec_agree_verified))
            .unwrap_or_default();
        let unsupported = unhonourable_required_tags(
            &message_guard.headers,
            &script_shaped_headers,
            &state.resolve_header_policy(call_id),
            sec_agree_verified,
        );
        if !unsupported.is_empty() {
            info!(
                call_id = %call_id,
                unsupported = %unsupported.join(", "),
                "B2BUA: the caller requires extensions this call cannot honour — refusing it"
            );
            // Concluded like any call that could not be connected, with no lock
            // held on the A-leg INVITE: `@b2bua.on_failure` may hold per-call
            // state only a failure releases, and may route again under a policy
            // that does relay the extension.
            drop(message_guard);
            conclude_failed_call(call_id, FailedCallEnd::BadExtension { unsupported }, state);
            return;
        }
    }

    match action {
        CallAction::Dial {
            target,
            next_hop,
            flow,
            route,
            send_socket,
            timeout,
        } => {
            debug!(
                call_id = %call_id,
                target = %target,
                next_hop = ?next_hop,
                flow = flow.is_some(),
                routes = route.len(),
                // The script's intent, as passed to `call.dial()` — before
                // resolution, the header policy or any number reshaping. The
                // dial that actually leaves the socket is the `b2bua.log_dial`
                // line in `b2bua_send_b_leg_invite`; this one can still be
                // followed by a resolve failure.
                "B2BUA: dial requested by script",
            );
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            let sent = b2bua_send_b_leg_invite(
                call_id,
                &target,
                next_hop.as_deref(),
                flow.as_ref(),
                &route,
                send_socket.as_ref(),
                None,
                &message_guard,
                None,
                None,
                None,
                None,
                None,
                &[],
                state,
            );
            if sent {
                set_b2bua_answer_deadline(call_id, timeout, state);
            } else {
                // Nothing was put on the wire, so nothing will ever answer.
                // Arming the deadline instead would leave the caller in ringback
                // for its full length (30 s by default) before a 408 — for a
                // failure siphon already logged. The proxy answers 502 the
                // moment a relay target will not resolve; this is that, for a
                // B2BUA, as the 503 the LCR path uses for a route it cannot take.
                warn!(
                    call_id = %call_id,
                    target = %target,
                    "B2BUA: B-leg INVITE was never sent — failing the call now",
                );
                fail_now = Some((503, "Destination Unreachable"));
            }
        }
        CallAction::Fork {
            targets,
            flows,
            routes,
            strategy: _,
            send_socket,
            timeout,
        } => {
            debug!(call_id = %call_id, targets = ?targets, "B2BUA: forking B-legs");
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            let mut branches_sent = 0usize;
            // Branches go out one at a time, and the first can fail (or answer)
            // before the next one exists. Hold settlement until all are out.
            state.call_actors.start_fork_dispatch(call_id);
            for (index, target) in targets.iter().enumerate() {
                // Each branch gets the route set of *its own* binding (RFC 3327
                // §5.3), which also decides where the branch is sent.  A shared
                // route set would put every branch through the first binding's
                // proxy chain — and, behind a Path-token edge proxy, deliver
                // them all back to the first binding.
                let branch_path = routes.get(index).map(Vec::as_slice).unwrap_or(&[]);
                let branch_route = crate::proxy::core::route_set_from_path(branch_path)
                    .map(|value| vec![value])
                    .unwrap_or_default();
                if b2bua_send_b_leg_invite(
                    call_id,
                    target,
                    None,
                    flows.get(index).and_then(|f| f.as_ref()),
                    &branch_route,
                    send_socket.as_ref(),
                    None,
                    &message_guard,
                    None,
                    None,
                    None,
                    None,
                    None,
                    &[],
                    state,
                ) {
                    branches_sent += 1;
                }
            }
            fork_settlement = state.call_actors.finish_fork_dispatch(call_id);
            // A branch that could not be sent is simply not a branch (RFC 3261
            // §16.7 aggregates over the branches that exist), so one bad
            // contact among several does not fail the call. All of them failing
            // does: there is no branch left to answer, and waiting for the ring
            // timeout would only turn a known failure into 30 s of ringback.
            if branches_sent > 0 {
                set_b2bua_answer_deadline(call_id, timeout, state);
            } else {
                warn!(
                    call_id = %call_id,
                    branches = targets.len(),
                    "B2BUA: no fork branch could be sent — failing the call now",
                );
                fail_now = Some((503, "Destination Unreachable"));
            }
        }
        CallAction::RouteSequence {
            mut routes,
            send_socket,
            default_timeout,
        } => {
            // LCR / sequential failover: dial the first routable carrier, keep
            // the rest as the call's failover queue, and advance on B-leg
            // reject/timeout (see b2bua_advance_route). Each attempt is a fresh
            // B-leg dialog (no reused Call-ID — the serial-fork footgun).
            for route in &mut routes {
                if route.timeout_secs.is_none() {
                    route.timeout_secs = Some(default_timeout);
                }
            }
            let carrier_count = routes.len();
            debug!(call_id = %call_id, carriers = carrier_count, "B2BUA: LCR sequential routing");
            state.call_actors.start_route_sequence(
                call_id,
                crate::b2bua::actor::RouteSequenceState {
                    pending: routes.into(),
                    active: None,
                    attempts: Vec::new(),
                    active_since: None,
                    active_progressed: false,
                    active_legs_start: 0,
                    send_socket,
                    default_timeout,
                },
            );
            let advanced = b2bua_advance_route(call_id, &message_guard, state);
            burned_routes = advanced.burned;
            if !advanced.dialed && state.call_actors.get_call(call_id).is_none() {
                // Every carrier was refused because the call ended while the
                // sequence was being dialled (a CANCEL during resolution). That
                // path already answered the A-leg; a 503 would be a second final
                // response on its INVITE transaction (RFC 3261 §17.2.1).
                debug!(call_id = %call_id, "B2BUA: LCR — call ended before any carrier was dialled");
            } else if !advanced.dialed {
                // No carrier was routable (e.g. every gateway group down and no
                // explicit next-hop): fail the call 503 instead of stalling. Not
                // until the burned-carrier hooks below have run: they read the
                // call's A-leg, and an exhausted sequence is exactly the case
                // where a script most needs to hear which carriers it went
                // through.
                debug!(call_id = %call_id, "B2BUA: LCR — no routable carrier");
                fail_now = Some((503, "No Route"));
            }
        }
        CallAction::Handover {
            app,
            on_lost,
            deadline_ms,
            vars,
            answer,
            profile,
            ws_uri,
        } => {
            control_handover(
                call_id,
                &message_guard,
                reply_to,
                ControlHandoverParams {
                    app: &app,
                    on_lost: on_lost.as_deref(),
                    deadline_ms,
                    vars,
                    answer,
                    profile: profile.as_deref(),
                    ws_uri: ws_uri.as_deref(),
                },
                state,
            );
        }
        other => debug!(
            call_id = %call_id,
            action = other.name(),
            "B2BUA: not a routing action — nothing to route"
        ),
    }

    // Release the A-leg INVITE before anything that re-locks it. The hooks do,
    // via the `Call` they are handed, and they run inline on this thread —
    // holding the guard across them would deadlock the dispatcher on a
    // non-reentrant mutex.
    drop(message_guard);
    b2bua_dispatch_burned_routes(call_id, &burned_routes, state);
    if let Some(settlement) = fork_settlement {
        cancel_settled_branches(&settlement.cancelled, state);
        if let Some(best) = settlement.failure {
            fail_forked_call(call_id, best, state);
        }
    }
    if let Some((status_code, reason)) = fail_now {
        b2bua_fail_undialed_call(call_id, status_code, reason, state);
    }
}

/// Fail a call that could not be routed as its handler asked: its B-leg INVITE
/// never reached the transport, or no LCR carrier was routable.
///
/// The alternative — the behaviour this replaces — is to arm the answer deadline
/// anyway and let the caller sit in ringback for its full length before a `408
/// Request Timeout`, for a failure siphon logged milliseconds earlier. `503` is
/// honest about whose problem this is: no callee ever saw the call.
///
/// It concludes like any failed call. The script asked for a route and did not
/// get one, so `@b2bua.on_failure` hears about it the way it would have had the
/// callee answered 503 (it may be holding per-call state, such as Rx / N5 QoS,
/// an anchored media session or an external reservation, that only a failure
/// releases), and can route the call somewhere else. Called with **no lock held
/// on the A-leg INVITE**, which the response and the handlers' `Call` both take.
pub fn b2bua_fail_undialed_call(
    call_id: &str,
    status_code: u16,
    reason: &str,
    state: &DispatcherState,
) {
    conclude_failed_call(
        call_id,
        FailedCallEnd::Local {
            status_code,
            reason: reason.to_string(),
        },
        state,
    );
}

/// Store on the call what a handler set on its `Call` besides the action: the
/// session-timer and header-policy overrides, B-leg credentials, URI host and
/// Contact rewrites, lawful-intercept recording, the duration cap, and who the
/// caller authenticated as.
///
/// Only what the handler set is applied. After `@b2bua.on_invite` the call has
/// nothing else; after `@b2bua.on_failure`, which is handed a fresh `Call`,
/// whatever `@b2bua.on_invite` set stays unless this handler sets it again.
pub fn apply_handler_side_state(
    call_id: &str,
    outcome: CallHandlerOutcome,
    state: &DispatcherState,
) {
    let CallHandlerOutcome {
        action: _,
        timer_override,
        credentials,
        li_record,
        preserve_call_id,
        policy_input,
        from_host_override,
        to_host_override,
        contact_user_override,
        contact_override,
        auth_passthrough,
        auth_user,
        max_duration_secs,
        script_shaped_headers,
    } = outcome;

    // A caller that answered a digest challenge inside `@b2bua.on_invite`
    // (`auth.require_proxy_digest(call, …)`) authenticated after
    // `cdr_track_b2bua_start` already opened the CDR session, so stamp the
    // username on now — the proxy path gets it at session-build time.
    if let Some(auth_user) = auth_user {
        if let Some(mut session) = state.cdr_sessions.get_mut(call_id) {
            session.set_auth_user(auth_user);
        }
    }

    // Resolve script-side header policy input into a per-call ResolvedPolicy.
    // Done outside the call_actors lock so the registry lookup + delta
    // translation doesn't hold the actor mutex.
    let resolved_policy = policy_input.map(|input| {
        let preset = match input.policy_name.as_deref() {
            Some(name) => match state.header_policy_registry.get(name) {
                Some(p) => p.clone(),
                None => {
                    warn!(
                        call_id = %call_id,
                        requested = %name,
                        "unknown header_policy preset — falling back to default"
                    );
                    state.default_header_policy.clone()
                }
            },
            None => state.default_header_policy.clone(),
        };
        let mut resolved = crate::b2bua::header_policy::ResolvedPolicy::from_preset(preset);
        resolved.deltas_copy = input.deltas_copy;
        resolved.deltas_strip = input.deltas_strip;
        resolved.deltas_translate = input
            .deltas_translate
            .into_iter()
            .filter_map(|(header, op_name)| {
                parse_translate_op_name(&op_name)
                    .map(|op| (header, op))
                    .or_else(|| {
                        warn!(
                            call_id = %call_id,
                            op = %op_name,
                            "unknown translate op — entry dropped"
                        );
                        None
                    })
            })
            .collect();
        Arc::new(resolved)
    });

    // auth_passthrough (relay the challenge for the endpoint to answer) and
    // set_credentials (siphon answers the challenge itself) are mutually
    // exclusive uses of the same 401/407 handling. If both are set, credentials
    // win (the auth_passthrough branch is only reachable when there are none) —
    // warn so the misconfiguration is visible.
    if credentials.is_some() && auth_passthrough {
        warn!(
            call_id = %call_id,
            "call has both set_credentials() and auth_passthrough=True — credentials win; ignoring auth_passthrough"
        );
    }

    if timer_override.is_none()
        && credentials.is_none()
        && !li_record
        && !preserve_call_id
        && resolved_policy.is_none()
        && from_host_override.is_none()
        && to_host_override.is_none()
        && contact_user_override.is_none()
        && contact_override.is_none()
        && !auth_passthrough
        && max_duration_secs.is_none()
        && script_shaped_headers.is_empty()
    {
        return;
    }
    let Some(mut call) = state.call_actors.get_call_mut(call_id) else {
        return;
    };
    if let Some(override_config) = timer_override {
        call.session_timer_override = Some(override_config);
    }
    if credentials.is_some() {
        call.outbound_credentials = credentials;
    }
    if li_record {
        call.li_record = true;
    }
    if preserve_call_id {
        call.preserve_call_id = true;
    }
    if resolved_policy.is_some() {
        call.resolved_header_policy = resolved_policy;
    }
    if from_host_override.is_some() {
        call.from_host_override = from_host_override;
    }
    if to_host_override.is_some() {
        call.to_host_override = to_host_override;
    }
    if contact_user_override.is_some() {
        call.contact_user_override = contact_user_override;
    }
    if contact_override.is_some() {
        call.contact_override = contact_override;
    }
    if auth_passthrough {
        call.auth_passthrough = true;
    }
    // Added to, never replaced: a header `@b2bua.on_invite` set is still the
    // script's value on the stored INVITE when `@b2bua.on_failure` routes again.
    call.script_shaped_headers.extend(script_shaped_headers);
    // Stored, not turned into a deadline: the clock starts at the answer, which
    // has not happened yet. Applies to every action shape — a dial, a fork, an
    // LCR sequence, a UAS-mode answer, a handover — because it lives on the
    // `Call`, not inside the action.
    if max_duration_secs.is_some() {
        call.max_duration_secs = max_duration_secs;
    }
}
