//! The background tasks the dispatcher spawns at start-up, and the hooks it
//! publishes for the layers that reach into it from outside.

use super::*;

/// Publish the hooks the charging paths reach from outside the dispatcher:
/// the Ro teardown, the Rf session lookup a CDR stamps itself from, the CDR
/// extra-field merger, and the script-set charging parameters.
pub fn install_charging_hooks(state: &Arc<DispatcherState>) {
    // Publish a handle to the running dispatcher + its tokio runtime so the
    // imperative `b2bua.terminate` script API can tear a call down by SIP
    // Call-ID from any thread (event callbacks, timers). First writer wins.
    let _ = B2BUA_CONTROL.set(B2buaControlHandle {
        state: Arc::clone(state),
        runtime: tokio::runtime::Handle::current(),
    });

    // Install the Ro teardown hook so a session's Rust-side re-auth timer can
    // disconnect a live call when the OCS refuses further credit. Ro enforcement
    // is B2BUA-only, so this always tears down a tracked B2BUA call. Pass the
    // reason as PLAIN TEXT — `b2bua_terminate_call` wraps it into a well-formed
    // `Reason: Q.850;cause=16;text="…"` header (pre-formatting it here would
    // nest a Q.850 string inside the text= parameter).
    if let Some(ro) = state.ro_charger.as_ref() {
        ro.set_teardown_hook(Arc::new(|sip_call_id, reason| {
            b2bua_terminate_call(sip_call_id, Some(reason));
        }));
        // Publish the Ro authorizer so the `call.ro_authorize()` scripting gate
        // can reserve credit (CCR-INITIAL) before dialing the B-leg and store the
        // session where BYE / teardown / failure paths find it.
        let _ = RO_CONTROL.set(RoControlHandle {
            charger: Arc::clone(ro),
            ro_sessions: Arc::clone(&state.ro_sessions),
            local_domains: Arc::clone(&state.local_domains),
        });
    }

    // Install the rf_sessions lookup so the CDR Python API can
    // auto-stamp `rf_session_id` / `rf_result_code` on every CDR
    // emitted while an Rf session is active for the SIP dialog.
    {
        let rf_sessions = Arc::clone(&state.rf_sessions);
        crate::diameter::rf_service::install_rf_lookup(Arc::new(move |dialog_key: &str| {
            rf_sessions.get(dialog_key).map(|entry| {
                let session = entry.value().rf_session();
                (session.session_id().to_string(), session.last_result_code())
            })
        }));
    }

    // Install the auto-emit CDR session merger so a script's
    // `cdr.write(request|call, extra=…)` attaches its fields to the record
    // this call is already accumulating instead of queueing a second,
    // timing-less record beside it.
    {
        let cdr_sessions = Arc::clone(&state.cdr_sessions);
        crate::cdr::install_extra_merger(Arc::new(
            move |keys: &[String], extra: &std::collections::HashMap<String, String>| {
                for key in keys {
                    if let Some(mut session) = cdr_sessions.get_mut(key.as_str()) {
                        session.merge_extra(extra);
                        return true;
                    }
                }
                false
            },
        ));
    }

    // Install the script → auto-emit charging-param channel so
    // `request.set_charging_param("outgoing-trunk-group-id", ...)` from
    // a Python handler bridges to the proxy/B2BUA ACR-START builders
    // without needing to thread state through every API surface.
    {
        let params_store: Arc<DashMap<String, Vec<(String, String)>>> = Arc::new(DashMap::new());
        let writer_store = Arc::clone(&params_store);
        let reader_store = Arc::clone(&params_store);
        crate::diameter::rf_service::install_rf_param_channel(
            Arc::new(move |dialog_key: &str, name: String, value: String| {
                writer_store
                    .entry(dialog_key.to_string())
                    .or_default()
                    .push((name, value));
            }),
            Arc::new(move |dialog_key: &str| {
                // Drain semantics: removing on read keeps the map
                // bounded even when an INVITE never reaches the
                // auto-emit path (rejected, dropped, etc.).
                reader_store
                    .remove(dialog_key)
                    .map(|(_, v)| v)
                    .unwrap_or_default()
            }),
        );
    }
}

/// Fire the transaction timers and sweep the stores: retransmissions every
/// 100 ms, the B2BUA call-lifetime checks every 500 ms.
pub fn spawn_timer_sweep(state: &Arc<DispatcherState>) {
    // Spawn background task: fire transaction timers + sweep stale entries
    {
        let state = Arc::clone(state);
        tokio::spawn(async move {
            // Timer check interval: 100ms for responsive retransmissions
            let mut timer_interval = tokio::time::interval(std::time::Duration::from_millis(100));
            // B2BUA call-lifetime checks: 500ms so a short per-carrier LCR ring
            // timeout re-routes within ~0.5s of its deadline (previously this was
            // folded into the 30s sweep, making short ring timeouts unusable),
            // and so an orphaned Ro reservation is released well inside one
            // re-auth window instead of billing against a call that has ended.
            let mut answer_timeout_interval =
                tokio::time::interval(std::time::Duration::from_millis(500));
            // Stale entry cleanup: every 30s
            let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = timer_interval.tick() => {
                        fire_expired_timers(&state);
                        sweep_b2bua_retransmits(&state);
                        sweep_unacked_uas_2xx(&state);
                    }
                    _ = answer_timeout_interval.tick() => {
                        check_b2bua_answer_timeouts(&state);
                        check_b2bua_max_call_durations(&state);
                        check_b2bua_replacement_timeouts(&state);
                        check_pending_inbound_refer_timeouts(&state);
                        check_orphaned_ro_sessions(&state);
                        check_deferred_referrer_byes(&state);
                    }
                    _ = cleanup_interval.tick() => {
                        sweep_stale_entries(&state).await;
                    }
                }
            }
        });
    }
}

/// RFC 4028 §10: re-INVITE each session whose refresh is due, and end the
/// ones nothing refreshed.
pub fn spawn_session_timer_refresh(state: &Arc<DispatcherState>) {
    // Spawn background task: RFC 4028 session timer refresh
    if state
        .session_timer_config
        .as_ref()
        .is_some_and(|c| c.enabled)
    {
        let state = Arc::clone(state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                // Run in spawn_blocking since it accesses DashMap and may build SIP messages
                let state = Arc::clone(&state);
                tokio::task::spawn_blocking(move || {
                    session_timer_sweep(&state);
                })
                .await
                .ok();
            }
        });
    }
}

/// Registration state changes to the script's `@registrar.on_change`, and
/// the Rf ACR-EVENT that TS 32.260 §5.1 owes each one.
pub fn spawn_registrar_events(
    state: &Arc<DispatcherState>,
    registrar_event_rx: Option<
        tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>,
    >,
) {
    // Spawn background task: registrar change event → on_change handlers
    if let Some(registrar) = crate::script::api::registrar_arc() {
        let mut event_receiver = registrar_event_rx.unwrap_or_else(|| registrar.subscribe_events());
        let state_for_events = Arc::clone(state);
        let registrar = Arc::clone(registrar);
        tokio::spawn(async move {
            while let Ok(event) = event_receiver.recv().await {
                let (aor, event_type) = match &event {
                    crate::registrar::RegistrationEvent::Registered { aor } => {
                        (aor.clone(), "registered")
                    }
                    crate::registrar::RegistrationEvent::Refreshed { aor } => {
                        (aor.clone(), "refreshed")
                    }
                    crate::registrar::RegistrationEvent::Deregistered { aor } => {
                        (aor.clone(), "deregistered")
                    }
                    crate::registrar::RegistrationEvent::Expired { aor } => {
                        (aor.clone(), "expired")
                    }
                };

                // CDR: emit a REGISTER record for this state change when
                // cdr.auto_emit + cdr.include_register are on — independent of
                // whether a @registrar.on_change handler is registered.
                if crate::cdr::auto_emit_enabled() && crate::cdr::include_register_enabled() {
                    cdr_emit_register(&aor, event_type);
                }

                // Control applications that asked for the registration class
                // (`control.apps[].events`). Emitted before the Python
                // short-circuit below so it fires whether or not a
                // `@registrar.on_change` handler is registered — a dashboard
                // should not depend on a script existing.
                if let Some(bus) = crate::control::ControlBus::global() {
                    let bindings: Vec<serde_json::Value> = registrar
                        .lookup(&aor)
                        .into_iter()
                        .map(|contact| {
                            serde_json::json!({
                                "uri": contact.uri.to_string(),
                                "expires": contact.remaining_seconds(),
                                "q": contact.q,
                            })
                        })
                        .collect();
                    bus.publish_app_event(
                        "registration",
                        "RegistrationChanged",
                        serde_json::json!({
                            "aor": aor,
                            "event": event_type,
                            "contacts": bindings,
                        }),
                    );
                }

                // Quick check if any handlers exist (avoids spawn_blocking overhead)
                {
                    let engine_state = state_for_events.engine.state();
                    if engine_state
                        .handlers_for(&HandlerKind::RegistrarOnChange)
                        .is_empty()
                    {
                        continue;
                    }
                }

                // Build contacts list for the callback
                let contacts: Vec<crate::script::api::registrar::PyContact> = registrar
                    .lookup(&aor)
                    .iter()
                    .map(crate::script::api::registrar::PyContact::from_rust_contact)
                    .collect();

                let event_type_str = event_type.to_string();
                let state_ref = Arc::clone(&state_for_events);

                // Invoke Python handlers in a blocking context
                run_event_handler("registrar.on_change", move || {
                    let engine_state = state_ref.engine.state();
                    let handlers = engine_state.handlers_for(&HandlerKind::RegistrarOnChange);

                    pyo3::Python::attach(|python| {
                        let py_items: Vec<_> = contacts
                            .into_iter()
                            .filter_map(|contact| match pyo3::Py::new(python, contact) {
                                Ok(py) => Some(py.into_bound(python)),
                                Err(error) => {
                                    error!("PyContact creation failed: {error}");
                                    None
                                }
                            })
                            .collect();
                        let Ok(py_contacts) = pyo3::types::PyList::new(python, py_items) else {
                            error!("PyList creation failed for registrar on_change contacts");
                            return;
                        };

                        for handler in handlers {
                            let callable = handler.callable.bind(python);
                            let result = callable.call1((
                                aor.as_str(),
                                event_type_str.as_str(),
                                &py_contacts,
                            ));
                            match result {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            tracing::error!(
                                                %error,
                                                "async registrar.on_change handler error"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        "registrar.on_change handler failed"
                                    );
                                }
                            }
                        }
                    });
                })
                .await;
            }
        });
    }
}

/// Outbound-REGISTER state changes to the script's `@registrar.on_change`.
pub fn spawn_registrant_events(state: &Arc<DispatcherState>) {
    // Spawn background task: registrant change event → on_change handlers
    if let Some(ref registrant) = state.registrant_manager {
        let mut event_receiver = registrant.subscribe_events();
        let state_for_events = Arc::clone(state);
        let registrant = Arc::clone(registrant);
        tokio::spawn(async move {
            while let Ok(event) = event_receiver.recv().await {
                let (aor, event_type, failed_status_code) = match &event {
                    crate::registrant::RegistrantEvent::Registered { aor } => {
                        (aor.clone(), "registered", None)
                    }
                    crate::registrant::RegistrantEvent::Refreshed { aor } => {
                        (aor.clone(), "refreshed", None)
                    }
                    crate::registrant::RegistrantEvent::Failed { aor, status_code } => {
                        (aor.clone(), "failed", Some(*status_code))
                    }
                    crate::registrant::RegistrantEvent::Deregistered { aor } => {
                        (aor.clone(), "deregistered", None)
                    }
                };

                // Quick check if any handlers exist (avoids spawn_blocking overhead)
                {
                    let engine_state = state_for_events.engine.state();
                    if engine_state
                        .handlers_for(&HandlerKind::RegistrantOnChange)
                        .is_empty()
                    {
                        continue;
                    }
                }

                // Build state dict for the callback
                let (expires_in, failure_count, registrar_uri) =
                    registrant.entry_info(&aor).unwrap_or((0, 0, String::new()));

                let event_type_str = event_type.to_string();
                let state_ref = Arc::clone(&state_for_events);

                // Invoke Python handlers in a blocking context
                run_event_handler("registrant.on_change", move || {
                    let engine_state = state_ref.engine.state();
                    let handlers = engine_state.handlers_for(&HandlerKind::RegistrantOnChange);

                    pyo3::Python::attach(|python| {
                        let py_state = pyo3::types::PyDict::new(python);
                        let status_code_ok = match failed_status_code {
                            Some(code) => py_state.set_item("status_code", code).is_ok(),
                            None => true,
                        };
                        if py_state.set_item("expires_in", expires_in).is_err()
                            || py_state.set_item("failure_count", failure_count).is_err()
                            || py_state.set_item("registrar", &registrar_uri).is_err()
                            || !status_code_ok
                        {
                            error!("PyDict creation failed for registration on_change state");
                            return;
                        }

                        for handler in handlers {
                            let callable = handler.callable.bind(python);
                            let result =
                                callable.call1((aor.as_str(), event_type_str.as_str(), &py_state));
                            match result {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            tracing::error!(
                                                %error,
                                                "async registration.on_change handler error"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        "registration.on_change handler failed"
                                    );
                                }
                            }
                        }
                    });
                })
                .await;
            }
        });
    }
}

/// Serve inbound Diameter requests (RFC 6733): every command on every
/// connection goes to `@diameter.on_request`, bounded by a semaphore so a
/// peer cannot outrun the script pool.
pub fn spawn_diameter_incoming(
    state: &Arc<DispatcherState>,
    diameter_incoming_rx: tokio::sync::mpsc::Receiver<(
        crate::diameter::peer::IncomingRequest,
        std::sync::Arc<crate::diameter::peer::DiameterPeer>,
    )>,
) {
    // Spawn background task: incoming Diameter requests (RTR from HSS, etc.)
    {
        let mut diameter_rx = diameter_incoming_rx;
        let state_for_diameter = Arc::clone(state);
        tokio::spawn(async move {
            let diameter_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(512));
            while let Some((incoming, peer)) = diameter_rx.recv().await {
                // Unified inbound dispatch (RFC 6733): every inbound request —
                // any application, any command — is handed to
                // @diameter.on_request. siphon transports; the script reads
                // AVPs and returns the answer (or 3002 when unhandled). Adding
                // a new server-side application needs zero Rust here.
                let engine = std::sync::Arc::clone(&state_for_diameter.engine);
                let config = peer.config();
                let peer_info = crate::script::api::diameter_server::PyInboundPeer {
                    name: config.host.clone(),
                    tenant: "default".to_string(),
                    addr: format!("{}:{}", config.host, config.port),
                    transport: "tcp".to_string(),
                };
                let origin_host = config.origin_host.clone();
                let origin_realm = config.origin_realm.clone();
                let inflight = std::sync::Arc::clone(&diameter_inflight);
                let inbound_peer = std::sync::Arc::clone(&peer);
                tokio::spawn(async move {
                    let _permit = match inflight.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    crate::script::diameter_dispatch::dispatch_request(
                        engine,
                        inbound_peer,
                        incoming,
                        peer_info,
                        origin_host,
                        origin_realm,
                    )
                    .await;
                });
            }
        });
    }
}
