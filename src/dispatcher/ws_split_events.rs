//! The split bridge's lifecycle events, from the media engine to the script's
//! `@rtpengine.on_ws_split_started` / `on_ws_split_ended` handlers and to the
//! control rail.
//!
//! What the engine names an engine call-id and the offerer's tag, the handlers
//! and the rail get as the SIP Call-ID of the offerer's dialog (the same
//! mapping a recording's end gets), so a script keys its own state on the id
//! it already holds.

use super::*;
use crate::rtpengine::CallScope;

/// The session store an event belongs to: the node's own, or the one of the
/// per-call scope the leg was anchored under (the engine reports such a leg
/// as `<call-id>;<scope>`, split by the event loop into the Call-ID and the
/// scope). `None` for a scope nothing was ever anchored under.
fn event_store(
    state: &DispatcherState,
    scope: Option<&CallScope>,
) -> Option<Arc<crate::rtpengine::MediaSessionStore>> {
    let root = state.rtpengine_sessions.as_ref()?;
    match scope {
        None => Some(Arc::clone(root)),
        Some(scope) => root.scoped_existing(scope),
    }
}

/// The SIP Call-ID of the offerer's dialog: channel 0 of the split. Falls back
/// to the engine's own call-id for a tag that names no party, so a handler
/// still learns which call the split was on. A scoped leg is looked up in its
/// own scope's store, not the node's.
fn offerer_call_id(
    state: &DispatcherState,
    scope: Option<&CallScope>,
    engine_call_id: &str,
    from_tag: &str,
) -> String {
    let mapped = match scope {
        None => engine_event_channel(state, engine_call_id, from_tag),
        Some(_) => {
            event_store(state, scope).and_then(|store| store.event_party(engine_call_id, from_tag))
        }
    };
    mapped.unwrap_or_else(|| engine_call_id.to_string())
}

pub(super) async fn on_ws_split_started(
    state: &Arc<DispatcherState>,
    started: crate::rtpengine::events::WsSplitStarted,
    scope: Option<CallScope>,
) {
    tracing::debug!(
        call_id = %started.call_id,
        from_tag = %started.from_tag,
        stream_id = %started.stream_id,
        ws_uri = %started.ws_uri,
        sample_rate = started.sample_rate,
        "media engine started a split bridge"
    );
    let call_id = offerer_call_id(state, scope.as_ref(), &started.call_id, &started.from_tag);
    // The call is isolated from here until a detach, whoever attached it: a
    // bridge plan on this leg has to take it off first.
    if let Some(store) = event_store(state, scope.as_ref()) {
        store.set_ws_split_attached(&call_id, true);
    }
    // A scoped leg is a proxy's, which has no channel on the control rail.
    if scope.is_none() {
        publish_ws_split_started(state, &started);
    }
    let engine = Arc::clone(&state.engine);
    if engine
        .state()
        .ws_split_started_handlers(&call_id, &started.from_tag)
        .is_empty()
    {
        return;
    }
    run_event_handler("rtpengine.on_ws_split_started", move || {
        let engine_state = engine.state();
        let handlers = engine_state.ws_split_started_handlers(&call_id, &started.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = crate::script::handler_keyword::call_with_optional_keyword(
                    python,
                    callable,
                    (
                        call_id.as_str(),
                        started.from_tag.as_str(),
                        started.stream_id.as_str(),
                        started.ws_uri.as_str(),
                        started.sample_rate,
                    ),
                    5,
                    "scope",
                    scope.as_ref().map(CallScope::as_str),
                );
                match result {
                    Ok(returned) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &returned) {
                                tracing::error!(
                                    error = %crate::script::error_report::describe(python, &error),
                                    "async rtpengine.on_ws_split_started handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %crate::script::error_report::describe(python, &error),
                            "rtpengine.on_ws_split_started handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}

pub(super) async fn on_ws_split_ended(
    state: &Arc<DispatcherState>,
    ended: crate::rtpengine::events::WsSplitEnded,
    scope: Option<CallScope>,
) {
    let call_id = offerer_call_id(state, scope.as_ref(), &ended.call_id, &ended.from_tag);
    if ended.restores_direct_audio() {
        tracing::debug!(
            call_id = %call_id,
            from_tag = %ended.from_tag,
            stream_id = %ended.stream_id,
            reason = %ended.reason,
            "split bridge ended"
        );
    } else {
        // The engine leaves the call isolated and silent in both directions
        // until a detach, so an end nobody acts on is two people on a dead
        // line: visible here even with no handler registered.
        tracing::warn!(
            call_id = %call_id,
            from_tag = %ended.from_tag,
            stream_id = %ended.stream_id,
            reason = %ended.reason,
            "split bridge ended without a detach: both parties stay isolated and silent until \
             rtpengine.detach_ws_split"
        );
    }
    // Isolation outlives every end but a detach and the call going: the leg
    // stays flagged so a bridge plan still sends its detach.
    if let Some(store) = event_store(state, scope.as_ref()) {
        store.set_ws_split_attached(&call_id, !ended.restores_direct_audio());
    }
    if scope.is_none() {
        publish_ws_split_ended(state, &ended);
    }
    let engine = Arc::clone(&state.engine);
    if engine
        .state()
        .ws_split_ended_handlers(&call_id, &ended.from_tag)
        .is_empty()
    {
        return;
    }
    run_event_handler("rtpengine.on_ws_split_ended", move || {
        let engine_state = engine.state();
        let handlers = engine_state.ws_split_ended_handlers(&call_id, &ended.from_tag);
        pyo3::Python::attach(|python| {
            for handler in handlers {
                let callable = handler.callable.bind(python);
                let result = crate::script::handler_keyword::call_with_optional_keyword(
                    python,
                    callable,
                    (
                        call_id.as_str(),
                        ended.from_tag.as_str(),
                        ended.stream_id.as_str(),
                        ended.reason.as_str(),
                    ),
                    4,
                    "scope",
                    scope.as_ref().map(CallScope::as_str),
                );
                match result {
                    Ok(returned) => {
                        if handler.is_async {
                            if let Err(error) = run_coroutine(python, &returned) {
                                tracing::error!(
                                    error = %crate::script::error_report::describe(python, &error),
                                    "async rtpengine.on_ws_split_ended handler error"
                                );
                            }
                        }
                    }
                    Err(error) => {
                        tracing::error!(
                            error = %crate::script::error_report::describe(python, &error),
                            "rtpengine.on_ws_split_ended handler failed"
                        );
                    }
                }
            }
        });
    })
    .await;
}
