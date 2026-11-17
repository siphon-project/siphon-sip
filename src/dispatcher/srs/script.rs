//! The `@srs.on_invite` and `@srs.on_session_end` script hooks, run on the
//! Python executor, never on a tokio worker: an attach there parks the worker
//! through every garbage collection's stop-the-world.

use super::*;

/// Run the `@srs.on_invite` handlers on the Python executor. `false` when one
/// declines the recording. An `async def` handler is awaited, with the thread
/// released from the interpreter while its coroutine runs on an asyncio driver.
pub(super) fn run_srs_invite_handlers(
    state: &DispatcherState,
    metadata: crate::script::api::srs::PyRecordingMetadata,
    call_id: &str,
) -> bool {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::SrsOnInvite);
    crate::script::attach::attach(|python| {
        let metadata = match pyo3::Py::new(python, metadata) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(call_id = %call_id, error = %error, "SRS: failed to create PyRecordingMetadata");
                return true; // Accept on error
            }
        };
        for handler in &handlers {
            let returned = handler
                .callable
                .bind(python)
                .call1((metadata.clone_ref(python),))
                .and_then(|returned| {
                    if handler.is_async {
                        crate::script::engine::run_coroutine_value(python, &returned)
                            .map(|value| value.into_bound(python))
                    } else {
                        Ok(returned)
                    }
                });
            match returned {
                Ok(result) => {
                    if let Ok(false) = result.extract::<bool>() {
                        return false;
                    }
                }
                Err(error) => {
                    warn!(call_id = %call_id, error = %crate::script::error_report::describe(python, &error), "SRS: on_invite handler error");
                }
            }
        }
        true
    })
}

/// Run the `@srs.on_session_end` handlers on the Python executor, awaiting an
/// `async def` one.
pub(super) fn run_srs_session_end_handlers(
    state: &DispatcherState,
    session: crate::script::api::srs::PySrsSession,
    call_id: &str,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::SrsOnSessionEnd);
    crate::script::attach::attach(|python| {
        let Ok(session) = pyo3::Py::new(python, session) else {
            return;
        };
        for handler in &handlers {
            let outcome = handler
                .callable
                .bind(python)
                .call1((session.clone_ref(python),))
                .and_then(|returned| {
                    if handler.is_async {
                        crate::script::engine::run_coroutine(python, &returned)
                    } else {
                        Ok(())
                    }
                });
            if let Err(error) = outcome {
                warn!(call_id = %call_id, error = %crate::script::error_report::describe(python, &error), "SRS: on_session_end handler error");
            }
        }
    });
}

/// Whether the `@srs.on_invite` handlers let the recording go ahead. With none
/// registered, it does; a handler that cannot run is taken as accepting, as one
/// that raised is, and the shed is already counted.
pub(super) async fn invite_accepted(
    state: &Arc<DispatcherState>,
    metadata: &crate::siprec::metadata::RecordingMetadata,
    call_id: &str,
) -> bool {
    if state
        .engine
        .state()
        .handlers_for(&HandlerKind::SrsOnInvite)
        .is_empty()
    {
        return true;
    }
    let py_metadata = crate::script::api::srs::PyRecordingMetadata::from_metadata(metadata);
    let job_state = Arc::clone(state);
    let job_call_id = call_id.to_string();
    match crate::script::py_executor::try_run(move || {
        run_srs_invite_handlers(&job_state, py_metadata, &job_call_id)
    })
    .await
    {
        Ok(accepted) => accepted,
        Err(_) => {
            warn!(call_id = %call_id, "SRS: on_invite handler did not run; accepting");
            true
        }
    }
}

/// Run the `@srs.on_session_end` handlers for an ended session, if any.
pub(super) async fn session_ended(
    state: &Arc<DispatcherState>,
    record: &crate::srs::RecordingRecord,
    call_id: &str,
) {
    if state
        .engine
        .state()
        .handlers_for(&HandlerKind::SrsOnSessionEnd)
        .is_empty()
    {
        return;
    }
    let py_session = crate::script::api::srs::PySrsSession::from_record(record);
    let job_state = Arc::clone(state);
    let job_call_id = call_id.to_string();
    if crate::script::py_executor::try_run(move || {
        run_srs_session_end_handlers(&job_state, py_session, &job_call_id);
    })
    .await
    .is_err()
    {
        warn!(call_id = %call_id, "SRS: on_session_end handler did not run");
    }
}
