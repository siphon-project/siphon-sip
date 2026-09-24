//! AF-side listener for the Npcf_PolicyAuthorization callbacks (TS 29.514).
//!
//! A script advertises one base URI, `http://<sbi.notif_listen>/sbi/events`,
//! as `ascReqData.notifUri` and as `ascReqData.evSubsc.notifUri`. The PCF
//! appends a different suffix per callback, so one listener serves both:
//!
//! | Route                        | TS 29.514 callback   | Body                 | Hook                 |
//! |------------------------------|----------------------|----------------------|----------------------|
//! | `POST /sbi/events/notify`    | `eventNotification`  | `EventsNotification` | `@sbi.on_event`      |
//! | `POST /sbi/events/terminate` | `terminationRequest` | `TerminationInfo`    | `@sbi.on_terminate`  |
//!
//! Everything else is 404, including the bare `POST /sbi/events`. That route
//! predated the suffixed ones and served a PCF that posted to the advertised
//! URI without the suffix; it was deprecated in 1.9.0 and removed in 1.10.0.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use crate::script::engine::{HandlerKind, ScriptState};

#[derive(Clone)]
struct CallbackState {
    /// The engine's swappable handler set, read per callback so a hot reload
    /// applies to the next one.
    script_state: Arc<ArcSwap<ScriptState>>,
}

/// The callback routes, dispatching to the handlers in `script_state`.
pub(super) fn router(script_state: Arc<ArcSwap<ScriptState>>) -> Router {
    Router::new()
        .route(
            "/sbi/events/notify",
            post(|State(state): State<CallbackState>, body: Bytes| {
                handle_callback(state, HandlerKind::SbiOnEvent, "sbi.on_event", body)
            }),
        )
        .route(
            "/sbi/events/terminate",
            post(|State(state): State<CallbackState>, body: Bytes| {
                handle_callback(state, HandlerKind::SbiOnTerminate, "sbi.on_terminate", body)
            }),
        )
        .with_state(CallbackState { script_state })
}

/// Bind `address` and serve the callback routes on it.
pub(super) fn spawn_listener(address: SocketAddr, script_state: Arc<ArcSwap<ScriptState>>) {
    let app = router(script_state);
    tokio::spawn(async move {
        match tokio::net::TcpListener::bind(address).await {
            Ok(listener) => {
                info!(
                    %address,
                    "SBI callback listener started on /sbi/events/notify and /sbi/events/terminate"
                );
                if let Err(error) = axum::serve(listener, app).await {
                    error!("SBI callback server failed: {error}");
                }
            }
            Err(error) => {
                error!(%address, "failed to bind SBI callback listener: {error}");
            }
        }
    });
}

async fn handle_callback(
    state: CallbackState,
    kind: HandlerKind,
    decorator: &'static str,
    body: Bytes,
) -> StatusCode {
    // The PCF document is handed to the script verbatim, never projected
    // through a typed struct (see pcf_notification_body_to_json).
    let Some(document) = pcf_notification_body_to_json(&body) else {
        error!(decorator, "PCF callback body was not valid JSON");
        return StatusCode::BAD_REQUEST;
    };
    let script_state = Arc::clone(&state.script_state);
    let outcome = crate::script::py_executor::try_run(move || {
        run_handlers(&script_state, &kind, decorator, &document);
    })
    .await;
    if let Err(payload) = &outcome {
        error!(
            decorator,
            reason = refusal_reason(payload.as_ref()),
            "PCF callback was not dispatched, answering 503"
        );
    }
    status_for_dispatch(&outcome)
}

/// The answer for one dispatch attempt. TS 29.514 acknowledges both callbacks
/// with 204.
///
/// `Ok` means the handlers ran, including one that raised: that exception is
/// logged where it happens, and a retry cannot fix a script bug. `Err` is what
/// `py_executor::try_run` returns when the job did not complete (the executor
/// queue was full or closed, or the job panicked), so the PCF gets a 503 rather
/// than an acknowledgement for a notification no handler saw.
pub(super) fn status_for_dispatch<T>(outcome: &std::thread::Result<T>) -> StatusCode {
    match outcome {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn refusal_reason(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&'static str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("unknown")
}

/// Run every handler registered for `kind` with `document` loaded as a dict.
/// Runs on a Python executor thread.
fn run_handlers(
    script_state: &ArcSwap<ScriptState>,
    kind: &HandlerKind,
    decorator: &'static str,
    document: &str,
) {
    Python::attach(|python| {
        let snapshot = script_state.load();
        let handlers = snapshot.handlers_for(kind);
        if handlers.is_empty() {
            if *kind == HandlerKind::SbiOnTerminate {
                // TS 29.514 expects the AF to delete the app session after a
                // termination; with no hook nothing will.
                warn!(
                    "PCF terminated an app session and no @sbi.on_terminate handler is registered"
                );
            } else {
                debug!(decorator, "no handler registered for PCF callback");
            }
            return;
        }

        let parsed = match python
            .import("json")
            .and_then(|json| json.call_method1("loads", (document,)))
        {
            Ok(parsed) => parsed,
            Err(error) => {
                error!(decorator, %error, "failed to load PCF callback body as a Python dict");
                return;
            }
        };

        for handler in handlers {
            let outcome = match handler.callable.bind(python).call1((&parsed,)) {
                Ok(returned) if handler.is_async => {
                    crate::script::engine::run_coroutine(python, &returned)
                }
                Ok(_) => Ok(()),
                Err(error) => Err(error),
            };
            if let Err(error) = outcome {
                error!(decorator, %error, "PCF callback handler failed");
            }
        }
    });
}

/// Decode a PCF callback body (TS 29.514 `EventsNotification` or
/// `TerminationInfo`) into the JSON string handed verbatim to the script.
///
/// The body is passed through **losslessly**, never projected through a typed
/// Rust struct. `EventsNotification` is large and evolving (`evSubsUri`,
/// `qosMonReports`, `succResourcAllocReports`, `accessType`, `plmnId`, …); a
/// typed model would silently drop every field it doesn't list, including the
/// required `evSubsUri` the script needs to correlate the event with a session,
/// and an unmodelled inner shape (e.g. `flows` = `{medCompN, fNums}`, not
/// `{flowId, …}`) would fail deserialization and `422` the entire callback,
/// dropping the event. Returns `None` only when the body is not well-formed
/// JSON.
pub(super) fn pcf_notification_body_to_json(raw: &[u8]) -> Option<String> {
    // Validate it parses as JSON (rejecting genuine garbage with a 400), then
    // re-emit — every key/value is preserved.
    let value: serde_json::Value = serde_json::from_slice(raw).ok()?;
    serde_json::to_string(&value).ok()
}
