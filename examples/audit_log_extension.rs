//! Example: a minimal host-side extension that reads custom-kind handlers
//! the script registered, and dispatches into each one on startup.
//!
//! Demonstrates the three building blocks of siphon's extension API:
//!   * [`SiphonServer::register_namespace`] — expose a host-provided
//!     `#[pyclass]` so the script can `from siphon import audit`
//!   * [`SiphonServer::register_task`] — spawn a background task that
//!     receives a [`siphon::script::ScriptHandle`]
//!   * [`siphon::script::ScriptHandle::handlers_for`] +
//!     [`siphon::script::ScriptHandle::call_handler`] — snapshot and
//!     dispatch into the script's `audit.sink` handlers
//!
//! See `examples/audit_log_extension.py` for the script side and
//! `examples/audit_log_extension.yaml` for the matching config.
//!
//! Run with:
//!   cargo run --example audit_log_extension

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use siphon::SiphonServer;

/// Host-provided pyclass exposed to scripts as `siphon.audit`.
/// Counts how many audit events the host task has dispatched.
#[pyclass]
struct AuditCounter {
    received: Arc<AtomicU64>,
}

#[pymethods]
impl AuditCounter {
    /// Total audit events the host has dispatched into script handlers.
    fn dispatched(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

fn main() {
    let received = Arc::new(AtomicU64::new(0));
    let counter = AuditCounter {
        received: Arc::clone(&received),
    };

    SiphonServer::builder()
        .config_path("examples/audit_log_extension.yaml")
        .register_namespace("audit", counter)
        .register_task(move |script| {
            let received = Arc::clone(&received);
            let runtime = script.tokio_handle().clone();
            // Spawn the dispatch loop on siphon's tokio runtime.
            runtime.spawn(async move {
                // Snapshot all handlers the script registered under the
                // "audit.sink" kind.
                let handlers = script.handlers_for("audit.sink");
                tracing::info!(count = handlers.len(), "audit handlers discovered");

                // Build a single audit event and dispatch it into each
                // handler. Real extensions would do this on a schedule
                // or in response to external triggers.
                for handler in &handlers {
                    let event = Python::attach(|py| {
                        let dict = PyDict::new(py);
                        dict.set_item("kind", "startup").unwrap();
                        dict.set_item("source", "audit_log_extension").unwrap();
                        dict.into_any().unbind()
                    });
                    match script.call_handler(handler, vec![event]).await {
                        Ok(_) => {
                            received.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "audit handler error");
                        }
                    }
                }
            });
        })
        .run();
}
