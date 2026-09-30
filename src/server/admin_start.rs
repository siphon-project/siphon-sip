//! Startup of the HTTP admin API.
//!
//! Split out of `server/mod.rs` to keep that file inside its size budget. The
//! rule this file carries: an admin API that was asked for and cannot run ends
//! the process, rather than leaving it up and reporting healthy without one.

use std::sync::Arc;

use tracing::{error, info, warn};

use crate::dispatcher::DrainState;
use crate::script::engine::ScriptEngine;

/// Start the admin API when `admin:` is configured.
///
/// Spawned from the server so it can share the drain signal: /admin/ready
/// reports 503 while draining. Independent of the Prometheus `metrics`
/// listener (the admin router also serves /metrics for convenience).
pub(super) fn start_admin_api(
    config: &crate::config::Config,
    drain: &Arc<DrainState>,
    engine: &Arc<ScriptEngine>,
) {
    let Some(ref admin_config) = config.admin else {
        return;
    };
    match admin_config.listen.parse::<std::net::SocketAddr>() {
        Ok(listen_addr) => {
            if let Some(registrar) = crate::script::api::registrar_arc() {
                let auth = admin_config.auth.clone().unwrap_or_default();
                let ui_enabled = admin_config
                    .ui
                    .as_ref()
                    .map(|ui| ui.enabled)
                    .unwrap_or(false);
                let instance_id = config
                    .server
                    .as_ref()
                    .and_then(|server| server.instance_id.clone())
                    .or_else(|| std::env::var("HOSTNAME").ok());

                // The log tail publishes signalling-adjacent content
                // (call-ids, numbers, peer addresses), so it is gated on
                // the bearer token regardless of `protect_reads`. With
                // no token there is nothing to gate it with, and
                // enabling it anyway would publish the node's log stream
                // to anyone who can reach the port — so refuse, loudly,
                // rather than silently serving it or silently ignoring
                // the setting.
                let has_token = auth.token.as_ref().is_some_and(|token| !token.is_empty());
                if let Some(ref log_tail) = admin_config.log_tail {
                    if log_tail.enabled && has_token {
                        // `retain_level` was refused at load if it is
                        // not a level, so a `None` here means unset.
                        let retain_level = log_tail
                            .retain_level
                            .as_deref()
                            .and_then(crate::log_tail::parse_level);
                        crate::log_tail::enable(crate::log_tail::LogTailSettings {
                            max_streams: log_tail.max_streams,
                            warn_capacity: log_tail.warn_capacity,
                            retain_level,
                            retain_capacity: log_tail.retain_capacity,
                        });
                        info!(
                            max_streams = log_tail.max_streams,
                            retain_level = retain_level.unwrap_or("WARN"),
                            "admin log tail enabled"
                        );
                    } else if log_tail.enabled {
                        error!(
                            "admin.log_tail.enabled is set but admin.auth.token is not; \
                             refusing to expose the log stream unauthenticated"
                        );
                    }
                }

                if let Some(ref capture) = admin_config.capture {
                    if capture.enabled && has_token {
                        crate::capture::enable(crate::capture::CaptureLimits {
                            max_bytes: capture.max_bytes,
                            max_calls: capture.max_calls,
                            max_messages_per_call: capture.max_messages_per_call,
                            redact_bodies: capture.redact_bodies,
                        });
                        warn!(
                            max_bytes = capture.max_bytes,
                            max_calls = capture.max_calls,
                            redact_bodies = capture.redact_bodies,
                            "SIP message capture enabled — signalling is retained in \
                             memory and readable over the admin API; this is a debugging \
                             facility, not lawful intercept"
                        );
                    } else if capture.enabled {
                        error!(
                            "admin.capture.enabled is set but admin.auth.token is not; \
                             refusing to expose captured signalling unauthenticated"
                        );
                    }
                }

                let admin_state = crate::admin::AdminState {
                    registrar: Arc::clone(registrar),
                    start_time: std::time::Instant::now(),
                    draining: Some(Arc::clone(drain)),
                    auth_token: auth
                        .token
                        .filter(|token| !token.is_empty())
                        .map(|token| std::sync::Arc::from(token.as_str())),
                    protect_reads: auth.protect_reads,
                    instance_id,
                    features: crate::admin::AdminFeatures::from_config(config),
                    script_engine: Some(Arc::clone(engine)),
                    // Overwritten by `router` from its own argument;
                    // set here only to satisfy the initializer.
                    ui_enabled: false,
                };
                // An admin API that cannot listen ends the process
                // rather than leaving it up and reporting healthy
                // without one: the orchestrator's probes and the
                // operator's console both live on this listener, and
                // their absence otherwise shows only as a blank page.
                let cors = admin_config.cors.clone();
                let tls = admin_config.tls.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        crate::admin::serve(listen_addr, admin_state, cors, ui_enabled, tls).await
                    {
                        error!(%listen_addr, "admin API stopped: {error}; exiting");
                        std::process::exit(1);
                    }
                });
            } else {
                error!(
                    "admin.listen is set but the registrar is not initialized, so the \
                     admin API cannot start; exiting"
                );
                std::process::exit(1);
            }
        }
        Err(error) => {
            // Refused at config load; kept so a config built in code
            // (not parsed from YAML) cannot reach here silently.
            error!(listen = %admin_config.listen, "invalid admin.listen address: {error}; exiting");
            std::process::exit(1);
        }
    }
}
