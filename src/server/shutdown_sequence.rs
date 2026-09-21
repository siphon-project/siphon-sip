//! The shutdown tail: signal → de-register → drain → end what is left → exit.
//!
//! Split out of `server/mod.rs`, which is one long `run_async`. This is the part
//! that runs once the node has stopped being useful, and the only part with a
//! contract an operator has to configure around: the container runtime's stop
//! timeout must exceed `drain_secs + teardown_secs`, or its `SIGKILL` lands
//! first and none of it happens.

use super::*;

/// Drain, then end the calls the deadline is still holding, then exit.
///
/// Never returns: it calls `std::process::exit(0)`.
pub(super) async fn run_shutdown_sequence(
    config: &Config,
    drain: &Arc<crate::dispatcher::DrainState>,
    shutdown_registrant: Option<&Arc<crate::registrant::RegistrantManager>>,
    shutdown_outbound: &Arc<crate::transport::OutboundRouter>,
    dispatcher_handle: tokio::task::JoinHandle<()>,
) -> ! {
    // Wait for shutdown signal (SIGINT or SIGTERM)
    shutdown::wait_for_signal().await;

    // Clear this node's outbound bindings before draining, so an upstream
    // registrar stops offering calls to a node that is going away rather
    // than waiting out the granted Expires (RFC 3261 §10.2.2). Done here
    // rather than in the registration loop: the loop sleeps in 5-second
    // ticks and would be racing `std::process::exit` below.
    if let Some(manager) = shutdown_registrant {
        let sent = crate::registrant::deregister_all(manager, shutdown_outbound);
        if sent > 0 {
            info!(count = sent, "de-registered outbound bindings");
        }
    }

    let drain_secs = config.server.as_ref().map(|s| s.drain_secs).unwrap_or(30);

    if drain_secs > 0 {
        // Stop accepting new INVITEs; let in-flight transactions and B2BUA
        // calls finish for up to drain_secs.
        drain
            .is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (initial_tx, initial_calls) = drain.active_counts();
        info!(
            drain_secs,
            active_transactions = initial_tx,
            active_calls = initial_calls,
            "draining — refusing new INVITEs while in-flight work completes"
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
        tick.tick().await; // burn the immediate first tick
        loop {
            let (txs, calls) = drain.active_counts();
            if txs == 0 && calls == 0 {
                info!("drain complete — all in-flight work finished");
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    active_transactions = txs,
                    active_calls = calls,
                    "drain timeout — ending the calls still up"
                );
                end_surviving_calls(config, drain).await;
                break;
            }
            tick.tick().await;
        }
    } else {
        info!("shutting down (drain disabled)");
    }

    dispatcher_handle.abort();
    let _ = dispatcher_handle.await;

    std::process::exit(0);
}

/// End the B2BUA calls the drain deadline is still holding, and wait for the
/// charging stops and media deletes their teardown spawns.
///
/// `server.teardown_secs: 0` restores the pre-1.9.2 behaviour exactly: exit at
/// the deadline, tearing nothing down.
///
/// **Proxy-mode calls are not covered, and cannot be.** `ProxySession` is
/// transaction state, not dialog state — no callee To-tag, no remote target, no
/// route set, no CSeq — so there is nothing an in-dialog BYE could be built
/// from, and `active_counts()` reports no calls on a pure proxy node at all.
/// Giving the proxy a BYE-capable dialog store is a feature in its own right.
async fn end_surviving_calls(config: &Config, drain: &Arc<crate::dispatcher::DrainState>) {
    let teardown_secs = config
        .server
        .as_ref()
        .map(|server| server.teardown_secs)
        .unwrap_or(5);
    if teardown_secs == 0 {
        return;
    }
    let report = crate::dispatcher::b2bua::shutdown::tear_down_surviving_calls();
    let drained = crate::dispatcher::b2bua::shutdown::await_teardown(
        drain,
        std::time::Duration::from_secs(teardown_secs),
    )
    .await;
    info!(
        calls_ended = report.calls_ended,
        rejected = report.rejected,
        already_ending = report.already_ending,
        teardown_secs,
        drained,
        "shutdown teardown complete"
    );
}
