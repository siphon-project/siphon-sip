//! The shutdown tail: signal → de-register → drain → end what is left → exit.
//!
//! Split out of `server/mod.rs`, which is one long `run_async`. This is the part
//! that runs once the node has stopped being useful, and the only part with a
//! contract an operator has to configure around: the container runtime's stop
//! timeout must exceed `drain_secs + teardown_secs`, and 25 seconds when the
//! registrant has bindings to clear (its de-REGISTERs get up to 20 seconds to
//! be answered, counted from the signal and overlapping the drain, and the IMS
//! UE security associations left up to 5 more to be deleted), or its `SIGKILL`
//! lands first and none of it happens.

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
    shut_down(config, drain, shutdown_registrant, shutdown_outbound).await;

    dispatcher_handle.abort();
    let _ = dispatcher_handle.await;

    std::process::exit(0);
}

/// Everything shutdown does between the signal and the exit: clear the
/// outbound bindings, drain, end the calls the deadline is still holding, wait
/// (bounded) for the de-registrations to end, and delete the IMS UE security
/// associations left. The dispatcher runs on throughout, so the answers to the
/// de-REGISTERs (a challenge among them) are handled.
pub(crate) async fn shut_down(
    config: &Config,
    drain: &Arc<crate::dispatcher::DrainState>,
    shutdown_registrant: Option<&Arc<crate::registrant::RegistrantManager>>,
    shutdown_outbound: &Arc<crate::transport::OutboundRouter>,
) {
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
    // The IMS UE SA sets those de-REGISTERs rode go once they are answered,
    // or after this, whichever comes first (deleted below, before exit).
    let sa_answers_by = tokio::time::Instant::now() + crate::registrant::SHUTDOWN_ANSWER_WAIT;

    drain_and_end(config, drain).await;

    // Before the dispatcher goes: it delivers the de-REGISTER answers that
    // release the IMS UE SA sets. Bounded, so it never holds the exit.
    if let Some(manager) = shutdown_registrant {
        // The de-REGISTERs ran on through the drain; what is left gets until
        // the answer bound.
        if !crate::registrant::await_deregistrations(manager, sa_answers_by).await {
            warn!("outbound de-registrations still unanswered at the shutdown bound");
        }
        let deleted =
            crate::registrant::retire_ue_security_associations(manager, sa_answers_by).await;
        if deleted > 0 {
            info!(
                pairs = deleted,
                "deleted the IMS UE security associations left at shutdown"
            );
        }
    }

    // Last, once nothing above needs a Diameter peer any more: tell every
    // peer why the connections go (RFC 6733 section 5.4), so none of them
    // reads a silent close as a failure. Bounded by the configured DPA wait,
    // so a dead peer does not hold the exit.
    if let Some(diameter) = config.diameter.as_ref() {
        disconnect_diameter_peers(diameter.disconnect_timeout_ms).await;
    }
}

/// Send every open Diameter connection a Disconnect-Peer-Request with cause
/// REBOOTING and wait, up to `disconnect_timeout_ms` (plus a little for the
/// close), for the answers.
async fn disconnect_diameter_peers(disconnect_timeout_ms: u64) {
    let bound = std::time::Duration::from_millis(disconnect_timeout_ms.saturating_add(500));
    match tokio::time::timeout(
        bound,
        crate::diameter::lifecycle::disconnect_all(
            crate::diameter::lifecycle::DisconnectCause::Rebooting,
        ),
    )
    .await
    {
        Ok(summary) => info!(
            answered = summary.answered,
            unanswered = summary.unanswered,
            "disconnected the Diameter peers"
        ),
        Err(_) => warn!("the Diameter peers did not all disconnect within the bound"),
    }
}

/// The drain: stop taking new work, wait (bounded by `server.drain_secs`) for
/// transactions, calls and the lifecycle participants' outstanding work, then at
/// the deadline end the calls still up and force the participants.
///
/// Participants hear `set_draining(true)` even when the drain is disabled
/// (`drain_secs: 0`), and are forced at once in that case: there is no time to
/// wait for them.
pub(crate) async fn drain_and_end(config: &Config, drain: &Arc<crate::dispatcher::DrainState>) {
    let drain_secs = config.server.as_ref().map(|s| s.drain_secs).unwrap_or(30);

    if drain_secs > 0 {
        // Stop accepting new INVITEs; let in-flight transactions and B2BUA
        // calls finish for up to drain_secs.
        drain
            .is_draining
            .store(true, std::sync::atomic::Ordering::SeqCst);
        drain.participants.set_draining(true);
        let (initial_tx, initial_calls) = drain.active_counts();
        info!(
            drain_secs,
            active_transactions = initial_tx,
            active_calls = initial_calls,
            outstanding = drain.participants.outstanding(),
            "draining — refusing new INVITEs while in-flight work completes"
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(drain_secs);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
        tick.tick().await; // burn the immediate first tick
        loop {
            let (txs, calls) = drain.active_counts();
            let outstanding = drain.participants.outstanding();
            if txs == 0 && calls == 0 && outstanding == 0 {
                info!("drain complete — all in-flight work finished");
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                warn!(
                    active_transactions = txs,
                    active_calls = calls,
                    outstanding,
                    "drain timeout — ending the calls still up"
                );
                end_surviving_calls(config, drain).await;
                drain.participants.force();
                break;
            }
            tick.tick().await;
        }
    } else {
        info!("shutting down (drain disabled)");
        drain.participants.set_draining(true);
        drain.participants.force();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::test_support::FakeParticipant;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    fn config(drain_secs: u64) -> Config {
        Config::from_str(&format!(
            concat!(
                "listen:\n  udp: [\"192.0.2.1:5060\"]\n",
                "domain:\n  local: [\"example.com\"]\n",
                "server:\n  drain_secs: {}\n  teardown_secs: 0\n",
            ),
            drain_secs
        ))
        .expect("a config")
    }

    /// No participant: the drain ends at once, as before.
    #[tokio::test(start_paused = true)]
    async fn drain_without_participants_ends_at_once() {
        let drain = Arc::new(crate::dispatcher::DrainState::new());
        let started = tokio::time::Instant::now();
        drain_and_end(&config(30), &drain).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(drain.is_draining.load(Ordering::SeqCst));
    }

    /// Participants hear the drain, and the exit is held until their work is gone.
    #[tokio::test(start_paused = true)]
    async fn drain_waits_for_participant_outstanding() {
        let drain = Arc::new(crate::dispatcher::DrainState::new());
        let first = FakeParticipant::with_outstanding(2);
        let second = FakeParticipant::with_outstanding(1);
        drain.participants.register(first.clone());
        drain.participants.register(second.clone());

        let releaser = {
            let first = first.clone();
            let second = second.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                first.outstanding.store(0, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_secs(2)).await;
                second.outstanding.store(0, Ordering::SeqCst);
            })
        };
        let started = tokio::time::Instant::now();
        drain_and_end(&config(30), &drain).await;
        let elapsed = started.elapsed();
        releaser.await.expect("releaser");

        assert!(elapsed >= Duration::from_secs(5), "left early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(7), "overran: {elapsed:?}");
        for participant in [&first, &second] {
            assert_eq!(participant.draining_calls.load(Ordering::SeqCst), 1);
            assert!(participant.draining.load(Ordering::SeqCst));
            assert_eq!(participant.forced.load(Ordering::SeqCst), 0);
        }
    }

    /// Work that never ends is forced at the deadline, once per participant.
    #[tokio::test(start_paused = true)]
    async fn drain_forces_participants_at_the_deadline() {
        let drain = Arc::new(crate::dispatcher::DrainState::new());
        let stuck = FakeParticipant::with_outstanding(4);
        let idle = FakeParticipant::with_outstanding(0);
        drain.participants.register(stuck.clone());
        drain.participants.register(idle.clone());

        let started = tokio::time::Instant::now();
        drain_and_end(&config(2), &drain).await;
        let elapsed = started.elapsed();

        assert!(elapsed >= Duration::from_secs(2), "left early: {elapsed:?}");
        assert!(elapsed < Duration::from_secs(3), "overran: {elapsed:?}");
        assert_eq!(stuck.forced.load(Ordering::SeqCst), 1);
        assert_eq!(idle.forced.load(Ordering::SeqCst), 1);
    }

    /// `drain_secs: 0` skips the wait: participants are told, then forced.
    #[tokio::test(start_paused = true)]
    async fn disabled_drain_still_informs_and_forces_participants() {
        let drain = Arc::new(crate::dispatcher::DrainState::new());
        let stuck = FakeParticipant::with_outstanding(4);
        drain.participants.register(stuck.clone());
        let started = tokio::time::Instant::now();
        drain_and_end(&config(0), &drain).await;
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(stuck.draining.load(Ordering::SeqCst));
        assert_eq!(stuck.forced.load(Ordering::SeqCst), 1);
    }
}
