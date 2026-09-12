//! Periodic cleanup of state no message will clear.
//!
//! A dialog whose BYE never arrived, a call actor orphaned by a crashed peer:
//! anything keyed by a live entity needs an age-out or it is a leak.

use super::*;

/// Backstop TTL for call-lifetime stores (rtpengine sessions, B2BUA call
/// actors, proxy Rf charging sessions, SIPREC recordings).
///
/// Normal calls reap their entries on BYE / teardown within seconds-to-minutes;
/// this only catches truly-orphaned entries whose teardown path never fired.
/// A call still alive after 24 h is abnormal/nonexistent, so ageing strictly
/// by creation time at this TTL never drops an active call.
pub(super) const ORPHAN_CALL_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Sweep stale proxy sessions.
pub(super) async fn sweep_stale_entries(state: &DispatcherState) {
    let now = std::time::Instant::now();
    let ttl = state.transaction_timeout;
    // Timer I (T4) is the ACK-absorption window (RFC 3261 §17.2.1), which is
    // all a dialog owes once its 2xx ACK has been routed.
    let expired_sessions = state
        .session_store
        .sweep_stale_with_ack_grace(ttl, crate::transaction::timer::DEFAULT_T4)
        as u64;

    // Expire UAC pending requests whose response never arrived. Callers
    // (NAT keepalive, gateway health probe, proxy.send_request) apply a short
    // receiver timeout and drop the receiver, but that does not remove the
    // pending entry — only a matching response or this sweep does. Without it
    // the map grows by one stranded oneshot::Sender per unanswered probe.
    let expired_uac = state.uac_sender.sweep_stale(ttl) as u64;
    let uac_pending = state.uac_sender.pending_count();
    let dialog_sessions = state.session_store.dialog_key_count();
    // Reap expired/abandoned SUBSCRIBE dialogs from the L1 store (L2 expires
    // via its own TTL; L1 has no reaper, so a subscriber that vanishes without
    // an un-SUBSCRIBE would otherwise pin its dialog forever).
    let (expired_subs, subscribe_dialogs) = match crate::subscribe_state::global_store() {
        Some(store) => (store.sweep_stale() as u64, store.local_count()),
        None => (0, 0),
    };

    // ── Orphan backstop sweeps (call-lifetime stores) ──────────────────────
    // These are reaped promptly on BYE for normal calls; the backstop only
    // catches entries whose teardown path never fired. Age strictly by
    // creation with a long TTL so active calls are never disturbed.

    // RTPEngine media sessions — ages by MediaSession::created_at, returns ().
    if let Some(store) = &state.rtpengine_sessions {
        store.sweep_stale(ORPHAN_CALL_TTL);
    }

    // (B2BUA answer-timeout is checked on a dedicated fast interval — see
    // `check_b2bua_answer_timeouts` in the dispatcher loop — so a short per-carrier
    // LCR ring timeout fails over promptly instead of waiting for this 30s sweep.)

    // B2BUA call actors — ages by CallActor::created_at (set once at creation,
    // never refreshed), returns the number reaped.
    let expired_calls = state.call_actors.sweep_stale(ORPHAN_CALL_TTL) as u64;

    // B-leg event receivers — the one call-lifetime store in this function that
    // had no backstop. Every teardown path removes it, but a call whose teardown
    // never reached the dispatcher (and which the sweep above just reaped) left
    // its receiver behind forever, holding up to a full 64-slot channel of
    // `CallEvent`s.
    //
    // It also matters for liveness, not just memory: the leg actors send on that
    // channel with an unbounded `await`, so a full channel parks the actor until
    // *something* drops the receiver. Dropping it here is what guarantees the
    // actor is eventually released (as `Closed`) instead of parking for the life
    // of the process. Keyed on the call still existing rather than on an age, so
    // it catches an orphan from any cause, not only from the sweep above.
    //
    // The brief window in `recv_b_leg_classification_event`, where the receiver
    // is extracted and re-inserted around a blocking recv, can re-add an entry
    // for a call reaped in the same pass; the next sweep collects it.
    let receivers_before = state.call_event_receivers.len();
    state
        .call_event_receivers
        .retain(|call_id, _| state.call_actors.contains_call(call_id));
    let expired_call_events = receivers_before.saturating_sub(state.call_event_receivers.len());
    if expired_call_events > 0 {
        debug!(
            expired_call_events,
            "swept B-leg event receivers whose call is gone"
        );
    }

    // Proxy Rf charging sessions — one Arc may be filed under several keys
    // (storage_keys aliases), so retain on the value's age to drop every alias
    // of an orphan in one pass.
    //
    // Dropping the map entry is not enough on its own: the accounting session
    // owns an ACR-INTERIM timer task and a slot in the `siphon_rf_sessions`
    // gauge, and both outlive the entry. Claim the stop as the entry goes so
    // the timer is aborted and the gauge released here rather than at the
    // charging layer's own 24h backstop.
    let rf_before = state.rf_sessions.len();
    state.rf_sessions.retain(|_, st| {
        let live = now.duration_since(st.created_at) < ORPHAN_CALL_TTL;
        if !live {
            if let Some(charger) = state.rf_charger.as_ref() {
                charger.release_abandoned(st.rf_session());
            }
        }
        live
    });
    let expired_rf = rf_before.saturating_sub(state.rf_sessions.len()) as u64;

    // In-flight ACR-START reservations — released by their own task on every
    // normal exit path; this only reaps one whose task never ran to completion
    // (runtime shutdown mid-flight), so a wedged key can't dedupe every future
    // record for that ICID.
    state
        .rf_pending_starts
        .retain(|_, started| now.duration_since(*started) < ORPHAN_CALL_TTL);

    // Auto-emit CDR sessions — orphan backstop. Normal calls drain on their
    // teardown hook (BYE / failure / cancel / timeout); this only reaps entries
    // whose teardown never reached the dispatcher (e.g. a UA that vanished after
    // answer). Dropped silently rather than emitting a misleading long-duration
    // record — every cleanly-ended call is already accounted by a direct hook.
    let cdr_before = state.cdr_sessions.len();
    state
        .cdr_sessions
        .retain(|_, session| now.duration_since(session.created_at()) < ORPHAN_CALL_TTL);
    let expired_cdr = cdr_before.saturating_sub(state.cdr_sessions.len()) as u64;

    // SIPREC recording sessions — ages by RecordingSession::created_at, and
    // clears the call_sessions / branch_to_session aliases too.
    let expired_recordings = state.recording_manager.sweep_stale(ORPHAN_CALL_TTL) as u64;

    // Expire stale presence documents/subscriptions from the L1 store (no TTL
    // reaper of its own; only removes already-expired entries, so it's safe).
    if let Some(presence) = crate::presence::global_store() {
        presence.expire_stale();
    }

    // Reap expired registrar bindings + emit RegistrationEvent::Expired. Only
    // removes entries whose own `expires` already elapsed, so an actively-
    // refreshing binding (future expires) is never disturbed. In production
    // nothing else calls this, so without it expired AoRs would pin memory
    // until the next REGISTER for the same AoR.
    let expired_registrations = match crate::script::api::registrar_arc() {
        Some(reg) => reg.expire_stale() as u64,
        None => 0,
    };

    // Sweep abandoned P-CSCF IPsec SA pairs whose own hard lifetime + grace
    // has elapsed (tears down the 4 XFRM states + 4 policies + the in-memory
    // entry). An ACTIVE registration re-REGISTERs and reinstalls a fresh SA
    // (new expires_at) before this deadline, so only truly-abandoned UEs are
    // reaped. None when no P-CSCF/ipsec role is configured.
    let (expired_ipsec_sas, ipsec_sa_pairs) = match crate::ipsec::global_manager() {
        Some(manager) => {
            let reaped = manager.sweep_expired_reaped().await;
            // Registrar-liveness Part B.4: an abandoned UE's SA pair just
            // aged out of the kernel — its SIP registration should go with it
            // rather than linger to its own Expires.  Only when liveness is on.
            if state.registrar_liveness.enabled && !reaped.is_empty() {
                liveness_dereg_reaped_sas(state, &reaped).await;
            }
            (reaped.len() as u64, manager.active_count())
        }
        None => (0, 0),
    };

    // Registrar-liveness Part B: UDP+IPsec idle detection (kernel SA use-time
    // poll → one OPTIONS probe → deregister on no answer).  No-op unless
    // enabled and a P-CSCF IPsec role is configured.
    if state.registrar_liveness.enabled {
        sweep_registrar_liveness(state).await;
    }

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.uac_pending_requests.set(uac_pending as i64);
        metrics.proxy_dialog_sessions.set(dialog_sessions as i64);
        metrics.cdr_sessions.set(state.cdr_sessions.len() as i64);
        metrics.subscribe_dialogs.set(subscribe_dialogs as i64);
        metrics.ipsec_sa_pairs.set(ipsec_sa_pairs as i64);
        // Keyed on a value the peer chooses, so its size is worth watching:
        // it should track live dialogs and fall back, never climb.
        if let Some(li) = state.li_manager.as_ref() {
            metrics
                .li_remembered_sessions
                .set(li.remembered_session_count() as i64);
        }

        // Store sizes that are a cheap `len()`. These were declared but never
        // published, so `siphon_transactions_active` reported 0 for the life of
        // the process no matter the load. `/admin/metrics.json` republishes the
        // same three on every poll — a 30 s-stale gauge reads as broken on a
        // dashboard that refreshes every 2 s.
        publish_store_gauges(
            metrics,
            state.transaction_manager.count(),
            state.call_actors.count(),
            dialog_sessions,
        );

        // Carrier burn rate. Iterates the answered calls, so it sits on this
        // 30 s sweep rather than in `publish_store_gauges`, whose contract is
        // O(1) because the admin poll calls it every two seconds.
        crate::metrics::publish_spend_rate(&crate::b2bua::actor::spend_rate_by_currency(
            &state.call_actors,
        ));
    }
    // Published here as well as on the admin poll: a deployment that scrapes
    // Prometheus without ever opening the dashboard was otherwise reading a
    // process uptime of zero.
    crate::metrics::update_uptime();
    // Refresh allocator memory gauges (jemalloc live/resident/retained bytes)
    // so operators can alert on `siphon_memory_allocated_bytes` growth — the
    // precise, RSS-noise-free leak signal.  Also refresh the Python-side block
    // count (jemalloc can't see CPython's allocator) for Python leak detection.
    crate::metrics::update_memory_stats();
    crate::metrics::update_python_stats();
    // Refresh the glibc allocator gauges — the C-side / CPython raw-domain pool
    // that jemalloc and CPython's mimalloc can't see (no-op off glibc).
    crate::metrics::update_glibc_stats();

    if expired_sessions > 0
        || expired_uac > 0
        || expired_subs > 0
        || expired_calls > 0
        || expired_rf > 0
        || expired_recordings > 0
        || expired_registrations > 0
        || expired_ipsec_sas > 0
        || expired_cdr > 0
    {
        info!(
            expired_sessions,
            expired_uac,
            expired_subs,
            expired_calls,
            expired_rf,
            expired_cdr,
            expired_recordings,
            expired_registrations,
            expired_ipsec_sas,
            uac_pending,
            sessions = state.session_store.session_count(),
            transactions = state.transaction_manager.count(),
            "stale entry cleanup"
        );
    }
}
