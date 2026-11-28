//! Entries a `registrant.backend` source created, and how long this node keeps
//! registering one after the source stops being readable.
//!
//! Several nodes can share one controller, each trunk leased to one of them
//! and each node served only its own. A node whose controller died but whose
//! siphon is alive keeps the last set it read, and with it a trunk another node
//! has taken over since. At a registrar that keeps one binding per AoR, that
//! node's refresh steals the binding from the node that holds the lease.
//!
//! A row may therefore carry `hold_secs` (see
//! [`RegistrantRow::hold_secs`](super::source::RegistrantRow::hold_secs)): how
//! long after the last good read the node may go on refreshing the trunk. The
//! anchor is that read, on a monotonic clock, and an entry is *stood down* when
//! the source is unreadable now (a read has failed since the last good one) and
//! the hold has run out. A node whose source reads fine is never held back,
//! and a row without `hold_secs` keeps its trunk registered however long the
//! outage lasts, as it always did.
//!
//! Standing down drops the entry **without a de-REGISTER**: what the registrar
//! holds for the AoR is not known to be this node's, and clearing it would
//! take the new holder's binding. The persisted binding record is kept too, so
//! the fetch-first clean-up of a later restart can still clear a binding the
//! registrar lists as this node's Contact. The next good read that serves the
//! row adds it afresh.
//!
//! It is checked wherever a REGISTER could start: on every failed read
//! ([`RegistrantManager::record_source_unreadable`]), when the loop asks what
//! is due, and where the request is built
//! ([`RegistrantManager::refuses_registration`]), so a refresh falling due
//! between two polls cannot slip through.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::time::Instant as MonotonicInstant;
use tracing::{debug, info, warn};

use super::{EntryOrigin, RegistrantEntry, RegistrantEvent, RegistrantManager, RegistrantState};

/// Added to the longest a client transaction can live before a stood-down
/// Call-ID is forgotten.
const TOMBSTONE_MARGIN: Duration = Duration::from_secs(5);

/// When the source was last read, and whether it has failed since.
#[derive(Default)]
pub(super) struct SourceRead(Mutex<ReadState>);

#[derive(Default)]
struct ReadState {
    last_success: Option<MonotonicInstant>,
    /// A read has failed since `last_success`.
    unreadable: bool,
}

impl SourceRead {
    fn state(&self) -> std::sync::MutexGuard<'_, ReadState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl RegistrantManager {
    /// The source was read: the anchor of every hold moves to now, and the
    /// outage, if there was one, is over.
    pub fn record_source_read(&self) {
        let mut state = self.source_read.state();
        state.last_success = Some(MonotonicInstant::now());
        state.unreadable = false;
    }

    /// The source could not be read. Stands down every entry whose hold has run
    /// out and returns how many.
    pub fn record_source_unreadable(&self) -> usize {
        self.source_read.state().unreadable = true;
        self.stand_down_expired()
    }

    /// Whether a hold of `hold_secs` has run out: the source is unreadable now
    /// and the last good read is at least that long ago. Never before a first
    /// good read, which every source-created entry has had.
    fn hold_elapsed(&self, hold_secs: u32) -> bool {
        let state = self.source_read.state();
        state.unreadable
            && state.last_success.is_some_and(|at| {
                MonotonicInstant::now().saturating_duration_since(at)
                    >= Duration::from_secs(u64::from(hold_secs))
            })
    }

    /// Whether `entry` is one a source created whose hold has run out.
    fn held_down(&self, entry: &RegistrantEntry) -> bool {
        entry.origin == EntryOrigin::Source
            && entry
                .hold_secs
                .is_some_and(|hold_secs| self.hold_elapsed(hold_secs))
    }

    /// Stand down every entry whose hold has run out; how many went.
    pub(super) fn stand_down_expired(&self) -> usize {
        // No entry has a hold (and no drain of one is tracked), or the source
        // reads fine: nothing to scan.
        if !self.any_hold() || !self.source_read.state().unreadable {
            return 0;
        }
        #[cfg(test)]
        self.expiry_scans.fetch_add(1, Ordering::Relaxed);
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|entry| self.held_down(entry))
            .map(|entry| entry.aor.clone())
            .collect();
        let stood_down = expired
            .iter()
            .filter(|aor| self.stand_down(aor.as_str()))
            .count();
        self.drop_held_drains();
        stood_down
    }

    /// Drop `aor` without a REGISTER of any kind, if its hold has run out.
    ///
    /// Nothing is queued: no fetch, no `Expires: 0`, and the stored binding
    /// record stays. Only what is local goes: the entry, and the SA sets of an
    /// entry that had them. A REGISTER of it still in flight is answered to no
    /// one (its Call-ID matches nothing), so the answer cannot bring it back.
    pub(super) fn stand_down(&self, aor: &str) -> bool {
        self.stand_down_entry(aor).is_some()
    }

    /// [`stand_down`](Self::stand_down), handing back the entry that went.
    ///
    /// The REGISTER it had in flight is abandoned with its client transaction:
    /// left running, Timer E would go on retransmitting it and a 2xx to that
    /// would refresh a binding another node holds now.
    pub(super) fn stand_down_entry(&self, aor: &str) -> Option<RegistrantEntry> {
        if !self.any_hold() {
            return None;
        }
        let drain_ids = self.drain_ids_of(aor);
        // The Call-IDs are tombstoned before the entry goes, under the entry's
        // lock, so a sender that no longer finds the entry already finds the
        // tombstone: it never sees neither.
        let (_, entry) = self.entries.remove_if(aor, |_, entry| {
            if !self.held_down(entry) {
                return false;
            }
            self.tombstone(entry.call_id.clone());
            for call_id in &drain_ids {
                self.tombstone(call_id.clone());
            }
            #[cfg(test)]
            run_stand_down_hook(&entry.call_id);
            true
        })?;
        self.hold_removed(entry.hold_secs);
        if let Some(branch) = entry.in_flight_branch.as_deref() {
            self.abandon_transaction(branch);
        }
        let mut retired = self.drop_drains_of(&entry.aor);
        retired.push(entry.call_id.clone());
        self.purge_unsent(&retired);
        self.retire_sa_sets(&entry, None);
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics.registrant_source_standdowns_total.inc();
        }
        warn!(
            aor = %entry.aor,
            hold_secs = entry.hold_secs,
            "registrant source unreadable for longer than hold_secs: no longer registering \
             this trunk (nothing is sent; another node may hold the binding)"
        );
        self.emit_event(RegistrantEvent::StoodDown {
            aor: entry.aor.clone(),
        });
        Some(entry)
    }

    /// Whether a REGISTER on `call_id` must not leave: its entry stood down
    /// (the Call-ID is in the tombstone set), or its hold has run out and the
    /// entry is stood down by this very ask. Asked by every send, the first one
    /// and each retransmission.
    ///
    /// A deny-list: a Call-ID nobody has stood down is allowed, whatever else
    /// is known of it, so a deployment without `hold_secs` is never affected
    /// (it never creates a tombstone, and the first line returns for it).
    ///
    /// The window between this check and the request leaving (the transport
    /// queue, a connect in progress, and the moment between the check and the
    /// send itself, at `open_transaction` and Timer E alike) is one accepted
    /// class: stand-down stops new REGISTERs, abandons in-flight transactions
    /// and purges the unsent ones, and what the controller's margin below the
    /// lease covers is that last window.
    pub fn send_refused(&self, call_id: &str) -> bool {
        if !self.any_hold() && !self.tombstones_live.load(Ordering::Relaxed) {
            return false;
        }
        self.stand_down_expired();
        self.stood_down_call_ids
            .get(call_id)
            .is_some_and(|until| *until > Instant::now())
    }

    /// Whether `call_id` is one a stand-down retired (and still remembered).
    pub(super) fn call_id_stood_down(&self, call_id: &str) -> bool {
        self.tombstones_live.load(Ordering::Relaxed)
            && self
                .stood_down_call_ids
                .get(call_id)
                .is_some_and(|until| *until > Instant::now())
    }

    /// How long a stood-down Call-ID is remembered: the longest a client
    /// transaction of the layer can live (Timer F as configured, then Timer K)
    /// and a margin, so no retransmission outlives it.
    fn tombstone_lifetime(&self) -> Duration {
        self.transactions.get().map_or(
            Duration::from_secs(32) + Duration::from_secs(5) + TOMBSTONE_MARGIN,
            |transactions| transactions.transaction_lifetime() + TOMBSTONE_MARGIN,
        )
    }

    fn tombstone(&self, call_id: String) {
        self.stood_down_call_ids
            .insert(call_id, Instant::now() + self.tombstone_lifetime());
        self.tombstones_live.store(true, Ordering::Relaxed);
    }

    /// Whether any live entry has a hold, or a drain of one is tracked.
    fn any_hold(&self) -> bool {
        self.held_entries.load(Ordering::Relaxed) > 0 || self.held_drains.load(Ordering::Relaxed)
    }

    pub(super) fn note_held_drain(&self) {
        self.held_drains.store(true, Ordering::Relaxed);
    }

    /// An entry with this hold became live.
    pub(super) fn hold_added(&self, hold_secs: Option<u32>) {
        if hold_secs.is_some() {
            self.held_entries.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// An entry with this hold left (or lost it).
    pub(super) fn hold_removed(&self, hold_secs: Option<u32>) {
        if hold_secs.is_some() {
            // `fetch_update` is deprecated from Rust 1.99 for `try_update`, which
            // the MSRV does not have. Same operation under either name.
            #[allow(deprecated)]
            let _ = self
                .held_entries
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    Some(count.saturating_sub(1))
                });
        }
    }

    /// Forget the stood-down Call-IDs whose time is over. Called by the loop
    /// every tick; empty for a deployment without holds.
    pub fn sweep_tombstones(&self, now: Instant) {
        if self.tombstones_live.load(Ordering::Relaxed) {
            self.stood_down_call_ids.retain(|_, until| *until > now);
            // Cleared first and set again if anything is left, so a tombstone
            // inserted meanwhile (which sets it after inserting) is never lost.
            self.tombstones_live.store(false, Ordering::Relaxed);
            if !self.stood_down_call_ids.is_empty() {
                self.tombstones_live.store(true, Ordering::Relaxed);
            }
        }
        if self.held_drains.load(Ordering::Relaxed) {
            self.held_drains.store(false, Ordering::Relaxed);
            if self
                .draining_deregistrations
                .iter()
                .any(|draining| draining.entry.hold_secs.is_some())
            {
                self.held_drains.store(true, Ordering::Relaxed);
            }
        }
    }

    /// How many stood-down Call-IDs are remembered.
    pub fn tombstones(&self) -> usize {
        self.stood_down_call_ids.len()
    }

    /// Forget every de-registration still tracked for `aor`, and remember its
    /// Call-ID as stood down: nothing it would send next (an authenticated
    /// retry, the `Expires: 0` after a fetch, a retransmission) may go once the
    /// AoR is stood down. The stored binding record is left.
    fn drop_drains_of(&self, aor: &str) -> Vec<String> {
        let of_aor = self.drain_ids_of(aor);
        for call_id in &of_aor {
            self.tombstone(call_id.clone());
            self.draining_deregistrations.remove(call_id);
        }
        of_aor
    }

    fn drain_ids_of(&self, aor: &str) -> Vec<String> {
        self.draining_deregistrations
            .iter()
            .filter(|draining| draining.entry.aor == aor)
            .map(|draining| draining.key().clone())
            .collect()
    }

    /// Take every request built for these Call-IDs and not yet sent out of the
    /// queues they wait in (the removed entries' de-registrations, and the
    /// restart clean-up's staged ones): a tombstone is forgotten after a
    /// transaction's lifetime, and a request still queued then would go out.
    fn purge_unsent(&self, call_ids: &[String]) {
        let queued = |built: &super::BuiltRegister| {
            built
                .message
                .headers
                .get("Call-ID")
                .is_some_and(|call_id| call_ids.contains(call_id))
        };
        match self.pending_deregistrations.lock() {
            Ok(mut pending) => pending.retain(|built| !queued(built)),
            Err(poisoned) => poisoned.into_inner().retain(|built| !queued(built)),
        }
        match self.restart.staged.lock() {
            Ok(mut staged) => staged.retain(|built| !queued(built)),
            Err(poisoned) => poisoned.into_inner().retain(|built| !queued(built)),
        }
    }

    /// Forget the de-registrations of removed entries whose own hold has run
    /// out, which carry the hold of the entry they were copied from, and
    /// remember their Call-IDs. Every kind of drain is in the one map; an IMS
    /// entry never carries a hold (only a source's digest entry does), so none
    /// of its de-registrations is tracked there to begin with.
    fn drop_held_drains(&self) {
        let held: Vec<String> = self
            .draining_deregistrations
            .iter()
            .filter(|draining| {
                draining.entry.origin == EntryOrigin::Source
                    && draining
                        .entry
                        .hold_secs
                        .is_some_and(|hold_secs| self.hold_elapsed(hold_secs))
            })
            .map(|draining| draining.key().clone())
            .collect();
        for call_id in &held {
            self.tombstone(call_id.clone());
            self.draining_deregistrations.remove(call_id);
        }
        self.purge_unsent(&held);
    }

    /// Whether the entry of `aor` holds the registration `call_id` now.
    pub fn holds_call_id(&self, aor: &str, call_id: &str) -> bool {
        self.entries
            .get(aor)
            .is_some_and(|entry| entry.call_id == call_id)
    }

    /// Whether a REGISTER of `aor` that would register (`expires > 0`) must not
    /// go because the entry's hold has run out. Stands the entry down when so,
    /// so the refusal leaves nothing to retry.
    pub(super) fn refuses_held_down(&self, aor: &str, expires: u32) -> bool {
        if expires == 0 {
            return false;
        }
        let held_down = self
            .entries
            .get(aor)
            .is_some_and(|entry| self.held_down(&entry));
        if held_down {
            self.stand_down(aor);
        }
        held_down
    }

    /// Apply a row's `hold_secs` to its live entry, in place: the hold is not
    /// part of the row's fingerprint, so a change of it alone re-registers
    /// nothing.
    pub fn set_source_hold(&self, aor: &str, hold_secs: Option<u32>) {
        if let Some(mut entry) = self.entries.get_mut(aor) {
            if entry.origin == EntryOrigin::Source && entry.hold_secs != hold_secs {
                self.hold_added(hold_secs);
                self.hold_removed(entry.hold_secs);
                entry.hold_secs = hold_secs;
            }
        }
    }

    /// AoR to source-row fingerprint, for the entries a source created.
    ///
    /// The live half of [`source::reconcile`]. Deliberately excludes YAML and
    /// script entries, so a reconcile can neither update nor remove one.
    pub fn source_fingerprints(&self) -> HashMap<String, u64> {
        self.entries
            .iter()
            .filter(|entry| entry.origin == EntryOrigin::Source)
            .filter_map(|entry| {
                entry
                    .source_fingerprint
                    .map(|fingerprint| (entry.aor.clone(), fingerprint))
            })
            .collect()
    }

    /// Whether an AoR is held by something other than a source, so a reconcile
    /// must leave it alone and say so rather than overwrite it.
    pub fn is_foreign_to_source(&self, aor: &str) -> bool {
        self.entries
            .get(aor)
            .is_some_and(|entry| entry.origin != EntryOrigin::Source)
    }

    /// Replace a source-created entry in place, keeping its registration
    /// identity.
    ///
    /// The upstream registrar should see a refresh of the binding it already
    /// holds, not an unrelated new registration from the same trunk, so the
    /// Call-ID carries over and the CSeq continues instead of restarting at 1
    /// (RFC 3261 §10.2.4 / §8.1.1.5). The entry is marked due immediately, so a
    /// rotated password takes effect on the next tick rather than at the next
    /// refresh interval.
    ///
    /// Returns `false` when the AoR is gone or is not the source's to change.
    pub fn update_from_source(&self, mut entry: RegistrantEntry) -> bool {
        if self.is_shutting_down() {
            return false;
        }
        let aor = entry.aor.clone();
        // Past its hold the old entry is not this node's to replace or clear.
        if self.stand_down(&aor) {
            return false;
        }
        let carried = self.entries.get(&aor).and_then(|existing| {
            (existing.origin == EntryOrigin::Source).then(|| {
                (
                    entry.carry_binding_from(&existing),
                    existing.call_id.clone(),
                )
            })
        });
        let Some((same_target, identity)) = carried else {
            return false;
        };
        // A binding on the registrar (or contact) being replaced is one no
        // REGISTER of the new entry reaches: clear it there, on its own
        // Call-ID, and let the new entry register afresh.
        let deregistration = (!same_target)
            .then(|| self.build_deregistration(&entry.aor))
            .flatten();
        entry.state = RegistrantState::Unregistered;
        entry.next_attempt = Instant::now();

        #[cfg(test)]
        run_update_hook(&entry.aor);

        // Replaced only if the entry looked at is still there: a failed read
        // can stand it down between the look-up and here, and an unconditional
        // insert would bring it back past its hold.
        let replaced = match self.entries.entry(aor.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied)
                if occupied.get().origin == EntryOrigin::Source
                    && occupied.get().call_id == identity =>
            {
                self.hold_added(entry.hold_secs);
                let replaced = occupied.insert(entry);
                self.hold_removed(replaced.hold_secs);
                replaced
            }
            _ => {
                debug!(aor = %aor, "registrant source update dropped: the entry is gone");
                return false;
            }
        };
        info!(aor = %aor, "registrant updated from source");
        // The replacement starts a fresh handshake; the old one's SAs go.
        self.retire_sa_sets(&replaced, None);
        if let Some(message) = deregistration {
            self.queue_removed_deregistration(&replaced, message);
        }
        true
    }
}

/// A test's view between an update's look-up and its replacement, called with
/// the AoR being updated (only when it names the AoR the hook was set for).
#[cfg(test)]
type UpdateHook = std::sync::Arc<dyn Fn() + Send + Sync>;

#[cfg(test)]
pub(crate) static UPDATE_HOOK: Mutex<Option<(String, UpdateHook)>> = Mutex::new(None);

/// A test's view of a stand-down at the moment the entry goes (under its
/// lock), with its Call-ID.
#[cfg(test)]
pub(crate) static STAND_DOWN_HOOK: Mutex<Option<(String, UpdateHook)>> = Mutex::new(None);

#[cfg(test)]
fn run_stand_down_hook(call_id: &str) {
    let hook = STAND_DOWN_HOOK.lock().ok().and_then(|hook| {
        hook.as_ref()
            .filter(|(set_for, _)| set_for == call_id)
            .cloned()
    });
    if let Some((_, hook)) = hook {
        hook();
    }
}

#[cfg(test)]
fn run_update_hook(aor: &str) {
    let hook = UPDATE_HOOK
        .lock()
        .ok()
        .and_then(|hook| hook.as_ref().filter(|(set_for, _)| set_for == aor).cloned());
    if let Some((_, hook)) = hook {
        hook();
    }
}

#[cfg(test)]
impl RegistrantManager {
    /// The source went unreadable `ago` after its last good read, with nothing
    /// stood down: the state a hold is in when it runs out between two checks.
    /// Remember `call_id` as stood down, without anything else happening.
    pub(crate) fn retire_call_id(&self, call_id: &str) {
        self.tombstone(call_id.to_string());
    }

    /// How many times a sweep for hold-elapsed entries actually scanned them.
    pub(crate) fn expiry_scans(&self) -> usize {
        self.expiry_scans.load(Ordering::Relaxed)
    }

    pub(crate) fn source_unreadable_since(&self, ago: Duration) {
        let mut state = self.source_read.state();
        state.last_success = MonotonicInstant::now().checked_sub(ago);
        state.unreadable = true;
    }
}

#[cfg(test)]
#[path = "hold_tests.rs"]
mod tests;
