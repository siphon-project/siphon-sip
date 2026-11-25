//! Clearing the bindings a hard-killed process left on its registrars.
//!
//! A process that was killed without its shutdown de-registration (see
//! [`super::lifecycle`]) leaves each binding it held on the registrar until it
//! expires. When the lease on a trunk moved to another node meanwhile, the
//! restarted node does not list the trunk any more and so nothing in memory
//! says the binding exists: the registrar then holds the dead contact beside
//! the live one for up to a whole interval. [`super::persist`] keeps what is
//! needed to find them again; this module acts on it once the process can.
//!
//! **When.** Once, after all of: the source's first successful read (so "no
//! longer listed" is a fact and not an outage), the egress and transaction
//! layer being in place (so a REGISTER can leave), and the store being attached
//! (Redis may come up after boot). In any order: [`RegistrantManager::startup_ready`].
//!
//! **What, per stored binding.**
//! - A live entry registers the same contact on the same registrar and has not
//!   sent anything yet: it takes over the binding's Call-ID and CSeq
//!   ([`RegistrantEntry::carry_binding_from`]'s rule, RFC 3261 §10.2.4), so its
//!   REGISTER refreshes the binding instead of adding a second one.
//! - A live entry that already registered the same contact has replaced the
//!   binding (§10.3: same contact, new Call-ID, is an update): left alone.
//! - Anything else is an orphan: a de-REGISTER (`Expires: 0`, §10.2.2) on the
//!   stored contact, the stored Call-ID and the next CSeq, queued as a removed
//!   entry's is ([`super::removed`]), so its challenge, Timer F and the sweep
//!   are handled there and the record is dropped at each way it ends.
//! - A binding of a row the source returned but siphon rejected counts as
//!   still listed: it is left, which is the safe side.
//!
//! A challenge to an orphan's de-REGISTER needs credentials the record does not
//! hold; they come from the source's lookup by AoR (see
//! [`super::source::CredentialLookup`]).

use std::collections::HashSet;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use super::persist::{unix_now, BindingRecord, BindingStore, MAX_STARTUP_ATTEMPTS};
use super::{
    default_contact_uri, AuthMode, EgressDefaults, RegistrantCredentials, RegistrantEntry,
    RegistrantManager, RegistrantState,
};

/// CSeqs skipped past the stored one. A REGISTER that was in flight (and its
/// challenged retry) when the process died used CSeqs the record never saw; the
/// registrar would refuse a de-REGISTER that does not outrank them (RFC 3261
/// §10.3 step 6). A gap in CSeq is legal, a repeat is not.
const CSEQ_HEADROOM: u32 = 4;

/// How often the start-up task looks at its conditions again.
const POLL: Duration = Duration::from_millis(200);

/// How long the task waits before saying it is still waiting.
const WAIT_NOTICE: Duration = Duration::from_secs(60);

/// What the restart clean-up keeps on the manager.
#[derive(Default)]
pub(super) struct RestartState {
    /// Where each granted binding is kept, so a restart can clear the ones this
    /// process leaves behind (see [`super::persist`]). Attached when the
    /// registrar's Redis is up, which may be after boot.
    pub(super) bindings: std::sync::OnceLock<Arc<BindingStore>>,
    /// The source was read once (or there is none).
    pub(super) source_loaded: std::sync::atomic::AtomicBool,
    /// Rows the source returned that siphon could not use.
    pub(super) source_unusable: std::sync::Mutex<HashSet<String>>,
    /// Looks credentials up by AoR for the challenge to a restart's
    /// de-REGISTER (see [`super::source::CredentialLookup`]).
    pub(super) credential_lookup: std::sync::OnceLock<Arc<dyn super::source::CredentialLookup>>,
}

/// What one start-up cleanup did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    /// Bindings a live entry took over.
    pub carried: usize,
    /// Orphans a de-REGISTER was queued for.
    pub deregistered: usize,
    /// Bindings left alone (replaced by a live REGISTER, or of a rejected row).
    pub left: usize,
    /// Records dropped without a de-REGISTER: attempts used up, an entry the
    /// de-REGISTER cannot be built for.
    pub dropped: usize,
}

impl RegistrantManager {
    /// Attach the store the bindings are kept in, and write what is registered
    /// already (a store that connected after the first REGISTERs). Only the
    /// first attach counts.
    pub fn attach_binding_store(&self, store: Arc<BindingStore>) {
        if self.restart.bindings.set(Arc::clone(&store)).is_err() {
            return;
        }
        for entry in self.entries.iter() {
            let remaining = entry
                .binding_until
                .and_then(|until| until.checked_duration_since(Instant::now()))
                .map(|remaining| remaining.as_secs());
            if let Some(record) = remaining.and_then(|secs| self.binding_record(&entry, secs)) {
                store.save(record);
            }
        }
    }

    /// The persisted form of `entry`'s binding, granted for `granted_secs`.
    /// `None` for an entry that cannot be cleared this way: an AKA or IPsec one
    /// (see [`super::removed`]), or one that has sent no REGISTER.
    pub(super) fn binding_record(
        &self,
        entry: &RegistrantEntry,
        granted_secs: u64,
    ) -> Option<BindingRecord> {
        let store = self.restart.bindings.get()?;
        // Shutdown clears the binding itself (see `lifecycle`); AKA and IPsec entries have
        // their own path (see `removed`).
        let shutting_down = entry.deregistration != super::Deregistration::NotStarted;
        if shutting_down || entry.auth_mode != AuthMode::Digest || entry.ue_ipsec.is_some() {
            return None;
        }
        Some(BindingRecord {
            instance: store.instance_id().to_string(),
            aor: entry.aor.clone(),
            registrar_uri: entry.registrar_uri.clone(),
            destination: entry.destination,
            address_str: entry.address_str.clone(),
            transport: entry.transport,
            contact: entry.sent_contact.clone()?,
            call_id: entry.call_id.clone(),
            next_cseq: entry.cseq.load(Ordering::Relaxed),
            local_addr: entry.local_addr,
            interval_secs: entry.interval_secs,
            binding_until_unix: unix_now().saturating_add(granted_secs),
            origin: entry.origin,
            attempts: 0,
        })
    }

    /// Store the binding `entry` was just granted for `granted_secs`, when there
    /// is a store. Never waits: the write is queued.
    pub(super) fn persist_granted(&self, entry: &RegistrantEntry, granted_secs: u64) {
        if let (Some(record), Some(store)) = (
            self.binding_record(entry, granted_secs),
            self.restart.bindings.get(),
        ) {
            store.save(record);
        }
    }

    /// The record of a removed `entry` whose de-REGISTER nothing tracks: no
    /// answer or Timer F will drop it, so it goes now.
    pub(super) fn forget_untracked_binding_record(&self, entry: &RegistrantEntry) {
        if !self.draining_deregistrations.contains_key(&entry.call_id) {
            self.forget_binding_record(&entry.aor, &entry.call_id);
        }
    }

    /// Drop the stored binding of `aor`, which the registration `call_id`
    /// owned. Not when a live entry of the AoR has another Call-ID: that one
    /// owns the record now.
    pub(super) fn forget_binding_record(&self, aor: &str, call_id: &str) {
        let Some(store) = self.restart.bindings.get() else {
            return;
        };
        let replaced = self
            .entries
            .get(aor)
            .is_some_and(|entry| entry.call_id != call_id);
        if !replaced {
            store.remove(aor);
        }
    }

    /// The source was read for the first time (or there is none): "no longer
    /// listed" means something from here on.
    pub fn mark_source_loaded(&self) {
        self.restart.source_loaded.store(true, Ordering::SeqCst);
    }

    /// The AoRs of rows the source returned and siphon could not use. Replaced
    /// by each reconcile pass.
    pub fn set_source_unusable(&self, aors: HashSet<String>) {
        match self.restart.source_unusable.lock() {
            Ok(mut current) => *current = aors,
            Err(poisoned) => *poisoned.into_inner() = aors,
        }
    }

    pub(super) fn source_row_unusable(&self, aor: &str) -> bool {
        match self.restart.source_unusable.lock() {
            Ok(current) => current.contains(aor),
            Err(poisoned) => poisoned.into_inner().contains(aor),
        }
    }

    /// Whether the start-up cleanup may run: the source was read, a REGISTER
    /// can leave, and the store is attached. In any order.
    pub fn startup_ready(&self) -> bool {
        self.restart.source_loaded.load(Ordering::SeqCst)
            && self.egress.get().is_some()
            && self.transactions.get().is_some()
            && self.restart.bindings.get().is_some()
    }

    /// Act on `records`, the bindings the process before this one left (see
    /// the module). Never blocks.
    pub fn startup_cleanup(
        &self,
        records: Vec<BindingRecord>,
        defaults: EgressDefaults<'_>,
    ) -> CleanupReport {
        let mut report = CleanupReport::default();
        let Some(store) = self.restart.bindings.get() else {
            return report;
        };
        for record in records {
            if self.is_shutting_down() {
                break;
            }
            if record.attempts >= MAX_STARTUP_ATTEMPTS {
                warn!(
                    aor = %record.aor,
                    registrar = %record.registrar_uri,
                    attempts = record.attempts,
                    "restart clean-up: giving up on a binding, it is left to expire"
                );
                store.remove(&record.aor);
                report.dropped += 1;
                continue;
            }
            if self.source_row_unusable(&record.aor) {
                debug!(aor = %record.aor, "restart clean-up: the source's row is unusable, binding left alone");
                report.left += 1;
                continue;
            }
            match self.adopt_or_orphan(&record, defaults) {
                Outcome::Carried => report.carried += 1,
                Outcome::Left => report.left += 1,
                Outcome::Dropped => {
                    store.remove(&record.aor);
                    report.dropped += 1;
                }
                Outcome::Orphan => {
                    if self.deregister_orphan(&record, defaults) {
                        let mut attempted = record.clone();
                        attempted.attempts += 1;
                        store.save(attempted);
                        report.deregistered += 1;
                    } else {
                        store.remove(&record.aor);
                        report.dropped += 1;
                    }
                }
            }
        }
        report
    }

    /// What a stored binding is to the live entries.
    fn adopt_or_orphan(&self, record: &BindingRecord, defaults: EgressDefaults<'_>) -> Outcome {
        let Some(mut live) = self.entries.get_mut(&record.aor) else {
            return Outcome::Orphan;
        };
        if live.auth_mode != AuthMode::Digest || live.ue_ipsec.is_some() {
            return Outcome::Dropped;
        }
        // The live entry's own record (it registered, and wrote it).
        if live.call_id == record.call_id {
            return Outcome::Left;
        }
        let contact = live.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(
                &live.credentials.username,
                super::messages::EntryEgress::of(&live, defaults).sent_by,
                live.transport,
            )
        });
        let same_target = live.registrar_uri == record.registrar_uri
            && live.destination == record.destination
            && live.transport == record.transport
            && contact == record.contact;
        if !same_target {
            return Outcome::Orphan;
        }
        let untouched = live.state == RegistrantState::Unregistered
            && live.in_flight_branch.is_none()
            && live.binding_until.is_none()
            && live.expires_at.is_none()
            && !live.register_unanswered
            && live.deregistration == super::Deregistration::NotStarted;
        if !untouched {
            // Registered since, on the same contact: that REGISTER replaced it.
            return Outcome::Left;
        }
        live.call_id = record.call_id.clone();
        live.cseq = AtomicU32::new(record.next_cseq.saturating_add(CSEQ_HEADROOM));
        live.binding_until =
            Some(Instant::now() + Duration::from_secs(record.remaining_secs(unix_now())));
        info!(
            aor = %record.aor,
            "restart clean-up: the entry takes over the binding the last process held"
        );
        Outcome::Carried
    }

    /// Queue the de-REGISTER of the binding `record` describes. `false` when it
    /// cannot be built.
    fn deregister_orphan(&self, record: &BindingRecord, defaults: EgressDefaults<'_>) -> bool {
        // What the challenge will be answered with is looked up, never stored:
        // these are placeholders no REGISTER is built from before the lookup.
        let mut copy = RegistrantEntry::new(
            record.aor.clone(),
            record.registrar_uri.clone(),
            record.destination,
            record.transport,
            RegistrantCredentials::password(String::new(), String::new(), None),
            record.interval_secs,
            Some(record.contact.clone()),
        );
        copy.address_str = record.address_str.clone();
        copy.call_id = record.call_id.clone();
        copy.cseq = AtomicU32::new(record.next_cseq.saturating_add(CSEQ_HEADROOM));
        copy.origin = record.origin;
        let Some(built) = self.build_unprotected_register(&mut copy, defaults, 0, None) else {
            warn!(
                aor = %record.aor,
                registrar = %record.registrar_uri,
                "restart clean-up: the de-REGISTER cannot be built, binding left to expire"
            );
            return false;
        };
        info!(
            aor = %record.aor,
            registrar = %record.registrar_uri,
            call_id = %record.call_id,
            "restart clean-up: de-registering a binding the last process left"
        );
        self.queue_startup_deregistration(copy, built);
        true
    }
}

enum Outcome {
    Carried,
    Left,
    Dropped,
    Orphan,
}

impl RegistrantManager {
    /// Install the lookup a challenge to a restart's de-REGISTER is answered
    /// from. Only the first counts.
    pub fn set_credential_lookup(&self, lookup: Arc<dyn super::source::CredentialLookup>) {
        let _ = self.restart.credential_lookup.set(lookup);
    }

    /// Look the credentials of `request`'s AoR up and answer its challenge with
    /// them: the authenticated de-REGISTER is queued for the loop to send (the
    /// path every removed entry's de-REGISTER takes). Without credentials the
    /// de-registration ends and the binding is left to expire.
    pub async fn complete_credential_lookup(self: Arc<Self>, request: super::CredentialRequest) {
        let outcome = match self.restart.credential_lookup.get() {
            Some(lookup) => match lookup.lookup(&request.aor).await {
                Ok(Some(row)) => super::source::credentials_from_row(&row).map(Some),
                Ok(None) => Ok(None),
                Err(error) => Err(error),
            },
            None => Err("no credential lookup is configured".to_string()),
        };
        let Some(egress) = self.egress.get() else {
            return;
        };
        if let super::RemovedAnswer::Retry(built) =
            self.answer_after_lookup(&request, outcome, egress.defaults())
        {
            self.push_pending_deregistration(*built);
        }
    }
}

/// Run the start-up cleanup once its conditions hold (see the module). Returns
/// when it has run, or at shutdown.
pub async fn run_startup_cleanup(manager: Arc<RegistrantManager>) {
    let started = Instant::now();
    let mut noticed = false;
    loop {
        if manager.is_shutting_down() {
            return;
        }
        if manager.restart.bindings.get().is_none() {
            if let Some(store) = super::persist::published_store() {
                manager.attach_binding_store(store);
            }
        }
        if manager.startup_ready() {
            break;
        }
        if !noticed && started.elapsed() >= WAIT_NOTICE {
            noticed = true;
            warn!(
                source_loaded = manager.restart.source_loaded.load(Ordering::SeqCst),
                store_attached = manager.restart.bindings.get().is_some(),
                "restart clean-up of the last process's bindings is still waiting"
            );
        }
        tokio::time::sleep(POLL).await;
    }
    let Some(store) = manager.restart.bindings.get().cloned() else {
        return;
    };
    let mut records = None;
    for attempt in 1..=6u32 {
        match store.load().await {
            Ok(loaded) => {
                records = Some(loaded);
                break;
            }
            Err(error) => {
                error!(%error, attempt, "restart clean-up: the stored bindings cannot be read");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }
    let (Some(records), Some(egress)) = (records, manager.egress.get()) else {
        return;
    };
    let stored = records.len();
    let report = manager.startup_cleanup(records, egress.defaults());
    info!(
        stored,
        carried = report.carried,
        deregistered = report.deregistered,
        left = report.left,
        dropped = report.dropped,
        "restart clean-up of the last process's bindings"
    );
    // The key every record is under: written before the task ends.
    store.flush(Duration::from_secs(5)).await;
}

#[cfg(test)]
#[path = "startup_tests.rs"]
mod tests;
