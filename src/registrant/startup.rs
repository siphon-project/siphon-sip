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
    /// The Call-ID of the latest record this process wrote for each AoR: a live
    /// registration's record, which a finished clean-up must not delete.
    pub(super) written: std::sync::Mutex<std::collections::HashMap<String, String>>,
    /// Restart de-REGISTERs built and waiting for the checks made just before
    /// they may go (see [`RegistrantManager::release_startup_deregistrations`]).
    pub(super) staged: std::sync::Mutex<Vec<super::BuiltRegister>>,
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
                self.save_tracked(&store, record);
            }
        }
    }

    /// Save a live registration's `record`, remembering it is the live one's.
    fn save_tracked(&self, store: &BindingStore, record: BindingRecord) {
        match self.restart.written.lock() {
            Ok(mut written) => written.insert(record.aor.clone(), record.call_id.clone()),
            Err(poisoned) => poisoned
                .into_inner()
                .insert(record.aor.clone(), record.call_id.clone()),
        };
        store.save(record);
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
            self.save_tracked(store, record);
        }
    }

    /// The record of a removed `entry` whose de-REGISTER nothing tracks: no
    /// answer or Timer F will drop it, so it goes now.
    pub(super) fn forget_untracked_binding_record(&self, entry: &RegistrantEntry) {
        if !self.draining_deregistrations.contains_key(&entry.call_id) {
            self.forget_binding_record(&entry.aor, &entry.call_id);
        }
    }

    /// Drop the stored binding of `aor` that the registration `call_id` owned,
    /// unless a live registration has written a record of its own for the AoR
    /// since (that record is not this one's to delete). A live entry that
    /// merely exists has written nothing.
    pub(super) fn forget_binding_record(&self, aor: &str, call_id: &str) {
        let Some(store) = self.restart.bindings.get() else {
            return;
        };
        let mut written = match self.restart.written.lock() {
            Ok(written) => written,
            Err(poisoned) => poisoned.into_inner(),
        };
        if written.get(aor).is_some_and(|written| written == call_id) {
            written.remove(aor);
        }
        drop(written);
        store.remove_if(aor, call_id);
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
                store.remove_if(&record.aor, &record.call_id);
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
                    store.remove_if(&record.aor, &record.call_id);
                    report.dropped += 1;
                }
                Outcome::Orphan
                    if !self.contact_is_held_here(&record.contact, &record.aor, defaults) =>
                {
                    info!(
                        aor = %record.aor,
                        registrar = %record.registrar_uri,
                        contact = %record.contact,
                        "restart clean-up: the binding's Contact is not exactly a socket this node \
                         registers from, so it may be another node's: left to expire"
                    );
                    store.remove_if(&record.aor, &record.call_id);
                    report.dropped += 1;
                }
                Outcome::Orphan => {
                    if self.deregister_orphan(&record, defaults) {
                        // Guarded by Call-ID: never over a newer registration's record.
                        store.set_attempts_if(&record.aor, &record.call_id, record.attempts + 1);
                        report.deregistered += 1;
                    } else {
                        store.remove_if(&record.aor, &record.call_id);
                        report.dropped += 1;
                    }
                }
            }
        }
        report
    }

    /// The Contact `live`'s REGISTER carries (or will).
    pub(super) fn predicted_contact(
        &self,
        live: &RegistrantEntry,
        defaults: EgressDefaults<'_>,
    ) -> String {
        live.contact_uri.clone().unwrap_or_else(|| {
            default_contact_uri(
                &live.credentials.username,
                defaults.header_sent_by(
                    live.transport,
                    super::messages::EntryEgress::of(live, defaults),
                ),
                live.transport,
                self.contact_token(live).as_deref(),
            )
        })
    }

    /// Whether the binding stored under `contact` is this node's to clear. A
    /// registrar keys a binding by its Contact (RFC 3261 §10.3, URIs compared
    /// per §19.1.4, parameters included), so an `Expires: 0` on a Contact
    /// another node holds would delete its binding.
    ///
    /// - A Contact carrying this instance's token for `aor` (see
    ///   [`super::contact::instance_token`]) is this node's, whatever its
    ///   address: a concrete socket, an advertised IP, a host name or an
    ///   address every node shares. Another instance's token never is, because
    ///   the two nodes' Contacts differ in that parameter and so do their
    ///   bindings. A token that is not this node's is not this node's even on
    ///   one of its own sockets.
    /// - A Contact with no token (a source row's explicit `contact`, or one an
    ///   older version stored) falls back to the old rule: exactly a specific
    ///   (non-wildcard) listener socket or the egress address, with an explicit
    ///   IP and port. A wildcard, a name, a missing port or an address the node
    ///   merely could bind never qualifies: those bindings expire.
    ///
    /// `others_holding` (no other node records the same AoR and Contact,
    /// checked again just before the de-REGISTER leaves) stays the second
    /// guard.
    fn contact_is_held_here(&self, contact: &str, aor: &str, defaults: EgressDefaults<'_>) -> bool {
        if let Some(token) = super::contact::contact_token_of(contact) {
            return self.instance_token(aor).as_deref() == Some(token);
        }
        let Some((host, Some(port))) = contact_host_port(contact) else {
            return false;
        };
        let Ok(address) = host.parse::<std::net::IpAddr>() else {
            return false;
        };
        if address.is_unspecified() {
            return false;
        }
        let socket = std::net::SocketAddr::new(address, port);
        defaults.local_addr == socket || defaults.listen_addrs.values().any(|l| *l == socket)
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
        // The configured registrar, not the address it resolved to: DNS can
        // answer with another frontend after a restart.
        let same_target = live.registrar_uri == record.registrar_uri
            && live.transport == record.transport
            && self.predicted_contact(&live, defaults) == record.contact;
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
            self.stage_startup_deregistration(*built);
        }
    }
}

impl RegistrantManager {
    /// Hold a restart's de-REGISTER back until the checks made just before it
    /// goes (see [`Self::release_startup_deregistrations`]).
    pub(super) fn stage_startup_deregistration(&self, built: super::BuiltRegister) {
        match self.restart.staged.lock() {
            Ok(mut staged) => staged.push(built),
            Err(poisoned) => poisoned.into_inner().push(built),
        }
    }

    /// Release the staged restart de-REGISTERs that still pass, to the queue the
    /// loop sends from; abandon the rest (and drop their records). Called by the
    /// loop right before it sends, so every one, the initial and the authorised
    /// retry after the lookup, is checked at the moment it would leave: a live
    /// entry holds the Contact now, the Contact is not exactly a socket of this
    /// node's, or another node's record holds the AoR on it (RFC 3261 §10.3).
    /// Anything that cannot be established, Redis unreadable included, abandons
    /// it: the binding then expires as it would have.
    pub async fn release_startup_deregistrations(&self) {
        let staged = match self.restart.staged.lock() {
            Ok(mut staged) => std::mem::take(&mut *staged),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        };
        for built in staged {
            let Some(call_id) = built.message.headers.get("Call-ID").cloned() else {
                continue;
            };
            if self.startup_deregistration_may_go(&call_id).await {
                self.push_pending_deregistration(built);
            } else {
                self.abandon_startup_deregistration(&call_id);
            }
        }
    }

    async fn startup_deregistration_may_go(&self, call_id: &str) -> bool {
        if self.startup_deregistration_superseded(call_id) {
            return false;
        }
        let Some((aor, contact)) =
            self.draining_deregistrations
                .get(call_id)
                .and_then(|draining| {
                    Some((
                        draining.entry.aor.clone(),
                        draining.entry.contact_uri.clone()?,
                    ))
                })
        else {
            return false;
        };
        let (Some(egress), Some(store)) = (self.egress.get(), self.restart.bindings.get()) else {
            return false;
        };
        if !self.contact_is_held_here(&contact, &aor, egress.defaults()) {
            return false;
        }
        match store.others_holding(std::slice::from_ref(&aor)).await {
            Ok(others) => !others
                .iter()
                .any(|other| other.aor == aor && other.contact == contact),
            Err(error) => {
                warn!(%aor, %error, "restart clean-up: the other nodes' bindings cannot be read, nothing is sent");
                false
            }
        }
    }

    fn abandon_startup_deregistration(&self, call_id: &str) {
        if let Some((_, draining)) = self.draining_deregistrations.remove(call_id) {
            info!(
                aor = %draining.entry.aor,
                registrar = %draining.entry.registrar_uri,
                "restart clean-up: the binding may be another node's now, its de-REGISTER is not sent"
            );
            self.forget_binding_record(&draining.entry.aor, call_id);
        }
    }
}

/// The host and port of a Contact URI (`sip:user@host:port;params`).
fn contact_host_port(contact: &str) -> Option<(String, Option<u16>)> {
    let rest = contact
        .strip_prefix("sips:")
        .or_else(|| contact.strip_prefix("sip:"))?;
    let rest = rest.split(';').next()?.split('?').next()?;
    let hostport = rest.rsplit_once('@').map_or(rest, |(_, hostport)| hostport);
    if let Some(bracketed) = hostport.strip_prefix('[') {
        let (host, tail) = bracketed.split_once(']')?;
        let port = tail.strip_prefix(':').and_then(|port| port.parse().ok());
        return Some((host.to_string(), port));
    }
    match hostport.rsplit_once(':') {
        Some((host, port)) => Some((host.to_string(), Some(port.parse().ok()?))),
        None => Some((hostport.to_string(), None)),
    }
}

/// Read the stored records, then attach the store. In that order: attaching
/// writes the live bindings, and a live binding written over a record is a
/// record the clean-up never sees.
pub(super) async fn snapshot_then_attach(
    manager: &RegistrantManager,
    store: Arc<BindingStore>,
) -> Result<Vec<BindingRecord>, String> {
    let records = store.load().await?;
    manager.attach_binding_store(store);
    Ok(records)
}

/// Run the start-up cleanup once its conditions hold (see the module). Returns
/// when it has run, or at shutdown.
pub async fn run_startup_cleanup(manager: Arc<RegistrantManager>) {
    run_startup_cleanup_from(manager, super::persist::published_store).await;
}

/// [`run_startup_cleanup`] taking the store from `published`, once it has one.
pub(super) async fn run_startup_cleanup_from(
    manager: Arc<RegistrantManager>,
    published: impl Fn() -> Option<Arc<BindingStore>>,
) {
    let started = Instant::now();
    let mut noticed = false;
    let mut snapshot: Option<Vec<BindingRecord>> = None;
    let mut retry_read_at = Instant::now();
    loop {
        if manager.is_shutting_down() {
            return;
        }
        if snapshot.is_none() && Instant::now() >= retry_read_at {
            if let Some(store) = published() {
                match snapshot_then_attach(&manager, store).await {
                    Ok(records) => snapshot = Some(records),
                    Err(error) => {
                        error!(%error, "restart clean-up: the stored bindings cannot be read, retrying");
                        retry_read_at = Instant::now() + Duration::from_secs(5);
                    }
                }
            }
        }
        if snapshot.is_some() && manager.startup_ready() {
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
    let (Some(records), Some(store), Some(egress)) = (
        snapshot,
        manager.restart.bindings.get().cloned(),
        manager.egress.get(),
    ) else {
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
