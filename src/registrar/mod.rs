//! In-memory SIP registrar — AoR (Address of Record) → Contact bindings.
//!
//! The registrar stores contact bindings for registered users and provides
//! save/lookup/expire operations. Contacts are sorted by q-value descending.
//!
//! This is the in-memory backend (always compiled). Redis and Postgres backends
//! are feature-gated for later phases.

pub mod backend;
pub mod reginfo;

use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::broadcast;

use crate::sip::uri::SipUri;

/// A registration change event emitted by the registrar.
#[derive(Debug, Clone)]
pub enum RegistrationEvent {
    /// A new contact was registered.
    Registered { aor: String },
    /// An existing contact was refreshed.
    Refreshed { aor: String },
    /// All contacts for an AoR were removed.
    Deregistered { aor: String },
    /// Contacts expired during cleanup.
    Expired { aor: String },
}

/// Address of Record — the canonical URI that contacts bind to.
/// Typically `sip:user@domain`.
pub type Aor = String;

/// Normalize a URI string to canonical AoR form.
///
/// - Strip surrounding angle brackets.
/// - If the input doesn't start with `sip:` or `sips:`, prepend `sip:`.
/// - Strip URI parameters (`;…`) and headers (`?…`).
/// - Strip the default port (`:5060` for sip, `:5061` for sips).
///
/// The same canonicalization is applied at the Python API boundary and
/// when populating the alias index, so both writes and reads of an AoR
/// land on the same key regardless of how the input is spelled.
pub fn normalize_aor(uri: &str) -> Aor {
    let uri = uri.trim_start_matches('<').trim_end_matches('>');

    let uri = if uri.starts_with("sip:") || uri.starts_with("sips:") {
        uri.to_string()
    } else {
        format!("sip:{uri}")
    };

    let uri = uri.split(';').next().unwrap_or(&uri).to_string();
    let uri = uri.split('?').next().unwrap_or(&uri).to_string();

    if uri.starts_with("sips:") {
        uri.trim_end_matches(":5061").to_string()
    } else {
        uri.trim_end_matches(":5060").to_string()
    }
}

/// A single contact binding.
#[derive(Debug, Clone)]
pub struct Contact {
    /// The contact URI (where to reach this user).
    pub uri: SipUri,
    /// Quality value (0.0–1.0). Higher = preferred.
    pub q: f32,
    /// When this binding was created/refreshed.
    pub registered_at: Instant,
    /// How long the binding is valid (from `registered_at`).
    pub expires: Duration,
    /// Call-ID from the REGISTER that created this binding.
    pub call_id: String,
    /// CSeq sequence number (for replay protection).
    pub cseq: u32,
    /// Source address the REGISTER came from (for NAT traversal routing).
    pub source_addr: Option<SocketAddr>,
    /// Transport protocol the REGISTER arrived on (for received URI construction).
    pub source_transport: Option<String>,
    /// RFC 5627 GRUU: `+sip.instance` (URN, e.g. "urn:uuid:f81d4fae-...").
    pub sip_instance: Option<String>,
    /// RFC 5626 Outbound: `reg-id` parameter.
    pub reg_id: Option<u32>,
    /// RFC 3327 Path headers from the REGISTER (for terminating request routing).
    pub path: Vec<String>,
    /// IMS registration state: pending (awaiting SAR) vs active.
    pub pending: bool,
    /// Stable identity of the siphon instance that originally accepted this
    /// REGISTER (typically the StatefulSet pod name or hostname).  `None` for
    /// bindings created before the field was introduced or when no identity
    /// is configured.
    pub instance_id: Option<String>,
    /// Boot-time epoch UUID of the process that accepted this REGISTER.
    /// Combined with `instance_id`, lets a restarted instance distinguish
    /// "I (this pod) accepted this binding in a previous life" from
    /// "another instance accepted it."
    pub instance_epoch: Option<String>,
}

impl Contact {
    /// Seconds remaining until this contact expires.
    pub fn remaining_seconds(&self) -> u64 {
        let elapsed = self.registered_at.elapsed();
        self.expires.as_secs().saturating_sub(elapsed.as_secs())
    }

    /// Whether this contact has expired.
    pub fn is_expired(&self) -> bool {
        self.registered_at.elapsed() >= self.expires
    }
}

/// Configuration for the registrar.
#[derive(Debug, Clone)]
pub struct RegistrarConfig {
    /// Default Expires value (seconds) when not specified by client.
    pub default_expires: u32,
    /// Maximum allowed Expires value (seconds).
    pub max_expires: u32,
    /// Minimum allowed Expires value (seconds). Below this → 423 Interval Too Brief.
    pub min_expires: u32,
    /// Maximum number of contacts per AoR.
    pub max_contacts: usize,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            default_expires: 3600,
            max_expires: 7200,
            min_expires: 60,
            max_contacts: 10,
        }
    }
}

/// Identity of the siphon process that accepts new REGISTERs.
///
/// `id` is stable across restarts of the same logical replica (e.g. the
/// StatefulSet pod name `siphon-2`).  `epoch` is a fresh UUID generated at
/// every boot, so two restarts of the same `id` are still distinguishable.
/// Together they let a restarted instance recognise its own bindings while
/// also detecting that they were written by a previous process.
#[derive(Clone, Debug)]
pub struct InstanceIdentity {
    pub id: String,
    pub epoch: String,
}

/// In-memory registrar store.
pub struct Registrar {
    /// AoR → list of contact bindings.
    pub(crate) bindings: DashMap<Aor, Vec<Contact>>,
    /// AoR → Service-Route headers (RFC 3608), stored from 200 OK to REGISTER.
    service_routes: DashMap<Aor, Vec<String>>,
    /// AoR → P-Asserted-Identity (IMS: stored from SAR user profile).
    asserted_identities: DashMap<Aor, String>,
    /// AoR → P-Associated-URI list (from upstream 200 OK to REGISTER).
    associated_uris: DashMap<Aor, Vec<String>>,
    /// Alias AoR → primary AoR.  Derived index, always reflects
    /// `associated_uris`.  Rebuilt on `set_associated_uris` and
    /// `apply_aor_state`; pruned on `drop_aor_state` / `remove_all`.
    /// Lookups (`lookup`, `is_registered`, etc.) resolve the input AoR
    /// through this index before touching `bindings`, so contacts saved
    /// under the primary IMS public identity are reachable via every
    /// IMPU in the implicit registration set (3GPP TS 23.228).
    aliases: DashMap<Aor, Aor>,
    pub config: RegistrarConfig,
    /// Broadcast channel for registration change events.
    event_sender: broadcast::Sender<RegistrationEvent>,
    /// Optional backend writer for write-through persistence (set once at startup).
    backend_writer: OnceLock<backend::BackendWriter>,
    /// Identity tag stamped onto every locally accepted contact.  Set once
    /// at startup; `None` means scripts can't tell who owns a binding (the
    /// pre-Tier-2 default).
    instance_identity: OnceLock<InstanceIdentity>,
}

impl std::fmt::Debug for Registrar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Registrar")
            .field("bindings_count", &self.bindings.len())
            .field("config", &self.config)
            .finish()
    }
}

impl Registrar {
    pub fn new(config: RegistrarConfig) -> Self {
        let (event_sender, _) = broadcast::channel(1024);
        Self {
            bindings: DashMap::new(),
            service_routes: DashMap::new(),
            asserted_identities: DashMap::new(),
            associated_uris: DashMap::new(),
            aliases: DashMap::new(),
            config,
            event_sender,
            backend_writer: OnceLock::new(),
            instance_identity: OnceLock::new(),
        }
    }

    /// Set the backend writer for write-through persistence.
    /// Can only be called once (at startup); subsequent calls are ignored.
    pub fn set_backend_writer(&self, writer: backend::BackendWriter) {
        let _ = self.backend_writer.set(writer);
    }

    /// Set the per-process identity used to tag locally accepted bindings.
    /// Should be called once at startup before traffic begins.  Subsequent
    /// calls are ignored.
    pub fn set_instance_identity(&self, identity: InstanceIdentity) {
        let _ = self.instance_identity.set(identity);
    }

    /// Returns the configured per-process identity, if any.
    pub fn instance_identity(&self) -> Option<&InstanceIdentity> {
        self.instance_identity.get()
    }

    /// Snapshot of `(instance_id, instance_epoch)` cloned for stamping onto
    /// a `Contact`.  Returns `(None, None)` if no identity is configured.
    fn current_identity_pair(&self) -> (Option<String>, Option<String>) {
        match self.instance_identity.get() {
            Some(identity) => (Some(identity.id.clone()), Some(identity.epoch.clone())),
            None => (None, None),
        }
    }

    /// Returns true when the contact carries this instance's id *and* epoch.
    /// Used by `PyContact.is_local` so scripts can distinguish bindings
    /// accepted by this process from bindings restored from a peer or a
    /// previous boot.
    pub fn is_local_contact(&self, contact: &Contact) -> bool {
        match (self.instance_identity.get(), contact.instance_id.as_deref(), contact.instance_epoch.as_deref()) {
            (Some(identity), Some(id), Some(epoch)) => identity.id == id && identity.epoch == epoch,
            _ => false,
        }
    }

    /// Resolve an AoR through the alias index to its primary.
    ///
    /// If `aor` is registered as an alias of some primary IMPU
    /// (via `set_associated_uris`), returns the primary; otherwise
    /// returns `aor` unchanged.  Single-hop only — alias chains are
    /// not followed (IMS implicit sets are flat per TS 23.228).
    ///
    /// Every AoR-keyed Registrar method funnels its input through this
    /// helper before touching `bindings` / `associated_uris` / etc.
    fn resolve_alias(&self, aor: &str) -> Aor {
        self.aliases
            .get(aor)
            .map(|entry| entry.value().clone())
            .unwrap_or_else(|| aor.to_string())
    }

    /// Drop every alias entry pointing at `primary`.  Used on dereg
    /// (`remove_all`, `drop_aor_state`) and as the first step of
    /// `install_aliases` when the implicit set is being replaced.
    fn prune_aliases_to(&self, primary: &str) {
        self.aliases.retain(|_, target| target != primary);
    }

    /// Replace the alias entries for `primary` with one entry per URI
    /// in `uris` (after canonicalization, skipping self-aliases).
    /// Caller is responsible for updating `associated_uris[primary]`
    /// and persistence.
    fn install_aliases(&self, primary: &str, uris: &[String]) {
        self.prune_aliases_to(primary);
        for uri in uris {
            let alias = normalize_aor(uri);
            if alias != primary {
                self.aliases.insert(alias, primary.to_string());
            }
        }
    }

    /// Subscribe to registration change events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<RegistrationEvent> {
        self.event_sender.subscribe()
    }

    /// Emit a registration event (best-effort, ignores if no receivers).
    fn emit_event(&self, event: RegistrationEvent) {
        let _ = self.event_sender.send(event);
    }

    /// Write-through an AoR's contacts to the backend (if configured).
    fn persist_aor(&self, aor: &str, contacts: Vec<backend::StoredContact>) {
        if let Some(writer) = self.backend_writer.get() {
            if contacts.is_empty() {
                writer.remove(aor);
            } else {
                writer.save(aor, contacts);
            }
        }
    }

    /// Snapshot the auxiliary maps for an AoR and write through to the
    /// backend.  Removes the backend entry when no auxiliary data remains.
    fn persist_aor_state(&self, aor: &str) {
        let writer = match self.backend_writer.get() {
            Some(writer) => writer,
            None => return,
        };
        let state = backend::StoredAorState {
            service_routes: self
                .service_routes
                .get(aor)
                .map(|entry| entry.value().clone())
                .unwrap_or_default(),
            asserted_identity: self
                .asserted_identities
                .get(aor)
                .map(|entry| entry.value().clone()),
            associated_uris: self
                .associated_uris
                .get(aor)
                .map(|entry| entry.value().clone())
                .unwrap_or_default(),
        };
        if state.is_empty() {
            writer.remove_aor_state(aor);
        } else {
            writer.save_aor_state(aor, state);
        }
    }

    /// Drop the in-memory auxiliary state for an AoR and write through to
    /// the backend.  Used on de-registration paths.
    fn drop_aor_state(&self, aor: &str) {
        let removed = self.service_routes.remove(aor).is_some()
            | self.asserted_identities.remove(aor).is_some()
            | self.associated_uris.remove(aor).is_some();
        // Always prune the alias index for this primary, even if no aux
        // state was attached — `set_associated_uris` may have populated
        // aliases without a service_route / asserted_identity.
        self.prune_aliases_to(aor);
        if removed {
            if let Some(writer) = self.backend_writer.get() {
                writer.remove_aor_state(aor);
            }
        }
    }

    /// Apply a `StoredAorState` (loaded from a backend) into the in-memory
    /// auxiliary maps.  Used by `restore_from_backend`.
    pub(crate) fn apply_aor_state(&self, aor: &str, state: backend::StoredAorState) {
        if !state.service_routes.is_empty() {
            self.service_routes.insert(aor.to_string(), state.service_routes);
        }
        if let Some(identity) = state.asserted_identity {
            self.asserted_identities.insert(aor.to_string(), identity);
        }
        if !state.associated_uris.is_empty() {
            // Rebuild the derived alias index from the persisted AU list so
            // `lookup(alias)` works immediately after a restart.
            self.install_aliases(aor, &state.associated_uris);
            self.associated_uris.insert(aor.to_string(), state.associated_uris);
        }
    }

    /// Save a contact binding for an AoR.
    ///
    /// If a binding with the same URI already exists, it is replaced.
    /// Returns `Err` if `max_contacts` would be exceeded.
    pub fn save(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        call_id: String,
        cseq: u32,
    ) -> Result<(), RegistrarError> {
        self.save_with_source(aor, uri, expires_secs, q, call_id, cseq, None, None)
    }

    /// Save a contact binding with the source address of the REGISTER request.
    ///
    /// When `source_addr` is provided, it is stored alongside the contact for
    /// NAT traversal routing — like OpenSIPS's `received_avp`. On lookup, the
    /// `PyContact.received` property returns a SIP URI built from this address,
    /// which scripts can use instead of the Contact URI to reach NATed clients.
    #[allow(clippy::too_many_arguments)]
    pub fn save_with_source(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        call_id: String,
        cseq: u32,
        source_addr: Option<SocketAddr>,
        source_transport: Option<String>,
    ) -> Result<(), RegistrarError> {
        self.save_full(aor, uri, expires_secs, q, call_id, cseq, source_addr, source_transport, None, None, vec![])
    }

    /// Core save with all fields including +sip.instance and reg-id.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn save_full(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        call_id: String,
        cseq: u32,
        source_addr: Option<SocketAddr>,
        source_transport: Option<String>,
        sip_instance: Option<String>,
        reg_id: Option<u32>,
        path: Vec<String>,
    ) -> Result<(), RegistrarError> {
        // Resolve alias → primary so a REGISTER arriving with a non-primary
        // IMPU still attaches contacts to the implicit set's primary AoR.
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        let expires_secs = std::cmp::min(expires_secs, self.config.max_expires);

        if expires_secs > 0 && expires_secs < self.config.min_expires {
            return Err(RegistrarError::IntervalTooBrief {
                min_expires: self.config.min_expires,
            });
        }

        let (instance_id, instance_epoch) = self.current_identity_pair();
        let contact = Contact {
            uri: uri.clone(),
            q,
            registered_at: Instant::now(),
            expires: Duration::from_secs(expires_secs as u64),
            call_id,
            cseq,
            source_addr,
            source_transport,
            sip_instance,
            reg_id,
            path,
            pending: false,
            instance_id,
            instance_epoch,
        };

        let uri_string = uri.to_string();

        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        let contacts = entry.value_mut();

        // Remove expired contacts first
        contacts.retain(|c| !c.is_expired());

        if expires_secs == 0 {
            // Expires=0 means deregister this specific contact
            contacts.retain(|c| c.uri.to_string() != uri_string);
            let remaining: Vec<_> = contacts
                .iter()
                .map(backend::StoredContact::from_contact)
                .collect();
            let aor_empty = contacts.is_empty();
            if aor_empty {
                drop(entry);
                self.bindings.remove(aor);
            } else {
                drop(entry);
            }
            self.persist_aor(aor, remaining);
            if aor_empty {
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.registrations_active.dec();
                }
            }
            self.emit_event(RegistrationEvent::Deregistered { aor: aor.to_string() });
            return Ok(());
        }

        // Replace existing contact with same URI, or same +sip.instance per RFC 5627 §4.2.
        // When a UE re-registers with a different port (e.g. IPsec port rotation),
        // the URI changes but the +sip.instance stays the same — match on instance first.
        let instance_match = contact.sip_instance.as_ref().and_then(|inst| {
            contacts.iter().position(|c| {
                c.sip_instance.as_ref().is_some_and(|ci| ci == inst)
            })
        });
        let uri_match = contacts.iter().position(|c| c.uri.to_string() == uri_string);
        let replace_idx = instance_match.or(uri_match);

        let is_refresh = replace_idx.is_some();
        if let Some(idx) = replace_idx {
            contacts[idx] = contact;
        } else {
            // Check max_contacts
            if contacts.len() >= self.config.max_contacts {
                return Err(RegistrarError::TooManyContacts {
                    max: self.config.max_contacts,
                });
            }
            contacts.push(contact);
        }

        // Sort by q-value descending
        contacts.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));

        // Write-through to backend before releasing the DashMap entry.
        let stored: Vec<_> = contacts
            .iter()
            .map(backend::StoredContact::from_contact)
            .collect();
        let aor_owned = aor.to_string();
        drop(entry);
        self.persist_aor(aor, stored);
        if is_refresh {
            self.emit_event(RegistrationEvent::Refreshed { aor: aor_owned });
        } else {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.registrations_active.inc();
            }
            self.emit_event(RegistrationEvent::Registered { aor: aor_owned });
        }

        Ok(())
    }

    /// Remove all contacts for an AoR (wildcard deregister, Contact: *).
    pub fn remove_all(&self, aor: &str) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        let had_bindings = self.bindings.remove(aor).is_some();
        if let Some(writer) = self.backend_writer.get() {
            writer.remove(aor);
        }
        self.drop_aor_state(aor);
        if had_bindings {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.registrations_active.dec();
            }
        }
        self.emit_event(RegistrationEvent::Deregistered { aor: aor.to_string() });
    }

    /// Remove all contacts for an AoR **without** emitting a change event.
    ///
    /// Used by `PyRegistrar::save(force=True)` to clear bindings before
    /// re-processing contacts — the subsequent per-contact `save()` calls
    /// emit the appropriate events themselves.
    pub fn clear_bindings(&self, aor: &str) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        self.bindings.remove(aor);
        if let Some(writer) = self.backend_writer.get() {
            writer.remove(aor);
        }
        self.drop_aor_state(aor);
    }

    /// Evict all connection-oriented contacts (TCP/TLS/WS/WSS) from the registrar.
    ///
    /// Called after restart: these contacts reference transport connections that
    /// no longer exist, so they are unreachable.  Emits `Deregistered` events
    /// and writes through to the backend so `@registrar.on_change` handlers fire.
    pub fn evict_connection_oriented(&self) -> usize {
        let mut evicted = 0usize;
        let aors: Vec<String> = self.bindings.iter().map(|e| e.key().clone()).collect();

        for aor in aors {
            let before;
            let after;

            if let Some(mut entry) = self.bindings.get_mut(&aor) {
                before = entry.value().len();
                entry.value_mut().retain(|c| {
                    let transport = c.uri.get_param("transport").unwrap_or("");
                    !matches!(
                        transport.to_ascii_lowercase().as_str(),
                        "tcp" | "tls" | "ws" | "wss"
                    )
                });
                after = entry.value().len();
            } else {
                continue;
            }

            if before == after {
                continue; // nothing evicted for this AoR
            }

            evicted += before - after;

            if after == 0 {
                // All contacts were connection-oriented — remove the AoR.
                self.bindings.remove(&aor);
                if let Some(writer) = self.backend_writer.get() {
                    writer.remove(&aor);
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.registrations_active.dec();
                }
                self.emit_event(RegistrationEvent::Deregistered { aor });
            } else {
                // Mixed: write back surviving contacts to backend.
                if let Some(writer) = self.backend_writer.get() {
                    if let Some(entry) = self.bindings.get(&aor) {
                        let stored: Vec<backend::StoredContact> = entry
                            .value()
                            .iter()
                            .map(backend::StoredContact::from_contact)
                            .collect();
                        writer.save(&aor, stored);
                    }
                }
                self.emit_event(RegistrationEvent::Deregistered { aor });
            }
        }

        evicted
    }

    /// Look up contacts for an AoR. Returns non-expired contacts sorted by q descending.
    ///
    /// If `aor` is an alias of an IMS implicit registration set's primary,
    /// returns the primary's contacts (so terminating routing on a non-primary
    /// IMPU like `tel:+15551234` resolves transparently).
    pub fn lookup(&self, aor: &str) -> Vec<Contact> {
        let primary = self.resolve_alias(aor);
        match self.bindings.get(primary.as_str()) {
            Some(entry) => entry
                .value()
                .iter()
                .filter(|c| !c.is_expired())
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Check if an AoR has any non-expired contacts.
    pub fn is_registered(&self, aor: &str) -> bool {
        let primary = self.resolve_alias(aor);
        match self.bindings.get(primary.as_str()) {
            Some(entry) => entry.value().iter().any(|c| !c.is_expired()),
            None => false,
        }
    }

    /// Number of registered AoRs (with at least one non-expired contact)
    /// known to *this* instance's in-memory map.
    pub fn aor_count(&self) -> usize {
        self.bindings
            .iter()
            .filter(|entry| entry.value().iter().any(|c| !c.is_expired()))
            .count()
    }

    /// Number of registered AoRs across the whole deployment.
    ///
    /// When a persistent backend (Redis, Postgres) is configured, this asks
    /// the backend so the count is authoritative across all siphon instances
    /// sharing it.  Without a backend, returns the local in-memory count.
    ///
    /// Backend errors propagate so the caller can distinguish "cluster
    /// state unknown" from "cluster has zero AoRs".
    pub async fn aor_count_distributed(&self) -> Result<usize, backend::BackendError> {
        if let Some(writer) = self.backend_writer.get() {
            return writer.count_aors().await;
        }
        Ok(self.aor_count())
    }

    /// Return all non-expired contacts across all AoRs, with their AoR key.
    pub fn all_contacts(&self) -> Vec<(Aor, Contact)> {
        let mut result = Vec::new();
        for entry in self.bindings.iter() {
            let aor = entry.key().clone();
            for contact in entry.value().iter() {
                if !contact.is_expired() {
                    result.push((aor.clone(), contact.clone()));
                }
            }
        }
        result
    }

    /// Remove a specific contact URI from an AoR.
    pub fn remove_contact(&self, aor: &str, contact_uri: &str) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        if let Some(mut entry) = self.bindings.get_mut(aor) {
            let before = entry.value().len();
            entry.value_mut().retain(|c| c.uri.to_string() != contact_uri);
            let removed = entry.value().len() < before;
            let aor_empty = entry.value().is_empty();
            if aor_empty {
                drop(entry);
                self.bindings.remove(aor);
            }
            if removed {
                if aor_empty {
                    if let Some(metrics) = crate::metrics::try_metrics() {
                        metrics.registrations_active.dec();
                    }
                }
                self.emit_event(RegistrationEvent::Deregistered { aor: aor.to_string() });
            }
        }
    }

    /// Save a contact binding with GRUU parameters (RFC 5627 + RFC 5626).
    #[allow(clippy::too_many_arguments)]
    pub fn save_with_gruu(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        call_id: String,
        cseq: u32,
        source_addr: Option<SocketAddr>,
        sip_instance: Option<String>,
        reg_id: Option<u32>,
    ) -> Result<(), RegistrarError> {
        self.save_full(aor, uri, expires_secs, q, call_id, cseq, source_addr, None, sip_instance, reg_id, vec![])
    }

    /// Generate a public GRUU for a contact with a `+sip.instance`.
    ///
    /// Format: `sip:<user>@<domain>;gr=<instance-id>`
    /// The instance-id is the `+sip.instance` value with angle brackets stripped.
    pub fn public_gruu(aor: &str, sip_instance: &str) -> Option<String> {
        // Strip angle brackets from sip.instance ("urn:uuid:..." or "<urn:uuid:...>")
        let instance = sip_instance
            .trim()
            .strip_prefix('"').unwrap_or(sip_instance.trim())
            .strip_suffix('"').unwrap_or(sip_instance.trim())
            .strip_prefix('<').unwrap_or(sip_instance.trim())
            .strip_suffix('>').unwrap_or(sip_instance.trim());

        if instance.is_empty() {
            return None;
        }

        // Extract user@host from AoR (strip sip: prefix)
        let aor_part = aor.strip_prefix("sip:").or_else(|| aor.strip_prefix("sips:"))?;
        Some(format!("sip:{aor_part};gr={instance}"))
    }

    /// Generate a temporary GRUU for a contact binding.
    ///
    /// Temp-GRUUs are opaque and unique per binding. We use a hash of the
    /// AoR + instance + call-id to make them deterministic but unguessable.
    pub fn temp_gruu(aor: &str, sip_instance: &str, call_id: &str) -> Option<String> {
        let instance = sip_instance
            .trim()
            .strip_prefix('"').unwrap_or(sip_instance.trim())
            .strip_suffix('"').unwrap_or(sip_instance.trim())
            .strip_prefix('<').unwrap_or(sip_instance.trim())
            .strip_suffix('>').unwrap_or(sip_instance.trim());

        if instance.is_empty() {
            return None;
        }

        let aor_part = aor.strip_prefix("sip:").or_else(|| aor.strip_prefix("sips:"))?;

        // Extract domain from AoR
        let domain = aor_part.split('@').nth(1).unwrap_or(aor_part);

        // Simple hash-based temp-gruu (in production, use a cryptographic MAC)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        aor.hash(&mut hasher);
        instance.hash(&mut hasher);
        call_id.hash(&mut hasher);
        let hash = hasher.finish();

        Some(format!("sip:tgruu.{hash:016x}@{domain};gr"))
    }

    /// Look up contacts by `+sip.instance` for an AoR (GRUU resolution).
    pub fn lookup_by_instance(&self, aor: &str, sip_instance: &str) -> Vec<Contact> {
        let instance = sip_instance
            .trim()
            .strip_prefix('"').unwrap_or(sip_instance.trim())
            .strip_suffix('"').unwrap_or(sip_instance.trim())
            .strip_prefix('<').unwrap_or(sip_instance.trim())
            .strip_suffix('>').unwrap_or(sip_instance.trim());

        let primary = self.resolve_alias(aor);
        match self.bindings.get(primary.as_str()) {
            Some(entry) => entry
                .value()
                .iter()
                .filter(|c| {
                    !c.is_expired()
                        && c.sip_instance.as_deref().map(|s| {
                            let s = s.strip_prefix('"').unwrap_or(s);
                            let s = s.strip_suffix('"').unwrap_or(s);
                            let s = s.strip_prefix('<').unwrap_or(s);
                            s.strip_suffix('>').unwrap_or(s)
                        }) == Some(instance)
                })
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Store Service-Route headers for an AoR (RFC 3608).
    /// Called when processing a 200 OK to REGISTER from the upstream registrar.
    pub fn set_service_routes(&self, aor: &str, routes: Vec<String>) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        if routes.is_empty() {
            self.service_routes.remove(aor);
        } else {
            self.service_routes.insert(aor.to_string(), routes);
        }
        self.persist_aor_state(aor);
    }

    /// Retrieve stored Service-Route headers for an AoR.
    pub fn service_routes(&self, aor: &str) -> Vec<String> {
        let primary = self.resolve_alias(aor);
        self.service_routes
            .get(primary.as_str())
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    /// Store the P-Associated-URI list for an AoR and rebuild the
    /// derived alias index so every URI in the list resolves back to
    /// `aor` on subsequent lookups.
    ///
    /// If `aor` is itself an alias, writes go to the resolved primary —
    /// which clobbers the primary's existing AU list, matching the IMS
    /// "implicit set is replaced wholesale by the latest SAR" semantic
    /// (3GPP TS 29.228 §6.1.2).  Empty `uris` clears the AU list and
    /// drops every alias entry that was pointing at this primary.
    pub fn set_associated_uris(&self, aor: &str, uris: Vec<String>) {
        let primary = self.resolve_alias(aor);
        self.install_aliases(&primary, &uris);
        if uris.is_empty() {
            self.associated_uris.remove(primary.as_str());
        } else {
            self.associated_uris.insert(primary.clone(), uris);
        }
        self.persist_aor_state(primary.as_str());
    }

    /// Retrieve stored P-Associated-URI list for an AoR.
    pub fn associated_uris(&self, aor: &str) -> Vec<String> {
        let primary = self.resolve_alias(aor);
        self.associated_uris
            .get(primary.as_str())
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    /// Save a contact binding in pending state (IMS: awaiting SAR confirmation).
    pub fn save_pending(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        call_id: String,
        cseq: u32,
    ) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        let (instance_id, instance_epoch) = self.current_identity_pair();
        let contact = Contact {
            uri: uri.clone(),
            q,
            registered_at: Instant::now(),
            expires: Duration::from_secs(expires_secs as u64),
            call_id,
            cseq,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: true,
            instance_id,
            instance_epoch,
        };

        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        let contacts = entry.value_mut();
        let uri_string = uri.to_string();

        // Replace existing contact with same URI, or append
        if let Some(existing) = contacts.iter_mut().find(|c| c.uri.to_string() == uri_string) {
            *existing = contact;
        } else {
            contacts.push(contact);
        }
    }

    /// Confirm pending contacts for an AoR (IMS: SAR succeeded).
    ///
    /// Promotes all pending contacts to active state.
    pub fn confirm_pending(&self, aor: &str) {
        let primary = self.resolve_alias(aor);
        if let Some(mut entry) = self.bindings.get_mut(primary.as_str()) {
            for contact in entry.value_mut().iter_mut() {
                contact.pending = false;
            }
        }
    }

    /// Store a P-Asserted-Identity for an AoR (from SAR user profile).
    pub fn set_asserted_identity(&self, aor: &str, identity: String) {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        self.asserted_identities.insert(aor.to_string(), identity);
        self.persist_aor_state(aor);
    }

    /// Look up stored P-Asserted-Identity for an AoR.
    pub fn asserted_identity(&self, aor: &str) -> Option<String> {
        let primary = self.resolve_alias(aor);
        self.asserted_identities
            .get(primary.as_str())
            .map(|v| v.value().clone())
    }

    /// Run a garbage-collection pass: remove expired contacts from all AoRs.
    pub fn expire_stale(&self) {
        let mut empty_aors = Vec::new();
        for mut entry in self.bindings.iter_mut() {
            let before = entry.value().len();
            entry.value_mut().retain(|c| !c.is_expired());
            if entry.value().is_empty() && before > 0 {
                empty_aors.push(entry.key().clone());
            }
        }
        if !empty_aors.is_empty() {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.registrations_active.sub(empty_aors.len() as i64);
            }
        }
        for aor in &empty_aors {
            self.bindings.remove(aor);
            self.emit_event(RegistrationEvent::Expired { aor: aor.clone() });
        }
    }
}

impl Default for Registrar {
    fn default() -> Self {
        Self::new(RegistrarConfig::default())
    }
}

/// Registrar errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrarError {
    /// Requested Expires is below the minimum.
    IntervalTooBrief { min_expires: u32 },
    /// AoR already has max_contacts bindings.
    TooManyContacts { max: usize },
}

impl std::fmt::Display for RegistrarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrarError::IntervalTooBrief { min_expires } => {
                write!(f, "423 Interval Too Brief (min: {min_expires}s)")
            }
            RegistrarError::TooManyContacts { max } => {
                write!(f, "too many contacts (max: {max})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn contact_uri(user: &str, host: &str) -> SipUri {
        SipUri::new(host.to_string()).with_user(user.to_string())
    }

    #[test]
    fn save_and_lookup() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "call-1".into(), 1)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.user.as_deref(), Some("alice"));
        assert_eq!(contacts[0].uri.host, "10.0.0.1");
    }

    #[test]
    fn lookup_returns_sorted_by_q() {
        let registrar = Registrar::default();
        registrar
            .save("sip:bob@example.com", contact_uri("bob", "10.0.0.1"), 3600, 0.5, "call-1".into(), 1)
            .unwrap();
        registrar
            .save("sip:bob@example.com", contact_uri("bob", "10.0.0.2"), 3600, 1.0, "call-2".into(), 2)
            .unwrap();
        registrar
            .save("sip:bob@example.com", contact_uri("bob", "10.0.0.3"), 3600, 0.8, "call-3".into(), 3)
            .unwrap();

        let contacts = registrar.lookup("sip:bob@example.com");
        assert_eq!(contacts.len(), 3);
        assert_eq!(contacts[0].uri.host, "10.0.0.2"); // q=1.0
        assert_eq!(contacts[1].uri.host, "10.0.0.3"); // q=0.8
        assert_eq!(contacts[2].uri.host, "10.0.0.1"); // q=0.5
    }

    #[test]
    fn deregister_with_expires_zero() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "call-1".into(), 1)
            .unwrap();
        assert!(registrar.is_registered("sip:alice@example.com"));

        // Expires=0 removes the specific contact
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 0, 1.0, "call-1".into(), 2)
            .unwrap();
        assert!(!registrar.is_registered("sip:alice@example.com"));
    }

    #[test]
    fn wildcard_deregister() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "call-1".into(), 1)
            .unwrap();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.2"), 3600, 0.5, "call-2".into(), 2)
            .unwrap();

        registrar.remove_all("sip:alice@example.com");
        assert!(!registrar.is_registered("sip:alice@example.com"));
        assert_eq!(registrar.lookup("sip:alice@example.com").len(), 0);
    }

    #[test]
    fn replace_existing_contact() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 0.5, "call-1".into(), 1)
            .unwrap();
        // Re-register same URI with different q
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "call-1".into(), 2)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].q, 1.0); // updated
    }

    #[test]
    fn max_contacts_enforced() {
        let config = RegistrarConfig {
            max_contacts: 2,
            ..Default::default()
        };
        let registrar = Registrar::new(config);

        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.2"), 3600, 0.8, "c2".into(), 2)
            .unwrap();

        let result = registrar.save(
            "sip:alice@example.com",
            contact_uri("alice", "10.0.0.3"),
            3600, 0.5, "c3".into(), 3,
        );
        assert_eq!(
            result,
            Err(RegistrarError::TooManyContacts { max: 2 })
        );
    }

    #[test]
    fn min_expires_enforced() {
        let config = RegistrarConfig {
            min_expires: 60,
            ..Default::default()
        };
        let registrar = Registrar::new(config);

        let result = registrar.save(
            "sip:alice@example.com",
            contact_uri("alice", "10.0.0.1"),
            30, 1.0, "c1".into(), 1,
        );
        assert_eq!(
            result,
            Err(RegistrarError::IntervalTooBrief { min_expires: 60 })
        );
    }

    #[test]
    fn max_expires_clamped() {
        let config = RegistrarConfig {
            max_expires: 1800,
            ..Default::default()
        };
        let registrar = Registrar::new(config);
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 99999, 1.0, "c1".into(), 1)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts[0].expires, Duration::from_secs(1800));
    }

    #[test]
    fn is_registered_false_for_unknown() {
        let registrar = Registrar::default();
        assert!(!registrar.is_registered("sip:nobody@example.com"));
    }

    #[test]
    fn aor_count() {
        let registrar = Registrar::default();
        assert_eq!(registrar.aor_count(), 0);

        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar
            .save("sip:bob@example.com", contact_uri("bob", "10.0.0.2"), 3600, 1.0, "c2".into(), 2)
            .unwrap();
        assert_eq!(registrar.aor_count(), 2);
    }

    #[test]
    fn save_stamps_instance_identity_when_set() {
        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "siphon-2".to_string(),
            epoch: "boot-1".to_string(),
        });
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts[0].instance_id.as_deref(), Some("siphon-2"));
        assert_eq!(contacts[0].instance_epoch.as_deref(), Some("boot-1"));
        assert!(registrar.is_local_contact(&contacts[0]));
    }

    #[test]
    fn save_without_identity_leaves_fields_none() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert!(contacts[0].instance_id.is_none());
        assert!(contacts[0].instance_epoch.is_none());
        assert!(!registrar.is_local_contact(&contacts[0]));
    }

    #[test]
    fn is_local_contact_rejects_foreign_or_stale_epoch() {
        let registrar = Registrar::default();
        registrar.set_instance_identity(InstanceIdentity {
            id: "siphon-2".to_string(),
            epoch: "boot-2".to_string(),
        });

        let foreign = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: "c".into(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: Some("siphon-7".to_string()),
            instance_epoch: Some("boot-2".to_string()),
        };
        assert!(
            !registrar.is_local_contact(&foreign),
            "different instance_id must not be local"
        );

        let stale = Contact {
            instance_id: Some("siphon-2".to_string()),
            instance_epoch: Some("boot-1".to_string()),
            ..foreign.clone()
        };
        assert!(
            !registrar.is_local_contact(&stale),
            "matching instance_id but different epoch must not be local"
        );

        let exact = Contact {
            instance_id: Some("siphon-2".to_string()),
            instance_epoch: Some("boot-2".to_string()),
            ..foreign
        };
        assert!(registrar.is_local_contact(&exact));
    }

    #[test]
    fn contact_remaining_seconds() {
        let contact = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: "test".to_string(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
        };
        // Just registered — remaining should be very close to 3600
        assert!(contact.remaining_seconds() >= 3599);
        assert!(!contact.is_expired());
    }

    #[test]
    fn expire_stale_cleans_up() {
        let registrar = Registrar::default();
        // Manually insert an already-expired contact
        {
            let contact = Contact {
                uri: contact_uri("alice", "10.0.0.1"),
                q: 1.0,
                registered_at: Instant::now() - Duration::from_secs(7200),
                expires: Duration::from_secs(3600),
                call_id: "old".to_string(),
                cseq: 1,
                source_addr: None,
                source_transport: None,
                sip_instance: None,
                reg_id: None,
                path: vec![],
                pending: false,
                instance_id: None,
                instance_epoch: None,
            };
            registrar.bindings.entry("sip:alice@example.com".to_string()).or_default().push(contact);
        }
        assert_eq!(registrar.aor_count(), 0); // expired contacts don't count
        registrar.expire_stale();
        assert_eq!(registrar.bindings.len(), 0); // cleaned up
    }

    #[test]
    fn path_stored_and_returned_on_lookup() {
        // RFC 3327: Path headers from the REGISTER must be stored per-contact
        // and returned on lookup so the registrar user can route terminating
        // requests through the proxy chain.
        let registrar = Registrar::default();
        let path = vec![
            "<sip:pcscf.ims.example.com;lr>".to_string(),
            "<sip:icscf.ims.example.com;lr>".to_string(),
        ];
        registrar
            .save_full(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, None, None, None,
                path.clone(),
            )
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].path, path);
    }

    #[test]
    fn path_updated_on_re_register() {
        // On re-REGISTER the Path may change (e.g. failover to a different P-CSCF).
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, None, None, None,
                vec!["<sip:old-pcscf.example.com;lr>".to_string()],
            )
            .unwrap();

        // Re-register with new Path
        registrar
            .save_full(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c2".into(), 2,
                None, None, None, None,
                vec!["<sip:new-pcscf.example.com;lr>".to_string()],
            )
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].path, vec!["<sip:new-pcscf.example.com;lr>"]);
    }

    #[test]
    fn path_empty_when_not_provided() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].path.is_empty());
    }

    #[test]
    fn all_contacts_returns_across_aors() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar
            .save("sip:bob@example.com", contact_uri("bob", "10.0.0.2"), 3600, 1.0, "c2".into(), 2)
            .unwrap();

        let all = registrar.all_contacts();
        assert_eq!(all.len(), 2);
        let aors: Vec<&str> = all.iter().map(|(aor, _)| aor.as_str()).collect();
        assert!(aors.contains(&"sip:alice@example.com"));
        assert!(aors.contains(&"sip:bob@example.com"));
    }

    #[test]
    fn remove_contact_removes_specific_uri() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.2"), 3600, 0.8, "c2".into(), 2)
            .unwrap();
        assert_eq!(registrar.lookup("sip:alice@example.com").len(), 2);

        registrar.remove_contact("sip:alice@example.com", "sip:alice@10.0.0.1");
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.host, "10.0.0.2");
    }

    #[test]
    fn remove_contact_cleans_up_empty_aor() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        registrar.remove_contact("sip:alice@example.com", "sip:alice@10.0.0.1");
        assert!(!registrar.is_registered("sip:alice@example.com"));
        assert_eq!(registrar.bindings.len(), 0);
    }

    #[test]
    fn remove_contact_emits_deregistered_event() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let mut receiver = registrar.subscribe_events();
        registrar.remove_contact("sip:alice@example.com", "sip:alice@10.0.0.1");

        let event = receiver.try_recv().unwrap();
        assert!(matches!(event, RegistrationEvent::Deregistered { ref aor } if aor == "sip:alice@example.com"));
    }

    #[test]
    fn remove_contact_no_event_for_nonexistent() {
        let registrar = Registrar::default();
        let mut receiver = registrar.subscribe_events();
        registrar.remove_contact("sip:alice@example.com", "sip:alice@10.0.0.1");
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn service_route_store_and_retrieve() {
        let registrar = Registrar::default();
        let routes = vec![
            "<sip:scscf.example.com;lr>".to_string(),
            "<sip:pcscf.example.com;lr>".to_string(),
        ];
        registrar.set_service_routes("sip:alice@example.com", routes.clone());

        let retrieved = registrar.service_routes("sip:alice@example.com");
        assert_eq!(retrieved, routes);
    }

    #[test]
    fn service_route_empty_returns_empty() {
        let registrar = Registrar::default();
        assert!(registrar.service_routes("sip:nobody@example.com").is_empty());
    }

    #[test]
    fn service_route_cleared_on_empty_set() {
        let registrar = Registrar::default();
        registrar.set_service_routes("sip:alice@example.com", vec!["<sip:scscf@x;lr>".into()]);
        registrar.set_service_routes("sip:alice@example.com", vec![]);
        assert!(registrar.service_routes("sip:alice@example.com").is_empty());
    }

    #[test]
    fn service_route_cleared_on_remove_all() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar.set_service_routes("sip:alice@example.com", vec!["<sip:scscf@x;lr>".into()]);

        registrar.remove_all("sip:alice@example.com");
        assert!(registrar.service_routes("sip:alice@example.com").is_empty());
    }

    #[test]
    fn public_gruu_generation() {
        let gruu = Registrar::public_gruu(
            "sip:alice@example.com",
            "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>",
        ).unwrap();
        assert_eq!(gruu, "sip:alice@example.com;gr=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
    }

    #[test]
    fn temp_gruu_generation() {
        let gruu = Registrar::temp_gruu(
            "sip:alice@example.com",
            "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>",
            "call-1@host",
        ).unwrap();
        assert!(gruu.starts_with("sip:tgruu."));
        assert!(gruu.contains("@example.com;gr"));
    }

    #[test]
    fn temp_gruu_unique_per_callid() {
        let gruu1 = Registrar::temp_gruu("sip:a@x.com", "<urn:uuid:123>", "call-1").unwrap();
        let gruu2 = Registrar::temp_gruu("sip:a@x.com", "<urn:uuid:123>", "call-2").unwrap();
        assert_ne!(gruu1, gruu2);
    }

    #[test]
    fn save_with_gruu_and_lookup_by_instance() {
        let registrar = Registrar::default();
        let instance = "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>";
        registrar
            .save_with_gruu(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None,
                Some(instance.to_string()),
                Some(1),
            )
            .unwrap();

        let contacts = registrar.lookup_by_instance("sip:alice@example.com", instance);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].sip_instance.as_deref(), Some(instance));
        assert_eq!(contacts[0].reg_id, Some(1));
    }

    #[test]
    fn save_with_gruu_replaces_by_instance_different_uri() {
        // RFC 5627 §4.2: contacts with same +sip.instance should be replaced
        // even if the Contact URI changes (e.g. IPsec port rotation).
        let registrar = Registrar::default();
        let instance = "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>";

        // First registration: port 5060
        registrar
            .save_with_gruu(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None,
                Some(instance.to_string()),
                Some(1),
            )
            .unwrap();
        assert_eq!(registrar.lookup("sip:alice@example.com").len(), 1);

        // Re-registration: different URI (port 5062) but same instance
        let mut uri2 = contact_uri("alice", "10.0.0.1");
        uri2.port = Some(5062);
        registrar
            .save_with_gruu(
                "sip:alice@example.com",
                uri2.clone(),
                3600, 1.0, "c2".into(), 2,
                None,
                Some(instance.to_string()),
                Some(1),
            )
            .unwrap();

        // Should still be 1 contact, not 2 — instance match replaced the old one
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1, "instance match should replace, not add");
        assert_eq!(contacts[0].uri.port, Some(5062), "URI should be updated");
        assert_eq!(contacts[0].sip_instance.as_deref(), Some(instance));
    }

    #[test]
    fn lookup_by_instance_no_match() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        let contacts = registrar.lookup_by_instance("sip:alice@example.com", "<urn:uuid:none>");
        assert!(contacts.is_empty());
    }

    #[test]
    fn save_with_source_preserves_addr() {
        let registrar = Registrar::default();
        let addr: SocketAddr = "192.168.1.100:50000".parse().unwrap();
        registrar
            .save_with_source(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                Some(addr), Some("tls".to_string()),
            )
            .unwrap();

        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts[0].source_addr, Some(addr));
        assert_eq!(contacts[0].source_transport.as_deref(), Some("tls"));
    }

    #[test]
    fn save_pending_and_confirm() {
        let registrar = Registrar::default();
        registrar.save_pending(
            "sip:alice@example.com",
            contact_uri("alice", "10.0.0.1"),
            3600, 1.0, "c1".into(), 1,
        );

        // Contact exists but is pending
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].pending);

        // Confirm promotes to active
        registrar.confirm_pending("sip:alice@example.com");
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(!contacts[0].pending);
    }

    #[test]
    fn asserted_identity_store_and_lookup() {
        let registrar = Registrar::default();
        assert_eq!(registrar.asserted_identity("sip:alice@example.com"), None);

        registrar.set_asserted_identity("sip:alice@example.com", "sip:+15551234@ims.example.com".to_string());
        assert_eq!(
            registrar.asserted_identity("sip:alice@example.com"),
            Some("sip:+15551234@ims.example.com".to_string()),
        );
    }

    #[test]
    fn evict_connection_oriented_removes_tls_contacts() {
        let registrar = Registrar::default();

        // UDP contact — should survive
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        // TLS contact — should be evicted
        let tls_uri = SipUri::new("10.0.0.2".to_string())
            .with_user("bob".to_string())
            .with_port(5061)
            .with_param("transport".to_string(), Some("TLS".to_string()));
        registrar
            .save("sip:bob@example.com", tls_uri, 3600, 1.0, "c2".into(), 1)
            .unwrap();

        // TCP contact — should be evicted
        let tcp_uri = SipUri::new("10.0.0.3".to_string())
            .with_user("carol".to_string())
            .with_param("transport".to_string(), Some("tcp".to_string()));
        registrar
            .save("sip:carol@example.com", tcp_uri, 3600, 1.0, "c3".into(), 1)
            .unwrap();

        assert_eq!(registrar.aor_count(), 3);

        let evicted = registrar.evict_connection_oriented();
        assert_eq!(evicted, 2);
        assert!(registrar.is_registered("sip:alice@example.com"));
        assert!(!registrar.is_registered("sip:bob@example.com"));
        assert!(!registrar.is_registered("sip:carol@example.com"));
    }

    #[test]
    fn evict_connection_oriented_mixed_aor() {
        let registrar = Registrar::default();

        // Same AoR, two contacts: one UDP, one TLS
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        let tls_uri = SipUri::new("10.0.0.2".to_string())
            .with_user("alice".to_string())
            .with_port(5061)
            .with_param("transport".to_string(), Some("TLS".to_string()));
        registrar
            .save("sip:alice@example.com", tls_uri, 3600, 0.8, "c2".into(), 2)
            .unwrap();

        assert_eq!(registrar.lookup("sip:alice@example.com").len(), 2);

        let evicted = registrar.evict_connection_oriented();
        assert_eq!(evicted, 1);
        assert!(registrar.is_registered("sip:alice@example.com"));
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.host, "10.0.0.1");
    }

    #[test]
    fn clear_bindings_removes_without_event() {
        let registrar = Registrar::default();
        let mut rx = registrar.subscribe_events();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        // Drain the Registered event
        let _ = rx.try_recv();

        registrar.clear_bindings("sip:alice@example.com");

        assert!(!registrar.is_registered("sip:alice@example.com"));
        // No event should have been emitted
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn force_save_then_deregister_emits_single_event() {
        let registrar = Registrar::default();
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let mut rx = registrar.subscribe_events();

        // Simulate force=True + Expires: 0 (what PyRegistrar::save does)
        registrar.clear_bindings("sip:alice@example.com");
        registrar
            .save("sip:alice@example.com", contact_uri("alice", "10.0.0.1"), 0, 1.0, "c1".into(), 2)
            .unwrap();

        // Should get exactly one Deregistered event (from save with expires=0)
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, RegistrationEvent::Deregistered { .. }));
        // No second event
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn associated_uris_set_get_clear() {
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com";

        // Initially empty
        assert!(registrar.associated_uris(aor).is_empty());

        // Store PAU list
        let uris = vec![
            "sip:alice@ims.example.com".to_string(),
            "tel:+1234567890".to_string(),
        ];
        registrar.set_associated_uris(aor, uris.clone());
        assert_eq!(registrar.associated_uris(aor), uris);

        // Clear with empty vec
        registrar.set_associated_uris(aor, Vec::new());
        assert!(registrar.associated_uris(aor).is_empty());

        // Re-store and clear via remove_all
        registrar.set_associated_uris(aor, uris.clone());
        registrar
            .save(aor, contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar.remove_all(aor);
        assert!(registrar.associated_uris(aor).is_empty());
    }

    // ---- alias-chain (IMS implicit registration set) ----

    #[test]
    fn alias_index_built_by_set_associated_uris() {
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar
            .save(primary, contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar.set_associated_uris(
            primary,
            vec![
                "tel:+15551234".to_string(),
                "sip:wildcard@ims.example.com".to_string(),
            ],
        );

        // Lookup by either alias resolves to the primary's contact.
        let by_tel = registrar.lookup("sip:tel:+15551234");
        assert_eq!(by_tel.len(), 1);
        assert_eq!(by_tel[0].uri.host, "10.0.0.1");

        let by_wildcard = registrar.lookup("sip:wildcard@ims.example.com");
        assert_eq!(by_wildcard.len(), 1);
        assert_eq!(by_wildcard[0].uri.host, "10.0.0.1");

        assert!(registrar.is_registered("sip:tel:+15551234"));
        assert!(registrar.is_registered(primary));
    }

    #[test]
    fn alias_index_skips_self_aliases() {
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar.set_associated_uris(
            primary,
            vec![
                primary.to_string(),
                "tel:+15551234".to_string(),
            ],
        );

        // The primary URI in the AU list must not become an alias of itself
        // (a self-loop would break resolve_alias semantics).
        assert!(registrar.aliases.get(primary).is_none());
        // The other URI is registered as an alias.
        assert_eq!(
            registrar
                .aliases
                .get("sip:tel:+15551234")
                .map(|e| e.value().clone()),
            Some(primary.to_string()),
        );
    }

    #[test]
    fn alias_index_replaces_on_resave() {
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar.set_associated_uris(
            primary,
            vec!["tel:+15550000".to_string()],
        );
        assert!(registrar.aliases.contains_key("sip:tel:+15550000"));

        // Replace the implicit set with a different list.
        registrar.set_associated_uris(
            primary,
            vec!["tel:+15551111".to_string()],
        );
        assert!(!registrar.aliases.contains_key("sip:tel:+15550000"));
        assert!(registrar.aliases.contains_key("sip:tel:+15551111"));
    }

    #[test]
    fn alias_index_resolved_on_save() {
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar.set_associated_uris(
            primary,
            vec!["tel:+15551234".to_string()],
        );

        // REGISTER arrives with To = alias; bindings should still land on primary.
        registrar
            .save("sip:tel:+15551234", contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();

        let by_primary = registrar.lookup(primary);
        assert_eq!(by_primary.len(), 1);
        assert_eq!(by_primary[0].uri.host, "10.0.0.1");

        // The bindings DashMap has a single key — the primary, not the alias.
        assert!(registrar.bindings.contains_key(primary));
        assert!(!registrar.bindings.contains_key("sip:tel:+15551234"));
    }

    #[test]
    fn dereg_clears_alias_index() {
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar
            .save(primary, contact_uri("alice", "10.0.0.1"), 3600, 1.0, "c1".into(), 1)
            .unwrap();
        registrar.set_associated_uris(
            primary,
            vec!["tel:+15551234".to_string()],
        );
        assert!(registrar.aliases.contains_key("sip:tel:+15551234"));

        registrar.remove_all(primary);

        // Aliases pruned along with bindings + AU list.
        assert!(!registrar.aliases.contains_key("sip:tel:+15551234"));
        assert!(registrar.lookup("sip:tel:+15551234").is_empty());
    }

    #[test]
    fn alias_set_via_alias_clobbers_primary() {
        // set_associated_uris on something already registered as an alias
        // resolves to the primary and replaces the primary's implicit set.
        let registrar = Registrar::default();
        let primary = "sip:alice@ims.example.com";
        registrar.set_associated_uris(primary, vec!["tel:+15550000".to_string()]);

        // Same caller now claims a different IMPU as the implicit set —
        // calling via the alias should land on the primary.
        registrar.set_associated_uris(
            "sip:tel:+15550000",
            vec!["tel:+15551111".to_string()],
        );

        assert_eq!(
            registrar.associated_uris(primary),
            vec!["tel:+15551111".to_string()],
        );
        // Old alias dropped, new one in place.
        assert!(!registrar.aliases.contains_key("sip:tel:+15550000"));
        assert!(registrar.aliases.contains_key("sip:tel:+15551111"));
    }
}
