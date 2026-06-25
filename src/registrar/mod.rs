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

/// Whether a contact's `source_transport` is a connection-oriented (stream)
/// transport whose socket close is a flow-failure signal (RFC 5626 §4.2.2).
///
/// Only stream transports are tracked in the `connection_index` and eligible
/// for `unregister_flow`: UDP `ConnectionId`s are deterministic `(local,remote)`
/// hashes with no closable socket, so a "connection closed" notification never
/// arrives for them.
pub(crate) fn is_stream_transport(transport: Option<&str>) -> bool {
    matches!(
        transport.map(|t| t.to_ascii_lowercase()).as_deref(),
        Some("tcp") | Some("tls") | Some("ws") | Some("wss")
    )
}

/// What kind of registration the contact represents.
///
/// `Ue` is the default — a UE-side binding that came in on a REGISTER and
/// participates in routing (`lookup()` returns these).
///
/// `As` is an application-server-side contact that the S-CSCF learned from
/// a 3PR 200 OK to an iFC-matched AS (TS 24.229 §5.4.2.1.2). AS contacts
/// carry the AS's `Contact:` URI and its RFC 3840 feature tags
/// (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, …) so they can be advertised back
/// to watchers of the reg event package (RFC 3680).  They are **not**
/// routing targets: `lookup()` filters them out, so a downstream INVITE
/// for the AoR will never be sent to `sip:mmtel.…:8060` by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContactKind {
    /// UE-side binding from a REGISTER (default).
    #[default]
    Ue,
    /// AS-side contact captured from a 3PR 200 OK; carries the AS's
    /// capability advertisement but is not a routing target.
    As,
}

impl ContactKind {
    /// Stable string form for persistence (Redis / Postgres).
    pub fn as_str(&self) -> &'static str {
        match self {
            ContactKind::Ue => "ue",
            ContactKind::As => "as",
        }
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
    /// Opaque proxy-side token that references this binding.  Set by the
    /// script (typically the P-CSCF) at REGISTER time to enable token-keyed
    /// MT routing — the token is embedded in the userpart of the Path URI
    /// the proxy advertises upstream, and `Registrar::lookup_by_token`
    /// resolves it back to the binding when the request comes back via the
    /// consumed Route header (RFC 3327 §5 / TS 24.229 §5.2.7.2).
    pub flow_token: Option<String>,
    /// The local socket the inbound REGISTER landed on.  Lets the relay
    /// path egress an MT request from the same listener — load-bearing
    /// for IPSec sec-agree where `pcscf_port_s` is non-default and the
    /// Via on the outbound message must reflect that port (3GPP TS 33.203
    /// §7.4).
    pub inbound_local_addr: Option<SocketAddr>,
    /// `ConnectionId.0` of the accepted inbound connection that delivered
    /// the REGISTER.  Meaningful only on the accepting instance and only
    /// for the lifetime of the connection (TCP/TLS/WS/WSS); recomputable
    /// on demand for UDP since UDP `ConnectionId`s are deterministic
    /// hashes of `(local_addr, remote_addr)`.
    pub inbound_connection_id: Option<u64>,
    /// Additional Contact-header parameters carried through from the
    /// originating REGISTER (or 3PR 200 OK), excluding the ones we
    /// already break out into typed fields (`tag`, `q`, `expires`,
    /// `+sip.instance`, `reg-id`).  Holds RFC 3840 feature tags
    /// (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, `+g.3gpp.iari-ref`, …)
    /// and any other vendor / future params, both flag form
    /// (`Some(name), None`) and valued form (`Some(name), Some(value)`).
    /// Surfaced verbatim in RFC 3680 reg-event NOTIFY bodies so
    /// watchers (UE / AS) see the same capability advertisement that
    /// the registrar received.
    pub params: Vec<(String, Option<String>)>,
    /// What kind of binding this is.  `Ue` (the default) participates
    /// in routing via `lookup()`.  `As` is captured from a 3PR 200 OK
    /// and exists only to surface the AS's capability advertisement in
    /// reg-event NOTIFY bodies — it is **excluded** from routing
    /// lookups so an MT INVITE never gets sent to the AS by mistake
    /// (TS 24.229 §5.4.2.1.2).
    pub kind: ContactKind,
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
    /// When true, `registrar.save()` requires the AoR (To-URI user) to match
    /// the authenticated digest user, rejecting a REGISTER that tries to bind a
    /// contact under another subscriber's AoR (account takeover / forced
    /// deregister). Default false for backward compatibility and IMS
    /// deployments where the public identity (AoR) legitimately differs from
    /// the private auth identity — those keep this off and authorize via the
    /// implicit registration set instead.
    pub enforce_auth_aor_match: bool,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            default_expires: 3600,
            max_expires: 7200,
            min_expires: 60,
            max_contacts: 10,
            enforce_auth_aor_match: false,
        }
    }
}

/// Captured inbound flow + opaque proxy-side token, supplied by the script
/// at REGISTER time to enable Path-token MT routing.  Stored on the
/// resulting `Contact`; reconstituted as a `Flow` view on lookup.
///
/// All fields default to `None`: callers that don't need flow-aware MT
/// routing pass `FlowCapture::default()` and the resulting Contact behaves
/// identically to a pre-feature binding.
#[derive(Debug, Clone, Default)]
pub struct FlowCapture {
    pub flow_token: Option<String>,
    pub inbound_local_addr: Option<SocketAddr>,
    pub inbound_connection_id: Option<u64>,
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
    /// Opaque flow-token → AoR reverse index.  Populated when a binding is
    /// saved with a `flow_token` (typically by P-CSCF for Path-token MT
    /// routing per TS 24.229 §5.2.7.2).  Maintained inline by every
    /// add/remove path that touches `bindings` and rebuilt wholesale by
    /// `rebuild_token_index` on `restore_from_backend` /
    /// `evict_connection_oriented`.
    tokens: DashMap<String, Aor>,
    /// `ConnectionId.0` → AoRs whose binding arrived on that stream
    /// connection (TCP/TLS/WS/WSS).  Reverse index for RFC 5626 §4.2.2
    /// flow-failure deregistration: when a stream connection closes, the
    /// transport layer notifies `unregister_flow(connection_id)`, which uses
    /// this index to drop only the affected bindings in O(bindings-for-that-id)
    /// instead of scanning every AoR on every connection close (scanner
    /// churn).  UDP bindings are deliberately **excluded** — UDP
    /// `ConnectionId`s are deterministic `(local,remote)` hashes that survive
    /// restart and don't correspond to a closable socket.  Maintained inline
    /// by every add/remove path that touches `bindings`; process-local, so a
    /// restart correctly starts empty (stream contacts are dropped on restart
    /// by `evict_connection_oriented`).
    connection_index: DashMap<u64, Vec<Aor>>,
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
            tokens: DashMap::new(),
            connection_index: DashMap::new(),
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
        self.save_full(aor, uri, expires_secs, q, call_id, cseq, source_addr, source_transport, None, None, vec![], FlowCapture::default(), Vec::new())
    }

    /// Core save with all fields including +sip.instance and reg-id.
    ///
    /// Applies the local `max_expires` cap. Most callers want this — they're
    /// the registrar of record and own the policy on how long a binding
    /// lives. Proxy-side caches that mirror an upstream registrar's grant
    /// should call [`save_full_uncapped`](Self::save_full_uncapped) instead,
    /// since the upstream is authoritative on lifetime.
    // Wide by necessity: a contact binding carries the full RFC 3261 + IMS
    // parameter set (q, expires, instance, flow token, aliases, …).
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
        flow: FlowCapture,
        params: Vec<(String, Option<String>)>,
    ) -> Result<(), RegistrarError> {
        let capped = std::cmp::min(expires_secs, self.config.max_expires);
        self.save_full_uncapped(
            aor, uri, capped, q, call_id, cseq, source_addr, source_transport,
            sip_instance, reg_id, path, flow, params,
        )
    }

    /// Core save without applying the local `max_expires` cap.
    ///
    /// Used by proxy-side `save_proxy` — the upstream registrar of record
    /// has already capped, and a local cap would shorten the cached binding
    /// below the upstream's grant, causing MT routing failures inside the
    /// upstream's still-valid expiry window.
    ///
    /// `min_expires` is still enforced (RFC 3261 §10.3 423 Interval Too
    /// Brief): callers must not save bindings shorter than the configured
    /// floor regardless of upstream grant.
    // Wide by necessity: mirrors [`save_full`]'s full RFC 3261 + IMS contact
    // parameter set, minus the local expires cap.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn save_full_uncapped(
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
        flow: FlowCapture,
        params: Vec<(String, Option<String>)>,
    ) -> Result<(), RegistrarError> {
        // Resolve alias → primary so a REGISTER arriving with a non-primary
        // IMPU still attaches contacts to the implicit set's primary AoR.
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();

        // Keyspace-safety invariant: never let a crafted AoR collide a contact
        // binding into the reserved `state:` namespace or inject control chars
        // into a storage key. See `is_aor_key_safe`.
        if !is_aor_key_safe(aor) {
            tracing::warn!(aor = %aor.escape_debug(), "rejecting REGISTER: unsafe AoR storage key");
            return Err(RegistrarError::InvalidAor);
        }

        if expires_secs > 0 && expires_secs < self.config.min_expires {
            return Err(RegistrarError::IntervalTooBrief {
                min_expires: self.config.min_expires,
            });
        }

        let (instance_id, instance_epoch) = self.current_identity_pair();
        let FlowCapture {
            flow_token,
            inbound_local_addr,
            inbound_connection_id,
        } = flow;
        // Captured before `source_transport` is moved into the Contact below;
        // drive the stream-only connection reverse index (`inbound_connection_id`
        // is `Copy`, so it stays usable after the struct takes it).
        let new_connection_id = inbound_connection_id;
        let new_is_stream = is_stream_transport(source_transport.as_deref());
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
            flow_token: flow_token.clone(),
            inbound_local_addr,
            inbound_connection_id,
            params,
            kind: ContactKind::Ue,
        };

        let uri_string = uri.to_string();

        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        let contacts = entry.value_mut();

        // Tokens to remove from the reverse index — collected from contacts
        // we drop in this critical section.  Applied after `drop(entry)` to
        // keep the index update outside the bindings shard guard, but still
        // before any await/IO so concurrent readers see a consistent view.
        let mut tokens_to_remove: Vec<String> = Vec::new();
        // Stream connection ids whose binding we drop in this critical section;
        // pruned from `connection_index` after `drop(entry)` (same ordering as
        // `tokens_to_remove`).
        let mut conns_to_deindex: Vec<u64> = Vec::new();

        // Remove expired contacts; harvest their tokens + connection ids.
        contacts.retain(|c| {
            if c.is_expired() {
                if let Some(token) = &c.flow_token {
                    tokens_to_remove.push(token.clone());
                }
                if is_stream_transport(c.source_transport.as_deref()) {
                    if let Some(id) = c.inbound_connection_id {
                        conns_to_deindex.push(id);
                    }
                }
                false
            } else {
                true
            }
        });

        if expires_secs == 0 {
            // Expires=0 means deregister this specific UE contact.  Only
            // touches UE-kind entries — an AS-side capability record
            // happens to share the same URI string only by coincidence
            // and survives until the cascade-clear below decides
            // otherwise.
            contacts.retain(|c| {
                if c.kind == ContactKind::Ue && c.uri.to_string() == uri_string {
                    if let Some(token) = &c.flow_token {
                        tokens_to_remove.push(token.clone());
                    }
                    if is_stream_transport(c.source_transport.as_deref()) {
                        if let Some(id) = c.inbound_connection_id {
                            conns_to_deindex.push(id);
                        }
                    }
                    false
                } else {
                    true
                }
            });
            // Cascade-clear: AS contacts only make sense while the user
            // is registered (TS 24.229 §5.4.2.1.2).  If the dereg
            // emptied the last UE binding, drop any remaining AS
            // capability records so the next reg-event NOTIFY emits a
            // clean terminated registration with no stale contacts.
            let any_ue_left = contacts
                .iter()
                .any(|c| c.kind == ContactKind::Ue && !c.is_expired());
            if !any_ue_left {
                contacts.clear();
            }
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
            for token in &tokens_to_remove {
                self.tokens.remove(token);
            }
            for id in &conns_to_deindex {
                self.deindex_connection(*id, aor);
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
            // Harvest the displaced contact's token + stream connection id so a
            // re-REGISTER (possibly over a new connection) cleanly retires the
            // old entry from both reverse indexes.  The new binding is
            // re-indexed below; if the connection is unchanged the deindex +
            // reindex nets to a no-op.
            if let Some(old_token) = &contacts[idx].flow_token {
                tokens_to_remove.push(old_token.clone());
            }
            if is_stream_transport(contacts[idx].source_transport.as_deref()) {
                if let Some(id) = contacts[idx].inbound_connection_id {
                    conns_to_deindex.push(id);
                }
            }
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

        // Update the token index: remove harvested tokens first (so a
        // refresh that reuses the same token isn't accidentally deleted),
        // then insert the new mapping.
        for token in &tokens_to_remove {
            // Don't drop the about-to-be-(re)inserted mapping if the
            // script reused the same token on the refresh.
            if Some(token.as_str()) != flow_token.as_deref() {
                self.tokens.remove(token);
            }
        }
        if let Some(token) = &flow_token {
            self.tokens.insert(token.clone(), aor_owned.clone());
        }

        // Maintain the stream connection reverse index: retire the ids of any
        // contacts dropped above (expired/displaced), then index the new
        // binding.  Order matters when a refresh reuses the same connection —
        // deindex first, reindex second nets to the binding staying indexed.
        for id in &conns_to_deindex {
            self.deindex_connection(*id, &aor_owned);
        }
        self.index_connection(new_connection_id, new_is_stream, &aor_owned);

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
        // Capture flow tokens before dropping the AoR so the reverse index
        // doesn't strand entries pointing at gone bindings.
        let removed = self.bindings.remove(aor);
        let had_bindings = removed.is_some();
        if let Some((_, contacts)) = removed {
            for contact in contacts {
                if let Some(token) = contact.flow_token {
                    self.tokens.remove(&token);
                }
                if is_stream_transport(contact.source_transport.as_deref()) {
                    if let Some(id) = contact.inbound_connection_id {
                        self.deindex_connection(id, aor);
                    }
                }
            }
        }
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
        if let Some((_, contacts)) = self.bindings.remove(aor) {
            for contact in contacts {
                if let Some(token) = contact.flow_token {
                    self.tokens.remove(&token);
                }
                if is_stream_transport(contact.source_transport.as_deref()) {
                    if let Some(id) = contact.inbound_connection_id {
                        self.deindex_connection(id, aor);
                    }
                }
            }
        }
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
        // Tokens harvested from evicted contacts; pruned from the reverse
        // index after the per-AoR loop so we don't hold the bindings entry
        // guard across the tokens DashMap write (different shards, but
        // explicit ordering keeps reasoning easy).
        let mut tokens_to_remove: Vec<String> = Vec::new();
        let mut conns_to_deindex: Vec<(u64, String)> = Vec::new();

        for aor in aors {
            let before;
            let after;

            if let Some(mut entry) = self.bindings.get_mut(&aor) {
                before = entry.value().len();
                entry.value_mut().retain(|c| {
                    let transport = c.uri.get_param("transport").unwrap_or("");
                    let evict = matches!(
                        transport.to_ascii_lowercase().as_str(),
                        "tcp" | "tls" | "ws" | "wss"
                    );
                    if evict {
                        if let Some(token) = &c.flow_token {
                            tokens_to_remove.push(token.clone());
                        }
                        if is_stream_transport(c.source_transport.as_deref()) {
                            if let Some(id) = c.inbound_connection_id {
                                conns_to_deindex.push((id, aor.clone()));
                            }
                        }
                    }
                    !evict
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

        for token in &tokens_to_remove {
            self.tokens.remove(token);
        }
        for (id, aor) in &conns_to_deindex {
            self.deindex_connection(*id, aor);
        }

        evicted
    }

    /// Look up routable contacts for an AoR. Returns non-expired UE-side
    /// contacts sorted by q descending.
    ///
    /// If `aor` is an alias of an IMS implicit registration set's primary,
    /// returns the primary's contacts (so terminating routing on a non-primary
    /// IMPU like `tel:+15551234` resolves transparently).
    ///
    /// AS-side contacts (captured from 3PR 200 OKs — TS 24.229 §5.4.2.1.2)
    /// are **excluded** from this list.  They are capability advertisements,
    /// not routing targets — see [`lookup_all`](Self::lookup_all) for the
    /// merged view that reg-event NOTIFY emission uses.
    pub fn lookup(&self, aor: &str) -> Vec<Contact> {
        let primary = self.resolve_alias(aor);
        match self.bindings.get(primary.as_str()) {
            Some(entry) => entry
                .value()
                .iter()
                .filter(|c| !c.is_expired() && c.kind == ContactKind::Ue)
                .cloned()
                .collect(),
            None => Vec::new(),
        }
    }

    /// Look up every non-expired contact for an AoR, including AS-side
    /// capability records.  Sorted UE-first, then AS, each by q descending.
    ///
    /// Used by reg-event NOTIFY emission (RFC 3680 + TS 24.229 §5.4.2.1.2)
    /// so a watcher (UE or AS) sees both the UE's routable bindings and
    /// the iFC-matched AS's `+g.3gpp.*` feature tags.
    pub fn lookup_all(&self, aor: &str) -> Vec<Contact> {
        let primary = self.resolve_alias(aor);
        let mut out: Vec<Contact> = match self.bindings.get(primary.as_str()) {
            Some(entry) => entry
                .value()
                .iter()
                .filter(|c| !c.is_expired())
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        out.sort_by(|a, b| {
            // UE-first then AS, then q desc within each kind.
            match (a.kind, b.kind) {
                (ContactKind::Ue, ContactKind::As) => std::cmp::Ordering::Less,
                (ContactKind::As, ContactKind::Ue) => std::cmp::Ordering::Greater,
                _ => b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal),
            }
        });
        out
    }

    /// Check if an AoR has any non-expired UE-side contacts.
    ///
    /// AS-side contacts (which exist only as capability advertisements) do
    /// not register a user — an AoR with only AS contacts is treated as
    /// unregistered, matching the IMS lifecycle (no UE binding → AS
    /// contacts should never have been written, or should be cleaned up).
    pub fn is_registered(&self, aor: &str) -> bool {
        let primary = self.resolve_alias(aor);
        match self.bindings.get(primary.as_str()) {
            Some(entry) => entry
                .value()
                .iter()
                .any(|c| !c.is_expired() && c.kind == ContactKind::Ue),
            None => false,
        }
    }

    /// Number of registered AoRs (with at least one non-expired UE-side
    /// contact) known to *this* instance's in-memory map.
    ///
    /// AS-side contacts don't count — they're capability records, not
    /// registrations.  An AoR populated only with AS contacts (which
    /// shouldn't happen with the cascade-clear semantic in `save_full`,
    /// but defends against externally manipulated state) is treated as
    /// unregistered.
    pub fn aor_count(&self) -> usize {
        self.bindings
            .iter()
            .filter(|entry| {
                entry
                    .value()
                    .iter()
                    .any(|c| !c.is_expired() && c.kind == ContactKind::Ue)
            })
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
        let mut tokens_to_remove: Vec<String> = Vec::new();
        let mut conns_to_deindex: Vec<u64> = Vec::new();
        if let Some(mut entry) = self.bindings.get_mut(aor) {
            let before = entry.value().len();
            entry.value_mut().retain(|c| {
                if c.uri.to_string() == contact_uri {
                    if let Some(token) = &c.flow_token {
                        tokens_to_remove.push(token.clone());
                    }
                    if is_stream_transport(c.source_transport.as_deref()) {
                        if let Some(id) = c.inbound_connection_id {
                            conns_to_deindex.push(id);
                        }
                    }
                    false
                } else {
                    true
                }
            });
            let removed = entry.value().len() < before;
            let aor_empty = entry.value().is_empty();
            if aor_empty {
                drop(entry);
                self.bindings.remove(aor);
            }
            for token in &tokens_to_remove {
                self.tokens.remove(token);
            }
            for id in &conns_to_deindex {
                self.deindex_connection(*id, aor);
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

    /// Save an application-server-side contact captured from a 3PR 200 OK
    /// (3GPP TS 24.229 §5.4.2.1.2).
    ///
    /// AS contacts carry the AS's `Contact:` URI plus its RFC 3840 feature
    /// tags (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, …) so reg-event NOTIFY
    /// emission can surface them to watchers.  They are **not** routing
    /// targets — `Registrar::lookup` filters them out so a downstream
    /// MT INVITE never gets sent to `sip:mmtel.…:8060` by mistake.
    ///
    /// Semantics differ from `save_full`:
    ///
    /// - No `+sip.instance` / `reg-id` matching — replacement is by URI
    ///   only, which is the natural identity for an AS-side contact.
    /// - No flow capture, source address, transport, or path — none of
    ///   those exist on a reply-side Contact.
    /// - `min_expires` / `max_expires` are not enforced — the AS chose
    ///   its own lifetime and the S-CSCF mirrors it.
    /// - `Expires: 0` removes any prior AS contact with the same URI.
    /// - An AoR with no UE-side contacts at all rejects new AS contacts
    ///   with `ContactKind` does not change registration state — keep the
    ///   capability record only while the user is registered.  Returns
    ///   `Ok(false)` in that case so callers can ignore silently.
    pub fn save_as_contact(
        &self,
        aor: &str,
        uri: SipUri,
        expires_secs: u32,
        q: f32,
        params: Vec<(String, Option<String>)>,
    ) -> Result<bool, RegistrarError> {
        let primary = self.resolve_alias(aor);
        let aor = primary.as_str();
        let uri_string = uri.to_string();

        let mut entry = self.bindings.entry(aor.to_string()).or_default();
        let contacts = entry.value_mut();

        // Drop expired entries first so we don't race against a UE
        // binding that is technically gone; harvest stream connection ids so
        // the reverse index doesn't strand entries for the dropped bindings.
        let mut conns_to_deindex: Vec<u64> = Vec::new();
        contacts.retain(|c| {
            if c.is_expired() {
                if is_stream_transport(c.source_transport.as_deref()) {
                    if let Some(id) = c.inbound_connection_id {
                        conns_to_deindex.push(id);
                    }
                }
                false
            } else {
                true
            }
        });
        for id in &conns_to_deindex {
            self.deindex_connection(*id, aor);
        }

        if expires_secs == 0 {
            // Targeted AS-contact removal — same URI, AS-kind only.
            let before = contacts.len();
            contacts.retain(|c| {
                !(c.kind == ContactKind::As && c.uri.to_string() == uri_string)
            });
            if contacts.len() == before {
                drop(entry);
                return Ok(false);
            }
            let stored: Vec<_> = contacts
                .iter()
                .map(backend::StoredContact::from_contact)
                .collect();
            let aor_owned = aor.to_string();
            let aor_empty = contacts.is_empty();
            if aor_empty {
                drop(entry);
                self.bindings.remove(aor);
            } else {
                drop(entry);
            }
            self.persist_aor(&aor_owned, stored);
            return Ok(true);
        }

        // Guard: never write an AS contact under an AoR that has no
        // UE-side binding.  This keeps reginfo emission honest — a
        // <contact> element only surfaces while the user is actually
        // registered.  Caller can check the return value if needed.
        let has_ue_binding = contacts
            .iter()
            .any(|c| c.kind == ContactKind::Ue && !c.is_expired());
        if !has_ue_binding {
            drop(entry);
            return Ok(false);
        }

        let contact = Contact {
            uri,
            q,
            registered_at: Instant::now(),
            expires: Duration::from_secs(expires_secs as u64),
            call_id: String::new(),
            cseq: 0,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params,
            kind: ContactKind::As,
        };

        // Replace existing AS contact with the same URI; never collide
        // with a UE contact even if URIs happen to match.
        let replace_idx = contacts.iter().position(|c| {
            c.kind == ContactKind::As && c.uri.to_string() == uri_string
        });
        if let Some(idx) = replace_idx {
            contacts[idx] = contact;
        } else {
            // No max_contacts cap for AS records — iFC chains can ramp
            // up legitimate AS counts.  Operator can enforce upstream.
            contacts.push(contact);
        }

        let stored: Vec<_> = contacts
            .iter()
            .map(backend::StoredContact::from_contact)
            .collect();
        let aor_owned = aor.to_string();
        drop(entry);
        self.persist_aor(&aor_owned, stored);
        Ok(true)
    }

    /// Save a contact binding with GRUU parameters (RFC 5627 + RFC 5626).
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
        self.save_full(aor, uri, expires_secs, q, call_id, cseq, source_addr, None, sip_instance, reg_id, vec![], FlowCapture::default(), Vec::new())
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

    /// Resolve an opaque proxy-side token to its (AoR, Contact) binding.
    ///
    /// Used by P-CSCF MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2): the
    /// proxy advertises a Path URI whose userpart contains the token; on
    /// the MT request, `request.consumed_route_user` exposes that token
    /// and this method locates the binding so the script can call
    /// `request.relay(flow=binding.flow)`.
    ///
    /// Returns `None` when:
    /// - The token is unknown (never set, or already evicted).
    /// - The token resolves to an AoR with no contacts carrying it
    ///   (race with deregister; the index entry is pruned on the next
    ///   maintenance pass).
    /// - The matching contact has expired (lazy expiry).
    pub fn lookup_by_token(&self, token: &str) -> Option<(Aor, Contact)> {
        let aor = self.tokens.get(token).map(|entry| entry.value().clone())?;
        let entry = self.bindings.get(&aor)?;
        for contact in entry.value().iter() {
            if contact.is_expired() || contact.kind != ContactKind::Ue {
                continue;
            }
            if contact.flow_token.as_deref() == Some(token) {
                return Some((aor.clone(), contact.clone()));
            }
        }
        None
    }

    /// Rebuild the `tokens` reverse index from scratch by scanning every
    /// non-expired contact in `bindings`.  Called by `restore_from_backend`
    /// after loading from a persistent backend, and after
    /// `evict_connection_oriented` discards stream-transport bindings whose
    /// connections did not survive restart.  Idempotent and O(N) over total
    /// contacts; runs once at startup.
    pub fn rebuild_token_index(&self) {
        self.tokens.clear();
        for entry in self.bindings.iter() {
            let aor = entry.key();
            for contact in entry.value().iter() {
                if contact.is_expired() {
                    continue;
                }
                if let Some(token) = &contact.flow_token {
                    self.tokens.insert(token.clone(), aor.clone());
                }
            }
        }
    }

    /// Add `aor` to the reverse connection index for a stream binding's
    /// `connection_id`.  No-op for non-stream transports (UDP `ConnectionId`s
    /// aren't backed by a closable socket) or when `connection_id` is `None`.
    /// Idempotent — re-indexing the same `(id, aor)` does not duplicate it.
    fn index_connection(&self, connection_id: Option<u64>, is_stream: bool, aor: &str) {
        if !is_stream {
            return;
        }
        if let Some(id) = connection_id {
            let mut entry = self.connection_index.entry(id).or_default();
            if !entry.iter().any(|a| a == aor) {
                entry.push(aor.to_string());
            }
        }
    }

    /// Remove the `(connection_id → aor)` mapping from the reverse connection
    /// index, dropping the id entry entirely once no AoRs remain under it.
    fn deindex_connection(&self, connection_id: u64, aor: &str) {
        if let Some(mut entry) = self.connection_index.get_mut(&connection_id) {
            entry.retain(|a| a != aor);
            if entry.is_empty() {
                drop(entry);
                self.connection_index.remove(&connection_id);
            }
        }
    }

    /// Deregister every UE binding that arrived on a now-dead stream
    /// connection (RFC 5626 §4.2.2 flow failure).
    ///
    /// Called by the transport layer when a TCP/TLS/WS/WSS connection closes
    /// — peer FIN/RST, read error, idle timeout, or a CRLF-keepalive failure
    /// (`CrlfPongTracker`).  Removes only contacts whose
    /// `inbound_connection_id` matches `connection_id` **and** whose transport
    /// is stream (so a UDP binding that happens to carry a colliding id is
    /// never touched); cascade-clears orphaned AS capability records once the
    /// last UE binding for an AoR is gone (TS 24.229 §5.4.2.1.2); prunes the
    /// `tokens` and `connection_index` reverse indexes; writes through to the
    /// backend; updates the `registrations_active` gauge; and emits
    /// `Deregistered` so `@registrar.on_change` fires the terminated
    /// reg-event NOTIFY cascade.
    ///
    /// Returns the number of contacts removed.  O(bindings-for-that-connection);
    /// an unknown id is an O(1) no-op — scanner/transient connections never
    /// registered, so they were never indexed.
    pub fn unregister_flow(&self, connection_id: u64) -> usize {
        self.unregister_flow_collect(connection_id).len()
    }

    /// Like [`unregister_flow`](Self::unregister_flow) but returns the
    /// `(aor, contact)` of every binding it removed, so the caller can run the
    /// network-dereg cascade — e.g. a P-CSCF synthesizing an `Expires: 0`
    /// REGISTER toward the S-CSCF under `dereg_mode: network_dereg`.  The
    /// per-AoR `service_routes` are deliberately **not** cleared here, so the
    /// caller can still resolve the upstream next hop after removal.
    pub fn unregister_flow_collect(&self, connection_id: u64) -> Vec<(Aor, Contact)> {
        let aors = match self.connection_index.remove(&connection_id) {
            Some((_, aors)) => aors,
            None => return Vec::new(),
        };

        let mut removed: Vec<(Aor, Contact)> = Vec::new();
        let mut tokens_to_remove: Vec<String> = Vec::new();
        let mut deregistered: Vec<String> = Vec::new();
        let mut emptied_count: i64 = 0;
        // The index may list an AoR more than once if an earlier removal path
        // didn't prune it; process each AoR at most once.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

        for aor in aors {
            if !seen.insert(aor.clone()) {
                continue;
            }
            let stored: Vec<backend::StoredContact>;
            let emptied: bool;
            let changed: bool;
            {
                let mut entry = match self.bindings.get_mut(&aor) {
                    Some(entry) => entry,
                    // Stale index entry — the binding was already removed by
                    // another path.  Harmless: nothing to deregister.
                    None => continue,
                };
                // Partition into kept vs removed so the caller gets the dropped
                // bindings (for the network-dereg cascade), harvesting their
                // tokens along the way.
                let contacts = std::mem::take(entry.value_mut());
                let before = contacts.len();
                let mut kept = Vec::with_capacity(before);
                for contact in contacts {
                    let drop_contact = contact.inbound_connection_id == Some(connection_id)
                        && is_stream_transport(contact.source_transport.as_deref());
                    if drop_contact {
                        if let Some(token) = &contact.flow_token {
                            tokens_to_remove.push(token.clone());
                        }
                        removed.push((aor.clone(), contact));
                    } else {
                        kept.push(contact);
                    }
                }
                changed = kept.len() < before;
                *entry.value_mut() = kept;
                // Cascade-clear orphaned AS records once no UE binding survives.
                let any_ue_left = entry
                    .value()
                    .iter()
                    .any(|c| c.kind == ContactKind::Ue && !c.is_expired());
                if !any_ue_left {
                    entry.value_mut().clear();
                }
                emptied = entry.value().is_empty();
                stored = entry
                    .value()
                    .iter()
                    .map(backend::StoredContact::from_contact)
                    .collect();
            }
            if emptied {
                self.bindings.remove(&aor);
                emptied_count += 1;
            }
            self.persist_aor(&aor, stored);
            if changed || emptied {
                deregistered.push(aor);
            }
        }

        for token in &tokens_to_remove {
            self.tokens.remove(token);
        }
        if emptied_count > 0 {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.registrations_active.sub(emptied_count);
            }
        }
        for aor in deregistered {
            self.emit_event(RegistrationEvent::Deregistered { aor });
        }

        removed
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
                        && c.kind == ContactKind::Ue
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
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: Vec::new(),
            kind: ContactKind::Ue,
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
    /// Reap expired bindings, cascade-clear AS contacts left orphaned by
    /// an expired UE, and emit [`RegistrationEvent::Expired`] for every
    /// AoR that drained to empty.  Only removes entries whose own
    /// `expires` has already elapsed, so it is safe to run on a periodic
    /// tick — an actively-refreshing binding has a future `expires` and is
    /// never touched.  Returns the number of AoRs reaped (drained to
    /// empty) so callers can log/meter the sweep.
    pub fn expire_stale(&self) -> usize {
        let mut empty_aors = Vec::new();
        let mut tokens_to_remove: Vec<String> = Vec::new();
        let mut conns_to_deindex: Vec<(u64, String)> = Vec::new();
        for mut entry in self.bindings.iter_mut() {
            let aor_key = entry.key().clone();
            let before = entry.value().len();
            entry.value_mut().retain(|c| {
                if c.is_expired() {
                    if let Some(token) = &c.flow_token {
                        tokens_to_remove.push(token.clone());
                    }
                    if is_stream_transport(c.source_transport.as_deref()) {
                        if let Some(id) = c.inbound_connection_id {
                            conns_to_deindex.push((id, aor_key.clone()));
                        }
                    }
                    false
                } else {
                    true
                }
            });
            // Cascade-clear AS contacts whose UE has expired out from
            // under them.  Keeps reginfo NOTIFY honest after the GC
            // pass.
            let any_ue_left = entry
                .value()
                .iter()
                .any(|c| c.kind == ContactKind::Ue);
            if !any_ue_left {
                entry.value_mut().clear();
            }
            if entry.value().is_empty() && before > 0 {
                empty_aors.push(entry.key().clone());
            }
        }
        for token in &tokens_to_remove {
            self.tokens.remove(token);
        }
        for (id, aor) in &conns_to_deindex {
            self.deindex_connection(*id, aor);
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
        empty_aors.len()
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
    /// AoR is not safe to use as a storage key (collides with the reserved
    /// `state:` namespace or contains control characters).
    InvalidAor,
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
            RegistrarError::InvalidAor => {
                write!(f, "invalid AoR (unsafe storage key)")
            }
        }
    }
}

/// Whether an AoR is safe to use as a registrar storage key.
///
/// The Redis contact key is `{prefix}{aor}` and the auxiliary-state key is
/// `{prefix}state:{aor}`. An AoR beginning with `state:` would collide a contact
/// binding into the reserved state namespace (stealth binding / restore
/// confusion); control characters enable log injection (the AoR is logged) and
/// produce malformed keys. `normalize_aor` always prepends `sip:`/`sips:`, which
/// already prevents the `state:` collision — this makes that invariant explicit
/// and enforced at the write boundary so it cannot silently regress.
pub fn is_aor_key_safe(aor: &str) -> bool {
    !aor.starts_with("state:") && !aor.bytes().any(|byte| byte.is_ascii_control())
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
    fn aor_key_safety_rejects_state_namespace_and_control_chars() {
        // Normal AoRs (scheme-prefixed and bare) are safe.
        assert!(is_aor_key_safe("sip:alice@example.com"));
        assert!(is_aor_key_safe("sips:alice@example.com"));
        assert!(is_aor_key_safe("alice@example.com"));
        // Reserved aux-state namespace collision (F7): a contact key must never
        // start with `state:`.
        assert!(!is_aor_key_safe("state:victim@example.com"));
        // Control characters (CR/LF/tab/NUL) — log injection + malformed keys.
        assert!(!is_aor_key_safe("alice\r\n@example.com"));
        assert!(!is_aor_key_safe("alice\t@example.com"));
        assert!(!is_aor_key_safe("alice\0@example.com"));
    }

    /// Save a binding tagged with a transport + inbound connection id, the way
    /// a REGISTER arriving over a stream transport (or UDP) populates the flow
    /// reverse indexes.
    fn save_flow(
        registrar: &Registrar,
        aor: &str,
        user: &str,
        host: &str,
        transport: &str,
        connection_id: Option<u64>,
        call_id: &str,
    ) {
        registrar
            .save_full(
                aor,
                contact_uri(user, host),
                3600,
                1.0,
                call_id.into(),
                1,
                Some("192.0.2.10:5060".parse().unwrap()),
                Some(transport.to_string()),
                None,
                None,
                vec![],
                FlowCapture {
                    flow_token: None,
                    inbound_local_addr: None,
                    inbound_connection_id: connection_id,
                },
                Vec::new(),
            )
            .unwrap();
    }

    #[test]
    fn unregister_flow_removes_only_matching_connection() {
        let registrar = Registrar::default();
        // Two AoRs share inbound connection 7 (e.g. a PBX trunk multiplexing
        // registrations over one TCP socket); a third is on connection 8.
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        save_flow(&registrar, "sip:b@example.com", "b", "10.0.0.2", "tcp", Some(7), "c-b");
        save_flow(&registrar, "sip:c@example.com", "c", "10.0.0.3", "tcp", Some(8), "c-c");

        let removed = registrar.unregister_flow(7);
        assert_eq!(removed, 2);
        assert!(!registrar.is_registered("sip:a@example.com"));
        assert!(!registrar.is_registered("sip:b@example.com"));
        // Connection 8's binding is untouched.
        assert!(registrar.is_registered("sip:c@example.com"));
        // Index entry for 7 is consumed; a repeat call is a no-op.
        assert_eq!(registrar.unregister_flow(7), 0);
    }

    #[test]
    fn unregister_flow_ignores_udp_binding_with_colliding_id() {
        let registrar = Registrar::default();
        // A UDP binding whose deterministic ConnectionId happens to equal a
        // stream connection id must never be torn down by flow failure — UDP
        // has no closable socket.
        save_flow(&registrar, "sip:stream@example.com", "s", "10.0.0.1", "tcp", Some(7), "c-s");
        save_flow(&registrar, "sip:udp@example.com", "u", "10.0.0.2", "udp", Some(7), "c-u");

        let removed = registrar.unregister_flow(7);
        assert_eq!(removed, 1);
        assert!(!registrar.is_registered("sip:stream@example.com"));
        assert!(registrar.is_registered("sip:udp@example.com"));
    }

    #[test]
    fn unregister_flow_collect_returns_removed_bindings_and_keeps_service_route() {
        let registrar = Registrar::default();
        // A P-CSCF cache binding: stream transport, flow_token, on connection 77.
        registrar
            .save_full(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600,
                1.0,
                "c-a".into(),
                1,
                Some("192.0.2.10:5060".parse().unwrap()),
                Some("tcp".to_string()),
                None,
                None,
                vec![],
                FlowCapture {
                    flow_token: Some("tok-1".into()),
                    inbound_local_addr: None,
                    inbound_connection_id: Some(77),
                },
                Vec::new(),
            )
            .unwrap();
        registrar.set_service_routes("sip:alice@example.com", vec!["<sip:scscf;lr>".into()]);

        let removed = registrar.unregister_flow_collect(77);
        assert_eq!(removed.len(), 1);
        let (aor, contact) = &removed[0];
        assert_eq!(aor, "sip:alice@example.com");
        assert_eq!(
            contact.flow_token.as_deref(),
            Some("tok-1"),
            "removed binding must carry the flow_token so the cascade can target a P-CSCF cache"
        );
        assert!(!registrar.is_registered("sip:alice@example.com"));
        // Service-Route survives removal so the network-dereg can still resolve
        // the upstream S-CSCF next hop.
        assert_eq!(
            registrar.service_routes("sip:alice@example.com"),
            vec!["<sip:scscf;lr>".to_string()]
        );
        // Idempotent: the index entry is consumed.
        assert!(registrar.unregister_flow_collect(77).is_empty());
    }

    #[test]
    fn unregister_flow_unknown_id_is_noop() {
        let registrar = Registrar::default();
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        assert_eq!(registrar.unregister_flow(999), 0);
        assert!(registrar.is_registered("sip:a@example.com"));
    }

    #[test]
    fn unregister_flow_emits_deregistered_event() {
        let registrar = Registrar::default();
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tls", Some(42), "c-a");
        // Subscribe after the save so we only observe the deregistration.
        let mut events = registrar.subscribe_events();
        assert_eq!(registrar.unregister_flow(42), 1);
        match events.try_recv() {
            Ok(RegistrationEvent::Deregistered { aor }) => {
                assert_eq!(aor, "sip:a@example.com");
            }
            other => panic!("expected Deregistered, got {other:?}"),
        }
    }

    #[test]
    fn unregister_flow_removes_one_contact_keeps_siblings() {
        let registrar = Registrar::default();
        // Same AoR, two devices on two different connections.
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-1");
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.2", "tcp", Some(8), "c-2");

        assert_eq!(registrar.unregister_flow(7), 1);
        let contacts = registrar.lookup("sip:a@example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].uri.host, "10.0.0.2");
        // Connection 8 still indexed.
        assert_eq!(registrar.unregister_flow(8), 1);
        assert!(!registrar.is_registered("sip:a@example.com"));
    }

    #[test]
    fn connection_index_pruned_by_remove_all() {
        let registrar = Registrar::default();
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        registrar.remove_all("sip:a@example.com");
        // Index pruned: a later flow failure for the same id finds nothing.
        assert_eq!(registrar.unregister_flow(7), 0);
    }

    #[test]
    fn connection_index_pruned_by_remove_contact() {
        let registrar = Registrar::default();
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        registrar.remove_contact("sip:a@example.com", &contact_uri("a", "10.0.0.1").to_string());
        assert_eq!(registrar.unregister_flow(7), 0);
    }

    #[test]
    fn connection_index_pruned_by_expire_stale() {
        let registrar = Registrar::default();
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        // Age the binding out without sleeping.
        if let Some(mut entry) = registrar.bindings.get_mut("sip:a@example.com") {
            for contact in entry.value_mut().iter_mut() {
                contact.expires = Duration::ZERO;
            }
        }
        assert_eq!(registrar.expire_stale(), 1);
        assert_eq!(registrar.unregister_flow(7), 0);
    }

    #[test]
    fn connection_index_follows_refresh_to_new_connection() {
        let registrar = Registrar::default();
        // Same +sip.instance re-registers over a new connection (id 7 → 8).
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(7), "c-a");
        save_flow(&registrar, "sip:a@example.com", "a", "10.0.0.1", "tcp", Some(8), "c-a");
        // The old connection's failure no longer deregisters the refreshed binding.
        assert_eq!(registrar.unregister_flow(7), 0);
        assert!(registrar.is_registered("sip:a@example.com"));
        // The new connection's failure does.
        assert_eq!(registrar.unregister_flow(8), 1);
        assert!(!registrar.is_registered("sip:a@example.com"));
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
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: Vec::new(),
            kind: ContactKind::Ue,
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
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: Vec::new(),
            kind: ContactKind::Ue,
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
                flow_token: None,
                inbound_local_addr: None,
                inbound_connection_id: None,
                params: Vec::new(),
                kind: ContactKind::Ue,
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
                FlowCapture::default(),
                Vec::new(),
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
                FlowCapture::default(),
                Vec::new(),
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
                FlowCapture::default(),
                Vec::new(),
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

    // -----------------------------------------------------------------------
    // Path-token MT routing (RFC 3327 §5 / TS 24.229 §5.2.7.2)
    // -----------------------------------------------------------------------

    fn flow_capture(token: &str, local_port: u16, remote_port: u16) -> FlowCapture {
        FlowCapture {
            flow_token: Some(token.to_string()),
            inbound_local_addr: Some(format!("127.0.0.1:{local_port}").parse().unwrap()),
            inbound_connection_id: Some(0xfeed_face_dead_beef ^ remote_port as u64),
        }
    }

    #[test]
    fn save_with_flow_token_indexes_for_lookup() {
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                Some("10.0.0.1:5066".parse().unwrap()), Some("udp".into()),
                None, None, vec![],
                flow_capture("token-abc", 5066, 5066),
                Vec::new(),
            )
            .unwrap();

        let resolved = registrar.lookup_by_token("token-abc").expect("token resolves");
        assert_eq!(resolved.0, "sip:alice@ims.example.com");
        assert_eq!(resolved.1.flow_token.as_deref(), Some("token-abc"));
        assert_eq!(resolved.1.inbound_local_addr.unwrap().port(), 5066);
    }

    #[test]
    fn lookup_by_token_returns_none_for_unknown_token() {
        let registrar = Registrar::default();
        assert!(registrar.lookup_by_token("never-saved").is_none());
    }

    #[test]
    fn re_register_with_new_token_retires_old_index_entry() {
        // Same +sip.instance, fresh token: the new entry must resolve
        // and the old one must not — the swap happens inside the
        // bindings entry guard so there is no stale window.
        let registrar = Registrar::default();
        let instance = "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>".to_string();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, Some("udp".into()),
                Some(instance.clone()), None, vec![],
                flow_capture("token-old", 5066, 5066),
                Vec::new(),
            )
            .unwrap();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c2".into(), 2,
                None, Some("udp".into()),
                Some(instance), None, vec![],
                flow_capture("token-new", 5066, 5066),
                Vec::new(),
            )
            .unwrap();

        assert!(
            registrar.lookup_by_token("token-old").is_none(),
            "old token must be retired by the same-instance refresh"
        );
        assert!(
            registrar.lookup_by_token("token-new").is_some(),
            "new token must resolve to the refreshed binding"
        );
    }

    #[test]
    fn refresh_with_same_token_keeps_index_entry() {
        // A pure refresh (same token) must NOT race-clear its own
        // entry: the harvester removes the old token first, the new
        // insertion would be skipped if we naively deleted-then-inserted
        // when they're equal.  Test the invariant.
        let registrar = Registrar::default();
        let instance = "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>".to_string();
        for cseq in 1..=3 {
            registrar
                .save_full(
                    "sip:alice@ims.example.com",
                    contact_uri("alice", "10.0.0.1"),
                    3600, 1.0, format!("c{cseq}"), cseq,
                    None, Some("udp".into()),
                    Some(instance.clone()), None, vec![],
                    flow_capture("token-stable", 5066, 5066),
                    Vec::new(),
                )
                .unwrap();
            assert!(
                registrar.lookup_by_token("token-stable").is_some(),
                "refresh #{cseq} must keep token-stable resolvable"
            );
        }
    }

    #[test]
    fn expires_zero_deregister_prunes_token() {
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, Some("udp".into()),
                None, None, vec![],
                flow_capture("token-x", 5066, 5066),
                Vec::new(),
            )
            .unwrap();
        assert!(registrar.lookup_by_token("token-x").is_some());

        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                0, 1.0, "c2".into(), 2,                 // Expires: 0
                None, Some("udp".into()),
                None, None, vec![],
                FlowCapture::default(),                  // de-REGISTER carries no token
                Vec::new(),
            )
            .unwrap();
        assert!(
            registrar.lookup_by_token("token-x").is_none(),
            "Expires=0 deregister must prune the token from the reverse index"
        );
    }

    #[test]
    fn wildcard_remove_all_prunes_tokens() {
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, Some("udp".into()),
                None, None, vec![],
                flow_capture("tok-1", 5066, 5066),
                Vec::new(),
            )
            .unwrap();
        registrar.remove_all("sip:alice@ims.example.com");
        assert!(registrar.lookup_by_token("tok-1").is_none());
        assert!(registrar.tokens.is_empty());
    }

    #[test]
    fn expire_stale_prunes_tokens() {
        let registrar = Registrar::default();
        // Insert an already-expired contact directly into bindings (the
        // public save_full enforces min_expires); also wire its token
        // into the reverse index manually so we can verify the GC pass
        // unwires it.
        let aor = "sip:alice@ims.example.com".to_string();
        let stale = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now() - Duration::from_secs(7200),
            expires: Duration::from_secs(3600),
            call_id: "stale".into(),
            cseq: 1,
            source_addr: None,
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok-gc".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: Some(42),
            params: vec![],
            kind: ContactKind::Ue,
        };
        registrar.bindings.entry(aor.clone()).or_default().push(stale);
        registrar.tokens.insert("tok-gc".into(), aor);

        registrar.expire_stale();
        assert!(registrar.lookup_by_token("tok-gc").is_none());
        assert!(registrar.tokens.is_empty());
    }

    #[test]
    fn rebuild_token_index_recovers_after_load() {
        // Simulate the post-restore state: bindings carry flow_tokens
        // but the in-memory index is empty (as if just deserialized).
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com".to_string();
        let live = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: None,
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok-restored".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: Some(7),
            params: vec![],
            kind: ContactKind::Ue,
        };
        registrar.bindings.entry(aor.clone()).or_default().push(live);

        // Index empty before rebuild — lookup misses.
        assert!(registrar.lookup_by_token("tok-restored").is_none());

        registrar.rebuild_token_index();
        let resolved = registrar.lookup_by_token("tok-restored").expect("token now resolves");
        assert_eq!(resolved.0, aor);
    }

    #[test]
    fn rebuild_token_index_skips_expired_contacts() {
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com".to_string();
        let stale = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now() - Duration::from_secs(7200),
            expires: Duration::from_secs(3600),
            call_id: "stale".into(),
            cseq: 1,
            source_addr: None,
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok-expired".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: Some(7),
            params: vec![],
            kind: ContactKind::Ue,
        };
        registrar.bindings.entry(aor).or_default().push(stale);

        registrar.rebuild_token_index();
        assert!(registrar.lookup_by_token("tok-expired").is_none());
    }

    #[test]
    fn evict_connection_oriented_unwires_stream_tokens() {
        // Two bindings, one UDP (survives) and one TCP (evicted).  The
        // TCP token's index entry must be pruned; the UDP one stays.
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, Some("udp".into()),
                None, None, vec![],
                flow_capture("tok-udp", 5066, 5066),
                Vec::new(),
            )
            .unwrap();
        // Manually inject a TCP-tagged contact (transport=tcp on the URI)
        // — the public save funnel doesn't carry the URI param, so we
        // mutate the binding in place to model the real-world case where
        // a UE registered over TCP and the URI carries `;transport=tcp`.
        let tcp_contact = {
            let entry = registrar.bindings.get("sip:alice@ims.example.com").unwrap();
            let template = entry.value()[0].clone();
            drop(entry);
            let mut tcp = template.clone();
            tcp.uri.params.push(("transport".into(), Some("tcp".into())));
            tcp.flow_token = Some("tok-tcp".into());
            tcp.inbound_connection_id = Some(99);
            tcp
        };
        registrar
            .bindings
            .entry("sip:alice@ims.example.com".to_string())
            .or_default()
            .push(tcp_contact);
        registrar.tokens.insert("tok-tcp".into(), "sip:alice@ims.example.com".into());

        let evicted = registrar.evict_connection_oriented();
        assert_eq!(evicted, 1, "exactly one TCP binding must be evicted");

        assert!(
            registrar.lookup_by_token("tok-udp").is_some(),
            "UDP binding's token survives eviction"
        );
        assert!(
            registrar.lookup_by_token("tok-tcp").is_none(),
            "TCP binding's token is unwired by eviction"
        );
    }

    #[test]
    fn token_lookup_filters_expired_contact() {
        // Contact carrying a token expires lazily — lookup_by_token must
        // not return a `(aor, contact)` whose underlying contact is past
        // its TTL even before the GC pass runs.
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com".to_string();
        let stale = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now() - Duration::from_secs(7200),
            expires: Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: None,
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("tok".into()),
            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
            inbound_connection_id: Some(1),
            params: vec![],
            kind: ContactKind::Ue,
        };
        registrar.bindings.entry(aor.clone()).or_default().push(stale);
        registrar.tokens.insert("tok".into(), aor);

        assert!(
            registrar.lookup_by_token("tok").is_none(),
            "expired contact must be filtered by lookup_by_token"
        );
    }

    #[test]
    fn token_index_concurrent_inserts_thread_safe() {
        // Hammer save_full from multiple threads with distinct tokens.
        // Every token written must be resolvable at the end — verifies
        // DashMap-backed token index is genuinely concurrent-safe.
        use std::sync::Arc;
        use std::thread;

        let registrar = Arc::new(Registrar::default());
        let mut handles = Vec::new();
        for thread_id in 0..8 {
            let r = Arc::clone(&registrar);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let token = format!("tok-{thread_id}-{i}");
                    let aor = format!("sip:user{thread_id}_{i}@ims.example.com");
                    r.save_full(
                        &aor,
                        SipUri::new("10.0.0.1".to_string()).with_user(format!("u{thread_id}_{i}")),
                        3600, 1.0, format!("c{thread_id}-{i}"), 1,
                        None, Some("udp".into()),
                        None, None, vec![],
                        FlowCapture {
                            flow_token: Some(token),
                            inbound_local_addr: Some("127.0.0.1:5066".parse().unwrap()),
                            inbound_connection_id: Some(thread_id * 1000 + i),
                        },
                        Vec::new(),
                    ).unwrap();
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        for thread_id in 0..8 {
            for i in 0..50 {
                let token = format!("tok-{thread_id}-{i}");
                assert!(
                    registrar.lookup_by_token(&token).is_some(),
                    "concurrent insert lost token: {token}"
                );
            }
        }
    }

    #[test]
    fn flow_capture_default_leaves_contact_unflagged() {
        // A bare save (no flow_token) must produce a Contact with all
        // three flow fields = None — preserves the pre-feature semantics
        // for non-P-CSCF deployments.
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:alice@example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, None, None, None, vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();
        let contacts = registrar.lookup("sip:alice@example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].flow_token.is_none());
        assert!(contacts[0].inbound_local_addr.is_none());
        assert!(contacts[0].inbound_connection_id.is_none());
        assert!(registrar.tokens.is_empty());
    }

    // -----------------------------------------------------------------------
    // RFC 3840 Contact-header parameters (feature tags etc.)
    // -----------------------------------------------------------------------

    #[test]
    fn save_full_preserves_contact_params_through_lookup() {
        // Feature tags carried on the originating REGISTER's Contact must
        // round-trip into the stored binding so reg-event NOTIFY bodies
        // can surface them to watchers (RFC 3680 §5.3 + RFC 3840 §9).
        let registrar = Registrar::default();
        let params = vec![
            ("+g.3gpp.smsip".to_string(), None),
            (
                "+g.3gpp.icsi-ref".to_string(),
                Some("\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"".to_string()),
            ),
            ("+sip.rcs".to_string(), Some("\"true\"".to_string())),
        ];
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                3600, 1.0, "c1".into(), 1,
                None, None, None, None, vec![],
                FlowCapture::default(),
                params.clone(),
            )
            .unwrap();

        let contacts = registrar.lookup("sip:alice@ims.example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].params, params);
    }

    #[test]
    fn save_full_with_empty_params_yields_empty_vec() {
        // Pre-feature semantics: callers that don't care about params
        // pass `Vec::new()` and the stored Contact's `params` is empty
        // (not `None`, not a unit type — just an empty Vec).
        let registrar = Registrar::default();
        registrar
            .save_full(
                "sip:bob@ims.example.com",
                contact_uri("bob", "10.0.0.2"),
                3600, 1.0, "c1".into(), 1,
                None, None, None, None, vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();
        let contacts = registrar.lookup("sip:bob@ims.example.com");
        assert_eq!(contacts.len(), 1);
        assert!(contacts[0].params.is_empty());
    }

    #[test]
    fn save_full_refresh_replaces_params() {
        // Re-REGISTER with a different params set must replace, not
        // accumulate — an AS that drops a feature on refresh must not
        // see the old tag stick around (RFC 3261 §10.3 step 7: refresh
        // == replace).
        let registrar = Registrar::default();
        let instance =
            "<urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6>".to_string();
        registrar
            .save_full(
                "sip:carol@ims.example.com",
                contact_uri("carol", "10.0.0.3"),
                3600, 1.0, "c1".into(), 1,
                None, None,
                Some(instance.clone()), None, vec![],
                FlowCapture::default(),
                vec![("+g.3gpp.smsip".to_string(), None)],
            )
            .unwrap();
        registrar
            .save_full(
                "sip:carol@ims.example.com",
                contact_uri("carol", "10.0.0.3"),
                3600, 1.0, "c2".into(), 2,
                None, None,
                Some(instance), None, vec![],
                FlowCapture::default(),
                vec![("+g.3gpp.iari-ref".to_string(), Some("\"x\"".to_string()))],
            )
            .unwrap();
        let contacts = registrar.lookup("sip:carol@ims.example.com");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].params.len(), 1);
        assert_eq!(contacts[0].params[0].0, "+g.3gpp.iari-ref");
    }

    // -----------------------------------------------------------------------
    // AS-side contacts (TS 24.229 §5.4.2.1.2): capture, lookup filtering,
    // reginfo merge, cascade-clear.
    // -----------------------------------------------------------------------

    fn save_ue(registrar: &Registrar, aor: &str, user: &str, host: &str) {
        registrar
            .save_full(
                aor,
                contact_uri(user, host),
                3600, 1.0, format!("c-{user}"), 1,
                None, None, None, None, vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .expect("UE save should succeed");
    }

    #[test]
    fn save_as_contact_requires_ue_binding() {
        // TS 24.229 §5.4.2.1.2 ties the AS capability record's lifetime
        // to the registration.  Without a UE binding, refusing to write
        // the AS contact keeps reginfo emission honest.
        let registrar = Registrar::default();
        let as_uri = SipUri::new("ims.example.com".to_string())
            .with_user("mmtel".into());
        let saved = registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                as_uri,
                3600,
                1.0,
                vec![("+g.3gpp.smsip".to_string(), None)],
            )
            .unwrap();
        assert!(!saved, "save must refuse when no UE binding exists");
        assert!(registrar.lookup_all("sip:alice@ims.example.com").is_empty());
    }

    #[test]
    fn save_as_contact_stored_with_kind_as() {
        let registrar = Registrar::default();
        save_ue(&registrar, "sip:alice@ims.example.com", "alice", "10.0.0.1");

        let as_uri = SipUri::new("ims.example.com".to_string())
            .with_user("mmtel".into());
        let saved = registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                as_uri,
                3600,
                1.0,
                vec![
                    (
                        "+g.3gpp.icsi-ref".to_string(),
                        Some(
                            "\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\""
                                .to_string(),
                        ),
                    ),
                ],
            )
            .unwrap();
        assert!(saved);

        let merged = registrar.lookup_all("sip:alice@ims.example.com");
        assert_eq!(merged.len(), 2);
        // UE-first ordering — routing-priority view stays consistent.
        assert_eq!(merged[0].kind, ContactKind::Ue);
        assert_eq!(merged[1].kind, ContactKind::As);
        assert_eq!(merged[1].params.len(), 1);
        assert_eq!(merged[1].params[0].0, "+g.3gpp.icsi-ref");
    }

    #[test]
    fn lookup_excludes_as_contacts() {
        // A misrouted MT INVITE must never go to an AS — `lookup()` is
        // the routing path and must return UE-only.
        let registrar = Registrar::default();
        save_ue(&registrar, "sip:alice@ims.example.com", "alice", "10.0.0.1");
        registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                SipUri::new("ims.example.com".to_string()).with_user("mmtel".into()),
                3600, 1.0,
                vec![("+g.3gpp.smsip".to_string(), None)],
            )
            .unwrap();

        let routes = registrar.lookup("sip:alice@ims.example.com");
        assert_eq!(routes.len(), 1, "AS contact must be hidden from routing");
        assert_eq!(routes[0].kind, ContactKind::Ue);
    }

    #[test]
    fn save_as_contact_refresh_replaces_same_uri() {
        let registrar = Registrar::default();
        save_ue(&registrar, "sip:alice@ims.example.com", "alice", "10.0.0.1");

        let as_uri = SipUri::new("ims.example.com".to_string())
            .with_user("mmtel".into());

        registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                as_uri.clone(),
                3600, 1.0,
                vec![("+g.3gpp.smsip".to_string(), None)],
            )
            .unwrap();
        // Refresh with a different param set — must replace, not stack.
        registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                as_uri,
                3600, 1.0,
                vec![("+g.3gpp.iari-ref".to_string(), Some("\"x\"".to_string()))],
            )
            .unwrap();

        let merged = registrar.lookup_all("sip:alice@ims.example.com");
        let as_contacts: Vec<_> = merged
            .iter()
            .filter(|c| c.kind == ContactKind::As)
            .collect();
        assert_eq!(as_contacts.len(), 1, "same-URI AS save must replace");
        assert_eq!(as_contacts[0].params[0].0, "+g.3gpp.iari-ref");
    }

    #[test]
    fn save_as_contact_expires_zero_removes_only_named_as() {
        let registrar = Registrar::default();
        save_ue(&registrar, "sip:alice@ims.example.com", "alice", "10.0.0.1");

        let mmtel = SipUri::new("ims.example.com".to_string()).with_user("mmtel".into());
        let ipsmgw = SipUri::new("ims.example.com".to_string()).with_user("ipsmgw".into());

        registrar
            .save_as_contact("sip:alice@ims.example.com", mmtel.clone(), 3600, 1.0,
                vec![("+g.3gpp.smsip".to_string(), None)])
            .unwrap();
        registrar
            .save_as_contact("sip:alice@ims.example.com", ipsmgw, 3600, 1.0,
                vec![("+g.3gpp.smsip".to_string(), None)])
            .unwrap();

        // Targeted removal of just the mmtel AS contact.
        registrar
            .save_as_contact("sip:alice@ims.example.com", mmtel, 0, 1.0, vec![])
            .unwrap();

        let as_contacts: Vec<_> = registrar
            .lookup_all("sip:alice@ims.example.com")
            .into_iter()
            .filter(|c| c.kind == ContactKind::As)
            .collect();
        assert_eq!(as_contacts.len(), 1);
        assert!(as_contacts[0].uri.user.as_deref() == Some("ipsmgw"));
    }

    #[test]
    fn cascade_clear_when_last_ue_contact_deregs() {
        // Dereg path: when the only UE contact's Expires:0 lands, AS
        // capability records must vanish too — keeps reg-event NOTIFY
        // emitting a clean terminated registration.
        let registrar = Registrar::default();
        save_ue(&registrar, "sip:alice@ims.example.com", "alice", "10.0.0.1");
        registrar
            .save_as_contact(
                "sip:alice@ims.example.com",
                SipUri::new("ims.example.com".to_string()).with_user("mmtel".into()),
                3600, 1.0,
                vec![("+g.3gpp.smsip".to_string(), None)],
            )
            .unwrap();

        // UE de-REGISTER
        registrar
            .save_full(
                "sip:alice@ims.example.com",
                contact_uri("alice", "10.0.0.1"),
                0, 1.0, "c-dereg".into(), 2,
                None, None, None, None, vec![],
                FlowCapture::default(),
                Vec::new(),
            )
            .unwrap();

        assert!(registrar.lookup_all("sip:alice@ims.example.com").is_empty());
        assert!(!registrar.is_registered("sip:alice@ims.example.com"));
    }

    #[test]
    fn cascade_clear_when_ue_contact_expires_via_gc() {
        // expire_stale path: AS records must also drop when the UE
        // binding hits its TTL.
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com".to_string();

        // Inject an already-expired UE contact + a live AS record so
        // we can verify the cascade.
        let stale_ue = Contact {
            uri: contact_uri("alice", "10.0.0.1"),
            q: 1.0,
            registered_at: Instant::now() - Duration::from_secs(7200),
            expires: Duration::from_secs(3600),
            call_id: "c1".into(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: vec![],
            kind: ContactKind::Ue,
        };
        let live_as = Contact {
            uri: SipUri::new("ims.example.com".to_string()).with_user("mmtel".into()),
            q: 1.0,
            registered_at: Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: String::new(),
            cseq: 0,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: vec![("+g.3gpp.smsip".to_string(), None)],
            kind: ContactKind::As,
        };
        registrar
            .bindings
            .entry(aor.clone())
            .or_default()
            .extend([stale_ue, live_as]);

        registrar.expire_stale();
        assert!(registrar.lookup_all(&aor).is_empty());
    }

    #[test]
    fn aor_count_ignores_as_only_aors() {
        // An AoR populated only with AS records doesn't count as a
        // registered user.  Defends against externally manipulated
        // state too.
        let registrar = Registrar::default();
        let aor = "sip:alice@ims.example.com".to_string();
        let as_only = Contact {
            uri: SipUri::new("ims.example.com".to_string()).with_user("mmtel".into()),
            q: 1.0,
            registered_at: Instant::now(),
            expires: Duration::from_secs(3600),
            call_id: String::new(),
            cseq: 0,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            pending: false,
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: vec![],
            kind: ContactKind::As,
        };
        registrar.bindings.entry(aor).or_default().push(as_only);
        assert_eq!(registrar.aor_count(), 0);
    }
}
