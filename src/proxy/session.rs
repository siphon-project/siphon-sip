//! Proxy session — links a server transaction to its client transaction(s).
//!
//! When the proxy receives a request (creating a server transaction) and relays
//! it downstream (creating one or more client transactions), a [`ProxySession`]
//! ties them together. This replaces the manual `PendingBranch` / `retransmit_map`
//! approach with proper transaction-layer state.
//!
//! The [`ProxySessionStore`] provides concurrent lookup by both client key
//! (for response routing) and server key (for CANCEL propagation).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use dashmap::DashMap;
use pyo3::prelude::*;

use crate::proxy::fork::ForkAggregator;
use crate::sip::message::{Method, SipMessage};
use crate::transaction::key::TransactionKey;
use crate::transport::{ConnectionId, Transport};

// ---------------------------------------------------------------------------
// ClientBranch — per-fork-branch downstream info
// ---------------------------------------------------------------------------

/// Downstream destination info for a single client transaction branch.
#[derive(Debug, Clone)]
pub struct ClientBranch {
    /// Where the relayed request was sent.
    pub destination: SocketAddr,
    /// Transport used for the downstream leg.
    pub transport: Transport,
    /// Connection ID for the downstream leg.
    pub connection_id: ConnectionId,
}

// ---------------------------------------------------------------------------
// ProxySession
// ---------------------------------------------------------------------------

/// A proxy session linking an inbound (server) transaction to one or more
/// outbound (client) transactions.
#[derive(Debug, Clone)]
pub struct ProxySession {
    /// Server transaction key (from the inbound request's Via branch + method).
    pub server_key: TransactionKey,
    /// Client transaction key(s) — one per fork branch.
    pub client_keys: Vec<TransactionKey>,
    /// Where to send responses back to the UAC.
    pub source_addr: SocketAddr,
    /// Local socket the original inbound request arrived on.
    /// Required for IPsec sec-agree (3GPP TS 33.203 §7.4) — the
    /// relayed-back response must egress on the same SA's local
    /// endpoint.  Without this, the OutboundRouter falls back to the
    /// default UDP listener and the kernel's outbound XFRM policy
    /// (keyed on src=local_addr:port_s, dst=ue:port_c) doesn't match,
    /// so the response leaves in the clear.
    pub inbound_local_addr: SocketAddr,
    /// Connection ID for the original inbound transport.
    pub connection_id: ConnectionId,
    /// Transport type for the original inbound connection.
    pub transport: Transport,
    /// The original inbound request (for ACK generation, CANCEL, response building).
    pub original_request: SipMessage,
    /// Per-client-branch downstream destination info (for CANCEL forwarding).
    pub client_branches: HashMap<TransactionKey, ClientBranch>,
    /// Fork aggregator for multi-target forking (None for single-target relay).
    pub fork_aggregator: Option<Arc<Mutex<ForkAggregator>>>,
    /// Captured inbound flow per fork branch, parallel to the aggregator's
    /// branches.  `Some` means that branch is routed over the captured
    /// connection (RFC 5626 §5.3 connection reuse — the only way to reach a
    /// WebSocket UE) instead of DNS-resolving the URI.  Stored on the session so
    /// sequential forking (`start_next_fork_branch`) can recover the flow for
    /// branches started after the first.  `PyFlow` is plain data (no
    /// `Py<PyAny>`), so cloning it off the dispatcher thread is sound.
    pub fork_flows: Vec<Option<crate::script::api::registrar::PyFlow>>,
    /// Maps client transaction key → branch index in the ForkAggregator.
    pub branch_index_map: HashMap<TransactionKey, usize>,
    /// Whether `record_route()` was called by the script.
    pub record_routed: bool,
    /// When this session was created (for TTL-based cleanup).
    pub created_at: Instant,
    /// Per-relay on_reply Python callback (called with `(request, reply)`).
    pub on_reply_callback: Option<Py<PyAny>>,
    /// Per-relay on_failure Python callback (called with `(request, code, reason)`).
    pub on_failure_callback: Option<Py<PyAny>>,
    /// Set once a final response has been committed upstream for this server
    /// transaction by a reply-time reject (`reply.reject(code, reason)` from
    /// `@proxy.on_reply`).  After a reject we send `code reason` to the UAC and
    /// CANCEL the pending downstream branch(es); the CANCEL draws a `487` back
    /// on each branch.  Without a fork aggregator (the single-target relay case,
    /// e.g. the IMS P-CSCF), there is no `final_forwarded` guard, so this flag
    /// is what tells the response path to ABSORB that straggler `487` (already
    /// ACKed by the client transaction) instead of forwarding a second final
    /// response upstream.
    pub final_response_sent: bool,
}

impl ProxySession {
    /// Create a new session with no client keys yet.
    pub fn new(
        server_key: TransactionKey,
        source_addr: SocketAddr,
        inbound_local_addr: SocketAddr,
        connection_id: ConnectionId,
        transport: Transport,
        original_request: SipMessage,
        record_routed: bool,
    ) -> Self {
        Self {
            server_key,
            client_keys: Vec::new(),
            client_branches: HashMap::new(),
            fork_aggregator: None,
            fork_flows: Vec::new(),
            branch_index_map: HashMap::new(),
            source_addr,
            inbound_local_addr,
            connection_id,
            transport,
            original_request,
            record_routed,
            created_at: Instant::now(),
            on_reply_callback: None,
            on_failure_callback: None,
            final_response_sent: false,
        }
    }

    /// Add a client transaction key (one per relay/fork branch).
    pub fn add_client_key(&mut self, key: TransactionKey) {
        self.client_keys.push(key);
    }

    /// Register downstream destination info for a client branch.
    pub fn set_client_branch(&mut self, key: TransactionKey, branch: ClientBranch) {
        self.client_branches.insert(key, branch);
    }

    /// Get downstream destination info for a client branch.
    pub fn get_client_branch(&self, key: &TransactionKey) -> Option<&ClientBranch> {
        self.client_branches.get(key)
    }

    /// Clone the per-relay `on_reply` / `on_failure` Python callbacks for use
    /// on the response path.
    ///
    /// Free-threaded CPython (3.14t / PEP 703, pyo3 0.28) requires the calling
    /// thread to be *attached* to the interpreter before a `Py<…>` refcount may
    /// be touched: `Py::clone` panics with "Cannot clone pointer into Python
    /// heap without the thread being attached" whenever it runs on a
    /// dispatcher/executor worker that is not currently inside a
    /// `Python::attach` scope. The dispatcher lifts these callbacks out of the
    /// session read-guard on exactly such a worker, so the bare `Clone` impl is
    /// unsound there. Clone through a `Python` token instead — matching the
    /// request path (`script::handle::call_handler`, which uses `clone_ref`).
    pub fn clone_relay_callbacks(&self) -> (Option<Py<PyAny>>, Option<Py<PyAny>>) {
        Python::attach(|python| {
            (
                self.on_reply_callback
                    .as_ref()
                    .map(|callback| callback.clone_ref(python)),
                self.on_failure_callback
                    .as_ref()
                    .map(|callback| callback.clone_ref(python)),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// ProxySessionStore
// ---------------------------------------------------------------------------

/// Concurrent store for proxy sessions with three lookup indices.
///
/// - **Primary index**: client transaction key → session (for response routing).
/// - **Reverse index**: server transaction key → list of client keys (for CANCEL).
/// - **Call-ID index**: SIP Call-ID → session (for ACK-2xx routing).
#[derive(Debug)]
pub struct ProxySessionStore {
    /// client_key → session.
    by_client_key: DashMap<TransactionKey, Arc<RwLock<ProxySession>>>,
    /// server_key → list of client keys.
    server_to_clients: DashMap<TransactionKey, Vec<TransactionKey>>,
    /// SIP dialog key (Call-ID + From-tag) → session (for ACK-2xx routing).
    /// Using Call-ID alone is ambiguous when both legs of a B2BUA call
    /// (e.g. caller→proxy→FS and FS→proxy→callee) share the same Call-ID.
    by_dialog_key: DashMap<String, Arc<RwLock<ProxySession>>>,
}

impl ProxySessionStore {
    pub fn new() -> Self {
        Self {
            by_client_key: DashMap::new(),
            server_to_clients: DashMap::new(),
            by_dialog_key: DashMap::new(),
        }
    }

    /// Insert a session, indexing it by all its client keys, server key, and dialog key.
    ///
    /// Returns the shared `Arc<RwLock<ProxySession>>` so the caller can mutate
    /// the session directly without re-querying the store.  This matters
    /// because the store entries can be removed (e.g. by `remove_client_key`
    /// after the final response forwards) between insert and any subsequent
    /// mutation — a store-side lookup would then miss and silently drop the
    /// update.
    ///
    /// `by_dialog_key` is populated with `or_insert_with` rather than a plain
    /// `insert` so that the FIRST writer for a given `(Call-ID, From-tag)`
    /// wins — i.e. the dialog-establishing INVITE.  Subsequent in-dialog
    /// requests (BYE, re-INVITE, UPDATE) routed through the script's
    /// `request.relay()` create their own per-transaction `ProxySession`,
    /// and without this guard their insert would overwrite the INVITE's
    /// dialog-key entry mid-call.  Under TCP at high CPS, the UAC sends
    /// ACK and BYE back-to-back; the BYE's `relay_request` can land its
    /// `session_store.insert(...)` before the in-flight ACK's
    /// `handle_ack_via_session` finishes its `by_dialog_key` lookup, so
    /// the ACK then iterates the BYE-session's `client_branches` (which
    /// holds `placeholder_connection_id = inbound.connection_id`, i.e.
    /// the UAC's inbound TCP `connection_id`) and routes the ACK back
    /// over the UAC's own socket.  Sipp logs that as "ACK CSeq value
    /// does NOT match value of related INVITE CSeq -- aborting call"
    /// and drops the subsequent BYE 200 OK as un-mappable, surfacing as
    /// the documented ~0.025 % Proxy/TCP FailedCall rate.
    pub fn insert(&self, session: ProxySession) -> Arc<RwLock<ProxySession>> {
        let server_key = session.server_key.clone();
        let client_keys: Vec<TransactionKey> = session.client_keys.clone();
        let dialog_key = Self::invite_dialog_key(&session.original_request);
        let session_arc = Arc::new(RwLock::new(session));

        for client_key in &client_keys {
            self.by_client_key
                .insert(client_key.clone(), Arc::clone(&session_arc));
        }

        if let Some(dk) = dialog_key {
            self.by_dialog_key
                .entry(dk)
                .or_insert_with(|| Arc::clone(&session_arc));
        }

        self.server_to_clients
            .entry(server_key)
            .and_modify(|existing| {
                for key in &client_keys {
                    if !existing.contains(key) {
                        existing.push(key.clone());
                    }
                }
            })
            .or_insert(client_keys);

        session_arc
    }

    /// Pre-insert a session for a fork *before* any branch has been registered.
    ///
    /// Returns the shared `Arc` that callers must pass to
    /// [`Self::register_fork_branch`] for each branch. This split exists so
    /// that the response handler can find the session via `by_client_key`
    /// *before* the network bytes go out — otherwise a fast peer (loopback,
    /// LAN) can deliver a response before the post-send registration finishes,
    /// stranding the call as "response for unknown branch".
    pub fn insert_for_fork(&self, session: ProxySession) -> Arc<RwLock<ProxySession>> {
        let server_key = session.server_key.clone();
        let dialog_key = Self::invite_dialog_key(&session.original_request);
        let session_arc = Arc::new(RwLock::new(session));
        if let Some(dk) = dialog_key {
            // Only an INVITE reaches here (see `invite_dialog_key`).  Keep
            // `or_insert_with` so a re-INVITE that arrives before the original
            // dialog-key entry was aged out doesn't displace it.
            self.by_dialog_key
                .entry(dk)
                .or_insert_with(|| Arc::clone(&session_arc));
        }
        self.server_to_clients.entry(server_key).or_default();
        session_arc
    }

    /// Register a fork branch's client transaction key against a pre-inserted
    /// session arc. MUST be called before the branch's request is sent on the
    /// wire so the response handler can locate the session via `by_client_key`.
    pub fn register_fork_branch(
        &self,
        session_arc: &Arc<RwLock<ProxySession>>,
        server_key: &TransactionKey,
        client_key: TransactionKey,
        branch: ClientBranch,
        branch_index: usize,
    ) {
        if let Ok(mut session) = session_arc.write() {
            session.add_client_key(client_key.clone());
            session.set_client_branch(client_key.clone(), branch);
            session.branch_index_map.insert(client_key.clone(), branch_index);
        }
        self.by_client_key
            .insert(client_key.clone(), Arc::clone(session_arc));
        self.server_to_clients
            .entry(server_key.clone())
            .and_modify(|keys| {
                if !keys.contains(&client_key) {
                    keys.push(client_key.clone());
                }
            })
            .or_insert_with(|| vec![client_key]);
    }

    /// Update the `connection_id` recorded for a registered fork branch.
    /// Called after `send_to_target` returns the actual connection id (may
    /// differ from the placeholder used at pre-registration time for TCP/TLS).
    pub fn update_branch_connection_id(
        &self,
        client_key: &TransactionKey,
        connection_id: ConnectionId,
    ) {
        if let Some(arc) = self.by_client_key.get(client_key) {
            if let Ok(mut session) = arc.write() {
                if let Some(branch) = session.client_branches.get_mut(client_key) {
                    branch.connection_id = connection_id;
                }
            }
        }
    }

    /// Add a client key to an existing session (for fork branches added after initial insert).
    pub fn add_client_key(
        &self,
        server_key: &TransactionKey,
        client_key: TransactionKey,
    ) -> bool {
        // Find the session via any existing client key for this server
        let session_arc = match self.server_to_clients.get(server_key) {
            Some(keys) => {
                if let Some(first) = keys.first() {
                    self.by_client_key.get(first).map(|e| Arc::clone(e.value()))
                } else {
                    None
                }
            }
            None => None,
        };

        let session_arc = match session_arc {
            Some(arc) => arc,
            None => return false,
        };

        // Update session
        if let Ok(mut session) = session_arc.write() {
            session.add_client_key(client_key.clone());
        }

        // Update indices
        self.by_client_key
            .insert(client_key.clone(), session_arc);
        self.server_to_clients
            .entry(server_key.clone())
            .and_modify(|keys| {
                if !keys.contains(&client_key) {
                    keys.push(client_key.clone());
                }
            })
            .or_insert_with(|| vec![client_key]);

        true
    }

    /// Look up a session by client transaction key.
    pub fn get_by_client_key(
        &self,
        client_key: &TransactionKey,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        self.by_client_key
            .get(client_key)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a session by its server transaction key.
    ///
    /// Returns the session via the first client key registered for this server key.
    pub fn get_by_server_key(
        &self,
        server_key: &TransactionKey,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        let client_keys = self.server_to_clients.get(server_key)?;
        let first_client_key = client_keys.first()?;
        self.by_client_key
            .get(first_client_key)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Look up a session by dialog key (Call-ID + From-tag) for ACK-2xx routing.
    pub fn get_by_dialog_key(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Option<Arc<RwLock<ProxySession>>> {
        let key = format!("{}\0{}", call_id, from_tag);
        self.by_dialog_key
            .get(&key)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Get all client keys for a given server transaction key.
    pub fn get_client_keys_for_server(
        &self,
        server_key: &TransactionKey,
    ) -> Option<Vec<TransactionKey>> {
        self.server_to_clients
            .get(server_key)
            .map(|entry| entry.value().clone())
    }

    /// Remove a session by its server key, cleaning up all indices.
    pub fn remove_by_server_key(&self, server_key: &TransactionKey) {
        if let Some((_, client_keys)) = self.server_to_clients.remove(server_key) {
            // Remove dialog key index entry via the session's original request
            if let Some(first) = client_keys.first() {
                if let Some(session_ref) = self.by_client_key.get(first) {
                    if let Ok(session) = session_ref.value().read() {
                        if let Some(dk) = Self::invite_dialog_key(&session.original_request) {
                            self.by_dialog_key.remove(&dk);
                        }
                    }
                }
            }
            for client_key in &client_keys {
                self.by_client_key.remove(client_key);
            }
        }
    }

    /// Drop only the `by_dialog_key` index entry for a request's dialog,
    /// leaving the `by_client_key` / `server_to_clients` indices intact.
    ///
    /// Used when an INVITE is rejected from the reply path
    /// (`reply.reject()` → no dialog is ever established): the `by_dialog_key`
    /// entry exists solely to route the end-to-end 2xx ACK, which now can never
    /// arrive, so it is dead.  Leaving it would let a stray/non-compliant ACK
    /// (To-tag present, R-URI pointing at the proxy) match the rejected call's
    /// dialog and reach `handle_ack_via_session`.  The client-key indices stay
    /// so the CANCEL's `487` straggler is still matched and absorbed.
    ///
    /// No-op for non-INVITE requests (they create no `by_dialog_key` entry).
    pub fn remove_dialog_key(&self, request: &SipMessage) {
        if let Some(dialog_key) = Self::invite_dialog_key(request) {
            self.by_dialog_key.remove(&dialog_key);
        }
    }

    /// Remove a single client key from the store.
    ///
    /// If the session has no remaining client keys, removes the session entirely.
    /// Returns `true` if a session was found and the key removed.
    pub fn remove_client_key(&self, client_key: &TransactionKey) -> bool {
        let session_arc = match self.by_client_key.remove(client_key) {
            Some((_, arc)) => arc,
            None => return false,
        };

        let server_key = {
            let session = match session_arc.read() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    tracing::error!("proxy session RwLock poisoned in remove_client_key, recovering");
                    poisoned.into_inner()
                }
            };
            session.server_key.clone()
        };

        // Update reverse index
        let mut should_remove_server = false;
        self.server_to_clients.entry(server_key.clone()).and_modify(|keys| {
            keys.retain(|key| key != client_key);
            if keys.is_empty() {
                should_remove_server = true;
            }
        });

        if should_remove_server {
            self.server_to_clients.remove(&server_key);
        }

        true
    }

    /// Sweep sessions older than `ttl`, returning the number removed.
    pub fn sweep_stale(&self, ttl: std::time::Duration) -> usize {
        let now = Instant::now();
        let mut stale_server_keys = Vec::new();

        // Find stale sessions by checking any client key's session
        for entry in self.by_client_key.iter() {
            if let Ok(session) = entry.value().read() {
                if now.duration_since(session.created_at) > ttl {
                    let server_key = session.server_key.clone();
                    if !stale_server_keys.contains(&server_key) {
                        stale_server_keys.push(server_key);
                    }
                }
            }
        }

        let count = stale_server_keys.len();
        for server_key in &stale_server_keys {
            self.remove_by_server_key(server_key);
        }

        // Age out orphaned `by_dialog_key` entries.  On a completed call the
        // 2xx final response drives `remove_client_key`, which drops the
        // session's `by_client_key` rows but deliberately leaves the
        // `by_dialog_key` entry alive so the end-to-end 2xx ACK can still be
        // routed (`get_by_dialog_key` → `handle_ack_via_session`).  The loop
        // above can only discover sessions that still have a `by_client_key`
        // row, so it never reaches these orphans — without this pass each one
        // pins a full cloned INVITE (`ProxySession::original_request`) for the
        // process lifetime, an unbounded per-answered-call heap leak that is
        // invisible to `session_count()` (which counts `server_to_clients`).
        // The 2xx ACK always lands within the transaction timeout, so aging
        // these by the same `ttl` (measured from `created_at`) is safe — after
        // that window the dialog-key entry is dead weight (in-dialog requests
        // route via loose routing, not `by_dialog_key`).
        let mut stale_dialog_keys = Vec::new();
        for entry in self.by_dialog_key.iter() {
            if let Ok(session) = entry.value().read() {
                if now.duration_since(session.created_at) > ttl {
                    stale_dialog_keys.push(entry.key().clone());
                }
            }
        }
        for dialog_key in &stale_dialog_keys {
            self.by_dialog_key.remove(dialog_key);
        }

        count + stale_dialog_keys.len()
    }

    /// Number of sessions (counted by unique server keys).
    pub fn session_count(&self) -> usize {
        self.server_to_clients.len()
    }

    /// Number of client key entries.
    pub fn client_key_count(&self) -> usize {
        self.by_client_key.len()
    }

    /// Number of dialog-key entries (Call-ID + From-tag → session).
    ///
    /// Distinct from [`session_count`](Self::session_count): a completed call's
    /// `by_dialog_key` entry outlives its `server_to_clients` row (kept for 2xx
    /// ACK routing), so this is the count to watch for the dialog-key leak.
    pub fn dialog_key_count(&self) -> usize {
        self.by_dialog_key.len()
    }

    /// Build a dialog key (Call-ID + From-tag) from a SIP message.
    ///
    /// Returns `None` if Call-ID or From tag is missing.
    fn dialog_key_from_message(msg: &SipMessage) -> Option<String> {
        let call_id = msg.headers.get("Call-ID")?;
        let from_tag = msg
            .typed_from()
            .ok()
            .flatten()
            .and_then(|na| na.tag)?;
        Some(format!("{}\0{}", call_id, from_tag))
    }

    /// Dialog key, but only for INVITE requests.
    ///
    /// `by_dialog_key` exists solely to route the end-to-end 2xx ACK, and only
    /// an INVITE's 2xx is ACKed.  Populating it for non-INVITE in-dialog
    /// requests (BYE, UPDATE, …) is both unnecessary (they are loose-routed)
    /// and a leak: each such request builds its own per-transaction
    /// `ProxySession`, and after its client key is removed on the final
    /// response its `by_dialog_key` entry is orphaned exactly like the INVITE's
    /// was.  Restricting population to INVITE also subsumes the older
    /// `or_insert_with` race guard — a BYE can no longer touch the entry at all,
    /// so it cannot displace the INVITE's mid-call.
    fn invite_dialog_key(msg: &SipMessage) -> Option<String> {
        if matches!(msg.method(), Some(Method::Invite)) {
            Self::dialog_key_from_message(msg)
        } else {
            None
        }
    }
}

impl Default for ProxySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::builder::SipMessageBuilder;
    use crate::sip::message::Method;
    use crate::sip::uri::SipUri;

    fn dummy_request() -> SipMessage {
        // INVITE so `by_dialog_key` is populated (it is INVITE-only — see
        // `invite_dialog_key`); the store keys themselves are method-agnostic.
        SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv".to_string())
            .to("<sip:example.com>".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("session-test".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap()
    }

    fn server_key() -> TransactionKey {
        TransactionKey::new("z9hG4bK-srv".to_string(), Method::Options, "10.0.0.1:5060".to_string())
    }

    fn client_key(suffix: &str) -> TransactionKey {
        TransactionKey::new(format!("z9hG4bK-cli-{suffix}"), Method::Options, "10.0.0.1:5060".to_string())
    }

    fn source_addr() -> SocketAddr {
        "10.0.0.1:5060".parse().unwrap()
    }

    fn local_addr() -> SocketAddr {
        "127.0.0.1:5060".parse().unwrap()
    }

    fn make_session() -> ProxySession {
        let mut session = ProxySession::new(
            server_key(),
            source_addr(),
            local_addr(),
            ConnectionId::default(),
            Transport::Udp,
            dummy_request(),
            false,
        );
        session.add_client_key(client_key("1"));
        session
    }

    // -- ProxySession tests --

    #[test]
    fn session_construction() {
        let session = make_session();
        assert_eq!(session.server_key, server_key());
        assert_eq!(session.client_keys.len(), 1);
        assert_eq!(session.source_addr, source_addr());
        assert!(!session.record_routed);
        // A fresh session has not finalized a response — only a reply-time
        // reject sets this.
        assert!(!session.final_response_sent);
    }

    #[test]
    fn final_response_sent_flag_toggles() {
        let mut session = make_session();
        assert!(!session.final_response_sent);
        session.final_response_sent = true;
        assert!(session.final_response_sent);
    }

    #[test]
    fn session_add_client_keys() {
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        session.add_client_key(client_key("3"));
        assert_eq!(session.client_keys.len(), 3);
    }

    /// Regression: the dispatcher response path clones a session's per-relay
    /// `on_reply` / `on_failure` callbacks on a Python-executor worker that is
    /// NOT inside a `Python::attach` scope. On free-threaded CPython (3.14t,
    /// pyo3 0.28) a bare `Py::clone` from such a thread panics with "Cannot
    /// clone pointer into Python heap without the thread being attached" — and
    /// the panic check is thread-attachment based, so it reproduces on any
    /// build from a freshly spawned (never-attached) OS thread.
    /// `clone_relay_callbacks` must attach first; if it regresses to a bare
    /// clone, the worker thread panics and `join()` returns `Err` here.
    #[test]
    fn clone_relay_callbacks_from_unattached_worker_thread() {
        pyo3::Python::initialize();

        // Real Python callables, built while attached on this (main) thread.
        let (on_reply, on_failure): (Py<PyAny>, Py<PyAny>) = Python::attach(|python| {
            let reply = python
                .eval(c"lambda request, reply: None", None, None)
                .expect("compile on_reply lambda")
                .unbind();
            let failure = python
                .eval(c"lambda request, code, reason: None", None, None)
                .expect("compile on_failure lambda")
                .unbind();
            (reply, failure)
        });
        let original_reply_ptr = on_reply.as_ptr() as usize;

        let mut session = make_session();
        session.on_reply_callback = Some(on_reply);
        session.on_failure_callback = Some(on_failure);
        let session = Arc::new(session);

        // A freshly spawned OS thread has pyo3 ATTACH_COUNT == 0 — the exact
        // precondition the dispatcher worker hits when a relayed response
        // arrives.
        let worker = {
            let session = Arc::clone(&session);
            std::thread::spawn(move || {
                let (reply_callback, failure_callback) = session.clone_relay_callbacks();
                let cloned_reply_ptr = reply_callback.as_ref().map(|cb| cb.as_ptr() as usize);
                (
                    reply_callback.is_some(),
                    failure_callback.is_some(),
                    cloned_reply_ptr,
                )
            })
        };
        let (has_reply, has_failure, cloned_reply_ptr) = worker
            .join()
            .expect("clone_relay_callbacks panicked on an unattached worker thread");

        assert!(has_reply, "on_reply callback lost in cross-thread clone");
        assert!(has_failure, "on_failure callback lost in cross-thread clone");
        // `clone_ref` must alias the same Python object, not substitute a new one.
        assert_eq!(
            cloned_reply_ptr,
            Some(original_reply_ptr),
            "clone must reference the same callable object"
        );
    }

    // -- ProxySessionStore tests --

    #[test]
    fn store_insert_and_lookup_by_client_key() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let found = store.get_by_client_key(&client_key("1"));
        assert!(found.is_some());
        let session_arc = found.unwrap();
        let session = session_arc.read().unwrap();
        assert_eq!(session.server_key, server_key());
    }

    #[test]
    fn store_lookup_unknown_key_returns_none() {
        let store = ProxySessionStore::new();
        assert!(store.get_by_client_key(&client_key("unknown")).is_none());
    }

    #[test]
    fn store_server_to_client_lookup() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let client_keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(client_keys.len(), 1);
        assert_eq!(client_keys[0], client_key("1"));
    }

    #[test]
    fn store_multiple_client_keys() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        // Both client keys should find the same session
        let session1 = store.get_by_client_key(&client_key("1")).unwrap();
        let session2 = store.get_by_client_key(&client_key("2")).unwrap();
        assert!(Arc::ptr_eq(&session1, &session2));

        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn store_add_client_key_after_insert() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let added = store.add_client_key(&server_key(), client_key("2"));
        assert!(added);

        // New key should find the session
        let found = store.get_by_client_key(&client_key("2"));
        assert!(found.is_some());

        // Server-to-clients should have both keys
        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 2);

        // Session object should have both keys
        let session = store.get_by_client_key(&client_key("1")).unwrap();
        let session = session.read().unwrap();
        assert_eq!(session.client_keys.len(), 2);
    }

    #[test]
    fn store_add_client_key_unknown_server_returns_false() {
        let store = ProxySessionStore::new();
        let unknown = TransactionKey::new("z9hG4bK-nope".to_string(), Method::Options, "10.0.0.1:5060".to_string());
        assert!(!store.add_client_key(&unknown, client_key("x")));
    }

    #[test]
    fn store_remove_by_server_key() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        store.remove_by_server_key(&server_key());

        assert!(store.get_by_client_key(&client_key("1")).is_none());
        assert!(store.get_by_client_key(&client_key("2")).is_none());
        assert!(store.get_client_keys_for_server(&server_key()).is_none());
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
    }

    #[test]
    fn store_remove_client_key() {
        let store = ProxySessionStore::new();
        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        let removed = store.remove_client_key(&client_key("1"));
        assert!(removed);

        // Client key 1 should be gone, client key 2 should remain
        assert!(store.get_by_client_key(&client_key("1")).is_none());
        assert!(store.get_by_client_key(&client_key("2")).is_some());
        assert_eq!(store.client_key_count(), 1);

        // Server-to-clients should only have key 2
        let keys = store.get_client_keys_for_server(&server_key()).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], client_key("2"));
    }

    #[test]
    fn store_remove_last_client_key_removes_session() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        store.remove_client_key(&client_key("1"));

        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
        assert!(store.get_client_keys_for_server(&server_key()).is_none());
    }

    #[test]
    fn store_remove_unknown_client_key_returns_false() {
        let store = ProxySessionStore::new();
        assert!(!store.remove_client_key(&client_key("unknown")));
    }

    #[test]
    fn store_sweep_stale() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        // With a zero TTL, everything is stale
        let swept = store.sweep_stale(std::time::Duration::ZERO);
        assert_eq!(swept, 1);
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);
    }

    #[test]
    fn store_sweep_preserves_fresh() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        // With a large TTL, nothing is stale
        let swept = store.sweep_stale(std::time::Duration::from_secs(3600));
        assert_eq!(swept, 0);
        assert_eq!(store.session_count(), 1);
    }

    /// Regression: a completed call leaves an orphaned `by_dialog_key` entry
    /// (kept for 2xx ACK routing) that the by_client_key-driven sweep can't
    /// reach.  Without the dedicated age-out pass it pins a cloned INVITE for
    /// the process lifetime — an unbounded, un-gauged per-answered-call leak.
    #[test]
    fn store_sweep_reclaims_orphaned_dialog_key_after_completed_call() {
        let store = ProxySessionStore::new();
        let session_arc = store.insert(make_session());

        assert_eq!(store.client_key_count(), 1);
        assert_eq!(store.session_count(), 1);
        assert_eq!(store.dialog_key_count(), 1);

        // 2xx final response → remove_client_key drops by_client_key and
        // server_to_clients but deliberately keeps by_dialog_key for the ACK.
        assert!(store.remove_client_key(&client_key("1")));
        assert_eq!(store.client_key_count(), 0);
        assert_eq!(store.session_count(), 0);
        // Orphaned dialog-key entry — invisible to session_count().
        assert_eq!(store.dialog_key_count(), 1);

        // Backdate creation past the ACK window so the sweep ages it out.
        session_arc.write().unwrap().created_at =
            std::time::Instant::now() - std::time::Duration::from_secs(60);

        let removed = store.sweep_stale(std::time::Duration::from_secs(32));
        assert_eq!(removed, 1, "orphaned dialog key must be reclaimed");
        assert_eq!(store.dialog_key_count(), 0);
    }

    /// A non-INVITE request (in-dialog BYE/UPDATE/etc.) must NOT create a
    /// dialog-key entry — only an INVITE's 2xx is ACKed via `by_dialog_key`.
    /// Otherwise each in-dialog request would orphan its own `ProxySession`.
    #[test]
    fn store_non_invite_does_not_create_dialog_key() {
        let bye = SipMessageBuilder::new()
            .request(Method::Bye, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-bye".to_string())
            .to("<sip:example.com>;tag=xyz".to_string())
            .from("<sip:user@example.com>;tag=abc".to_string())
            .call_id("bye-test".to_string())
            .cseq("2 BYE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let mut session = ProxySession::new(
            server_key(),
            source_addr(),
            local_addr(),
            ConnectionId::default(),
            Transport::Udp,
            bye,
            false,
        );
        session.add_client_key(client_key("1"));

        let store = ProxySessionStore::new();
        store.insert(session);

        assert_eq!(store.session_count(), 1);
        assert_eq!(
            store.dialog_key_count(),
            0,
            "non-INVITE request must not create a by_dialog_key entry"
        );
    }

    /// The dialog-key entry must survive a sweep while still fresh, so the
    /// end-to-end 2xx ACK can be routed via `get_by_dialog_key`.
    #[test]
    fn store_sweep_keeps_fresh_dialog_key_for_ack_routing() {
        let store = ProxySessionStore::new();
        store.insert(make_session());
        store.remove_client_key(&client_key("1"));
        assert_eq!(store.dialog_key_count(), 1);

        // Just created — must NOT be aged out (the ACK may still be in flight).
        let removed = store.sweep_stale(std::time::Duration::from_secs(32));
        assert_eq!(removed, 0);
        assert_eq!(store.dialog_key_count(), 1);
    }

    #[test]
    fn store_session_and_client_key_counts() {
        let store = ProxySessionStore::new();
        assert_eq!(store.session_count(), 0);
        assert_eq!(store.client_key_count(), 0);

        let mut session = make_session();
        session.add_client_key(client_key("2"));
        store.insert(session);

        assert_eq!(store.session_count(), 1);
        assert_eq!(store.client_key_count(), 2);
    }

    #[test]
    fn store_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ProxySessionStore::new());
        let mut handles = Vec::new();

        // Spawn threads that each insert a session
        for index in 0..10 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let server = TransactionKey::new(
                    format!("z9hG4bK-srv-{index}"),
                    Method::Options,
                    "10.0.0.1:5060".to_string(),
                );
                let client = TransactionKey::new(
                    format!("z9hG4bK-cli-{index}"),
                    Method::Options,
                    "10.0.0.1:5060".to_string(),
                );
                let mut session = ProxySession::new(
                    server,
                    source_addr(),
                    local_addr(),
                    ConnectionId::default(),
                    Transport::Udp,
                    dummy_request(),
                    false,
                );
                session.add_client_key(client);
                store.insert(session);
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.session_count(), 10);
        assert_eq!(store.client_key_count(), 10);
    }

    // -- get_by_server_key tests --

    #[test]
    fn store_get_by_server_key() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        let found = store.get_by_server_key(&server_key());
        assert!(found.is_some());
        let session_arc = found.unwrap();
        let session = session_arc.read().unwrap();
        assert_eq!(session.server_key, server_key());
        assert_eq!(session.client_keys.len(), 1);
    }

    #[test]
    fn store_get_by_server_key_unknown_returns_none() {
        let store = ProxySessionStore::new();
        let unknown = TransactionKey::new("z9hG4bK-nope".to_string(), Method::Options, "10.0.0.1:5060".to_string());
        assert!(store.get_by_server_key(&unknown).is_none());
    }

    // -- ClientBranch tests --

    #[test]
    fn session_client_branch_set_and_get() {
        let mut session = make_session();
        let key = client_key("1");
        session.set_client_branch(key.clone(), ClientBranch {
            destination: "10.0.0.2:5060".parse().unwrap(),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
        });

        let branch = session.get_client_branch(&key);
        assert!(branch.is_some());
        assert_eq!(branch.unwrap().destination, "10.0.0.2:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn session_client_branch_unknown_returns_none() {
        let session = make_session();
        assert!(session.get_client_branch(&client_key("unknown")).is_none());
    }

    // -- Fork aggregator integration tests --

    #[test]
    fn session_with_fork_aggregator() {
        use crate::proxy::fork::{ForkAggregator, ForkStrategy};
        use crate::sip::uri::SipUri;

        let mut session = ProxySession::new(
            server_key(),
            source_addr(),
            local_addr(),
            ConnectionId::default(),
            Transport::Udp,
            dummy_request(),
            false,
        );

        let targets = vec![
            SipUri::new("target1.example.com".to_string()),
            SipUri::new("target2.example.com".to_string()),
        ];
        let aggregator = Arc::new(Mutex::new(
            ForkAggregator::new(targets, ForkStrategy::Parallel),
        ));
        session.fork_aggregator = Some(Arc::clone(&aggregator));

        // Add two client branches with index mapping
        let key1 = client_key("1");
        let key2 = client_key("2");
        session.add_client_key(key1.clone());
        session.add_client_key(key2.clone());
        session.branch_index_map.insert(key1, 0);
        session.branch_index_map.insert(key2, 1);

        assert!(session.fork_aggregator.is_some());
        assert_eq!(session.branch_index_map.len(), 2);
        let agg = aggregator.lock().unwrap();
        assert_eq!(agg.branch_count(), 2);
    }

    #[test]
    fn session_without_fork_aggregator() {
        let session = make_session();
        assert!(session.fork_aggregator.is_none());
        assert!(session.branch_index_map.is_empty());
    }

    // -- Dialog key (Call-ID + From-tag) tests --

    #[test]
    fn store_dialog_key_lookup() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        // dummy_request() has Call-ID "session-test" and From tag "abc"
        let found = store.get_by_dialog_key("session-test", "abc");
        assert!(found.is_some());

        // Wrong From-tag should not match
        assert!(store.get_by_dialog_key("session-test", "wrong").is_none());

        // Wrong Call-ID should not match
        assert!(store.get_by_dialog_key("wrong", "abc").is_none());
    }

    #[test]
    fn store_dialog_key_disambiguates_same_call_id() {
        // Simulates a B2BUA (e.g. FreeSWITCH) that reuses the same Call-ID
        // for both call legs through the proxy.
        let store = ProxySessionStore::new();

        // Leg 1: caller → proxy → FS (From-tag = "caller-tag")
        let leg1_request = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("fs.local".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-leg1".to_string())
            .to("<sip:callee@example.com>".to_string())
            .from("<sip:caller@example.com>;tag=caller-tag".to_string())
            .call_id("shared-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let leg1_server = TransactionKey::new("z9hG4bK-leg1".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
        let leg1_client = TransactionKey::new("z9hG4bK-leg1-c".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
        let mut session1 = ProxySession::new(
            leg1_server.clone(),
            "10.0.0.1:5060".parse().unwrap(),
            local_addr(),
            ConnectionId::default(),
            Transport::Udp,
            leg1_request,
            false,
        );
        session1.add_client_key(leg1_client.clone());
        session1.set_client_branch(leg1_client.clone(), ClientBranch {
            destination: "10.0.0.2:5060".parse().unwrap(), // FreeSWITCH
            transport: Transport::Tcp,
            connection_id: ConnectionId::default(),
        });
        store.insert(session1);

        // Leg 2: FS → proxy → callee (same Call-ID, different From-tag = "fs-tag")
        let leg2_request = SipMessageBuilder::new()
            .request(Method::Invite, SipUri::new("callee.local".to_string()))
            .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-leg2".to_string())
            .to("<sip:callee@example.com>".to_string())
            .from("<sip:caller@example.com>;tag=fs-tag".to_string())
            .call_id("shared-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        let leg2_server = TransactionKey::new("z9hG4bK-leg2".to_string(), Method::Invite, "10.0.0.2:5060".to_string());
        let leg2_client = TransactionKey::new("z9hG4bK-leg2-c".to_string(), Method::Invite, "10.0.0.2:5060".to_string());
        let mut session2 = ProxySession::new(
            leg2_server.clone(),
            "10.0.0.2:5060".parse().unwrap(),
            local_addr(),
            ConnectionId::default(),
            Transport::Udp,
            leg2_request,
            false,
        );
        session2.add_client_key(leg2_client.clone());
        session2.set_client_branch(leg2_client.clone(), ClientBranch {
            destination: "10.0.0.3:5060".parse().unwrap(), // callee
            transport: Transport::Tls,
            connection_id: ConnectionId::default(),
        });
        store.insert(session2);

        // ACK from caller (From-tag = "caller-tag") should find Leg 1 → FS
        let found1 = store.get_by_dialog_key("shared-call-id", "caller-tag").unwrap();
        let s1 = found1.read().unwrap();
        let branch1 = s1.get_client_branch(&leg1_client).unwrap();
        assert_eq!(branch1.destination, "10.0.0.2:5060".parse::<SocketAddr>().unwrap());

        // ACK from FS (From-tag = "fs-tag") should find Leg 2 → callee
        let found2 = store.get_by_dialog_key("shared-call-id", "fs-tag").unwrap();
        let s2 = found2.read().unwrap();
        let branch2 = s2.get_client_branch(&leg2_client).unwrap();
        assert_eq!(branch2.destination, "10.0.0.3:5060".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn store_remove_cleans_dialog_key() {
        let store = ProxySessionStore::new();
        store.insert(make_session());

        assert!(store.get_by_dialog_key("session-test", "abc").is_some());
        store.remove_by_server_key(&server_key());
        assert!(store.get_by_dialog_key("session-test", "abc").is_none());
    }

    #[test]
    fn remove_dialog_key_drops_only_the_dialog_index() {
        // reply.reject() hygiene: a rejected INVITE forms no dialog, so its
        // by_dialog_key entry must be dropped — but the client-key index must
        // survive so the CANCEL's 487 straggler is still matched and absorbed.
        let store = ProxySessionStore::new();
        let session = make_session();
        let request = session.original_request.clone();
        let client = client_key("1");
        store.insert(session);

        assert!(store.get_by_dialog_key("session-test", "abc").is_some());
        assert!(store.get_by_client_key(&client).is_some());

        store.remove_dialog_key(&request);

        // Dialog index gone — a stray ACK can no longer match the dead dialog.
        assert!(store.get_by_dialog_key("session-test", "abc").is_none());
        // Client index intact — the 487 straggler still resolves to the session.
        assert!(store.get_by_client_key(&client).is_some());
    }
}
